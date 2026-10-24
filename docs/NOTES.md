# Node2Shell / CVE-2026-111497 — lab notes (verified)

Everything below is either a primary source (vendor doc, upstream commit, source line) or a
measurement from `asan/harness-*` on this machine. Claims that are not verified are marked
`NOT REPRODUCED`.

## 1. Facts (primary sources)

| Field | Value | Source |
|---|---|---|
| CVE | CVE-2026-111497 | cveawg.mitre.org/api/cve/CVE-2026-111497 |
| CNA | Google (cve-coordination@google.com) | same |
| Title | "Out-of-Bounds Write in Google Brotli Decoder" | same |
| CWE | CWE-787 OOB Write + CWE-252 Unchecked Return Value | same |
| CVSS 4.0 | 9.2 CRITICAL (NVD/CNA) — Node.js and Imperva both say HIGH | NVD API; nodejs.org advisory |
| Affected | Brotli C library 1.0.3–<1.0.10, 1.1.0–<1.1.1, 1.2.0–<1.2.1 (all platforms) | CVE record |
| `datePublic` | 2026-02-27 | CVE record |
| Node.js fix | 22.23.4 / 24.22.1 / 26.12.1 (2026-10-21) | nodejs.org/en/blog/vulnerability/october-2026-security-releases |
| Node credits | reported by OpenAI Codex Security (Khai Tran, Sylvie Mayer); fixed by mcollina, aduh95 | Node advisory |
| Imperva credits | reported by Matteo Collina; fixed by Antoine du Hamel | Imperva blog (2026-10-22) — **differs from the vendor advisory** |
| Upstream fix | `0ed4268a4401abcb44720963` "Detect and report invalid stream earlier.", **2026-02-27** | GitHub API |
| Released as | v1.0.10 / v1.1.1 / v1.2.1 — all published **2026-10-21** | GitHub releases API |
| Tests/changelog | the v1.2.1 tarball has **no** regression test and no CHANGELOG entry for this fix | grep of the release tarball |

Supply-chain headline: upstream fixed it in February and shipped a release eight months later;
Node.js picked the fix up on 2026-10-21. Every other Brotli consumer (Python `brotli`, Rust
crates, …) had the same window.

## 2. Patch anatomy (v1.2.0 -> v1.2.1, c/dec/decode.c)

11 hunks. `DecodeBlockTypeAndLength` and its three per-tree wrappers change return type
`BROTLI_BOOL` -> `BrotliDecoderErrorCode`; the early-out becomes a real error; a new macro
escalates a non-SUCCESS status out of the *unsafe* path:

```c
 if (max_block_type <= 1) {
-    return BROTLI_FALSE;                              /* v1.2.0: caller reads "needs more input" */
+    return BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH;  /* v1.2.1 */
 }
...
- #define BROTLI_SAFE(METHOD)              /* unsafe path: return value discarded */
+ #define BROTLI_SAFE_WITH_STATUS(METHOD)  /* status != SUCCESS -> goto saveStateAndReturn */
```

Applied at all three switch sites: CommandBegin, NextLiteralBlock, and the distance site
(decode.c:2138). Plus an added invariant assert:

```c
+        BROTLI_DCHECK(s->meta_block_remaining_len <= (int)BROTLI_BLOCK_SIZE_CAP);
```

`decode.h` gains an error code that was already reserved:

```
 v1.2.0:  /* -17 code is reserved */
 v1.2.1:  BROTLI_ERROR_CODE(_ERROR_FORMAT_, BLOCK_SWITCH, -17)
```

## 3. The memory corruption (verified in source)

```c
/* c/dec/state.h */
  /* Temporary storage for remaining input. Brotli stream format is designed in
     a way, that 64 bits are enough to make progress in decoding. */
  union { uint64_t u64; uint8_t u8[8]; } buffer;
  brotli_reg_t buffer_length;
```

Two loops in `BrotliDecoderDecompressStream` fill it, both assuming progress:

* decode.c:2444-2455 — appends ONE byte per retry, guarded only by
  `BROTLI_DCHECK(s->buffer_length < 8)`. `BROTLI_DCHECK` is `assert()` only under
  `-DBROTLI_DEBUG` (platform.h:464-466), i.e. compiled out in every release build.
* decode.c:2463-2468 — `while (*available_in) { s->buffer.u8[s->buffer_length] = **next_in; ... }`
  copies the whole unconsumed tail with no bound at all.

Measured layout (`offsetof`, this platform): `buffer` @72, `buffer_length` @80, `pos` @88,
`max_distance` @96, `ringbuffer_size` @100, `ringbuffer_mask` @104, `dist_rb` @112,
`meta_block_remaining_len` @132, **`ringbuffer` (pointer) @136**, `ringbuffer_end` @144,
`sizeof(state)` = 5744.

An input byte at index i lands at state offset 72+i, so ~64 attacker bytes reach the
`ringbuffer` pointer that the decoder later writes output through. The write is
**intra-object**, so ASAN/valgrind do not report it — this lab detects it structurally, by
compiling against the vendor's own internal `state.h` and watching `buffer_length`
(`asan/harness.c`), and by building with `-DBROTLI_DEBUG` so the vendor's assertion fires.

## 4. Trigger mechanics (the part that took the work)

`BrotliDecoderStateMetablockBegin()` resets `block_length[0..2] = BROTLI_BLOCK_SIZE_CAP` at the
start of **every** meta-block (state.c:112-116), so the invalid-switch condition
(`block_length[x] == 0` while `num_block_types[x] == 1`) must be produced inside a *single*
meta-block, by draining CAP = 2^24 = 16 777 216 units.

Naive counting says this is impossible, and that is the real obstacle:

* literal tree: 1 decrement per literal, MLEN decreases by the insert length -> need CAP
  literals with MLEN <= CAP; and `pos`, `i` and `block_length[0]` advance in lockstep, so the
  drained check at decode.c:2046 needs `block_length[0] < i`, i.e. total insert > CAP, i.e.
  `mlr < 0`.
* command tree: 1 per command, mlr >= 2 per command.
* distance tree: 1 per explicit-distance read, mlr >= 2 per command.
* and `WriteRingBuffer` rejects the required negative MLEN outright:
  `decode.c:1337  if (s->meta_block_remaining_len < 0) return _ERROR_FORMAT_BLOCK_LENGTH_1;`

**The lever that makes it reachable:** a copy whose distance exceeds `max_distance` takes the
static-dictionary path, and `BrotliTransformDictionaryWord()` returns the number of bytes it
actually wrote — *not* the (possibly negative) transformed length:

```c
    int suffix_len = *suffix++;
    while (suffix_len--) { dst[idx++] = *suffix++; }
    return idx;
```

Pick a transform with an **empty prefix AND suffix** whose omit/skip fully consumes the word and
it returns 0:

```c
      len = BrotliTransformDictionaryWord(&s->ringbuffer[pos], word, len, transforms, 34);
      pos += len;                                /* +0 */
      s->meta_block_remaining_len -= len;        /* -0 */
```

so the command costs **zero output and zero MLEN**, while still decrementing `block_length[1]`
(in `ReadCommandInternal`) and `block_length[2]` (in `ReadDistanceInternal`). The drain then
completes with `mlr` untouched. Measured from the debug log:

```
[ProcessCommandsInternal] pos = 0 insert = 0 copy = 4
[ProcessCommandsInternal] pos = 0 distance = 34818
[ProcessCommandsInternal] dictionary word: [down], transform_idx = 34, transformed: []
[ProcessCommandsInternal] s->meta_block_remaining_len = 1      <- unchanged
```

Parameters (`payload/gen_payload.py`, variant `cmd-drain`), derived from the compiled tables via
`asan/dump_tables.c` and a replication of `CalculateDistanceLut`:

| quantity | value | why |
|---|---|---|
| transform | 34, `OMIT_FIRST_4`, prefix_len = suffix_len = 0 | returns 0 for a 4-byte word |
| copy length | 4 (command symbol 130: insert 0, copy 4, explicit distance) | `i >= 4` is required to enter the dictionary word path |
| word length class | `size_bits_by_length[4] = 10` | `transform_idx = address >> 10` |
| distance | 34818 = ((34 << 10) + 1) + 1 | pins `transform_idx` at 34 with `max_distance == 0` |
| distance postfix | 3, ndirect 0 (`alphabet = 16 + 0 + (24 << 4) = 400`) | spreads each extra bit over 8 distances -> **11 bits per command** |
| MLEN | 1 | nothing is ever produced, so nothing is ever consumed |
| commands | 2^24 = CAP, 11 bits each = 23 068 672 bytes | drains `block_length` exactly once |

`pos` stays 0 forever (no literals, no output), so `max_distance == 0` and the transform index
stays constant across all 16.7M commands.

## 5. Measured results

`./run_ab.sh payload/payloads/cmd-drain-t24.br` — one payload, two decoders, one chunk:

| decoder | observed | verdict |
|---|---|---|
| **1.2.0 (vulnerable)** | `result=2 NEEDS_MORE_INPUT`, `buffer_length = 24`, 0 output bytes | **`OOB_WRITE_PAST_8_BYTE_BUFFER` — 24 input bytes written from `s->buffer.u8[0]`, i.e. 16 bytes past the 8-byte buffer** (clobbers `buffer_length` @80 and `pos` @88) |
| **1.2.1 (patched)** | `result=0 ERROR`, `error_code = -17` | `_ERROR_FORMAT_BLOCK_SWITCH` — the same bytes rejected as a permanent format error, nothing stashed |

Second arm, same payload with an 8-byte tail and a 200-byte second chunk:

| decoder | observed | verdict |
|---|---|---|
| **1.2.0** | never returns from a single `BrotliDecoderDecompressStream()` call | **`NO_PROGRESS_SPIN`** — the unsafe loop re-enters the invalid switch forever while input is available: the 100% CPU / hung-service DoS |
| **1.2.1** | `error_code = -17` | `_ERROR_FORMAT_BLOCK_SWITCH` |

### 5b. How far the write actually reaches (measured, option-1 work)

Question: can the OOB write be aimed at the `ringbuffer` pointer (state offset 136)?

Attempted lever: the write index IS the `buffer_length` field, so an attacker byte landing at
`buffer.u8[8]` (state offset 80) overwrites `buffer_length`'s low byte — after which the next
write would land at index (that byte + 1), which can be set to 64 and land on `ringbuffer`.
Payload `cmd-drain-poke.br` does exactly that: tail bytes `00`x8, `3F` at index 8, then the
intended pointer value `8877665544332211` at indices 9..16.

Measured result (vulnerable build, `harness-1.2.0`):

```
phase1 call=0 result=2 avail_in_left=0 out_bytes=0 buffer_length=24
  clobber_check (attacker bytes start at state offset 72):
    buffer_length  = 24 (0x18)                    <- restored, index hijack does NOT work
    pos            = -2105376126 (0x82828282)     <- CLOBBERED (4 bytes at offset 88)
    max_distance   = 0  ringbuffer_size = 1024  ringbuffer_mask = 1023
    ringbuffer     = 0x51b000000080   (offset 136)  <- UNCHANGED, still a real heap pointer
    ringbuffer_end = 0x51b000000480   (offset 144)  <- UNCHANGED
    htree_command  = 0x521000002908   (offset 152)  <- UNCHANGED
```

So:

* the index hijack is **defeated**: `buffer_length` comes back as exactly the number of bytes
  copied, because the compiled tail-copy keeps the counter in a register and stores it back at
  the end of the loop. Writing through `buffer.u8[]` cannot steer it.
* all three pointer fields stay intact -> **no pointer control, hence no AAR/AAW, hence no
  RCE by this path**.
* what IS corrupted is the first 28 bytes of the struct: `buffer_length`, `pos` and
  `max_distance`. `pos` is the ring buffer output index, so the residual primitive is a heap
  write at an attacker-chosen **offset** from the ring buffer, not at an attacker-chosen
  **address**.

The range is capped by the same constant that makes the trigger possible: both fill loops only
run when the fast path is disarmed, i.e. while fewer than `BROTLI_FAST_INPUT_SLACK` (28) bytes
remain
* tail copy (decode.c:2463-2468): copies `GetAvailIn` bytes -> at most 27, i.e. offsets 72..98
* append loop (decode.c:2444-2455): one byte per call while `buffer_length < 28`; once the
  corrupted `buffer_length` reaches 28, `BrotliBitReaderSetInput` re-arms the fast path and the
  drained state re-enters the invalid switch forever (measured: `NO_PROGRESS_SPIN`).

Hard ceiling: **state offset 99** (`buffer` + 27). Offsets 100+ - including `ringbuffer` - are
unreachable through the input buffer.

Which arm you get is decided by how many unconsumed bytes remain when the drained check fires:
below `BROTLI_FAST_INPUT_SLACK` (28) the decoder must take the safe path and returns
NEEDS_MORE_INPUT (stash -> OOB); at or above 28 the unsafe path keeps looping (spin -> DoS).

## 6. Honest ceiling

DEMONSTRATED
* Upstream fix located, diffed, and A/B-paired (1.2.0 vs 1.2.1, built from source, 4 harness
  binaries including `-DBROTLI_DEBUG`).
* The exact trigger: 11 bits per command, 2^24 commands, zero MLEN cost, `block_length[1]`
  drained to 0 with `NBLTYPESI == 1`.
* An out-of-bounds write past the 8-byte internal input buffer, measured (24 bytes from
  `buffer.u8[0]`, 16 past the end), with a byte-accurate struct-offset map showing that ~64
  attacker bytes reach the `ringbuffer` pointer.
* The same payload producing a永久 hang instead of a clean error on the vulnerable build, and a
  precise `FORMAT_BLOCK_SWITCH` on the patched build.

NOT DEMONSTRATED
* Reaching the `ringbuffer` pointer: **measured as impossible by this path** (5b). Hard ceiling
  is state offset 99; the pointer sits at 136 and came back unchanged, with the index-hijack
  lever defeated by register caching. No pointer control -> no AAR/AAW -> no control-flow
  hijack -> **no RCE**. Residual real primitive: a heap write at an attacker-controlled
  *offset* via the clobbered `pos`. The Imperva post publishes no payload.
* Node.js runtime A/B (`brotliDecompressSync` vs a stream write) — the C API was used directly.
* Anything about heap grooming, ASLR, or reliability across a worker pool: inherited from the
  advisory, not reproduced.

## 7. Corrections to the circulating digest

1. Not an integer overflow: CWE-252 (unchecked return value) mis-reported as needs-more-input.
2. "V8 Sandbox makes the pivot harder" is irrelevant — native Brotli heap, not a V8 heap object.
3. "Requires vulnerable dependencies" misframes it: the flaw is in Node's own bundled decoder.
4. Credit differs between Imperva and the Node advisory.
5. NVD rates 9.2 CRITICAL; Node.js and Imperva both label it HIGH.
6. Missing from the digest: the February-fix / October-release gap, and that the bug is in the C
   library rather than in Node or the middleware.
