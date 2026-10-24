# Node2Shell — CVE-2026-111497 · independent reproduction report

**Subject** Out-of-bounds write in the Brotli decoder's internal input buffer, reachable through
Node.js / any consumer of the Brotli C library, from a maliciously crafted compressed stream.
**Prepared** 2026-10-24 · **Platform** Linux x86-64, no root, no container runtime.
**Method** Primary sources only (CVE records, vendor advisories, upstream commit diff, source
code) plus builds of Brotli 1.2.0 and 1.2.1 from the official tarballs, driven by an
instrumented harness. No third-party exploit code was used or copied.

---

## TL;DR

| Question | Answer | Evidence |
|---|---|---|
| Is the bug real? | **Yes.** | Upstream fix `0ed4268` + v1.2.1 diff; reproduced OOB write at `decode.c:2463-2468`. |
| Is the trigger reachable from a stream? | **Yes**, and we build a working payload. | 11 bits/command × 2²⁴ commands = 23 068 672 bytes; drains `block_length` with `mlr` untouched. |
| Does the vulnerable build mis-handle it? | **Yes, two ways.** | `NEEDS_MORE_INPUT` + a 16-byte OOB write past the 8-byte input buffer; or a permanent 100 %-CPU spin. |
| Does the patched build reject it? | **Yes, precisely.** | `_ERROR_FORMAT_BLOCK_SWITCH` (-17), nothing stashed. |
| Does it reach a **pointer** (AAR/AAW/RCE)? | **No — measured as unreachable.** | `ringbuffer`, `ringbuffer_end`, `htree_command` all came back unchanged; the index-hijack lever is defeated by register caching; hard ceiling is state offset 99, the pointer sits at 136. |
| Real residual impact | Memory corruption at a controlled **offset** + a hard DoS. | `pos` (offset 88) clobbered by the OOB write; spin arm hangs the decoder inside one call. |
| Headline process failure | **8-month silent window.** | Fixed upstream 2026-02-27, released 2026-10-21. Shipped with no regression test and no CHANGELOG entry. |

---

## 1. Scope and what "reproduced" means here

Two different claims circulate about this CVE and they must be scored separately:

1. **"A crafted Brotli stream corrupts decoder memory and can wedge the process."** — this is
   what the CVE record and the Node.js advisory assert. *Reproduced in full.*
2. **"…and this extends to remote code execution."** — this is the framing of the Imperva blog
   post ("Node2Shell: From Brotli Data to Remote Code Execution"). *Not reproduced, and the
   mechanism is shown here to be blocked at the pointer-access step in this configuration.*

Reproduction throughout means: a payload we generated ourselves, run against decoders we built
ourselves from the vendor's tarballs, with the corruption observed structurally (the vendor's
own internal `state.h`, its own `BROTLI_DEBUG` assertion, and an explicit check of
`buffer_length`) rather than inferred from a crash.

## 2. Facts and timeline

| Date | Event | Source |
|---|---|---|
| 2026-02-27 | upstream fix `0ed4268a4401abcb44720963` "Detect and report invalid stream earlier." | GitHub API |
| 2026-02-27 | CVE record `datePublic` | CVE record |
| 2026-10-16 | CVE-2026-111497 reserved (CNA: Google) | CVE record |
| 2026-10-21 | Brotli **v1.0.10 / v1.1.1 / v1.2.1** released with the fix | GitHub releases API |
| 2026-10-21 | Node.js **22.23.4 / 24.22.1 / 26.12.1** security release | nodejs.org |
| 2026-10-22 | CVE published; Imperva blog post | CVE record / imperva.com |

| Attribute | Value |
|---|---|
| CWE | CWE-787 (out-of-bounds write) + CWE-252 (unchecked return value) |
| CVSS 4.0 | 9.2 **CRITICAL** per NVD/CNA — Node.js and Imperva both label it **HIGH** (disagreement) |
| Affected | Brotli C library 1.0.3–<1.0.10, 1.1.0–<1.1.1, 1.2.0–<1.2.1 — all platforms |
| Fixed in | 1.0.10, 1.1.1, 1.2.1 (library) · Node.js 22.23.4, 24.22.1, 26.12.1 |
| Credits | Node advisory: reported by OpenAI Codex Security (Khai Tran, Sylvie Mayer), fixed by mcollina / aduh95. Imperva: reported by Matteo Collina, fixed by Antoine du Hamel. **The two accounts disagree.** |

The affected range is a *library* range, not a Node.js one. Anything statically or dynamically
linking Brotli in that range is in scope: Python `brotli` wheels, Rust crates, browsers,
proxies, CDN edge decompressors. Node.js is the highest-profile consumer, not the only one.

## 3. Root cause

`DecodeBlockTypeAndLength()` reports a malformed stream — a block-type switch requested when the
meta-block header declared `num_block_types == 1` — through a `BROTLI_BOOL` return of
`BROTLI_FALSE`. Every caller interprets `FALSE` as "not enough input yet" and returns
`NEEDS_MORE_INPUT`, which the API contract defines as *transient*. Feeding more bytes can never
satisfy the condition, so the state is permanently wedged in an unrecoverable "needs more input"
position:

```c
 if (max_block_type <= 1) {
-    return BROTLI_FALSE;                              /* v1.2.0: "needs more input" */
+    return BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH;  /* v1.2.1: permanent format error */
 }
```

The fix, 11 hunks in `c/dec/decode.c`, changes the return type to `BrotliDecoderErrorCode` and
escalates non-success statuses out of the hot path:

```c
- #define BROTLI_SAFE(METHOD)              /* unsafe path: status discarded */
+ #define BROTLI_SAFE_WITH_STATUS(METHOD)  /* status != SUCCESS -> saveStateAndReturn */
```

applied at all three switch sites — `CommandBegin`, `NextLiteralBlock`, and the distance site
(decode.c:2138) — plus an added invariant:

```c
+        BROTLI_DCHECK(s->meta_block_remaining_len <= (int)BROTLI_BLOCK_SIZE_CAP);
```

and a new public error code that `decode.h` had already reserved:

```
 v1.2.0:  /* -17 code is reserved */
 v1.2.1:  BROTLI_ERROR_CODE(_ERROR_FORMAT_, BLOCK_SWITCH, -17)
```

The security meaning of the patch is therefore: *a malformed stream must be rejected, not
reported as an I/O condition.* The escalation matters because the "needs more input" answer
drives code that assumes progress is possible.

## 4. The memory-corruption site

```c
/* c/dec/state.h */
  /* Temporary storage for remaining input. Brotli stream format is designed in
     a way, that 64 bits are enough to make progress in decoding. */
  union { uint64_t u64; uint8_t u8[8]; } buffer;
  brotli_reg_t buffer_length;
```

Two loops in `BrotliDecoderDecompressStream` fill it. Both assume forward progress:

* **decode.c:2444-2455** — the append loop, one byte per call, whose only guard is
  `BROTLI_DCHECK(s->buffer_length < 8)`. `BROTLI_DCHECK` is `assert()` **only** under
  `-DBROTLI_DEBUG` (platform.h:464-466) — compiled out of every release build.
* **decode.c:2463-2468** — the tail copy, `while (*available_in) { s->buffer.u8[s->buffer_length] = **next_in; s->buffer_length++; … }` — **no bound at all**.

State layout on this platform (from `offsetof` on the vendor's own header):

| offset | field | size |
|---|---|---|
| 72 | `buffer` (`uint8_t u8[8]`) | 8 |
| **80** | **`buffer_length`** — doubles as the write index | 8 |
| **88** | **`pos`** — ring-buffer output index | 4 |
| 96 | `max_distance` | 4 |
| 100 / 104 | `ringbuffer_size` / `ringbuffer_mask` | 4 / 4 |
| 112 | `dist_rb[4]` | 16 |
| 132 | `meta_block_remaining_len` | 4 |
| **136** | **`ringbuffer`** — output pointer | 8 |
| 144 | `ringbuffer_end` | 8 |
| 152 | `htree_command` — command prefix code pointer | 8 |
| — | `sizeof(state)` | 5744 |

`buffer.u8[i]` lands at state offset `72 + i`, so an attacker byte index ≥ 8 writes into live
decoder fields. The write is **intra-object** — one heap allocation — so ASAN, valgrind and
hardened allocators do not report it; this is why the lab instruments the struct instead.

## 5. The trigger, and why it took real work to reach

`block_length[tree] == 0` while `num_block_types[tree] == 1` is the condition. Because
`BrotliDecoderStateMetablockBegin()` resets `block_length[0..2] = 2²⁴` at the start of **every**
meta-block, the drain must happen inside one meta-block: 16 777 216 units, exactly.

Naive draining is impossible, and this is the crux of the whole reproduction:

* **literal tree** — one decrement per literal, `mlr` decreases by the insert length: needs
  `insert > CAP` with `MLEN ≤ CAP`, i.e. `mlr < 0`. Worse, `pos`, the literal counter and
  `block_length[0]` advance in lockstep, so the drained check can never observe
  `block_length[0] < i`.
* **command tree** — one decrement per command, at least 2 bytes of `mlr` per command.
* **distance tree** — one decrement per explicit-distance read, likewise ≥ 2 `mlr` per command.
* and any negative `mlr` is rejected outright by `WriteRingBuffer`
  (`decode.c:1337 if (s->meta_block_remaining_len < 0) return _ERROR_FORMAT_BLOCK_LENGTH_1;`).

**The lever that makes it reachable.** A copy whose distance exceeds `max_distance` takes the
static-dictionary path, and `BrotliTransformDictionaryWord()` returns the number of bytes it
actually wrote — *not* the transformed length, which can be zero or negative:

```c
    while (suffix_len--) { dst[idx++] = *suffix++; }
    return idx;
```

Choose a transform with an **empty prefix and empty suffix** whose omit/skip fully consumes the
word, and the function returns 0:

```c
      len = BrotliTransformDictionaryWord(&s->ringbuffer[pos], word, len, transforms, 34);
      pos += len;                                /* +0 */
      s->meta_block_remaining_len -= len;        /* -0 */
```

That command costs **zero output and zero `mlr`** while still decrementing `block_length[1]`
(in `ReadCommandInternal`) and `block_length[2]` (in `ReadDistanceInternal`). The drain finishes
with `mlr` untouched. Verified from the decoder's own debug log:

```
[ProcessCommandsInternal] pos = 0 insert = 0 copy = 4
[ProcessCommandsInternal] pos = 0 distance = 34818
[ProcessCommandsInternal] dictionary word: [down], transform_idx = 34, transformed: []
[ProcessCommandsInternal] s->meta_block_remaining_len = 1      <- unchanged
```

Parameters, derived from the *compiled* tables (a helper reads them out of the library rather
than parsing the C string tables by hand) and from a replication of `CalculateDistanceLut`:

| quantity | value | why |
|---|---|---|
| transform | **34** = `OMIT_FIRST_4`, `prefix_len = suffix_len = 0` | returns 0 for a 4-byte word |
| copy length | 4 (command symbol 130: insert 0, copy 4, explicit distance) | `i >= 4` required to enter the dictionary word path |
| word class | `size_bits_by_length[4] = 10` | `transform_idx = address >> 10` |
| distance | 34818 = ((34 << 10) + 1) + 1 | pins `transform_idx` at 34 because `max_distance == 0` |
| distance postfix | 3, direct codes 0 → alphabet 400 | spreads each extra bit over 8 distances → **11 bits per command** |
| `MLEN` | 1 | nothing is produced, so nothing is consumed |
| commands | 2²⁴ × 11 bits = **23 068 672 bytes** | drains `block_length` exactly once |

`pos` stays 0 for the entire run (no literals, no output ⇒ `max_distance == 0`), so the
dictionary address — and therefore the transform index — stays constant across all 16.7 M
commands. `NBLTYPESI = 1` keeps the command counter as the drained tree while `NBLTYPESL = 1`,
`NBLTYPESD = 1` avoid any other switch firing first.

## 6. Measurements

**A/B, single chunk, payload `cmd-drain-t24.br`** (23 068 706 bytes):

| decoder | observed | verdict |
|---|---|---|
| **Brotli 1.2.0** | `result = 2 NEEDS_MORE_INPUT`, `buffer_length = 24`, 0 output bytes | **out-of-bounds write: 24 bytes from `s->buffer.u8[0]`, i.e. 16 bytes past the 8-byte buffer** |
| **Brotli 1.2.1** | `result = 0 ERROR`, `error_code = -17` | `_ERROR_FORMAT_BLOCK_SWITCH`, `buffer_length = 0` — nothing stashed |

**Second arm, same payload with an 8-byte tail plus a second chunk:**

| decoder | observed | verdict |
|---|---|---|
| **Brotli 1.2.0** | never returns from one `BrotliDecoderDecompressStream()` call | **100 % CPU spin** — the unsafe loop re-enters the invalid switch forever; a caller feeding this stream in a stream/HTTP path hangs the worker |
| **Brotli 1.2.1** | `error_code = -17` | clean format error |

Which arm fires is decided by how many unconsumed bytes remain when the drained check is
evaluated. Below `BROTLI_FAST_INPUT_SLACK` (28, bit_reader.h:22) the decoder must take the safe
path and returns `NEEDS_MORE_INPUT`, which triggers the tail copy; at or above 28 the unsafe path
keeps looping and the process spins.

**How far the write reaches — the pointer question.** The write index *is* the `buffer_length`
field, so a byte landing at `buffer.u8[8]` (offset 80) overwrites `buffer_length`'s low byte;
after that the next write should land at index (byte + 1), which can be aimed at
`ringbuffer` (index 64). Payload `cmd-drain-poke.br` does exactly that (tail `00`×8, `3F` at
index 8, then `8877665544332211` intended for the pointer). Result:

```
buffer_length  = 24 (0x18)                    <- restored: the index hijack does NOT work
pos            = 0x82828282                   <- CLOBBERED (offset 88)
max_distance   = 0  ringbuffer_size = 1024  ringbuffer_mask = 1023
ringbuffer     = 0x51b000000080   (offset 136)  <- UNCHANGED, real heap pointer
ringbuffer_end = 0x51b000000480   (offset 144)  <- UNCHANGED
htree_command  = 0x521000002908   (offset 152)  <- UNCHANGED
```

Two independent mechanisms cap this:

1. the compiled tail copy keeps the counter in a **register** and stores it back after the loop,
   so writing through `buffer.u8[]` cannot steer the index; and
2. both fill loops only execute while the fast path is disarmed, i.e. while fewer than 28 bytes
   remain — so at most 27 bytes are ever written: **hard ceiling = state offset 99**
   (`buffer` + 27), clobbering `buffer_length`, `pos` and (with a 27-byte tail) `max_distance`.

`ringbuffer` sits at 136, i.e. 37 bytes beyond the ceiling. Reaching it would require the
register-caching and the 28-byte slack to both be absent.

## 7. Exploitability assessment

**Demonstrated impact**

* Memory corruption of adjacent decoder state (16-19 bytes past the intended buffer), including
  `pos` — the ring-buffer output index — and `max_distance`.
* A hard denial of service: the vulnerable build can be driven into an unbounded loop inside a
  single `BrotliDecoderDecompressStream()` call, i.e. a worker thread that never returns and
  never yields. A service that decompresses attacker-supplied Brotli (HTTP content-encoding,
  `.br` uploads, cache warmers) loses that worker permanently. Bounded only by a supervisor
  killing the process.
* The patched build rejects the same bytes with a precise, permanent format error.

**Not demonstrated**

* No control of any pointer: all pointer fields measured intact. Consequently no arbitrary read,
  no arbitrary write, no control-flow hijack, **no RCE by this path**.
* The residual primitive is a heap write at an attacker-chosen **offset** from the ring buffer
  (via the clobbered `pos`) — real, but a different and weaker capability than the arbitrary
  read/write a code-execution chain needs.
* Nothing about heap grooming, ASLR defeat or reliability across a worker pool was tested, and
  the Imperva post publishes no payload. An RCE claim would need, at minimum: pointer reach
  (blocked here), an address disclosure (not shown), and a stable target in the corrupted
  window.

**Reading of the CVE record.** CWE-787 is accurate for the *effect* (a write past the intended
bound) and CWE-252 for the *cause* (an unchecked/unpropagated error status). CVSS 4.0 9.2 with
`AV:N/AC:L/AT:P` describes the pre-patch situation for a network-facing decompressor; the
`AT:P` (attack complexity: present) sub-score is the honest place where "needs a very specific
malformed stream" lives. The HIGH/CRITICAL disagreement between NVD and the two vendors is
unresolved in the record.

## 8. Corrections to the circulating summary

1. **Not an integer overflow.** The root cause is a `BROTLI_BOOL` return value that callers read
   as "needs more input" (CWE-252), which turns a permanent format error into a transient one.
2. **The V8 sandbox is irrelevant.** This is a native-heap corruption in the bundled C
   decompressor; no V8 heap object is involved, so V8 heap protections do not gate it.
3. **"Requires vulnerable dependencies" misframes it.** The flaw is in Node.js's *own* bundled
   decoder; there is no separate dependency for a user to pin.
4. **Credits differ** between the Imperva post and the Node.js advisory.
5. **Severity ratings differ** (9.2 CRITICAL vs HIGH).
6. **Missing from the summary:** the 8-month fix-to-release gap; the fact that the affected range
   is the C library (so non-Node consumers are exposed); and that the fix shipped with no
   regression test and no CHANGELOG entry, which is why a payload had to be reconstructed from
   first principles here.

## 9. Remediation and detection

**Remediation** — upgrade past the fix; nothing else is required, as the patch is a pure
validation change: Brotli ≥ 1.0.10 / 1.1.1 / 1.2.1, or Node.js ≥ 22.23.4 / 24.22.1 / 26.12.1.
Non-Node consumers must check their own bundled Brotli (Python `brotli`, Rust `brotli` crates,
embedded copies inside other runtimes), and rebuild — a distribution package bump alone is not
sufficient if the library was vendored.

**Detection** — the pre-patch signature is distinctive and cheap to watch for: a process pinned
at 100 % CPU inside a single decompression call, or a decompression loop that repeatedly reports
"needs more input" while consuming no input. Application-level mitigations that blunt both arms
without a patch: bound the decompressed size and the decompression wall-clock/steps at the
gateway (nginx `brotli` off for untrusted bodies, request timeouts, worker recycling), and reject
bodies whose compressed size cannot plausibly expand to their declared length.

## 10. Reproduction

```sh
scripts/setup.sh                 # fetch brotli 1.2.0 / 1.2.1 tarballs, verify sha256, build harnesses
payload/gen_payload.py --variant cmd-drain --tail 24 --out payload/payloads/cmd-drain-t24.br
./run_ab.sh payload/payloads/cmd-drain-t24.br 900      # vulnerable vs patched, prints a verdict
```

Payload sizes and digests are listed in `payload/MANIFEST.txt`; the 23 MB generated payloads are
not committed (the generator is deterministic and reproduces them byte-for-byte).

`docs/NOTES.md` is the working log: every measurement, the offset table, and the dead ends
(meta-block counter resets, phase-locked counters, the `mlr < 0` guard, the register-cached
index) are recorded there so the negative results are reproducible too.

## 11. Limitations

* Measurements are from one platform (Linux x86-64, gcc, one compiler version). Register caching
  of the tail-copy counter is compiler-dependent; a build that reloads `buffer_length` per
  iteration would let the write index be steered (though the 28-byte slack ceiling would still
  cap the reach).
* The Node.js runtime layer was not exercised; the C API of the same library that Node bundles
  was driven directly. A Node-level A/B (`brotliDecompressSync` vs a two-chunk stream write) is
  the obvious next step and is expected to show a clean error versus a hang.
* The spin's exact trigger interaction with the harness's chunking was observed but not fully
  reduced to a state-machine trace; the observation (`NO_PROGRESS_SPIN`) is reported as measured.
* No attempt was made to weaponise the `pos` corruption further (e.g. an ASAN heap-overflow
  demonstration), so its practical reach is stated as relative-offset memory corruption, not as
  a finished exploitation primitive.
