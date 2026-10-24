# node2shell — CVE-2026-111497 reproduction lab

Independent reproduction of the Brotli decoder out-of-bounds write behind
**CVE-2026-111497** ("Node2Shell"), with an A/B against the patched release.

Everything here was built from primary sources: the CVE records, the vendor advisories, the
upstream fix commit, and Brotli 1.2.0 / 1.2.1 compiled from the official tarballs. No
third-party exploit code was used or copied.

**Full report: [docs/REPORT.md](docs/REPORT.md)** · working log: [docs/NOTES.md](docs/NOTES.md)

**Interactive walkthrough → https://lesterlam.github.io/node2shell/** — single file, no
dependencies, works offline too: [`index.html`](index.html).

## Result

| question | answer |
|---|---|
| Bug real, trigger reachable from a stream? | **yes** — payload generated from first principles: 2^24 commands x 11 bits = 23 068 672 bytes |
| Vulnerable build (1.2.0) | `NEEDS_MORE_INPUT` + **out-of-bounds write 16 bytes past the 8-byte internal input buffer**; or a permanent **100 % CPU spin** |
| Patched build (1.2.1) | `_ERROR_FORMAT_BLOCK_SWITCH` (-17), nothing stashed |
| Pointer control / AAR-AAW / **RCE** | **not reachable — measured.** `ringbuffer`, `ringbuffer_end`, `htree_command` all came back unchanged; hard ceiling is state offset 98, the pointer sits at 136 |
| Residual impact | memory corruption at an attacker-controlled *offset* (clobbered `pos`), plus a hard DoS |
| Process finding | fixed upstream **2026-02-27**, released **2026-10-21** — an 8-month silent window; the release carried no regression test and no CHANGELOG entry |

The mechanism in one line: a malformed stream requests a block-type switch while only one block
type exists, `DecodeBlockTypeAndLength()` signals that through a `BROTLI_BOOL`, callers read
`FALSE` as "needs more input", and the decoder's internal 8-byte input buffer is then grown one
byte at a time past its end (guarded in release builds only by a compiled-out `BROTLI_DCHECK`).

## Reproduce

```sh
scripts/setup.sh                       # fetch brotli 1.2.0/1.2.1 (checked), build the harnesses
payload/gen_payload.py --variant cmd-drain --tail 24 --out payload/payloads/cmd-drain-t24.br
./run_ab.sh payload/payloads/cmd-drain-t24.br 900
```

`run_ab.sh` runs the same payload through both decoders and prints a verdict per build.
Payload digests are in [payload/MANIFEST.txt](payload/MANIFEST.txt); the 23 MB generated payloads
are not committed because the generator is deterministic.

## Layout

| path | what |
|---|---|
| `docs/REPORT.md` | review-grade report: root cause, trigger, measurements, exploitability, remediation |
| `docs/NOTES.md` | working log, including the dead ends (state resets, phase-locked counters, the `mlr < 0` guard, register-cached index) |
| `index.html` | interactive walkthrough (also the GitHub Pages site root): trigger animation, state offset map, A/B transcript, timeline |
| `payload/gen_payload.py` | Brotli bitstream generator (`cmd-drain`, `lit-flood`, `lab-trigger`, …) |
| `asan/harness.c` | instrumented decoder driver: state introspection, `offsetof` map, `BROTLI_DEBUG` build, spin watchdog, clobber dump |
| `asan/dump_tables.c` | reads the *compiled* transform + dictionary tables out of the library |
| `run_ab.sh` | vulnerable vs patched comparison with verdicts |

## Scope and honesty

*Reproduced:* the trigger, the out-of-bounds write, both failure arms (corruption and hang), the
patch behaviour, and the reach ceiling.

*Not reproduced:* pointer control, arbitrary read/write, control-flow hijack, RCE. The Imperva
post publishes no payload, and the two fill loops are capped by `BROTLI_FAST_INPUT_SLACK = 28`
in a way that is measured here, not assumed. A code-execution claim would additionally need
pointer reach (blocked), an address disclosure (not shown), and a stable corrupted target.

Measurements are from one platform (Linux x86-64, gcc); register caching of the tail-copy
counter is compiler-dependent, and the Node.js runtime layer was not exercised (the C API of the
same bundled library was driven directly).
