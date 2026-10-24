/* Dump the decoder's real transform + dictionary tables.
 *
 * The static dictionary word path in ProcessCommandsInternal derives both the
 * word and the transform index from the *distance code*, and
 * BrotliTransformDictionaryWord() can return 0 (zero output, zero
 * meta_block_remaining_len cost) when the selected transform has an empty
 * prefix/suffix and its omit/skip fully consumes the word. Finding such a
 * transform by parsing the C string tables by hand is error-prone, so read the
 * compiled tables instead.
 *
 * Prints, per transform index: prefix length, type, suffix length, and per
 * dictionary word length: size_bits (log2 of the word count).
 */
#include <stdio.h>
#include "common/dictionary.h"
#include "common/transform.h"

int main(void) {
  const BrotliTransforms* t = BrotliGetTransforms();
  int i;
  printf("num_transforms=%d\n", (int)t->num_transforms);
  printf("idx prefix_len type suffix_len\n");
  for (i = 0; i < (int)t->num_transforms; ++i) {
    const uint8_t* prefix = BROTLI_TRANSFORM_PREFIX(t, i);
    const uint8_t* suffix = BROTLI_TRANSFORM_SUFFIX(t, i);
    printf("%3d %2d %2d %2d\n", i, (int)prefix[0], (int)BROTLI_TRANSFORM_TYPE(t, i),
           (int)suffix[0]);
  }
  printf("\ntransform type constants: OMIT_LAST_1..9 = %d..%d, OMIT_FIRST_1..9 = %d..%d,"
         " IDENTITY = %d, UPPERCASE_FIRST = %d, UPPERCASE_ALL = %d\n",
         BROTLI_TRANSFORM_OMIT_LAST_1, BROTLI_TRANSFORM_OMIT_LAST_9,
         BROTLI_TRANSFORM_OMIT_FIRST_1, BROTLI_TRANSFORM_OMIT_FIRST_9,
         BROTLI_TRANSFORM_IDENTITY, BROTLI_TRANSFORM_UPPERCASE_FIRST,
         BROTLI_TRANSFORM_UPPERCASE_ALL);

  const BrotliDictionary* d = BrotliGetDictionary();
  printf("\nlen size_bits offsets_by_length\n");
  for (i = 0; i < 25; ++i) {
    printf("%2d %2d %d\n", i, (int)d->size_bits_by_length[i],
           (int)d->offsets_by_length[i]);
  }
  return 0;
}
