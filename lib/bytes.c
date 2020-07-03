#include "bytes.h"
#include <stdio.h>
#include <stdlib.h>
#include <openssl/rand.h>

void *sfmalloc(size_t size) {
    void *buffer = malloc(size);
    if (buffer == NULL) {
        fputs("Failed to allocate memory", stderr);
        exit(EXIT_FAILURE);
    }
    return buffer;
}

void *sfcalloc(size_t nmemb, size_t size) {
    void *buffer = calloc(nmemb, size);
    if (buffer == NULL) {
        fputs("Failed to allocate memory", stderr);
        exit(EXIT_FAILURE);
    }
    return buffer;
}

void *sfrealloc(void *ptr, size_t size) {
    void *buffer = realloc(ptr, size);
    if (buffer == NULL) {
        fputs("Failed to allocate memory", stderr);
        exit(EXIT_FAILURE);
    }
    return buffer;
}

unsigned int random_word() {
    static unsigned char buf[2];
    RAND_bytes(buf, sizeof(buf));
    return (buf[0] << 8) | buf[1];
}

uint8_t CircularShift(uint8_t b, int s) {
    s %= 8;
    if (s == 0) {
        return b;
    }
    if (s < 0) {
        s += 8;
    }
    uint8_t rmask = (1 << s) - 1;
    return ((b & rmask) << (8 - s)) | (b >> s);
}

uint8_t *PermutateBits(
    const uint8_t *bytes,
    size_t size,
    const size_t *table,
    size_t tsize
) {
    size_t rsize = tsize / 8;
    uint8_t *result = NULL;
    const size_t *tval = table;
    size_t ti = 0;
    if (tsize % 8 > 0) {
        fprintf(
            stderr,
            "WARNING: Permutation table size %zd is not a multiple of 8",
            tsize
        );
        rsize++;
    }

    result = sfcalloc(rsize, sizeof(*result));
    for (size_t i = 0; i < rsize; i++) {
        for (uint8_t j = 0; j < 8; j++) {
            if (ti++ >= tsize) {
                break;
            }
            size_t bit = *tval++;
            size_t byte = bit / 8;
            size_t le_bit = 7 - bit % 8;
            if (byte >= size) {
                fprintf(
                    stderr,
                    "WARNING: Bit position %zd exceeds bytes size",
                    bit
                );
            }
            if (bytes[byte] & (1 << le_bit)) {
                result[i] |= 128 >> j;
            }
        }
    }

    return result;
}
