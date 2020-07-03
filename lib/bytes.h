#ifndef BYTES_H
#define BYTES_H

#include <stddef.h>
#include <stdint.h>

void *sfmalloc(size_t size);
void *sfcalloc(size_t nmemb, size_t size);
void *sfrealloc(void *ptr, size_t size);
unsigned int random_word();
uint8_t CircularShift(uint8_t b, int s);
uint8_t *PermutateBits(
    const uint8_t *bytes,
    size_t size,
    const size_t *table,
    size_t tsize
);

#endif
