#include "debug.h"
#include <stdio.h>
#include <ctype.h>
#include "bytes.h"

void print_hexdump(const uint8_t *bytes, size_t size) {
    for (size_t b = 0; b < size; b += DUMP_LINE_BYTES) {
        size_t abytes = size - b < DUMP_LINE_BYTES ? size - b : DUMP_LINE_BYTES;
        printf("%08lx: ", b);
        for (size_t i = 0; i < DUMP_LINE_BYTES; i++) {
            size_t bi = b + i;
            if (bi < size) {
                printf("%02x", bytes[bi]);
            } else {
                printf("  ");
            }
            if (i % 2 == 1) {
                printf(" ");
            }
        }

        printf(" ");
        for (size_t i = 0; i < abytes; i++) {
            size_t bi = b + i;
            uint8_t byte = bytes[bi];
            if (isprint(byte)) {
                putchar(byte);
            } else {
                putchar('.');
            }
        }
        printf("\n");
    }
}

const char *dump_hexstream(const uint8_t *bytes, size_t size) {
    size_t len = size * 2 + 1;
    char *result = sfmalloc(sizeof(*result) * len);
    char *rptr = result;
    for (size_t b = 0; b < size; b++) {
        sprintf(rptr, "%02x", bytes[b]);
        rptr += 2;
    }
    return (const char*) result;
}
