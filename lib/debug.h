#ifndef DEBUG_H
#define DEBUG_H

#include <stddef.h>
#include <stdint.h>

#define DUMP_LINE_BYTES 16

void print_hexdump(const uint8_t *bytes, size_t size);
const char *dump_hexstream(const uint8_t *bytes, size_t size);

#endif
