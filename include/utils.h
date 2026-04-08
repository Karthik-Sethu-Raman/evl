#ifndef UTILS_H
#define UTILS_H
#include <stdint.h>

void write_u64_le(uint8_t *buf, uint64_t val);
uint64_t read_u64_le(const uint8_t *buf);
void write_u32_le(uint8_t * buf, uint32_t val);
uint32_t read_u32_le(const uint8_t *buf);

#endif