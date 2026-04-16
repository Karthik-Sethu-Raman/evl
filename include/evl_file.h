#ifndef EVL_FILE_H
#define EVL_FILE_H

#include <stdint.h>
#include <stddef.h>
#include "evl_types.h"
#include "header.h"

typedef struct {
    int fd;
    evl_header_t header;
    uint8_t enc_key[32];
    uint8_t header_key[32];
} evl_file_t;

int evl_file_create(
    const char *path,
    const char *password,
    uint32_t block_size,
    evl_file_t *out
);

int evl_file_open(
    const char *path,
    const char *password,
    evl_file_t *out
);

int evl_file_close(
    evl_file_t *ctx
);

int evl_read_block(
    evl_file_t *ctx,
    uint64_t block_index,
    uint8_t *plaintext_out,
    size_t *plaintext_len_out
);

int evl_write_block(
    evl_file_t *ctx,
    uint64_t block_index,
    const uint8_t *plaintext,
    size_t plaintext_len
);

#endif