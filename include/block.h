#ifndef BLOCK_H
#define BLOCK_H

#include <stdint.h>
#include <stddef.h>
#include "evl_types.h"

int evl_encrypt_block(
    const evl_header_t *header,
    const uint8_t *enc_key,
    uint64_t block_index,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *ciphertext_out,
    uint8_t *tag_out
);

int evl_decrypt_block(
    const evl_header_t *header,
    const uint8_t *enc_key,
    uint64_t block_index,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *tag,
    uint8_t *plaintext_out
);
#endif