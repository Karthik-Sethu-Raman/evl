#ifndef KDF_H
#define KDF_H
#include <stdint.h>
#include <stddef.h>
#include "evl_types.h"

int evl_derive_master_key(
    const char *password,
    const uint8_t *salt,
    size_t salt_len,
    uint8_t *master_key_out
);

int evl_expand_keys(
    const uint8_t *master_key,
    size_t master_key_len,
    uint8_t *enc_key_out,
    uint8_t *header_key_out
);

#endif