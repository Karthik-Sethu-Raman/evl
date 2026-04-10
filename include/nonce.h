#ifndef NONCE_H
#define NONCE_H
#include <stdint.h>


int evl_derive_block_nonce(
    const uint8_t *file_id,
    uint64_t block_index,
    uint64_t version,
    uint8_t *nonce_out
);
#endif