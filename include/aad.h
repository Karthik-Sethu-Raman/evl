#ifndef AAD_H
#define AAD_H

#include <stdint.h>
#include <stddef.h>

#define EVL_AAD_SIZE 36

int evl_build_block_aad(
    const uint8_t *file_id,
    uint64_t block_index,
    uint64_t version,
    uint32_t block_size,
    uint8_t *aad_out,
    size_t *aad_len_out
);
#endif