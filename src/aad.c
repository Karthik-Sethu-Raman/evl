#include <string.h>
#include "aad.h"
#include "evl_types.h"
#include "utils.h"

int evl_build_block_aad(
    const uint8_t *file_id,
    uint64_t block_index,
    uint32_t block_size,
    uint8_t *aad_out,
    size_t *aad_len_out
){
    memcpy(aad_out, file_id, EVL_FILE_ID_SIZE);
    write_u64_le(aad_out+16, block_index);
    write_u32_le(aad_out+24, block_size);
    *aad_len_out = EVL_AAD_SIZE;
    return 0;
}