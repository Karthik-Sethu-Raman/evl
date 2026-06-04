#include <string.h>
#include "aad.h"
#include "evl_types.h"
#include "utils.h"

//Prevention of block relocation attack, attacker moves block 10 to block 99, AAD changes, tag mismatch occurs.
//Prevention of cross-container block swapping, as file id differes, AAD differs, tag mismath occurs.
//Preventing block size manipulation, AAD changes, tag mismatch occurs.

int evl_build_block_aad(
    const uint8_t *file_id,
    uint64_t block_index,
    uint32_t block_size,
    uint8_t *aad_out, //buffer wher AAD will be written
    size_t *aad_len_out
){
    memcpy(aad_out, file_id, EVL_FILE_ID_SIZE); //writting the file id to output buffer.
    write_u64_le(aad_out+16, block_index); //writting in Little-Endian format.
    write_u32_le(aad_out+24, block_size);
    *aad_len_out = EVL_AAD_SIZE;
    return 0;
}