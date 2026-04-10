#include <openssl/sha.h>
#include <string.h>

#include "nonce.h"
#include "utils.h"

int evl_derive_block_nonce(
    const uint8_t *file_id,
    uint64_t block_index,
    uint64_t version,
    uint8_t *nonce_out
){
    uint8_t buffer[16+8+8];
    uint8_t hash[32];
    memcpy(buffer, file_id, 16);
    write_u64_le(buffer+16, block_index);
    write_u64_le(buffer+24, version);
    SHA256(buffer, sizeof(buffer), hash);
    memcpy(nonce_out, hash, EVL_NONCE_SIZE);
    return 0;
}