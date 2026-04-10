#include <openssl/rand.h>
#include "nonce.h"
#include "evl_types.h"

int evl_generate_block_nonce(
    uint8_t *nonce_out
){
    if (!nonce_out)
        return -1;

    if (RAND_bytes(nonce_out, EVL_NONCE_SIZE) != 1)
        return -1;

    return 0;
}