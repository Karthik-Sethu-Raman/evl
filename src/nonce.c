#include <openssl/rand.h>
#include "nonce.h"
#include "evl_types.h"

//possible nonce values => 2^96, resonable enough in this case!

int evl_generate_block_nonce( //Function generating a fresh nonce for a block encryption operation.
    uint8_t *nonce_out //nonce buffer, 96 random bits (12 bytes).
){
    if (!nonce_out)
        return -1;

    if (RAND_bytes(nonce_out, EVL_NONCE_SIZE) != 1) //CSPRNG
        return -1;

    return 0;
}