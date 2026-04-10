#ifndef NONCE_H
#define NONCE_H

#include <stdint.h>
#include "evl_types.h"

int evl_generate_block_nonce(
    uint8_t *nonce_out
);

#endif