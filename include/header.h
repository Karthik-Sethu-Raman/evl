#ifndef HEADER_H
#define HEADER_H

#include <stdint.h>
#include "evl_types.h"

#define EVL_HEADER_SIZE       65
#define EVL_HEADER_NONCE_SIZE 12
#define EVL_HEADER_TAG_SIZE   16

#define EVL_BLOCKS_OFFSET (EVL_HEADER_SIZE + EVL_HEADER_NONCE_SIZE + EVL_HEADER_TAG_SIZE)

int evl_header_serialize(
    const evl_header_t *header,
    uint8_t *buffer_out
);

int evl_header_deserialize(
    const uint8_t *buffer,
    evl_header_t *header_out
);

#endif