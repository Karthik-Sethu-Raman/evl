#ifndef HEADER_H
#define HEADER_H

#include <stdint.h>
#include "evl_types.h"

#define EVL_HEADER_SIZE 57

int evl_header_serialize(
    const evl_header_t *header,
    uint8_t *buffer_out
);

int evl_header_deserialize(
    const uint8_t *buffer,
    evl_header_t *header_out
);

#endif
