#include <stdint.h>
#include <string.h>
#include "evl_types.h"
#include "utils.h"

int evl_header_serialize(const evl_header_t *h, uint8_t *buf){
    memcpy(buf+0, h->magic, 4);
    buf[4] = h->format_version;
    memcpy(buf+5, h->salt, 16);
    memcpy(buf+21, h->file_id, 16);
    write_u64_le(buf+37, h->file_size);
    write_u32_le(buf+45, h->block_size);
    write_u64_le(buf+49, h->version);
    return 0;
}

int evl_header_deserialize(const uint8_t *buf, evl_header_t *h){
    if (memcmp(buf+0, "EVL1", 4) != 0){
        return -1;
    }
    if (buf[4]!=1){
        return -2;
    }
    memcpy(h->magic, buf+0, 4);
    h->format_version = buf[4];
    memcpy(h->salt, buf+5, 16);
    memcpy(h->file_id, buf+21, 16);
    h->file_size = read_u64_le(buf+37);
    h->block_size = read_u32_le(buf+45);
    h->version = read_u64_le(buf+49);
    return 0;
}

