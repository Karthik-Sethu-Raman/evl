#include <stdint.h>
#include <string.h>
#include "evl_types.h"
#include "header.h"
#include "utils.h"

int evl_header_serialize(const evl_header_t *h, uint8_t *buf){
    if (h == NULL || buf == NULL){
        return -3;
    }
    if (h->block_size == 0){
        return -4;
    }
    memcpy(buf+0, h->magic, 4);
    buf[4] = h->format_version;
    memcpy(buf+5, h->salt, EVL_SALT_SIZE);
    memcpy(buf+37, h->file_id, EVL_FILE_ID_SIZE);
    write_u64_le(buf+53, h->file_size);
    write_u32_le(buf+61, h->block_size);
    write_u64_le(buf+65, h->version);
    return 0;
}

int evl_header_deserialize(const uint8_t *buf, evl_header_t *h){
    if (buf == NULL || h == NULL){
        return -3;
    }
    if (memcmp(buf+0, "EVL1", 4) != 0){
        return -1;
    }
    if (buf[4]!=1){
        return -2;
    }
    memcpy(h->magic, buf+0, 4);
    h->format_version = buf[4];
    memcpy(h->salt, buf+5, EVL_SALT_SIZE);
    memcpy(h->file_id, buf+37, EVL_FILE_ID_SIZE);
    h->file_size = read_u64_le(buf+53);
    h->block_size = read_u32_le(buf+61);
    if (h->block_size == 0){
        return -4;
    }
    h->version = read_u64_le(buf+65);
    return 0;
}

