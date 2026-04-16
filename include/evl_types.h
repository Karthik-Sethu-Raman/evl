#ifndef EVL_TYPES_H
#define EVL_TYPES_H

#include <stdint.h>
#define EVL_SALT_SIZE 32
#define EVL_FILE_ID_SIZE 16
#define EVL_NONCE_SIZE 12
#define EVL_TAG_SIZE 16
#define EVL_MASTER_KEY_SIZE 32
#define EVL_KEY_SIZE 32
#define EVL_DEFAULT_BLOCK_SIZE 4096
#define EVL_AAD_SIZE 28  

typedef struct {
    uint8_t magic[4];
    uint8_t format_version;
    uint8_t salt[EVL_SALT_SIZE];
    uint8_t file_id[EVL_FILE_ID_SIZE];
    uint64_t file_size;
    uint32_t block_size;
} evl_header_t;

#endif