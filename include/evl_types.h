#ifndef EVL_TYPES_H
#define EVL_TYPES_H

#include <stdint.h>
#define EVL_SALT_SIZE 32 //32 bytes (256 bits)
#define EVL_FILE_ID_SIZE 16 //16 bytes (128 bits)
#define EVL_NONCE_SIZE 12 //12 bytes (96 bits)
#define EVL_TAG_SIZE 16 //16 bytes (128 bits)
#define EVL_MASTER_KEY_SIZE 32 //32 bytes (256 bits)
#define EVL_KEY_SIZE 32 //32 bytes (256 bits)
#define EVL_DEFAULT_BLOCK_SIZE 4096 //4kb block size
#define EVL_AAD_SIZE 28 //28 bytes (224 bits)

typedef struct {
    uint8_t magic[4]; //to check if its an evl file.
    uint8_t format_version;
    uint8_t salt[EVL_SALT_SIZE];
    uint8_t file_id[EVL_FILE_ID_SIZE];
    uint64_t file_size; //original logical file size.
    uint32_t block_size;
} evl_header_t;

#endif