#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "aad.h"
#include "evl_types.h"

void print_hex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

int main() {
    uint8_t file_id[EVL_FILE_ID_SIZE];
    memset(file_id, 0xBB, EVL_FILE_ID_SIZE);

    uint8_t aad1[EVL_AAD_SIZE];
    uint8_t aad2[EVL_AAD_SIZE];

    size_t len1 = 0;
    size_t len2 = 0;

    printf("=== AAD TEST ===\n\n");

    
    evl_build_block_aad(file_id, 0, 4096, aad1, &len1);

    printf("AAD1: ");
    print_hex(aad1, len1);
    printf("Length: %zu\n", len1);

    if (len1 != EVL_AAD_SIZE) {
        printf("FAIL: Incorrect AAD size\n");
        return 1;
    }
    printf("PASS: Correct AAD size (%d bytes)\n\n", EVL_AAD_SIZE);

    
    evl_build_block_aad(file_id, 0, 4096, aad2, &len2);

    if (memcmp(aad1, aad2, EVL_AAD_SIZE) == 0) {
        printf("PASS: Deterministic AAD\n\n");
    } else {
        printf("FAIL: AAD mismatch on identical inputs\n");
        return 1;
    }

    
    evl_build_block_aad(file_id, 1, 4096, aad2, &len2);

    if (memcmp(aad1, aad2, EVL_AAD_SIZE) != 0) {
        printf("PASS: AAD changes with block_index\n\n");
    } else {
        printf("FAIL: AAD not sensitive to block_index\n");
        return 1;
    }

   
    uint8_t file_id2[EVL_FILE_ID_SIZE];
    memset(file_id2, 0xCC, EVL_FILE_ID_SIZE);
    evl_build_block_aad(file_id2, 0, 4096, aad2, &len2);

    if (memcmp(aad1, aad2, EVL_AAD_SIZE) != 0) {
        printf("PASS: AAD changes with file_id\n\n");
    } else {
        printf("FAIL: AAD not sensitive to file_id\n");
        return 1;
    }

    
    evl_build_block_aad(file_id, 0, 2048, aad2, &len2);

    if (memcmp(aad1, aad2, EVL_AAD_SIZE) != 0) {
        printf("PASS: AAD changes with block_size\n\n");
    } else {
        printf("FAIL: AAD not sensitive to block_size\n");
        return 1;
    }

    return 0;
}