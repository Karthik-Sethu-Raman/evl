#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "aad.h"

void print_hex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

int main() {
    uint8_t file_id[16];
    memset(file_id, 0xBB, 16);

    uint8_t aad1[EVL_AAD_SIZE];
    uint8_t aad2[EVL_AAD_SIZE];

    size_t len1 = 0;
    size_t len2 = 0;

    printf("=== AAD TEST ===\n\n");

    evl_build_block_aad(file_id, 0, 1, 4096, aad1, &len1);

    printf("AAD1: ");
    print_hex(aad1, len1);

    printf("Length: %zu\n", len1);

    if (len1 != EVL_AAD_SIZE) {
        printf("FAIL: Incorrect AAD size\n");
        return 1;
    } else {
        printf("PASS: Correct AAD size\n");
    }

    printf("\n");

    // same input → same AAD
    evl_build_block_aad(file_id, 0, 1, 4096, aad2, &len2);

    if (memcmp(aad1, aad2, EVL_AAD_SIZE) == 0) {
        printf("PASS: Deterministic AAD\n");
    } else {
        printf("FAIL: AAD mismatch\n");
        return 1;
    }

    printf("\n");

    // change block_index → must change AAD
    evl_build_block_aad(file_id, 1, 1, 4096, aad2, &len2);

    if (memcmp(aad1, aad2, EVL_AAD_SIZE) != 0) {
        printf("PASS: AAD changes with block_index\n");
    } else {
        printf("FAIL: AAD not sensitive to input change\n");
        return 1;
    }

    return 0;
}