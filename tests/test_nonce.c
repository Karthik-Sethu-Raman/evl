#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "nonce.h"

void print_hex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

int main() {
    uint8_t file_id[16];
    memset(file_id, 0xAA, 16);

    uint8_t nonce1[EVL_NONCE_SIZE];
    uint8_t nonce2[EVL_NONCE_SIZE];
    uint8_t nonce3[EVL_NONCE_SIZE];

    printf("=== NONCE TEST ===\n\n");

    // same input → same nonce
    evl_derive_block_nonce(file_id, 0, 1, nonce1);
    evl_derive_block_nonce(file_id, 0, 1, nonce2);

    printf("Nonce1: ");
    print_hex(nonce1, EVL_NONCE_SIZE);

    printf("Nonce2: ");
    print_hex(nonce2, EVL_NONCE_SIZE);

    if (memcmp(nonce1, nonce2, EVL_NONCE_SIZE) == 0) {
        printf("PASS: Deterministic nonce\n");
    } else {
        printf("FAIL: Non-deterministic nonce\n");
        return 1;
    }

    printf("\n");

    // different block_index → different nonce
    evl_derive_block_nonce(file_id, 1, 1, nonce3);

    printf("Nonce3 (different block_index): ");
    print_hex(nonce3, EVL_NONCE_SIZE);

    if (memcmp(nonce1, nonce3, EVL_NONCE_SIZE) != 0) {
        printf("PASS: Different inputs → different nonce\n");
    } else {
        printf("FAIL: Nonce collision\n");
        return 1;
    }

    return 0;
}