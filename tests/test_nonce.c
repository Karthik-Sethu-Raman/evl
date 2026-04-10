#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "nonce.h"
#include "evl_types.h"

void print_hex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

int main() {
    uint8_t nonce1[EVL_NONCE_SIZE];
    uint8_t nonce2[EVL_NONCE_SIZE];

    printf("=== NONCE TEST ===\n\n");

    if (evl_generate_block_nonce(NULL) != -1) {
        printf("FAIL: NULL output should return -1\n");
        return 1;
    }
    printf("PASS: NULL output rejected\n\n");

    if (evl_generate_block_nonce(nonce1) != 0) {
        printf("FAIL: Nonce generation failed\n");
        return 1;
    }
    printf("Nonce1: ");
    print_hex(nonce1, EVL_NONCE_SIZE);
    printf("PASS: Nonce generation succeeded\n\n");

    if (evl_generate_block_nonce(nonce2) != 0) {
        printf("FAIL: Nonce generation failed\n");
        return 1;
    }
    printf("Nonce2: ");
    print_hex(nonce2, EVL_NONCE_SIZE);

    if (memcmp(nonce1, nonce2, EVL_NONCE_SIZE) != 0) {
        printf("PASS: Successive nonces are distinct\n\n");
    } else {
        printf("FAIL: Nonce collision (CSPRNG may be broken)\n");
        return 1;
    }

    return 0;
}