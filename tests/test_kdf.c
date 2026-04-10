#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "kdf.h"
#include "evl_types.h"

void print_hex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

int main() {
    const char *password = "secure_password";

    uint8_t salt[EVL_SALT_SIZE];
    memset(salt, 0xAA, EVL_SALT_SIZE);  // fixed test salt

    uint8_t master1[32];
    uint8_t master2[32];
    uint8_t master3[32];

    uint8_t enc_key1[32], hdr_key1[32];
    uint8_t enc_key2[32], hdr_key2[32];

    printf("=== KDF TEST ===\n\n");

    // ---- Determinism test ----
    evl_derive_master_key(password, salt, EVL_SALT_SIZE, master1);
    evl_derive_master_key(password, salt, EVL_SALT_SIZE, master2);

    printf("Master Key 1: ");
    print_hex(master1, 32);

    printf("Master Key 2: ");
    print_hex(master2, 32);

    if (memcmp(master1, master2, 32) == 0) {
        printf("PASS: Deterministic master key\n");
    } else {
        printf("FAIL: Master key mismatch\n");
        return 1;
    }

    printf("\n");

    // ---- Password sensitivity ----
    evl_derive_master_key("different_password", salt, EVL_SALT_SIZE, master3);

    if (memcmp(master1, master3, 32) != 0) {
        printf("PASS: Different password → different key\n");
    } else {
        printf("FAIL: Password sensitivity broken\n");
        return 1;
    }

    printf("\n");

    // ---- Salt sensitivity ----
    uint8_t salt2[EVL_SALT_SIZE];
    memset(salt2, 0xBB, EVL_SALT_SIZE);

    evl_derive_master_key(password, salt2, EVL_SALT_SIZE, master3);

    if (memcmp(master1, master3, 32) != 0) {
        printf("PASS: Different salt → different key\n");
    } else {
        printf("FAIL: Salt sensitivity broken\n");
        return 1;
    }

    printf("\n");

    // ---- HKDF expansion ----
    if (evl_expand_keys(master1, 32, enc_key1, hdr_key1) != 0) {
        printf("FAIL: HKDF expansion failed\n");
        return 1;
    }

    if (evl_expand_keys(master1, 32, enc_key2, hdr_key2) != 0) {
        printf("FAIL: HKDF expansion failed\n");
        return 1;
    }

    printf("Enc Key: ");
    print_hex(enc_key1, 32);

    printf("Header Key: ");
    print_hex(hdr_key1, 32);

    // ---- Deterministic expansion ----
    if (memcmp(enc_key1, enc_key2, 32) == 0 &&
        memcmp(hdr_key1, hdr_key2, 32) == 0) {
        printf("PASS: Deterministic key expansion\n");
    } else {
        printf("FAIL: HKDF mismatch\n");
        return 1;
    }

    printf("\n");

    // ---- Domain separation test ----
    if (memcmp(enc_key1, hdr_key1, 32) != 0) {
        printf("PASS: Domain separation works\n");
    } else {
        printf("FAIL: Keys are identical (BAD)\n");
        return 1;
    }

    return 0;
}