#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "crypto.h"

void print_hex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

int main() {
    // ---- Test inputs ----
    uint8_t key[32] = {0};        // 256-bit key (all zeros for test)
    uint8_t nonce[12] = {0};      // 96-bit nonce (all zeros for test)
    uint8_t aad[] = "test_aad";
    uint8_t plaintext[] = "hello world";

    size_t pt_len = strlen((char*)plaintext);
    size_t aad_len = strlen((char*)aad);

    uint8_t ciphertext[128] = {0};
    uint8_t decrypted[128] = {0};
    uint8_t tag[EVL_TAG_SIZE];

    printf("=== AES-GCM TEST ===\n\n");

    // ---- Encrypt ----
    if (evl_aes_gcm_encrypt(
        key,
        nonce,
        aad,
        aad_len,
        plaintext,
        pt_len,
        ciphertext,
        tag
    ) != 0) {
        printf("Encryption failed\n");
        return 1;
    }

    printf("Plaintext:  %s\n", plaintext);

    printf("Ciphertext: ");
    print_hex(ciphertext, pt_len);

    printf("Tag:        ");
    print_hex(tag, EVL_TAG_SIZE);

    printf("\n");

    // ---- Decrypt ----
    if (evl_aes_gcm_decrypt(
        key,
        nonce,
        aad,
        aad_len,
        ciphertext,
        pt_len,
        tag,
        decrypted
    ) != 0) {
        printf("Decryption failed\n");
        return 1;
    }

    printf("Decrypted:  %s\n", decrypted);

    // ---- Verify correctness ----
    if (memcmp(plaintext, decrypted, pt_len) == 0) {
        printf("PASS: Decryption matches original\n");
    } else {
        printf("FAIL: Decryption mismatch\n");
        return 1;
    }

    printf("\n");

    // ---- Tamper test ----
    printf("=== Tamper Test ===\n");

    tag[0] ^= 0xFF;  // corrupt tag

    if (evl_aes_gcm_decrypt(
        key,
        nonce,
        aad,
        aad_len,
        ciphertext,
        pt_len,
        tag,
        decrypted
    ) != 0) {
        printf("PASS: Tampering detected (decryption failed)\n");
    } else {
        printf("FAIL: Tampering NOT detected\n");
        return 1;
    }

    return 0;
}