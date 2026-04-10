#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "block.h"

int main() {
    evl_header_t header;

    // ---- Setup header ----
    memcpy(header.file_id, "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA", 16);
    header.version = 1;
    header.block_size = 4096;

    uint8_t key[32] = {0};

    uint8_t plaintext[] = "block test data";
    size_t pt_len = strlen((char*)plaintext);

    uint8_t ciphertext[128];
    uint8_t decrypted[128];
    uint8_t tag[16];

    printf("=== BLOCK TEST ===\n\n");

    // encrypt
    if (evl_encrypt_block(
        &header,
        key,
        0,
        plaintext,
        pt_len,
        ciphertext,
        tag
    ) != 0) {
        printf("Encrypt failed\n");
        return 1;
    }

    // decrypt
    if (evl_decrypt_block(
        &header,
        key,
        0,
        ciphertext,
        pt_len,
        tag,
        decrypted
    ) != 0) {
        printf("Decrypt failed\n");
        return 1;
    }

    if (memcmp(plaintext, decrypted, pt_len) == 0) {
        printf("PASS: Block encryption/decryption correct\n");
    } else {
        printf("FAIL: Mismatch\n");
        return 1;
    }

    // ---- Tamper test ----
    tag[0] ^= 0xFF;

    if (evl_decrypt_block(
        &header,
        key,
        0,
        ciphertext,
        pt_len,
        tag,
        decrypted
    ) != 0) {
        printf("PASS: Tampering detected\n");
    } else {
        printf("FAIL: Tampering NOT detected\n");
        return 1;
    }

    return 0;
}