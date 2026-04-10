#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "evl_types.h"
#include "block.h"
#include "evl_types.h"

int main() {
    evl_header_t header;

    // ---- Setup header ----
    memset(header.file_id, 0xAA, EVL_FILE_ID_SIZE);
    header.block_size = 4096;

    uint8_t key[32] = {0};

    uint8_t plaintext[] = "block test data";
    size_t pt_len = strlen((char*)plaintext);

    uint8_t nonce[EVL_NONCE_SIZE];
    uint8_t ciphertext[128];
    uint8_t decrypted[128];
    uint8_t tag[EVL_TAG_SIZE];

    printf("=== BLOCK TEST ===\n\n");

    // ---- Encrypt ----
    if (evl_encrypt_block(
        &header,
        key,
        0,
        plaintext,
        pt_len,
        nonce,
        ciphertext,
        tag
    ) != 0) {
        printf("FAIL: Encrypt failed\n");
        return 1;
    }
    printf("PASS: Encryption succeeded\n");

    // ---- Decrypt ----
    if (evl_decrypt_block(
        &header,
        key,
        0,
        nonce,
        ciphertext,
        pt_len,
        tag,
        decrypted
    ) != 0) {
        printf("FAIL: Decrypt failed\n");
        return 1;
    }

    if (memcmp(plaintext, decrypted, pt_len) == 0) {
        printf("PASS: Block encrypt/decrypt roundtrip correct\n\n");
    } else {
        printf("FAIL: Plaintext mismatch after decryption\n");
        return 1;
    }

    // ---- Tamper test: corrupt tag ----
    tag[0] ^= 0xFF;

    if (evl_decrypt_block(
        &header,
        key,
        0,
        nonce,
        ciphertext,
        pt_len,
        tag,
        decrypted
    ) != 0) {
        printf("PASS: Tag tampering detected\n\n");
    } else {
        printf("FAIL: Tag tampering NOT detected\n");
        return 1;
    }

    // ---- Tamper test: corrupt nonce ----
    tag[0] ^= 0xFF;  // restore tag
    nonce[0] ^= 0xFF;

    if (evl_decrypt_block(
        &header,
        key,
        0,
        nonce,
        ciphertext,
        pt_len,
        tag,
        decrypted
    ) != 0) {
        printf("PASS: Nonce tampering detected\n\n");
    } else {
        printf("FAIL: Nonce tampering NOT detected\n");
        return 1;
    }

    return 0;
}