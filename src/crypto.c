#include <openssl/evp.h>
#include <string.h>
#include "crypto.h"

int evl_aes_gcm_encrypt(
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *ciphertext_out,
    uint8_t *tag_out
) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len = 0;
    int ret = -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, EVL_NONCE_SIZE, NULL) != 1)
        goto cleanup;

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto cleanup;

    if (aad && aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len) != 1)
            goto cleanup;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext_out, &len, plaintext, plaintext_len) != 1)
        goto cleanup;

    if (EVP_EncryptFinal_ex(ctx, ciphertext_out + len, &len) != 1)
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, EVL_TAG_SIZE, tag_out) != 1)
        goto cleanup;

    ret = 0;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}


int evl_aes_gcm_decrypt(
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *tag,
    uint8_t *plaintext_out
) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len = 0;
    int ret = -1;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, EVL_NONCE_SIZE, NULL) != 1)
        goto cleanup;

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto cleanup;

    if (aad && aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len) != 1)
            goto cleanup;
    }
    if (EVP_DecryptUpdate(ctx, plaintext_out, &len, ciphertext, ciphertext_len) != 1)
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, EVL_TAG_SIZE, (void *)tag) != 1)
        goto cleanup;

    if (EVP_DecryptFinal_ex(ctx, plaintext_out + len, &len) != 1) {
        goto cleanup;
    }

    ret = 0;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}