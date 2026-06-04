#include <openssl/evp.h>
#include <string.h>
#include "crypto.h"
#include "evl_types.h"

/*This file implements EVL's authenticated encryption layer using AES-256-GCM through OpenSSL's EVP API.
During encryption, it takes a derived AES key, a unique block nonce, optional AAD, and plaintext block data, then produces ciphertext and a GCM authentication tag.
uring decryption, it verifies the authentication tag before accepting the plaintext, ensuring both confidentiality and integrity of every encrypted block stored in the EVL container.
*/

//OpenSSL functions usually return 1 = success and 0 = failure.

int evl_aes_gcm_encrypt( //ENCRYPTION FUNCTION
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *ciphertext_out,
    uint8_t *tag_out
) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); //OpenSSLs encryption context.
    if (!ctx) return -1;

    int len = 0;
    int ret = -1; //Return variable assumes failure by default.

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) //selecting aes-gcm cipher with other parameters null initially.
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, EVL_NONCE_SIZE, NULL) != 1) //setting nonce length.
        goto cleanup;

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) //deriving H and counter state for GCM. (nonce and key are now loaded!)
        goto cleanup;

    if (aad && aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) //AAD processing, not encryption, only GHASH state updation.
            goto cleanup;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext_out, &len, plaintext, plaintext_len) != 1) //Actual encryption (AES-CTR)
        goto cleanup;

    if (EVP_EncryptFinal_ex(ctx, ciphertext_out + len, &len) != 1)
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, EVL_TAG_SIZE, tag_out) != 1) //Retrieving authentication tag.
        goto cleanup;

    ret = 0; //If everything succeeds.

cleanup:
    EVP_CIPHER_CTX_free(ctx); //free the memory
    return ret;
}


int evl_aes_gcm_decrypt( //DECRYPTION FUNCTION
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

    if (EVP_DecryptFinal_ex(ctx, plaintext_out + len, &len) != 1) { //if tag mismatch, reject data.
        goto cleanup;
    }

    ret = 0;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}