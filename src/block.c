#include <string.h>
#include "block.h"
#include "nonce.h"
#include "aad.h"
#include "crypto.h"

int evl_encrypt_block(
    const evl_header_t *header,
    const uint8_t *enc_key,
    uint64_t block_index,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *nonce_out,
    uint8_t *ciphertext_out,
    uint8_t *tag_out
){
    uint8_t aad[EVL_AAD_SIZE];
    size_t aad_len = 0;

    if (evl_generate_block_nonce(nonce_out) != 0)
        return -1;

    evl_build_block_aad(
        header->file_id,
        block_index,
        header->block_size,
        aad,
        &aad_len
    );

    return evl_aes_gcm_encrypt(
        enc_key,
        nonce_out,
        aad,
        aad_len,
        plaintext,
        plaintext_len,
        ciphertext_out,
        tag_out
    );
}

int evl_decrypt_block(
    const evl_header_t *header,
    const uint8_t *enc_key,
    uint64_t block_index,
    const uint8_t *nonce,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *tag,
    uint8_t *plaintext_out
){
    uint8_t aad[EVL_AAD_SIZE];
    size_t aad_len = 0;

    evl_build_block_aad(
        header->file_id,
        block_index,
        header->block_size,
        aad,
        &aad_len
    );

    return evl_aes_gcm_decrypt(
        enc_key,
        nonce,
        aad,
        aad_len,
        ciphertext,
        ciphertext_len,
        tag,
        plaintext_out
    );
}