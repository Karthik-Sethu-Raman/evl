#include <argon2.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include "kdf.h"
#define EVL_MASTER_KEY_SIZE 32

int evl_derive_master_key(
    const char *password,
    const uint8_t *salt,
    size_t salt_len,
    uint8_t *master_key_out
){
    if (!password || !salt || !master_key_out){
        return -1;
    }
    uint32_t t_cost = 3;
    uint32_t m_cost = 1 << 16;
    uint32_t parallelism = 1;

    int result = argon2id_hash_raw(
        t_cost,
        m_cost,
        parallelism,
        password,
        strlen(password),
        salt,
        salt_len,
        master_key_out,
        EVL_MASTER_KEY_SIZE
    );

    if(result != ARGON2_OK){
        return -1;
    }
    return 0;
}

static int hkdf_expand(
    const uint8_t *key,
    size_t key_len,
    const char *info,
    uint8_t *out,
    size_t out_len
){
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx)
        return -1;

    int ret = -1;
    size_t len = out_len;

    if (EVP_PKEY_derive_init(pctx) <= 0)
        goto cleanup;

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0)
        goto cleanup;

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, key, key_len) <= 0)
        goto cleanup;

    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, strlen(info)) <= 0)
        goto cleanup;

    if (EVP_PKEY_derive(pctx, out, &len) <= 0)
        goto cleanup;

    ret = 0;

cleanup:
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

int evl_expand_keys(
    const uint8_t *master_key,
    size_t master_key_len,
    uint8_t *enc_key_out,
    uint8_t *header_key_out
) {
    if (hkdf_expand(master_key, master_key_len, "EVL_ENC_KEY_v1", enc_key_out, 32) != 0)
        return -1;

    if (hkdf_expand(master_key, master_key_len, "EVL_HDR_KEY_v1", header_key_out, 32) != 0)
        return -1;

    return 0;
}



