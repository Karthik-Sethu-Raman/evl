#include <argon2.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include "kdf.h"
#define EVL_MASTER_KEY_SIZE 32

int evl_derive_master_key( //deriving a master key from the provided password using argon2id.
    const char *password,
    const uint8_t *salt, //from evl header
    size_t salt_len,
    uint8_t *master_key_out //derived key written in this buffer.
){
    if (!password || !salt || !master_key_out){
        return -1;
    }
    //Argon2id parameters:
    uint32_t t_cost = 3; //time cost (3 passes through memory)
    uint32_t m_cost = 1 << 16; //memory cost (64mb)
    uint32_t parallelism = 1; //parallelism, single threaded.

    int result = argon2id_hash_raw( //produces random looking bytes, if "....hash_embedded" were used, it would produce string.
        t_cost,
        m_cost,
        parallelism,
        password,
        strlen(password),
        salt,
        salt_len,
        master_key_out,
        EVL_MASTER_KEY_SIZE //32 bytes
    );

    if(result != ARGON2_OK){
        return -1;
    }
    return 0;
}

static int hkdf_expand( //Internal linkage (only this file can call thi function)
    const uint8_t *key,
    size_t key_len,
    const char *info,
    uint8_t *out,
    size_t out_len
){
    
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL); //Creating HKDF context.
    if (!pctx)
        return -1;

    int ret = -1;
    size_t len = out_len;

    if (EVP_PKEY_derive_init(pctx) <= 0)
        goto cleanup;

    if (EVP_PKEY_CTX_set_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0) //Extraction already done by argon2id (high entropy master key)
        goto cleanup;

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) //Using SHA-256
        goto cleanup;

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, key, key_len) <= 0) //Loading master key.
        goto cleanup;

    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, (const unsigned char *)info, strlen(info)) <= 0) //Different info strings.
        goto cleanup;

    if (EVP_PKEY_derive(pctx, out, &len) <= 0)
        goto cleanup;

    ret = 0;

cleanup:
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

int evl_expand_keys( //key seperation.
    const uint8_t *master_key,
    size_t master_key_len,
    uint8_t *enc_key_out, //Encryption key
    uint8_t *header_key_out //Header key
) {
    if (hkdf_expand(master_key, master_key_len, "EVL_ENC_KEY_v1", enc_key_out, 32) != 0)
        return -1;

    if (hkdf_expand(master_key, master_key_len, "EVL_HDR_KEY_v1", header_key_out, 32) != 0)
        return -1;

    return 0;
}



