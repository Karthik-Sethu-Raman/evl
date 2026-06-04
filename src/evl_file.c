#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <openssl/rand.h>
#include <assert.h>
#include "evl_file.h"
#include "evl_types.h"
#include "kdf.h"
#include "crypto.h"
#include "header.h"
#include "aad.h"
#include "nonce.h"

#define HEADER_AAD_STR "EVL_HEADER_V1"
#define EVL_HEADER_AAD_PREFIX "EVL_HEADER_V1"
#define EVL_HEADER_AAD_PREFIX_LEN 13

static int evl_seal_header(
    const uint8_t *header_key,
    const uint8_t *header_nonce,
    const uint8_t *header_buf,
    uint8_t *tag_out
) {
    //domain seperation ensuring header authentication != block authentication
    uint8_t aad[EVL_HEADER_AAD_PREFIX_LEN + EVL_HEADER_SIZE];

    memcpy(aad, EVL_HEADER_AAD_PREFIX, EVL_HEADER_AAD_PREFIX_LEN);
    memcpy(aad + EVL_HEADER_AAD_PREFIX_LEN, header_buf, EVL_HEADER_SIZE);

    uint8_t dummy[1]={0};
    //header itself becomes AAD
    return evl_aes_gcm_encrypt(
        header_key,
        header_nonce,
        aad,
        sizeof(aad),
        dummy, 0,
        dummy,
        tag_out //header tag
    );
}

static int evl_verify_header(
    const uint8_t *header_key,
    const uint8_t *header_nonce,
    const uint8_t *header_buf,
    const uint8_t *tag
) {
    uint8_t aad[EVL_HEADER_AAD_PREFIX_LEN + EVL_HEADER_SIZE];

    memcpy(aad, EVL_HEADER_AAD_PREFIX, EVL_HEADER_AAD_PREFIX_LEN);
    memcpy(aad + EVL_HEADER_AAD_PREFIX_LEN, header_buf, EVL_HEADER_SIZE);

    uint8_t dummy[1]={0};

    return evl_aes_gcm_decrypt(
        header_key,
        header_nonce,
        aad,
        sizeof(aad),
        dummy, 0,
        tag,
        dummy
    );
}

int evl_file_create(
    const char *path,
    const char *password,
    uint32_t block_size,
    evl_file_t *out
){
    if (!path || !password || !out)
        return -1;

    int fd = -1;

    uint8_t salt[EVL_SALT_SIZE];
    uint8_t file_id[EVL_FILE_ID_SIZE];

    uint8_t header_nonce[EVL_HEADER_NONCE_SIZE];
    uint8_t header_tag[EVL_HEADER_TAG_SIZE];

    uint8_t master_key[EVL_MASTER_KEY_SIZE];
    uint8_t enc_key[EVL_KEY_SIZE];
    uint8_t header_key[EVL_KEY_SIZE];

    uint8_t header_buf[EVL_HEADER_SIZE];

    fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600); //fail if already exists.
    if (fd < 0)
        goto fail;

    if (RAND_bytes(salt, EVL_SALT_SIZE) != 1) //generating salt
        goto fail;

    if (RAND_bytes(file_id, EVL_FILE_ID_SIZE) != 1) //generating file_id
        goto fail;

    if (RAND_bytes(header_nonce, EVL_HEADER_NONCE_SIZE) != 1) //generating header nonce.
        goto fail;
    
    if (evl_derive_master_key(password, salt, EVL_SALT_SIZE, master_key) != 0) //master key derivation
        goto fail;

    if (evl_expand_keys(master_key, EVL_MASTER_KEY_SIZE, enc_key, header_key) != 0) //key expansion
        goto fail;
    
    //building the header
    evl_header_t header;
    memset(&header, 0, sizeof(header));
    memcpy(header.magic, "EVL1", 4); //Magic
    header.format_version = 1; //Version
    memcpy(header.salt, salt, EVL_SALT_SIZE); //salt
    memcpy(header.file_id, file_id, EVL_FILE_ID_SIZE); //FileSize
    header.file_size = 0;
    header.block_size = block_size; //Block size

    if (evl_header_serialize(&header, header_buf) != 0) //Serializing the header
        goto fail;

    if (evl_seal_header(header_key, header_nonce, header_buf, header_tag) != 0) //Producing the header tag.
        goto fail;

    //Writting header, Nonce and tag to disk
    if (write(fd, header_buf, EVL_HEADER_SIZE) != EVL_HEADER_SIZE)
        goto fail;

    if (write(fd, header_nonce, EVL_HEADER_NONCE_SIZE) != EVL_HEADER_NONCE_SIZE)
        goto fail;

    if (write(fd, header_tag, EVL_HEADER_TAG_SIZE) != EVL_HEADER_TAG_SIZE)
        goto fail;

    out->fd = fd;
    out->header = header;
    memcpy(out->enc_key, enc_key, EVL_KEY_SIZE);
    memcpy(out->header_key, header_key, EVL_KEY_SIZE);

    return 0;

fail:
    if (fd >= 0) {
        close(fd);
        unlink(path);
    }

    OPENSSL_cleanse(master_key, EVL_MASTER_KEY_SIZE);
    OPENSSL_cleanse(enc_key, EVL_KEY_SIZE);
    OPENSSL_cleanse(header_key, EVL_KEY_SIZE);

    return -1;
}


int evl_file_close(evl_file_t *f)
{
    if (!f)
        return -1;

    if (f->fd >= 0) {
        close(f->fd);
        f->fd = -1;
    }

    OPENSSL_cleanse(f->enc_key, EVL_KEY_SIZE);
    OPENSSL_cleanse(f->header_key, EVL_KEY_SIZE);

    memset(&f->header, 0, sizeof(f->header));

    return 0;
}

int evl_file_open(
    const char *path,
    const char *password,
    evl_file_t *out
){
    if (!path || !password || !out)
        return -1;

    int fd = -1;

    uint8_t header_buf[EVL_HEADER_SIZE];
    uint8_t header_nonce[EVL_HEADER_NONCE_SIZE];
    uint8_t header_tag[EVL_HEADER_TAG_SIZE];
    uint8_t master_key[EVL_MASTER_KEY_SIZE];
    uint8_t enc_key[EVL_KEY_SIZE];
    uint8_t header_key[EVL_KEY_SIZE];

    evl_header_t header;

    fd = open(path, O_RDWR);
    if (fd < 0)
        goto fail;

    //Read Header, Nonce, tag
    if (read(fd, header_buf, EVL_HEADER_SIZE) != EVL_HEADER_SIZE) {
        goto fail;
    }

    if (read(fd, header_nonce, EVL_HEADER_NONCE_SIZE) != EVL_HEADER_NONCE_SIZE) {
        goto fail;
    }

    if (read(fd, header_tag, EVL_HEADER_TAG_SIZE) != EVL_HEADER_TAG_SIZE) {
        goto fail;
    }

    //Deserialize
    if (evl_header_deserialize(header_buf, &header) != 0) {
        goto fail;
    }

    //Derive and expand keys
    if (evl_derive_master_key(password, header.salt, EVL_SALT_SIZE, master_key) != 0) {
        goto fail;
    }

    if (evl_expand_keys(master_key, EVL_MASTER_KEY_SIZE, enc_key, header_key) != 0) {
        goto fail;
    }

    //Verify
    if (evl_verify_header(header_key, header_nonce, header_buf, header_tag) != 0)
    goto fail;

    out->fd = fd;
    out->header = header;
    memcpy(out->enc_key, enc_key, EVL_KEY_SIZE);
    memcpy(out->header_key, header_key, EVL_KEY_SIZE);

    return 0;

fail:
    if (fd >= 0)
        close(fd);

    OPENSSL_cleanse(master_key, EVL_MASTER_KEY_SIZE);
    OPENSSL_cleanse(enc_key, EVL_KEY_SIZE);
    OPENSSL_cleanse(header_key, EVL_KEY_SIZE);

    return -1;
}


int evl_write_block(
    evl_file_t *f,
    uint64_t block_index,
    const uint8_t *data,
    size_t data_len
){
    
    if (!f || !data)
        return -1;
    assert(f->header.block_size <= EVL_DEFAULT_BLOCK_SIZE);
    if (data_len > f->header.block_size)
        return -1;

    uint8_t nonce[EVL_NONCE_SIZE];
    uint8_t tag[EVL_TAG_SIZE];

    uint8_t plaintext_buf[EVL_DEFAULT_BLOCK_SIZE];
    uint8_t ciphertext[EVL_DEFAULT_BLOCK_SIZE];

    uint8_t aad[EVL_AAD_SIZE];

    size_t aad_len = 0;
    off_t offset;

    //Entire block encrypts as 4096 bytes
    memset(plaintext_buf, 0, f->header.block_size);
    memcpy(plaintext_buf, data, data_len);

    //Building the AAD
    evl_build_block_aad(
        f->header.file_id,
        block_index,
        f->header.block_size,
        aad,
        &aad_len
    );

    //Generating the Nonce
    if (evl_generate_block_nonce(nonce) != 0)
        return -1;

    //Block encryption
    if (evl_aes_gcm_encrypt(
            f->enc_key,
            nonce,
            aad,
            aad_len,
            plaintext_buf,
            f->header.block_size,
            ciphertext,
            tag
        ) != 0)
        return -1;

    //Disk offset calculation, block N is located directly via arithmetic, no scanning or random access.
    offset =
        EVL_HEADER_SIZE +
        EVL_HEADER_NONCE_SIZE +
        EVL_HEADER_TAG_SIZE +
        block_index * (EVL_NONCE_SIZE + f->header.block_size + EVL_TAG_SIZE);

    if (pwrite(f->fd, nonce, EVL_NONCE_SIZE, offset) != EVL_NONCE_SIZE)  return -1;
    if (pwrite(f->fd, ciphertext, f->header.block_size, offset + EVL_NONCE_SIZE) != (ssize_t)f->header.block_size) return -1;
    if (pwrite(f->fd, tag, EVL_TAG_SIZE, offset + EVL_NONCE_SIZE + f->header.block_size) != EVL_TAG_SIZE) return -1;

    uint64_t old_size = f->header.file_size;
    uint64_t end_pos = block_index * f->header.block_size + data_len;

    if (end_pos > old_size) {

        f->header.file_size = end_pos;

        uint8_t header_buf[EVL_HEADER_SIZE];
        uint8_t header_nonce[EVL_HEADER_NONCE_SIZE];
        uint8_t header_tag[EVL_HEADER_TAG_SIZE];

        //Old header tag is invalid so again:
        if (evl_header_serialize(&f->header, header_buf) != 0)
            goto header_fail;
        
        if (RAND_bytes(header_nonce, EVL_HEADER_NONCE_SIZE) != 1)
            goto header_fail;
        
        if (evl_seal_header(f->header_key, header_nonce, header_buf, header_tag) != 0)
            goto header_fail;
       
        if (pwrite(f->fd, header_buf, EVL_HEADER_SIZE, 0) != EVL_HEADER_SIZE) goto header_fail;
        if (pwrite(f->fd, header_nonce, EVL_HEADER_NONCE_SIZE, EVL_HEADER_SIZE) != EVL_HEADER_NONCE_SIZE) goto header_fail;
        if (pwrite(f->fd, header_tag, EVL_HEADER_TAG_SIZE, EVL_HEADER_SIZE + EVL_HEADER_NONCE_SIZE) != EVL_HEADER_TAG_SIZE) goto header_fail;
        

    }

    OPENSSL_cleanse(plaintext_buf, f->header.block_size);

    return 0;

header_fail:
    f->header.file_size = old_size;

    OPENSSL_cleanse(plaintext_buf, f->header.block_size); //Overwrite data in memory instead of leaving key sitting in RAM.

    return -1;
}


int evl_read_block(
    evl_file_t *f,
    uint64_t block_index,
    uint8_t *out,
    size_t *out_len
){
    
    if (!f || !out || !out_len)
        return -1;
    assert(f->header.block_size <= EVL_DEFAULT_BLOCK_SIZE);
    uint32_t block_size = f->header.block_size;


    uint64_t block_start = block_index * block_size;
    if (block_start >= f->header.file_size)
        return -1;

    size_t valid_len;
    uint64_t remaining = f->header.file_size - block_start;

    if (remaining >= block_size)
        valid_len = block_size;
    else
        valid_len = (size_t)remaining;

    uint8_t nonce[EVL_NONCE_SIZE];
    uint8_t tag[EVL_TAG_SIZE];
    uint8_t ciphertext[EVL_DEFAULT_BLOCK_SIZE];
    uint8_t plaintext[EVL_DEFAULT_BLOCK_SIZE];
    uint8_t aad[EVL_AAD_SIZE];

    size_t aad_len = 0;

    //Disk offset calculation as before
    off_t offset =
        EVL_HEADER_SIZE +
        EVL_HEADER_NONCE_SIZE +
        EVL_HEADER_TAG_SIZE +
        block_index * (EVL_NONCE_SIZE + block_size + EVL_TAG_SIZE);

    //Read Nonce, ciphertext and tag.
    if (pread(f->fd, nonce, EVL_NONCE_SIZE, offset) != EVL_NONCE_SIZE) return -1;
    if (pread(f->fd, ciphertext, block_size, offset + EVL_NONCE_SIZE) != (ssize_t)block_size) return -1;
    if (pread(f->fd, tag, EVL_TAG_SIZE, offset + EVL_NONCE_SIZE + block_size) != EVL_TAG_SIZE) return -1;

    //Rebuild AAD
    evl_build_block_aad(
        f->header.file_id,
        block_index,
        block_size,
        aad,
        &aad_len
    );

    //Decrypt and verfy
    if (evl_aes_gcm_decrypt(
            f->enc_key,
            nonce,
            aad,
            aad_len,
            ciphertext,
            block_size,
            tag,
            plaintext
        ) != 0)
        return -1;

    memcpy(out, plaintext, valid_len);
    *out_len = valid_len;

    return 0;
}