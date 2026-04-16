#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <openssl/rand.h>

#include "evl_file.h"
#include "evl_types.h"
#include "kdf.h"
#include "crypto.h"
#include "header.h"
#include "aad.h"
#include "nonce.h"

#define HEADER_AAD_STR "EVL_HEADER_V1"


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


    fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd < 0)
        goto fail;

    if (RAND_bytes(salt, EVL_SALT_SIZE) != 1)
        goto fail;
    
    printf("[DBG] create salt: %02X %02X %02X %02X\n",
    salt[0], salt[1], salt[2], salt[3]);

    if (RAND_bytes(file_id, EVL_FILE_ID_SIZE) != 1)
        goto fail;

    if (RAND_bytes(header_nonce, EVL_HEADER_NONCE_SIZE) != 1)
        goto fail;
    
    printf("[DBG] create nonce: %02X %02X %02X %02X\n", header_nonce[0], header_nonce[1], header_nonce[2], header_nonce[3]);


    if (evl_derive_master_key(password, salt, EVL_SALT_SIZE, master_key) != 0)
        goto fail;

    if (evl_expand_keys(master_key, EVL_MASTER_KEY_SIZE, enc_key, header_key) != 0)
        goto fail;
    
    printf("[DBG] create master: %02X %02X %02X %02X\n", master_key[0], master_key[1], master_key[2], master_key[3]);
    printf("[DBG] create hkey:   %02X %02X %02X %02X\n", header_key[0], header_key[1], header_key[2], header_key[3]);


    evl_header_t header;
    memset(&header, 0, sizeof(header));

    memcpy(header.magic, "EVL1", 4);
    header.format_version = 1;
    memcpy(header.salt, salt, EVL_SALT_SIZE);
    memcpy(header.file_id, file_id, EVL_FILE_ID_SIZE);
    header.file_size = 0;
    header.block_size = block_size;

    if (evl_header_serialize(&header, header_buf) != 0)
        goto fail;


    uint8_t header_aad[13 + EVL_HEADER_SIZE];
    memcpy(header_aad, "EVL_HEADER_V1", 13);
    memcpy(header_aad + 13, header_buf, EVL_HEADER_SIZE);
    uint8_t dummy[1];
    if (evl_aes_gcm_encrypt(
            header_key,
            header_nonce,
            header_aad,
            sizeof(header_aad),
            dummy, 0, dummy,
            header_tag
        ) != 0)
        goto fail;

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

    uint8_t header_ct[EVL_HEADER_SIZE];

    uint8_t master_key[EVL_MASTER_KEY_SIZE];
    uint8_t enc_key[EVL_KEY_SIZE];
    uint8_t header_key[EVL_KEY_SIZE];

    evl_header_t header;


    fd = open(path, O_RDWR);
    if (fd < 0)
        goto fail;



    if (read(fd, header_buf, EVL_HEADER_SIZE) != EVL_HEADER_SIZE) {
        printf("[DBG] failed reading header_buf\n");
        goto fail;
    }
    printf("[DBG] magic bytes: %02X %02X %02X %02X\n",
    header_buf[0], header_buf[1], header_buf[2], header_buf[3]);

    printf("[DBG] format_version: %02X\n", header_buf[4]);

    printf("[DBG] block_size bytes: %02X %02X %02X %02X\n",
    header_buf[61], header_buf[62], header_buf[63], header_buf[64]);

    if (read(fd, header_nonce, EVL_HEADER_NONCE_SIZE) != EVL_HEADER_NONCE_SIZE) {
        printf("[DBG] failed reading header_nonce\n");
        goto fail;
    }
    printf("[DBG] open nonce:   %02X %02X %02X %02X\n",
    header_nonce[0], header_nonce[1], header_nonce[2], header_nonce[3]);

    if (read(fd, header_tag, EVL_HEADER_TAG_SIZE) != EVL_HEADER_TAG_SIZE) {
        printf("[DBG] failed reading header_tag\n");
        goto fail;
    }
    printf("[DBG] open tag:  %02X %02X %02X %02X\n",
    header_tag[0], header_tag[1], header_tag[2], header_tag[3]);


    if (evl_header_deserialize(header_buf, &header) != 0) {
        printf("[DBG] deserialize failed\n");
        goto fail;
    }
    printf("[DBG] open file_size:  %llu\n", (unsigned long long)header.file_size);
    printf("[DBG] open salt:   %02X %02X %02X %02X\n", header.salt[0], header.salt[1], header.salt[2], header.salt[3]);
    printf("[DBG] open file_size:  %llu\n", (unsigned long long)header.file_size);


    if (evl_derive_master_key(password, header.salt, EVL_SALT_SIZE, master_key) != 0) {
        printf("[DBG] derive_master_key failed\n");
        goto fail;
    }

    if (evl_expand_keys(master_key, EVL_MASTER_KEY_SIZE, enc_key, header_key) != 0) {
        printf("[DBG] expand_keys failed\n");
        goto fail;
    }
    printf("[DBG] open master:   %02X %02X %02X %02X\n", master_key[0], master_key[1], master_key[2], master_key[3]);
    printf("[DBG] open hkey:     %02X %02X %02X %02X\n", header_key[0], header_key[1], header_key[2], header_key[3]);


    uint8_t header_aad[13 + EVL_HEADER_SIZE];
    memcpy(header_aad, "EVL_HEADER_V1", 13);
    memcpy(header_aad + 13, header_buf, EVL_HEADER_SIZE);
    uint8_t dummy[1];
    if (evl_aes_gcm_decrypt(
            header_key,
            header_nonce,
            header_aad,
            sizeof(header_aad),
            dummy, 0,
            header_tag,
            dummy
        ) != 0) {
        printf("[DBG] header tag verification failed\n");
        goto fail;
    }

    out->fd = fd;
    out->header = header;
    memcpy(out->enc_key, enc_key, EVL_KEY_SIZE);
    memcpy(out->header_key, header_key, EVL_KEY_SIZE);
    printf("[DBG] deserialize passed\n");

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

    if (data_len > f->header.block_size)
        return -1;

    uint8_t nonce[EVL_NONCE_SIZE];
    uint8_t tag[EVL_TAG_SIZE];

    uint8_t plaintext_buf[EVL_DEFAULT_BLOCK_SIZE];
    uint8_t ciphertext[EVL_DEFAULT_BLOCK_SIZE];

    uint8_t aad[EVL_AAD_SIZE];
    uint8_t header_buf[EVL_HEADER_SIZE];

    
    

    size_t aad_len = 0;
    off_t offset;


    memset(plaintext_buf, 0, f->header.block_size);
    memcpy(plaintext_buf, data, data_len);


    evl_build_block_aad(
        f->header.file_id,
        block_index,
        f->header.block_size,
        aad,
        &aad_len
    );


    if (evl_generate_block_nonce(nonce) != 0)
        return -1;


    

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


    offset =
        EVL_HEADER_SIZE +
        EVL_HEADER_NONCE_SIZE +
        EVL_HEADER_TAG_SIZE +
        block_index * (EVL_NONCE_SIZE + f->header.block_size + EVL_TAG_SIZE);

    if (lseek(f->fd, offset, SEEK_SET) < 0)
        return -1;


    if (write(f->fd, nonce, EVL_NONCE_SIZE) != EVL_NONCE_SIZE)
        return -1;

    if (write(f->fd, ciphertext, f->header.block_size) != (ssize_t)f->header.block_size)
        return -1;

    if (write(f->fd, tag, EVL_TAG_SIZE) != EVL_TAG_SIZE)
        return -1;

    uint64_t old_size = f->header.file_size;
    uint64_t end_pos = block_index * f->header.block_size + data_len;

    if (end_pos > old_size) {

        f->header.file_size = end_pos;

        uint8_t header_buf[EVL_HEADER_SIZE];
        uint8_t header_nonce[EVL_HEADER_NONCE_SIZE];
        uint8_t header_tag[EVL_HEADER_TAG_SIZE];

        if (evl_header_serialize(&f->header, header_buf) != 0)
            goto header_fail;
        
        printf("[DBG] write file_size: %llu\n", (unsigned long long)f->header.file_size);

        if (RAND_bytes(header_nonce, EVL_HEADER_NONCE_SIZE) != 1)
            goto header_fail;
        
        printf("[DBG] write nonce:  %02X %02X %02X %02X\n", header_nonce[0], header_nonce[1], header_nonce[2], header_nonce[3]);

        uint8_t header_aad[13 + EVL_HEADER_SIZE];
        memcpy(header_aad, "EVL_HEADER_V1", 13);
        memcpy(header_aad + 13, header_buf, EVL_HEADER_SIZE);
        uint8_t dummy[1];
        if (evl_aes_gcm_encrypt(
                f->header_key,
                header_nonce,
                header_aad,
                sizeof(header_aad),
                dummy, 0, dummy,
                header_tag
            ) != 0)
            goto header_fail;
        printf("[DBG] write file_size: %llu\n", (unsigned long long)f->header.file_size); printf("[DBG] write tag: %02X %02X %02X %02X\n", header_tag[0], header_tag[1], header_tag[2], header_tag[3]);

        if (lseek(f->fd, 0, SEEK_SET) < 0)
            goto header_fail;

        if (write(f->fd, header_buf, EVL_HEADER_SIZE) != EVL_HEADER_SIZE)
            goto header_fail;

        if (write(f->fd, header_nonce, EVL_HEADER_NONCE_SIZE) != EVL_HEADER_NONCE_SIZE)
            goto header_fail;

        if (write(f->fd, header_tag, EVL_HEADER_TAG_SIZE) != EVL_HEADER_TAG_SIZE)
            goto header_fail;
        

    }

    OPENSSL_cleanse(plaintext_buf, f->header.block_size);

    return 0;

header_fail:
    f->header.file_size = old_size;

    OPENSSL_cleanse(plaintext_buf, f->header.block_size);

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

    off_t offset =
        EVL_HEADER_SIZE +
        EVL_HEADER_NONCE_SIZE +
        EVL_HEADER_TAG_SIZE +
        block_index * (EVL_NONCE_SIZE + block_size + EVL_TAG_SIZE);


    if (lseek(f->fd, offset, SEEK_SET) < 0)
        return -1;


    if (read(f->fd, nonce, EVL_NONCE_SIZE) != EVL_NONCE_SIZE)
        return -1;

    if (read(f->fd, ciphertext, block_size) != (ssize_t)block_size)
        return -1;

    if (read(f->fd, tag, EVL_TAG_SIZE) != EVL_TAG_SIZE)
        return -1;


    evl_build_block_aad(
        f->header.file_id,
        block_index,
        block_size,
        aad,
        &aad_len
    );


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

