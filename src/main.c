#define FUSE_USE_VERSION 31
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "evl_file.h"
#include "evl_types.h"
#include <fuse.h>
#include <errno.h>

static void usage(void)
{
    fprintf(stderr,
        "Usage:\n"
        "  evl create <file.evl>\n"
        "  evl write  <file.evl> <infile>\n"
        "  evl read   <file.evl>\n"
        "  evl info   <file.evl>\n"
        "  evl verify <file.evl>\n"
        "  evl mount <file.evl> <mountpoint> [-f]\n"
    );
}

static char *prompt_password(const char *prompt)
{
    char *pw = getpass(prompt);
    if (!pw || strlen(pw) == 0) {
        fprintf(stderr, "error: empty password\n");
        return NULL;
    }
    return pw;
}


static const char *VIRTUAL_FILENAME = "/locker.bin";

static evl_file_t *get_evl_ctx(void)
{
    return (evl_file_t *)fuse_get_context()->private_data;
}

static int evl_fuse_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi)
{
    (void)fi;
    memset(stbuf, 0, sizeof(struct stat));

    if (strcmp(path, "/") == 0) {
        stbuf->st_mode  = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
        return 0;
    }

    if (strcmp(path, VIRTUAL_FILENAME) == 0) {
        evl_file_t *f   = get_evl_ctx();
        stbuf->st_mode  = S_IFREG | 0644;
        stbuf->st_nlink = 1;
        stbuf->st_size  = (off_t)f->header.file_size;
        return 0;
    }

    return -ENOENT;
}

static int evl_fuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags)
{
    (void)offset; (void)fi; (void)flags;

    if (strcmp(path, "/") != 0)
        return -ENOENT;

    filler(buf, ".",                  NULL, 0, 0);
    filler(buf, "..",                 NULL, 0, 0);
    filler(buf, VIRTUAL_FILENAME + 1, NULL, 0, 0);

    return 0;
}

static int evl_fuse_open(const char *path, struct fuse_file_info *fi)
{
    (void)fi;
    if (strcmp(path, VIRTUAL_FILENAME) != 0)
        return -ENOENT;
    return 0;
}

static int evl_fuse_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    (void)fi;
    if (strcmp(path, VIRTUAL_FILENAME) != 0)
        return -ENOENT;

    evl_file_t *f        = get_evl_ctx();
    uint64_t    file_size = f->header.file_size;
    uint32_t    block_size = f->header.block_size;

    if ((uint64_t)offset >= file_size)
        return 0;

    if ((uint64_t)offset + size > file_size)
        size = file_size - offset;

    size_t total_read = 0;

    while (total_read < size) {
        uint64_t cur_offset    = (uint64_t)offset + total_read;
        uint64_t block_index   = cur_offset / block_size;
        uint64_t offset_in_blk = cur_offset % block_size;

        uint8_t  block_buf[EVL_DEFAULT_BLOCK_SIZE];
        size_t   out_len = 0;

        if (evl_read_block(f, block_index, block_buf, &out_len) != 0){
            return -EIO;
        }
            

        size_t available = out_len - offset_in_blk;
        size_t to_copy   = size - total_read;
        if (to_copy > available)
            to_copy = available;

        memcpy(buf + total_read, block_buf + offset_in_blk, to_copy);
        total_read += to_copy;
    }

    return (int)total_read;
}

static int evl_fuse_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    (void)fi;
    if (strcmp(path, VIRTUAL_FILENAME) != 0)
        return -ENOENT;

    evl_file_t *f          = get_evl_ctx();
    uint32_t    block_size  = f->header.block_size;
    size_t      total_written = 0;

    while (total_written < size) {
        uint64_t cur_offset    = (uint64_t)offset + total_written;
        uint64_t block_index   = cur_offset / block_size;
        uint64_t offset_in_blk = cur_offset % block_size;

        uint8_t block_buf[EVL_DEFAULT_BLOCK_SIZE];
        size_t  out_len   = 0;
        size_t  to_write  = size - total_written;

        if (to_write > block_size - offset_in_blk)
            to_write = block_size - offset_in_blk;

        if (offset_in_blk != 0 || to_write < block_size) {
            int r = evl_read_block(f, block_index, block_buf, &out_len);
            if (r != 0)
                memset(block_buf, 0, block_size);
        } else {
            memset(block_buf, 0, block_size);
        }

        memcpy(block_buf + offset_in_blk, buf + total_written, to_write);

        size_t write_len = (offset_in_blk + to_write > out_len) ? offset_in_blk + to_write : out_len;

        if (evl_write_block(f, block_index, block_buf, write_len) != 0){
            return -EIO;
        }
            

        total_written += to_write;
    }

    return (int)total_written;
}

static void evl_fuse_destroy(void *private_data)
{
    evl_file_t *f = (evl_file_t *)private_data;
    if (f) {
        evl_file_close(f);
        free(f);
    }
}

static const struct fuse_operations evl_oper = {
    .getattr = evl_fuse_getattr,
    .readdir = evl_fuse_readdir,
    .open    = evl_fuse_open,
    .read    = evl_fuse_read,
    .write   = evl_fuse_write,
    .destroy = evl_fuse_destroy,
};

static int cmd_mount(int argc, char *argv[])
{
    if (argc < 4) {
        usage();
        return 1;
    }

    const char *evl_path   = argv[2];
    const char *mountpoint = argv[3];

    char *pw = prompt_password("Password: ");
    if (!pw) return 1;

    evl_file_t *f = malloc(sizeof(evl_file_t));
    if (!f) return 1;

    if (evl_file_open(evl_path, pw, f) != 0) {
        fprintf(stderr, "error: could not open %s (wrong password?)\n", evl_path);
        free(f);
        return 1;
    }

    printf("Mounting %s at %s\n", evl_path, mountpoint);

    int fuse_argc    = 2 + (argc - 4);
    char **fuse_argv = malloc(fuse_argc * sizeof(char *));
    if (!fuse_argv) { evl_file_close(f); free(f); return 1; }

    fuse_argv[0] = argv[0];
    fuse_argv[1] = (char *)mountpoint;
    for (int i = 4; i < argc; i++)
        fuse_argv[i - 2] = argv[i];

    int ret = fuse_main(fuse_argc, fuse_argv, &evl_oper, f);
    free(fuse_argv);
    return ret;
}

static int cmd_create(const char *path)
{
    char *pw = prompt_password("Password: ");
    if (!pw) return 1;

    char *pw2 = getpass("Confirm password: ");
    if (!pw2 || strcmp(pw, pw2) != 0) {
        fprintf(stderr, "error: passwords do not match\n");
        return 1;
    }

    evl_file_t f;
    if (evl_file_create(path, pw, EVL_DEFAULT_BLOCK_SIZE, &f) != 0) {
        fprintf(stderr, "error: failed to create %s\n", path);
        return 1;
    }

    evl_file_close(&f);
    printf("created: %s\n", path);
    return 0;
}

static int cmd_write(const char *evl_path, const char *in_path)
{
    char *pw = prompt_password("Password: ");
    if (!pw) return 1;

    evl_file_t f;
    if (evl_file_open(evl_path, pw, &f) != 0) {
        fprintf(stderr, "error: could not open %s (wrong password?)\n", evl_path);
        return 1;
    }

    int infd = open(in_path, O_RDONLY);
    if (infd < 0) {
        fprintf(stderr, "error: could not open input file %s\n", in_path);
        evl_file_close(&f);
        return 1;
    }

    uint8_t buf[EVL_DEFAULT_BLOCK_SIZE];
    uint64_t block_index = 0;
    ssize_t bytes_read;
    int ret = 0;

    while ((bytes_read = read(infd, buf, sizeof(buf))) > 0) {
        if (evl_write_block(&f, block_index, buf, (size_t)bytes_read) != 0) {
            fprintf(stderr, "error: write failed at block %llu\n",
                    (unsigned long long)block_index);
            ret = 1;
            break;
        }
        block_index++;
    }

    if (bytes_read < 0) {
        fprintf(stderr, "error: read error on input file\n");
        ret = 1;
    }

    close(infd);
    evl_file_close(&f);

    if (ret == 0)
        fprintf(stderr, "wrote %llu block(s) to %s\n",
                (unsigned long long)block_index, evl_path);
    return ret;
}

static int cmd_read(const char *evl_path)
{
    char *pw = prompt_password("Password: ");
    if (!pw) return 1;

    evl_file_t f;
    if (evl_file_open(evl_path, pw, &f) != 0) {
        fprintf(stderr, "error: could not open %s (wrong password?)\n", evl_path);
        return 1;
    }

    uint8_t buf[EVL_DEFAULT_BLOCK_SIZE];
    uint64_t block_index = 0;
    size_t out_len = 0;
    int ret = 0;

    while (evl_read_block(&f, block_index, buf, &out_len) == 0) {
        if (write(STDOUT_FILENO, buf, out_len) != (ssize_t)out_len) {
            fprintf(stderr, "error: write to stdout failed\n");
            ret = 1;
            break;
        }
        block_index++;
    }

    evl_file_close(&f);
    return ret;
}

static int cmd_info(const char *evl_path)
{
    char *pw = prompt_password("Password: ");
    if (!pw) return 1;

    evl_file_t f;
    if (evl_file_open(evl_path, pw, &f) != 0) {
        fprintf(stderr, "error: could not open %s (wrong password?)\n", evl_path);
        return 1;
    }

    printf("file:         %s\n",   evl_path);
    printf("format:       EVL v%u\n", f.header.format_version);
    printf("block_size:   %u bytes\n", f.header.block_size);
    printf("file_size:    %llu bytes\n", (unsigned long long)f.header.file_size);

    printf("file_id:      ");
    for (int i = 0; i < EVL_FILE_ID_SIZE; i++)
        printf("%02x", f.header.file_id[i]);
    printf("\n");

    evl_file_close(&f);
    return 0;
}

static int cmd_verify(const char *evl_path)
{
    char *pw = prompt_password("Password: ");
    if (!pw) return 1;

    evl_file_t f;
    if (evl_file_open(evl_path, pw, &f) != 0) {
        fprintf(stderr, "FAIL: %s (wrong password or tampered header)\n", evl_path);
        return 1;
    }

    printf("OK: %s authenticates correctly\n", evl_path);
    evl_file_close(&f);
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        usage();
        return 1;
    }

    const char *cmd  = argv[1];
    const char *path = argv[2];

    if (strcmp(cmd, "create") == 0 && argc == 3)
        return cmd_create(path);

    if (strcmp(cmd, "write") == 0 && argc == 4)
        return cmd_write(path, argv[3]);

    if (strcmp(cmd, "read") == 0 && argc == 3)
        return cmd_read(path);

    if (strcmp(cmd, "info") == 0 && argc == 3)
        return cmd_info(path);

    if (strcmp(cmd, "verify") == 0 && argc == 3)
        return cmd_verify(path);

    if (strcmp(cmd, "mount")==0 && argc >=4)
        return cmd_mount(argc, argv);

    usage();
    return 1;
}