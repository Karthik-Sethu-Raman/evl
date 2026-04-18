#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "evl_file.h"
#include "evl_types.h"

static void usage(void)
{
    fprintf(stderr,
        "Usage:\n"
        "  evl create <file.evl>\n"
        "  evl write  <file.evl> <infile>\n"
        "  evl read   <file.evl>\n"
        "  evl info   <file.evl>\n"
        "  evl verify <file.evl>\n"
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

    usage();
    return 1;
}