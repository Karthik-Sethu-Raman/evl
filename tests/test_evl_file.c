#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "evl_file.h"
#include "evl_types.h"

#define TEST_FILE "test.evl"
#define PASSWORD  "testpassword"

static void die(const char *msg) {
    printf("[FAIL] %s\n", msg);
    exit(1);
}

static void ok(const char *msg) {
    printf("[OK] %s\n", msg);
}

int main() {

    evl_file_t f;

    if (evl_file_create(TEST_FILE, PASSWORD, EVL_DEFAULT_BLOCK_SIZE, &f) != 0)
        die("create failed");

    ok("file created");


    uint8_t data0[EVL_DEFAULT_BLOCK_SIZE];
    memset(data0, 'A', sizeof(data0));

    if (evl_write_block(&f, 0, data0, sizeof(data0)) != 0)
        die("write block 0 failed");

    ok("block 0 written");


    uint8_t data1[100];
    memset(data1, 'B', sizeof(data1));

    if (evl_write_block(&f, 1, data1, sizeof(data1)) != 0)
        die("write block 1 failed");

    ok("block 1 (partial) written");


    if (evl_file_close(&f) != 0)
        die("close failed");

    ok("file closed");


    if (evl_file_open(TEST_FILE, PASSWORD, &f) != 0)
        die("open failed");

    ok("file reopened");


    uint8_t out0[EVL_DEFAULT_BLOCK_SIZE];
    size_t out0_len = 0;

    if (evl_read_block(&f, 0, out0, &out0_len) != 0)
        die("read block 0 failed");

    if (out0_len != EVL_DEFAULT_BLOCK_SIZE)
        die("block 0 size mismatch");

    if (memcmp(out0, data0, EVL_DEFAULT_BLOCK_SIZE) != 0)
        die("block 0 data mismatch");

    ok("block 0 verified");


    uint8_t out1[EVL_DEFAULT_BLOCK_SIZE];
    size_t out1_len = 0;

    if (evl_read_block(&f, 1, out1, &out1_len) != 0)
        die("read block 1 failed");

    if (out1_len != sizeof(data1))
        die("block 1 size mismatch");

    if (memcmp(out1, data1, sizeof(data1)) != 0)
        die("block 1 data mismatch");

    ok("block 1 verified");


    memset(data0, 'C', sizeof(data0));

    if (evl_write_block(&f, 0, data0, sizeof(data0)) != 0)
        die("overwrite block 0 failed");

    if (evl_read_block(&f, 0, out0, &out0_len) != 0)
        die("read after overwrite failed");

    if (memcmp(out0, data0, EVL_DEFAULT_BLOCK_SIZE) != 0)
        die("overwrite verification failed");

    ok("block overwrite verified");


    if (evl_file_close(&f) != 0)
        die("final close failed");

    ok("all tests passed");


    evl_file_t f2;
    if (evl_file_open(TEST_FILE, "wrongpassword", &f2) == 0) {
        evl_file_close(&f2);
        die("wrong password should have been rejected");
    }

    ok("wrong password correctly rejected");


    if (unlink(TEST_FILE) != 0)
        die("failed to cleanup test file");

    ok("cleanup complete");

    return 0;
}