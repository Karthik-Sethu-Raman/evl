CC      = gcc
CFLAGS  = -Wall -Wextra -Iinclude $(shell pkg-config --cflags fuse3)
LIBS    = -lssl -lcrypto -largon2 -lfuse3

SRCS    = src/utils.c src/kdf.c src/header.c src/nonce.c \
          src/aad.c src/crypto.c src/evl_file.c

CLI     = src/main.c
BIN     = build/evl

TEST_SRCS = tests/test_evl_file.c tests/test_crypto.c \
            tests/test_kdf.c tests/test_header.c \
            tests/test_aad.c tests/test_nonce.c \
            tests/test_block.c tests/test_utils.c

.PHONY: all clean test

all: $(BIN)

$(BIN): $(SRCS) $(CLI) | build
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

build:
	mkdir -p build

test_%: $(SRCS) tests/test_%.c | build
	$(CC) $(CFLAGS) $^ -o build/$@ $(LIBS)
	./build/$@

test: $(patsubst tests/test_%.c, test_%, $(TEST_SRCS))

clean:
	rm -rf build/