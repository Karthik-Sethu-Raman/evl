CC      = gcc
CFLAGS  = -Wall -Wextra -Iinclude
LIBS    = -lssl -lcrypto -largon2

SRCS    = src/utils.c src/kdf.c src/header.c src/nonce.c \
          src/aad.c src/crypto.c src/evl_file.c

CLI     = src/main.c
BIN     = evl

TEST_SRCS = tests/test_evl_file.c tests/test_crypto.c \
            tests/test_kdf.c tests/test_header.c \
            tests/test_aad.c tests/test_nonce.c \
            tests/test_utils.c

.PHONY: all clean test

all: $(BIN)

$(BIN): $(SRCS) $(CLI)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

test_%: $(SRCS) tests/test_%.c
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)
	./$@
	rm -f $@

test: $(patsubst tests/test_%.c, test_%, $(TEST_SRCS))

clean:
	rm -f $(BIN) test_*