#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "evl_types.h"
#include "header.h"

#define BUF_SIZE 57

void print_hex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

int compare_headers(const evl_header_t *a, const evl_header_t *b) {
    if (memcmp(a->magic, b->magic, 4) != 0) return 0;
    if (a->format_version != b->format_version) return 0;
    if (memcmp(a->salt, b->salt, 16) != 0) return 0;
    if (memcmp(a->file_id, b->file_id, 16) != 0) return 0;
    if (a->file_size != b->file_size) return 0;
    if (a->block_size != b->block_size) return 0;
    if (a->version != b->version) return 0;
    return 1;
}

int main() {
    evl_header_t original;
    evl_header_t reconstructed;
    uint8_t buffer[BUF_SIZE];

    memcpy(original.magic, "EVL1", 4);
    original.format_version = 1;


    for (int i = 0; i < 16; i++) {
        original.salt[i] = 0xAA;
    }

    for (int i = 0; i < 16; i++) {
        original.file_id[i] = 0xBB;
    }

    original.file_size = 123456789;
    original.block_size = 4096;
    original.version = 1;

 
    evl_header_serialize(&original, buffer);
    if (evl_header_serialize(&original, buffer) != 0) {
        printf("\nFAIL: Serialization failed for valid header\n");
        return 1;
    }

    printf("Serialized Header (hex):\n");
    print_hex(buffer, BUF_SIZE);

    evl_header_deserialize(buffer, &reconstructed);
    if (evl_header_deserialize(buffer, &reconstructed) != 0) {
        printf("\nFAIL: Deserialization failed for valid header\n");
        return 1;
    }

 
    if (compare_headers(&original, &reconstructed)) {
        printf("\nPASS: Header serialization/deserialization correct\n");
    } else {
        printf("\nFAIL: Header mismatch\n");
        return 1;
    }

    if (evl_header_deserialize(NULL, &reconstructed) != -3) {
        printf("FAIL: NULL buffer should return -3\n");
        return 1;
    }

    if (evl_header_deserialize(buffer, NULL) != -3) {
        printf("FAIL: NULL output header should return -3\n");
        return 1;
    }

    original.block_size = 0;
    if (evl_header_serialize(&original, buffer) != -4) {
        printf("FAIL: block_size=0 should fail serialization with -4\n");
        return 1;
    }

    return 0;
}