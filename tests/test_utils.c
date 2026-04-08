#include <stdio.h>
#include <stdint.h>


void write_u32_le(uint8_t *buf, uint32_t val);
uint32_t read_u32_le(const uint8_t *buf);

void print_hex(uint8_t *buf, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

int main() {
    uint32_t x = 0x11223344;
    uint8_t buf[4];

    write_u32_le(buf, x);

    printf("Serialized bytes: ");
    print_hex(buf, 4);

    uint32_t y = read_u32_le(buf);

    printf("Original: 0x%X\n", x);
    printf("Recovered: 0x%X\n", y);

    if (x == y) {
        printf("PASS\n");
    } else {
        printf("FAIL\n");
    }

    return 0;
}