#include <stdint.h>
#include "utils.h"

//This avoids compiler padding and platform-dependent memory layouts

//Writting in Little Endian
void write_u64_le(uint8_t *buf, uint64_t val) {
    for (int i = 0; i < 8; i++) {
        buf[i] = (val >> (8 * i)) & 0xFF; //LE, using right shift operation
    }
}

//Reading in little endian.
uint64_t read_u64_le(const uint8_t *buf){
    uint64_t val = 0;
    for (int i=0; i<8; i++){
        val |= ((uint64_t)buf[i]) << (8*i);
    }
    return val;
}


void write_u32_le(uint8_t *buf, uint32_t val) {
    for (int i = 0; i < 4; i++) {
        buf[i] = (val >> (8 * i)) & 0xFF; //LE, using right shift operation
    }
}

uint32_t read_u32_le(const uint8_t *buf){
    uint32_t val = 0;
    for (int i=0; i<4; i++){
        val |= ((uint32_t)buf[i]) << (8*i);
    }
    return val;
}



