sources:

https://wiki.osdev.org/ELF



algo:

“I chose TEA because it is a well-known lightweight block cipher using Feistel-like rounds and simple integer operations, making it suitable for low-level implementation while still being cryptographically structured.”



#include <stdint.h>

void tea_encrypt(uint32_t v[2], uint32_t k[4]) {
    uint32_t v0 = v[0], v1 = v[1];
    uint32_t sum = 0;
    uint32_t delta = 0x9E3779B9;

    for (int i = 0; i < 32; i++) {
        sum += delta;
        v0 += ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        v1 += ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
    }

    v[0] = v0;
    v[1] = v1;
}


/// notes later if you found .rodata change the variable in stub to let it know it exist seem goes for the case if you found .data