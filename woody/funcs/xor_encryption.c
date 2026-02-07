#include "../woody.h"
void encrypt_simple_xor(char *data, size_t len)
{
    unsigned char key = 0xAA;
    for (size_t i = 0; i < len; i++)
    {
        data[i] ^= key;
    }
}