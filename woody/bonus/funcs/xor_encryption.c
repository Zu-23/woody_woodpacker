#include "../woody.h"

void encrypt_simple_xor(char *data, size_t len)
{
    unsigned char key = 0xAA;
    for (size_t i = 0; i < len; i++)
    {
        data[i] ^= key;
    }
}

void encrypt_rotate_64(char *data, size_t len, uint64_t key)
{
    for (size_t i = 0; i < len; i++)
    {
        data[i] ^= (unsigned char)(key & 0xFF);
        key = (key >> 8) | (key << 56);
    }
}

uint64_t generate_64bit_key()
{
    uint64_t key;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
        return 0x6969696969696969;
    read(fd, &key, sizeof(key));
    close(fd);
    return key;
}