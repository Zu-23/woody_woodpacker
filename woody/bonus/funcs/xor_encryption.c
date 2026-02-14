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
        data[i] ^= (unsigned char)(key & 0xFF);//come here
        key = (key >> 8) | (key << 56);
    }
}

void encrypt_rotate_32(char *data, size_t len, uint32_t key)
{
    for (size_t i = 0; i < len; i++)
    {
        data[i] ^= (unsigned char)(key & 0xFF);        
        key = (key >> 8) | (key << 24); 
    }
}

uint64_t generate_64bit_key()
{
    uint64_t key;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
    {
        perror("Error opening urandom\n");
        exit(1);
    }
    if (read(fd, &key, sizeof(key)) == -1)
    {
        perror("Error reading for key\n");
        exit(1);
    }
    close(fd);
    return key;
}