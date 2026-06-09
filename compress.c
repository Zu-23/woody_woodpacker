#include "woody.h"

typedef struct {
    int index;
    int length;
} pair;


pair look_in_window(unsigned char *src, int index, int size){
    pair big = {0, 0};
    for (int i = 1;index-i > 0 && i< 4096;i++){
        int j = 0;
        if (src[index - i] == src[index+j]){
            while (src[index-i+j] == src[index+j] && j < 18 && index+j < size)
                j++;
        }
        if (j >= 3){
            if (j > big.length){
                big.index = i;
                big.length = j;
            }
        }
    }
    return (big);
}

void compress_algo(unsigned char *src, int src_sz, unsigned char *dest, int *dest_sz){
    int index = 0;
    int i = 0;
    while (index < src_sz){
        int flag_pos = i++;
        uint8_t flags = 0;
        for (int bit = 0; bit < 8 && index < src_sz; bit++){
            pair data = look_in_window(src, index, src_sz);
            if(data.length >= 3){
                // printf("token size=[%d]\n", data.length);
                flags |= (0 << bit);// token
                uint16_t packed = (data.index << 4) | (data.length - 3);
                dest[i++] = (packed >> 8) & 0xFF;
                dest[i++] = packed & 0xFF;
                index += data.length;
            }
            else{
                flags |= (1 << bit);// literal
                dest[i++] = src[index];
                index++;
            }
        }
        dest[flag_pos] = flags;
    }
    *dest_sz = i;
}

void decompress_algo(unsigned char *src, int src_sz, unsigned char *dest, int *dest_sz)
{
    int index = 0;
    int i = 0;
    while (index < src_sz){
        uint8_t flags = src[index++];
        for (int bit = 0; bit < 8 && index < src_sz; bit++){
            if (flags & (1 << bit)){
                dest[i++] = src[index++];
            }
            else{
                uint16_t packed = (src[index] << 8) | src[index+1];
                index += 2;
                int offset = packed >> 4;
                int length = (packed & 0xF) + 3;
                int start = i - offset;
                for (int j = 0; j < length; j++){
                    dest[i++] = dest[start + j];
                }
            }
        }
    }
    *dest_sz = i;
}

void print_section(unsigned char *section, int size){
    for (int i = 0; i < size;i++){
        printf("%02x ", section[i]);
        if (i % 24 == 0 && i != 0)
            printf("\n");
    }
    printf("\n");
}
