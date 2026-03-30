#include "woody.h"

void compress_algo(unsigned char *src, uint64_t src_sz, unsigned char *dest, int *dest_sz){
    uint64_t i = 0;
    uint64_t j = 0;
    while (i < src_sz) {
        unsigned char count = 1;
        while (i + 1 < src_sz && src[i] == src[i+1] && count < 255) {
            count++;
            i++;
        }
        // puts("here");
        dest[j++] = count;
        // puts("here");
        dest[j++] = src[i++];
        // printf("i=[%d] j=[%d]\n", (int)i, (int)j);
    }
    // puts("ok");
    dest[j] = '\0';
    // puts("ok");
    *dest_sz = j;
    // puts("ok");
}

void print_section(unsigned char *section, int size){
    for (int i = 0; i < size;i++){
        printf("%x ", section[i]);
    }
    printf("\n");
}