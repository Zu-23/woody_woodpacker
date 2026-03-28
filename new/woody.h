#ifndef WOODY_H
#define WOODY_H

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <stdint.h>

typedef struct
{
    int fd;
    uint64_t key;
    Elf32_Ehdr *elf32_hdr;
    Elf64_Ehdr *elf64_hdr;
} Woody_data;

unsigned char *stub64_bin;

int stub_size = 0;

typedef struct {
    uint64_t text_sh_addr; 
    uint64_t text_sh_offset; 
    uint64_t text_sh_size;

    uint64_t ro_sh_addr;
    uint64_t ro_sh_offset;
    uint64_t ro_sh_size;
    
    uint64_t data_sh_addr;
    uint64_t data_sh_offset;
    uint64_t data_sh_size;
} sections;

extern void encrypt_section(unsigned char *buffer, uint64_t offset, uint64_t size, uint64_t key);

#endif