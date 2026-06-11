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
    Elf64_Ehdr *elf64_hdr;
} Woody_data;


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

#endif