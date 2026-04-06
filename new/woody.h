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



typedef struct {
    uint64_t text_sh_addr; 
    uint64_t text_sh_offset; 
    uint64_t text_sh_size;
    uint64_t text_sh_new_size;

    uint64_t ro_sh_addr;
    uint64_t ro_sh_offset;
    uint64_t ro_sh_size;
    
    uint64_t data_sh_addr;
    uint64_t data_sh_offset;
    uint64_t data_sh_size;
} sections;

typedef struct s_node{
    int index;
    uint64_t address;
    struct s_node *next;
} t_node;

typedef struct s_book{
    unsigned char *buffer;
    t_node *nodes;
} t_book;

t_book *create_book(unsigned char *buffer);
void add_page(t_book *book, int _index, uint64_t _address);
void compress_algo(unsigned char *src, int src_sz, unsigned char *dest, int *dest_sz);
void decompress_algo(unsigned char *src, int src_sz, unsigned char *dest, int *dest_sz);
void print_section(unsigned char *section, int size);
extern void encrypt_section(unsigned char *buffer, uint64_t offset, uint64_t size, uint64_t key);

#endif