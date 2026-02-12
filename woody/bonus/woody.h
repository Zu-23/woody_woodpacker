#ifndef WOODY_H
#define WOODY_H

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <stdint.h>

typedef struct
{
    int fd;
    uint64_t key;
    int is_32bit;
    union {
        struct {
            Elf64_Ehdr *ehdr;
            Elf64_Phdr *phdr;
        } elf64;
        struct {
            Elf32_Ehdr *ehdr;
            Elf32_Phdr *phdr;
        } elf32;
    } spec;
   union {
        Elf64_Phdr *text_segment64;
        Elf32_Phdr *text_segment32;
    } phdr;
    int text_index;
    int stub_len;
    int cave_size;
    long cave_start_offset;
    long after_text_segment_offset;
    long file_size;
    char *stub;
} Woody_data;





void check_elf(Woody_data *var);
void find_text_segment(Woody_data *var);
void find_cave(Woody_data *var);
void read_stub_and_patch(Woody_data *var);
void create_woody(Woody_data *var);
void encrypt_simple_xor(char *data, size_t len);
uint64_t generate_64bit_key();
void encrypt_rotate_64(char *data, size_t len, uint64_t key);

#endif