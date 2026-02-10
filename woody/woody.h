#ifndef WOODY_H
#define WOODY_H

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <stdint.h>

struct Woody_data
{
    int fd;
    long key;
    Elf64_Ehdr *header;
    Elf64_Phdr *p_header;
    Elf64_Phdr *text_segment;
    int text_index;
    int stub_len;
    int cave_size;
    long cave_start_offset;
    long after_text_segment_offset;
    long file_size;
    char *stub;
};

void check_elf(struct Woody_data *var);
void find_text_segment(struct Woody_data *var);
void find_cave(struct Woody_data *var);
void read_stub_and_patch(struct Woody_data *var);
void create_woody(struct Woody_data *var);
void encrypt_simple_xor(char *data, size_t len);
uint64_t generate_64bit_key();
void encrypt_rotate_64(char *data, size_t len, uint64_t key);

#endif