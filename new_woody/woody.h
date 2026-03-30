#ifndef WOODY_H
#define WOODY_H

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <stdint.h>

// 1. Include the specific format headers
#include "woody_elf.h"
#include "pe.h"

// 2. Define your master environment struct
typedef struct s_woody
{
    void *file_data;  
    size_t file_size; 
    size_t new_file_size; 
    size_t stub_size; 
    void *stub;       
    uint64_t key; 
    
    t_elf elf_hdr;  
    t_pe_hdr pe_hdr;  
    void *format_state;

    struct s_type_handler *handler;
} t_woody;

// 3. Define the interface handler
typedef struct s_type_handler
{
    int (*check_magic)(void *file_data);
    int (*parse_headers)(t_woody *env);
    size_t (*find_cave)(t_woody *env, size_t stub_size);
    int (*inject)(t_woody *env, size_t cave_offset);
    const char *format_name;
} t_type_handler;

// 4. Global utility prototypes
int ft_atoierr(const char *str, uint64_t *out_key);
void encrypt_rotate_64(void *data, size_t len, uint64_t key);
void patch_stub_64(t_woody *env, uint64_t old_entry, uint64_t new_entry, uint32_t p_encrypt_size);

#endif