#ifndef WOODY_H
#define WOODY_H

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <string.h>
#include <sys/mman.h>

typedef struct s_elf
{
    int text_index;
    union
    {
        struct
        {
            Elf64_Ehdr *ehdr;
            Elf64_Phdr *phdr;
        } elf64;
        struct
        {
            Elf32_Ehdr *ehdr;
            Elf32_Phdr *phdr;
        } elf32;
    } spec;

} t_elf;

typedef struct s_woody
{
    void *file_data;  
    size_t file_size; 
    size_t stub_size; 
    void *stub;       
    unsigned int key; 
    t_elf elf_hdr;    
    void *format_state;

    struct s_type_handler *handler;
} t_woody;


typedef struct s_type_handler
{
    int (*check_magic)(void *file_data);
    int (*parse_headers)(t_woody *env);
    size_t (*find_cave)(t_woody *env, size_t stub_size);
    int (*inject)(t_woody *env, size_t cave_offset);
    const char *format_name;
} t_type_handler;

int ft_atoierr(const char *str, uint64_t *out_key);
#endif