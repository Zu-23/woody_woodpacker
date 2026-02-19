#ifndef WOODY_H
#define WOODY_H

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <stdint.h>

typedef struct elf_header {
    unsigned char magic; // 1 = ELF 2 = PE
    unsigned char arch; // 1 = 32 bit, 2 = 64 bit
    unsigned char endian; // 1 = little endian, 2 = big endian
    unsigned char version; // ELF header version
    unsigned char os_abi; // OS ABI - usually 0 for System V
    unsigned char type; // Type (1 = relocatable, 2 = executable, 3 = shared, 4 = core)
    unsigned char instruction_set; // AMD/Intel x86-64 or Intel 386 (32-bit) ...
    unsigned char elf_version; // always 1
    unsigned long long entry_offset;
    unsigned long long header_table_offset;
    unsigned long long section_header_table_offset;
    unsigned char flags;
    unsigned int elf_header_size;
    unsigned int size_of_an_enter_in_the_program_heaer_table;
    unsigned int number_of_entries_in_the_section_header_table;
    unsigned int section_index_to_the_section_header_string_table;
} elf_header;


// typedef struct {
// 	Elf32_Word	p_type;
// 	Elf32_Off	p_offset;
// 	Elf32_Addr	p_vaddr;
// 	Elf32_Addr	p_paddr;
// 	Elf32_Word	p_filesz;
// 	Elf32_Word	p_memsz;
// 	Elf32_Word	p_flags;
// 	Elf32_Word	p_align;
// } Elf32_Phdr;

// typedef struct {
// 	Elf64_Word	p_type; // 8 bytes
// 	Elf64_Word	p_flags; // 8 bytes
// 	Elf64_Off	p_offset; // 8 bytes
// 	Elf64_Addr	p_vaddr; // 8 bytes
// 	Elf64_Addr	p_paddr; // 8 bytes
// 	Elf64_Xword	p_filesz; // 8 bytes
// 	Elf64_Xword	p_memsz; // 8 bytes
// 	Elf64_Xword	p_align; // 8 bytes
// } Elf64_Phdr;


typedef struct
{
    int fd;
    elf_header *elfHeader;
} Woody_data;




#endif