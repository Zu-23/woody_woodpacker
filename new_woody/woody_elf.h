#ifndef WOODY_ELF_H
#define WOODY_ELF_H

// Pull in the standard Linux ELF structs provided by the OS
#include <elf.h>

// =========================================================================
// WOODY ELF STATE
// =========================================================================

// The state block that woody.h will keep track of for ELF files
typedef struct s_elf {
    int text_index;
    
    // Using a union allows you to easily support both 32-bit and 64-bit 
    // Linux binaries later without changing the struct shape!
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

} t_elf;

#endif