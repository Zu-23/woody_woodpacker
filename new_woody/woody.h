#ifndef WOODY_H
#define WOODY_H

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <string.h>
#include <sys/mman.h>


//////////////////////////////////////////////////////////////////////////////////

#include <stdint.h>

#define IMAGE_DOS_SIGNATURE         0x5A4D      // 'MZ'
#define IMAGE_NT_SIGNATURE          0x00004550  // 'PE\0\0'
#define IMAGE_FILE_MACHINE_AMD64    0x8664      // x86-64 Architecture
#define IMAGE_SCN_MEM_EXECUTE       0x20000000  // Executable section
#define IMAGE_SCN_MEM_WRITE         0x80000000  // Writable section

#pragma pack(push, 1)

// --- DOS Header (64 bytes) ---
typedef struct {
    uint16_t e_magic;          // 0x00: 'MZ'
    uint8_t  _pad1[58];        // 0x02: Unused
    uint32_t e_lfanew;         // 0x3C: Offset to NT Headers
} IMAGE_DOS_HEADER;

// --- Flattened NT Headers 64-bit (264 bytes) ---
typedef struct {
    uint32_t Signature;             // 0x00: 'PE\0\0'
    uint16_t Machine;               // 0x04: Architecture
    uint16_t NumberOfSections;      // 0x06: Loop counter
    uint8_t  _pad1[12];             // 0x08: Unused
    uint16_t SizeOfOptionalHeader;  // 0x14: Needed to find sections
    uint16_t Characteristics;       // 0x16: File flags
    uint16_t Magic;                 // 0x18: PE32+ Magic
    uint8_t  _pad2[14];             // 0x1A: Unused
    uint32_t AddressOfEntryPoint;   // 0x28: Original Entry Point RVA
    uint8_t  _pad3[220];            // 0x2C: Unused
} IMAGE_NT_HEADERS64;

// --- Section Header (40 bytes) ---
typedef struct {
    uint8_t  Name[8];               // 0x00: Section name
    uint32_t VirtualSize;           // 0x08: Size in memory
    uint32_t VirtualAddress;        // 0x0C: Relative Virtual Address (RVA)
    uint32_t SizeOfRawData;         // 0x10: Size physically on disk
    uint32_t PointerToRawData;      // 0x14: Physical file offset
    uint8_t  _pad1[12];             // 0x18: Unused
    uint32_t Characteristics;       // 0x24: Executable/Readable/Writable flags
} IMAGE_SECTION_HEADER;

#pragma pack(pop)

// Macro to locate the first section header
#define IMAGE_FIRST_SECTION(ntheader) ((IMAGE_SECTION_HEADER*) \
    ((uint8_t*)(ntheader) + 24 + (ntheader)->SizeOfOptionalHeader))

// Add this to your main t_woody struct or union
typedef struct s_pe_hdr {
    IMAGE_NT_HEADERS64     *nt_headers;
    IMAGE_SECTION_HEADER   *section_headers;
    int                     text_index;
} t_pe_hdr;

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
    t_pe_hdr pe_hdr;  
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
void encrypt_rotate_64(void *data, size_t len, uint64_t key);
void patch_stub_64(t_woody *env, uint64_t old_entry, uint64_t new_entry, uint32_t p_encrypt_size);
#endif