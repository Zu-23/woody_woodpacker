#ifndef PE_H
#define PE_H

#include <stdint.h>

// =========================================================================
// CONSTANTS & FLAGS
// =========================================================================
#define IMAGE_DOS_SIGNATURE         0x5A4D      // 'MZ'
#define IMAGE_NT_SIGNATURE          0x00004550  // 'PE\0\0'
#define IMAGE_FILE_MACHINE_AMD64    0x8664      // x86-64 Architecture

// Section Characteristics Flags
#define IMAGE_SCN_CNT_CODE          0x00000020  // Contains executable code
#define IMAGE_SCN_MEM_EXECUTE       0x20000000  // Executable memory
#define IMAGE_SCN_MEM_READ          0x40000000  // Readable memory
#define IMAGE_SCN_MEM_WRITE         0x80000000  // Writable memory

// =========================================================================
// RAW PE STRUCTURES (Packed to exactly match file bytes)
// =========================================================================
#pragma pack(push, 1)

typedef struct {
    uint16_t e_magic;          
    uint8_t  _pad1[58];        
    uint32_t e_lfanew;         
} IMAGE_DOS_HEADER;

typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER;

typedef struct {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
} IMAGE_OPTIONAL_HEADER64;

typedef struct {
    uint32_t Signature;             
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64;

typedef struct {
    uint8_t  Name[8];
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} IMAGE_SECTION_HEADER;

#pragma pack(pop)

// =========================================================================
// MACROS & WOODY STATE
// =========================================================================

// Dynamically jumps past the NT headers to find the start of the section table
#define IMAGE_FIRST_SECTION(ntheader) ((IMAGE_SECTION_HEADER*) \
    ((uint8_t*)(ntheader) + 4 + sizeof(IMAGE_FILE_HEADER) + \
    (ntheader)->FileHeader.SizeOfOptionalHeader))

// The state block that woody.h will keep track of for PE files
typedef struct s_pe_hdr {
    IMAGE_NT_HEADERS64     *nt_headers;
    IMAGE_SECTION_HEADER   *section_headers;
    int                     text_index;
} t_pe_hdr;

#endif