#include "../woody.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void load_stub(t_woody *env, const char *stub_filename)
{
    int fd = open(stub_filename, O_RDONLY);
    if (fd < 0)
    {
        fprintf(stderr, "[!] Error: Could not open stub file: %s\n", stub_filename);
        exit(1);
    }

    long size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    env->stub_size = size;

    // Allocate memory and read the stub bytes into the environment
    env->stub = malloc(size);
    if (!env->stub)
    {
        perror("[!] Error: Malloc failed for stub");
        close(fd);
        exit(1);
    }

    if (read(fd, env->stub, size) != size)
    {
        perror("[!] Error: Failed to read the entire stub file");
        close(fd);
        exit(1);
    }

    close(fd);
    printf("[+] Successfully loaded %s (%ld bytes)\n", stub_filename, size);
}
// Helper: RVA to physical file offset
uint32_t rva_to_raw(uint32_t rva, IMAGE_SECTION_HEADER *section)
{
    return rva - section->VirtualAddress + section->PointerToRawData;
}

int check_magic_pe64(void *file_data)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)file_data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)((uint8_t *)file_data + dos->e_lfanew);
    if (nt->Signature == IMAGE_NT_SIGNATURE && nt->Machine == IMAGE_FILE_MACHINE_AMD64)
    {
        return 1;
    }
    return 0;
}

int parse_pe64(t_woody *env)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)env->file_data;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)((uint8_t *)env->file_data + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(nt);

    env->pe_hdr.nt_headers = nt;
    env->pe_hdr.section_headers = sections;

    uint32_t entry_rva = nt->AddressOfEntryPoint;
    env->pe_hdr.text_index = -1;

    // HUNT: Find the exact section where the Entry Point lives
    for (int i = 0; i < nt->NumberOfSections; i++)
    {
        uint32_t sec_start = sections[i].VirtualAddress;
        uint32_t sec_end = sec_start + sections[i].VirtualSize;

        if (entry_rva >= sec_start && entry_rva < sec_end)
        {
            env->pe_hdr.text_index = i;
            break;
        }
    }

    if (env->pe_hdr.text_index == -1)
    {
        printf("[!] Error: Could not locate the section containing the Entry Point!\n");
        return 0;
    }

    // Load the Windows payload
    load_stub(env, "stubs/stub_pe64.bin");
    return 1;
}

size_t find_cave_pe64(t_woody *env, size_t stub_size)
{
    int ndx = env->pe_hdr.text_index;
    IMAGE_SECTION_HEADER *section = &env->pe_hdr.section_headers[ndx];

    // Windows usually pads sections on disk.
    // The cave is the difference between the physical size and the virtual size.
    size_t end_of_code = section->PointerToRawData + section->VirtualSize;
    size_t available_padding = section->SizeOfRawData - section->VirtualSize;

    if (available_padding >= stub_size)
    {
        return end_of_code; // Return the exact file offset for injection
    }
    else
    {
        printf("Not enough padding in PE .text section!\n");
        exit(1);
    }
    return 0;
}

int inject_pe64(t_woody *env, size_t cave_offset)
{
    int ndx = env->pe_hdr.text_index;
    IMAGE_NT_HEADERS64 *nt = env->pe_hdr.nt_headers;
    IMAGE_SECTION_HEADER *section = &env->pe_hdr.section_headers[ndx];

    uint32_t old_entry_rva = nt->AddressOfEntryPoint;
    uint32_t new_entry_rva = section->VirtualAddress + section->VirtualSize;
    nt->AddressOfEntryPoint = new_entry_rva;
    uint32_t entry_raw_offset = rva_to_raw(old_entry_rva, section);
    uint8_t *code_seg = (uint8_t *)env->file_data + entry_raw_offset;
    uint32_t encrypt_size = section->VirtualSize - (old_entry_rva - section->VirtualAddress);
    if (encrypt_size > 256) {
        encrypt_size = 256; 
    }
    encrypt_rotate_64(code_seg, encrypt_size, env->key);
    section->VirtualSize += env->stub_size;
    section->Characteristics |= IMAGE_SCN_MEM_WRITE;
    patch_stub_64(env, old_entry_rva, new_entry_rva, encrypt_size);
    memcpy((uint8_t *)env->file_data + cave_offset, env->stub, env->stub_size);

    return 1;
}

const t_type_handler pe64_type = {
    .check_magic = check_magic_pe64,
    .parse_headers = parse_pe64,
    .find_cave = find_cave_pe64,
    .inject = inject_pe64,
    .format_name = "PE 64-bit"};