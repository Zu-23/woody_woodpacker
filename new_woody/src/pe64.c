#include "../woody.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>



static uint32_t align_up(uint32_t value, uint32_t alignment)
{
    if (alignment == 0) return value;
    return ((value + alignment - 1) / alignment) * alignment;
}

uint32_t rva_to_raw(uint32_t rva, IMAGE_SECTION_HEADER *section)
{
    return rva - section->VirtualAddress + section->PointerToRawData;
}


static void load_stub(t_woody *env, const char *stub_filename)
{
    int fd = open(stub_filename, O_RDONLY);
    if (fd < 0)
    {
        perror("Failed to open stub file");
        exit(1);
    }
    long size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    env->stub_size = size;
    env->stub = malloc(size);
    if (!env->stub)
    {
        perror("Malloc failed for stub");
        close(fd);
        exit(1);
    }

    if (read(fd, env->stub, size) != size)
    {
        perror("Failed to read stub");
        close(fd);
        exit(1);
    }
    close(fd);
}



int check_magic_pe64(void *file_data)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)file_data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)((uint8_t *)file_data + dos->e_lfanew);
    
    
    if (nt->Signature == IMAGE_NT_SIGNATURE && nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
        return 1;
    return 0;
}
int parse_pe64(t_woody *env)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)env->file_data;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)((uint8_t *)env->file_data + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(nt);

    env->pe_hdr.nt_headers = nt;
    env->pe_hdr.section_headers = sections;

    
    uint32_t entry_rva = nt->OptionalHeader.AddressOfEntryPoint;
    env->pe_hdr.text_index = -1;

    
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        uint32_t sec_start = sections[i].VirtualAddress;
        
        
        uint32_t sec_end = sec_start + sections[i].Misc.VirtualSize;

        if (entry_rva >= sec_start && entry_rva < sec_end)
        {
            env->pe_hdr.text_index = i;
            break;
        }
    }

    if (env->pe_hdr.text_index == -1)
    {
       perror("text section not found for entry point");
       exit(1);
    }
    load_stub(env, "stubs/stub_pe64.bin");
    return 1;
}

size_t find_cave_pe64(t_woody *env, size_t stub_size)
{
    IMAGE_NT_HEADERS64 *nt = env->pe_hdr.nt_headers;
    
    
    int last_ndx = nt->FileHeader.NumberOfSections - 1;
    IMAGE_SECTION_HEADER *last_section = &env->pe_hdr.section_headers[last_ndx];
    
    
    IMAGE_SECTION_HEADER *new_section = &env->pe_hdr.section_headers[last_ndx + 1];

    
    memset(new_section, 0, sizeof(IMAGE_SECTION_HEADER));
    memcpy(new_section->Name, ".woody", 6);
    
    
    new_section->Misc.VirtualSize = stub_size;
    new_section->VirtualAddress = align_up(last_section->VirtualAddress + last_section->Misc.VirtualSize, nt->OptionalHeader.SectionAlignment);
    
    
    new_section->SizeOfRawData = align_up(stub_size, nt->OptionalHeader.FileAlignment);
    new_section->PointerToRawData = align_up(last_section->PointerToRawData + last_section->SizeOfRawData, nt->OptionalHeader.FileAlignment);
    
    
    
    new_section->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_CODE; 

    
    nt->FileHeader.NumberOfSections += 1;
    nt->OptionalHeader.SizeOfImage = align_up(new_section->VirtualAddress + new_section->Misc.VirtualSize, nt->OptionalHeader.SectionAlignment);

    
    return new_section->PointerToRawData;
}





int inject_pe64(t_woody *env, size_t cave_offset)
{
    IMAGE_NT_HEADERS64 *nt = env->pe_hdr.nt_headers;
    int new_ndx = nt->FileHeader.NumberOfSections - 1;
    IMAGE_SECTION_HEADER *new_section = &env->pe_hdr.section_headers[new_ndx];
    IMAGE_SECTION_HEADER *text_section = &env->pe_hdr.section_headers[env->pe_hdr.text_index];
    uint32_t old_entry_rva = nt->OptionalHeader.AddressOfEntryPoint;
    uint32_t new_entry_rva = new_section->VirtualAddress;
    nt->OptionalHeader.AddressOfEntryPoint = new_entry_rva;
    uint32_t entry_raw_offset = rva_to_raw(old_entry_rva, text_section);
    uint8_t *code_seg = (uint8_t *)env->file_data + entry_raw_offset;
    uint32_t encrypt_size = text_section->Misc.VirtualSize - (old_entry_rva - text_section->VirtualAddress);
    if (encrypt_size > 256) {
        encrypt_size = 256; 
    }
    encrypt_rotate_64(code_seg, encrypt_size, env->key);

    text_section->Characteristics |= IMAGE_SCN_MEM_WRITE;

    patch_stub_64(env, old_entry_rva, new_entry_rva, encrypt_size);

    size_t new_file_size = new_section->PointerToRawData + new_section->SizeOfRawData;
    
    uint8_t *new_buffer = malloc(new_file_size);
    if (!new_buffer) {
        perror("Failed to allocate expanded file buffer");
        exit(1);
    }
    
    memset(new_buffer, 0, new_file_size);
    memcpy(new_buffer, env->file_data, cave_offset);
    memcpy(new_buffer + cave_offset, env->stub, env->stub_size);
    
    env->file_data = new_buffer; 
    env->new_file_size = new_file_size; 

    return 1;
}

const t_type_handler pe64_type = {
    .check_magic = check_magic_pe64,
    .parse_headers = parse_pe64,
    .find_cave = find_cave_pe64,
    .inject = inject_pe64,
    .format_name = "PE 64-bit"
};
