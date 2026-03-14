#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// 1. Helper to convert Windows RVA to Physical File Offset
uint32_t rva_to_raw(uint32_t rva, PIMAGE_SECTION_HEADER section) {
    return rva - section->VirtualAddress + section->PointerToRawData;
}

// 2. Encryption Engine
void encrypt_rotate_64(uint8_t *data, size_t len, uint64_t key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= (uint8_t)(key & 0xFF);
        key = (key >> 8) | (key << 56);
    }
}

// 3. Stub Patcher
void patch_stub_64(uint8_t *stub, size_t stub_size, uint32_t old_entry, uint32_t new_entry, uint32_t p_encrypt_size, uint64_t key) {
    uint32_t p_dist = new_entry - old_entry;
    
    printf("[*] Patching stub...\n");
    for (size_t i = 0; i < stub_size - 8; i++) {
        uint32_t *ptr = (uint32_t *)(stub + i);
        
        if (*ptr == 0x11111111) {
            *ptr = p_dist;
            printf("    [+] Patched p_dist: 0x%X\n", p_dist);
            i += 3;
        }
        else if (*ptr == 0x22222222) {
            *ptr = p_encrypt_size;
            printf("    [+] Patched p_size: 0x%X\n", p_encrypt_size);
            i += 3;
        }
        else if (*ptr == 0xAAAAAAAA) {
            *ptr = (uint32_t)(old_entry - (new_entry + i + 4));
            printf("    [+] Patched p_jmp offset\n");
            i += 3;
        }
        else if (*ptr == 0x33333333) {
            uint64_t *ptr64 = (uint64_t *)(stub + i);
            if (*ptr64 == 0x3333333333333333ULL) { 
                *ptr64 = key;
                printf("    [+] Patched p_key: 0x%llX\n", (unsigned long long)key);
                i += 7;
            }
        }
    }
}

// 4. File I/O Helper
uint8_t* read_file(const char *filename, size_t *out_size) {
    FILE *f = fopen(filename, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    *out_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buffer = malloc(*out_size);
    fread(buffer, 1, *out_size, f);
    fclose(f);
    return buffer;
}

// 5. Main Execution
int main(int argc, char **argv) {
    if (argc != 3) {
        printf("Usage: %s <target.exe> <stub_pe64.bin>\n", argv[0]);
        return 1;
    }

    size_t file_size, stub_size;
    uint8_t *file_data = read_file(argv[1], &file_size);
    uint8_t *stub_data = read_file(argv[2], &stub_size);

    if (!file_data || !stub_data) {
        printf("[!] Error loading files.\n");
        return 1;
    }

    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)file_data;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] Not a valid DOS executable.\n");
        return 1;
    }

    PIMAGE_NT_HEADERS64 nt_headers = (PIMAGE_NT_HEADERS64)(file_data + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE || nt_headers->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        printf("[!] Not a valid 64-bit PE file.\n");
        return 1;
    }

    // Find .text section
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers);
    PIMAGE_SECTION_HEADER text_section = NULL;

    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        if (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            text_section = &section[i];
            break;
        }
    }

    if (!text_section) {
        printf("[!] Could not find executable section.\n");
        return 1;
    }

    

    // Code Cave Logic: Windows pads sections on disk to `FileAlignment` (usually 512 bytes). 
    // The space between VirtualSize (actual code) and SizeOfRawData (padded disk size) is our code cave!
    uint32_t available_padding = text_section->SizeOfRawData - text_section->Misc.VirtualSize;
    if (available_padding < stub_size) {
        printf("[!] Not enough code cave padding at the end of the section.\n");
        return 1;
    }

    // Calculate Offsets
    uint32_t old_entry_rva = nt_headers->OptionalHeader.AddressOfEntryPoint;
    uint32_t inject_rva = text_section->VirtualAddress + text_section->Misc.VirtualSize;
    uint32_t inject_raw = text_section->PointerToRawData + text_section->Misc.VirtualSize;
    
    uint32_t old_entry_raw = rva_to_raw(old_entry_rva, text_section);
    uint32_t encrypt_size = text_section->Misc.VirtualSize - (old_entry_rva - text_section->VirtualAddress);
    uint64_t key = 0xDEADBEEFCAFEBABE; // Hardcoded test key

    printf("[*] Old Entry RVA: 0x%X\n", old_entry_rva);
    printf("[*] New Entry RVA: 0x%X\n", inject_rva);
    printf("[*] Encrypting %u bytes...\n", encrypt_size);

    // Encrypt Host
    encrypt_rotate_64(file_data + old_entry_raw, encrypt_size, key);

    // Patch Stub & Inject
    patch_stub_64(stub_data, stub_size, old_entry_rva, inject_rva, encrypt_size, key);
    memcpy(file_data + inject_raw, stub_data, stub_size);

    // Update Headers
    nt_headers->OptionalHeader.AddressOfEntryPoint = inject_rva;
    text_section->Misc.VirtualSize += stub_size; // Inform Windows to map our stub into memory
    text_section->Characteristics |= IMAGE_SCN_MEM_WRITE; // Grant Write permissions for decryption

    // Write packed file
    FILE *out = fopen("woody.exe", "wb");
    fwrite(file_data, 1, file_size, out);
    fclose(out);

    printf("[*] Successfully packed into woody.exe!\n");

    free(file_data);
    free(stub_data);
    return 0;
}