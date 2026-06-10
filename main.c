#include "woody.h"
unsigned char sig[7] = "meljira";
uint64_t new_entry_point;
int stub = 0;
unsigned char *stub64_bin;
int stub_size = 0;

unsigned char *load_stub(int type){
    if (type == 1){
        int fd = open("stub64.bin", O_RDONLY);
        if (fd < 0){
            write(2, "Error can't open stub64.bin\n", 28);
            exit(1);
        }
        long long size = lseek(fd, 0, SEEK_END);
        unsigned char *buffer = malloc(size+1);
        if (!buffer){
            write(2, "Error malloc failed\n", 20);
            exit(1);
        }
        lseek(fd, 0, SEEK_SET);
        stub_size = read(fd, buffer, size);
        if (stub_size <= 0){
            write(2, "Error read failed\n", 20);
            exit(1);
        }
        buffer[size+1] = '\0';
        return buffer;
    }
    return NULL;
}

// void encrypt_section(unsigned char *buffer, uint64_t offset, uint64_t size, uint64_t key) {
//     for (size_t i = offset; i < offset+size; i++)
//     {
//         ((unsigned char *)buffer)[i] ^= (unsigned char)(key & 0xFF);
//         key = (key >> 8) | (key << 56);
//     }
// }

void my_strcpy(unsigned char *dest, unsigned const char *src, int size){
    while (size > 0) {
        *dest = *src;
        dest++;
        src++;
        size--;
    }
}

int my_strncmp(unsigned char *dest, unsigned char *src, int size){
    while (size > 0){
        if (*dest != *src){
            return 1;
        }
        dest++;
        src++;
        size--;
    }
    return 0;
}

void patch_stub(unsigned char *stub, size_t len, uint64_t text_va, uint64_t text_sz, uint64_t text_nsz,
                uint64_t ro_va, uint64_t ro_sz, uint64_t data_va, uint64_t data_sz,
                 uint64_t oep, uint64_t key) {
    printf("text=[%lx] p_dist=[%lx]\n", text_va, oep - new_entry_point);
    for (size_t i = 0; i < len - 8; i++) {
        uint64_t *ptr = (uint64_t *)&stub[i];
        if (*ptr == 0xAAAAAAAAAAAAAAA1){
            printf("0xAAAAAAAAAAAAAAA1: %lx\n", new_entry_point - text_va);
            *ptr = new_entry_point - text_va;
        }
        else if (*ptr == 0xAAAAAAAAAAAAAAA2){
            printf("0xAAAAAAAAAAAAAAA2: %lx\n", new_entry_point - ro_va);
            *ptr = (ro_sz == 0) ? 0 : new_entry_point - ro_va;  
        }
        else if (*ptr == 0xAAAAAAAAAAAAAAA3){
            printf("0xAAAAAAAAAAAAAAA3: %lx\n", new_entry_point - data_va);
            *ptr = (data_sz == 0) ? 0 : new_entry_point - data_va;
        }
        else if (*ptr == 0xBBBBBBBBBBBBBBB1) *ptr = text_sz;
        else if (*ptr == 0xEEEEEEEEEEEEEEE1){
            printf("compressed size %lu\n", text_nsz);
            *ptr = text_nsz;
        }
        else if (*ptr == 0xBBBBBBBBBBBBBBB2) *ptr = ro_sz;
        else if (*ptr == 0xBBBBBBBBBBBBBBB3) *ptr = data_sz;
        else if (*ptr == 0xCCCCCCCCCCCCCCCC){
            printf("replace the oep %lx\n", new_entry_point-oep);
            *ptr = new_entry_point - oep;
        }
        else if (*(uint64_t *)ptr == 0xDDDDDDDDDDDDDDD1){
            printf("key was replaced ->>>>>>>>>>>>>>>>>>>>>>>>>>>>>> %lu\n", key);
            *(uint64_t *)ptr = key;
        }
    }
}

int read_header(Woody_data *data){
    unsigned char *buffer;
    
    buffer = NULL;
    off_t fileSize = lseek(data->fd, 0, SEEK_END);
    buffer = malloc(fileSize+4096);
    if (!buffer){
        perror("Error malloc\n");
        return (2);
    }
    lseek(data->fd, 0, SEEK_SET);
    int size2 = read(data->fd, buffer, fileSize);
    if (size2 < 0){
        perror("Error read failed\n");
        free(buffer);
        return (4);
    }

    if (buffer[0] == 0x7f && buffer[1] == 'E' && buffer[2] == 'L' && buffer[3] == 'F'){ // .ELF
        if (!my_strncmp(buffer+8, sig, 6)){ exit(0);}
        if (buffer[4] == 1){
            Elf32_Ehdr *elfHeader = malloc(sizeof(Elf32_Ehdr));
            if (!elfHeader){
                perror("Error malloc\n");
                free(buffer);
                exit(2);
            }
            data->elf32_hdr = elfHeader;
            data->elf32_hdr->e_ident[0] = 1;
            data->elf32_hdr->e_machine = 1;
            data->elf32_hdr->e_entry = *(uint32_t *)(buffer + 24);
        }
        else if (buffer[4] == 2){
            Elf64_Ehdr *elfHeader = malloc(sizeof(Elf64_Ehdr));
            uint64_t original_entry_point;
            if (!elfHeader){
                perror("Error malloc in check_magic_number\n");
                free(buffer);
                exit(2);
            }
            data->elf64_hdr = elfHeader;
            data->elf64_hdr->e_ident[0] = 1;
            data->elf64_hdr->e_machine = 2;
            data->elf64_hdr->e_entry = *(uint64_t *)(buffer + 24);
            original_entry_point = data->elf64_hdr->e_entry;

            uint16_t ph_num = *(uint16_t *)(buffer + 56);

            data->elf64_hdr->e_phoff = *(uint64_t *)(buffer + 32);
            uint64_t ph_off = data->elf64_hdr->e_phoff;

            uint16_t ph_size = *(uint16_t *)(buffer + 54);
            
            data->elf64_hdr->e_shoff = *(uint64_t *)(buffer + 40);
            uint16_t section_header_size = *(uint16_t *)(buffer + 58);
            uint16_t num_sections = *(uint16_t *)(buffer + 60);
            uint16_t string_table_index = *(uint16_t *)(buffer + 62);

            uint64_t initial_shoff = *(uint64_t *)(buffer + 40);
            unsigned char *strtab_hdr = buffer + initial_shoff + (string_table_index * section_header_size);

            uint64_t strtab_file_offset = *(uint64_t *)(strtab_hdr + 24); // sh_offset is at +24
            uint64_t strtab_size = *(uint64_t *)(strtab_hdr + 32);        // sh_size is at +32

            // 3. Keep your malloc for the string table data
            // (We malloc this because when you compress .text and memmove the buffer, 
            // the physical string table will shift. Having a separate copy in memory 
            // prevents your section names from getting corrupted during the shift).
            char *strtab = malloc(strtab_size);
            lseek(data->fd, strtab_file_offset, SEEK_SET);
            read(data->fd, strtab, strtab_size);

            sections Sections;
            Sections.text_sh_size = 0;
            Sections.text_sh_new_size = 0;
            Sections.ro_sh_size = 0;
            Sections.data_sh_size = 0;

            for (int i = 0; i < num_sections; i++) {
                uint64_t current_shoff = *(uint64_t *)(buffer + 40);

                unsigned char *sh_entry = buffer + current_shoff + (i * section_header_size);
                uint32_t name_idx = *(uint32_t *)(sh_entry);
                char *name = strtab + name_idx;

                if (!strcmp(name, ".text")) {
                    Sections.text_sh_addr = *(uint64_t *)(sh_entry + 0x10);
                    Sections.text_sh_offset = *(uint64_t *)(sh_entry + 0x18);
                    Sections.text_sh_size  = *(uint64_t *)(sh_entry + 0x20);
                    unsigned char *tmp = malloc((Sections.text_sh_size*2)+1);
                    memset(tmp, 0, (Sections.text_sh_size * 2) + 1);
                    compress_algo(buffer+Sections.text_sh_offset, Sections.text_sh_size, tmp, (int *)&Sections.text_sh_new_size);
                    memcpy(buffer+Sections.text_sh_offset, tmp, Sections.text_sh_new_size);
                    memset((buffer + Sections.text_sh_offset + Sections.text_sh_new_size), 0, Sections.text_sh_size-Sections.text_sh_new_size);
                    free(tmp);
                    encrypt_section(buffer, Sections.text_sh_offset, Sections.text_sh_size, data->key);
                }
                else if (!strcmp(name, ".rodata")) {
                    Sections.ro_sh_addr = *(uint64_t *)(sh_entry + 0x10);
                    Sections.ro_sh_offset = *(uint64_t *)(sh_entry + 0x18);
                    Sections.ro_sh_size    = *(uint64_t *)(sh_entry + 0x20);
                    encrypt_section(buffer, Sections.ro_sh_offset, Sections.ro_sh_size, data->key);
                }
                else if (!strcmp(name, ".data")) {
                    Sections.data_sh_addr = *(uint64_t *)(sh_entry + 0x10);
                    Sections.data_sh_offset = *(uint64_t *)(sh_entry + 0x18);
                    Sections.data_sh_size    = *(uint64_t *)(sh_entry + 0x20);
                    encrypt_section(buffer, Sections.data_sh_offset, Sections.data_sh_size, data->key);
                }
            }

            uint64_t highest_physical_offset = 0;
            uint16_t phnum = *(uint16_t *)(buffer + 56);
            uint64_t phoff = *(uint64_t *)(buffer + 32);
            uint16_t phentsize = *(uint16_t *)(buffer + 54);

            for (int i = 0; i < phnum; i++) {
                unsigned char *phdr = buffer + phoff + (i * phentsize);
                uint32_t p_type = *(uint32_t *)phdr;
                
                if (p_type == 1 || p_type == 2) { // PT_LOAD or PT_DYNAMIC
                    uint64_t p_offset = *(uint64_t *)(phdr + 0x08);
                    uint64_t p_filesz = *(uint64_t *)(phdr + 0x20);
                    
                    uint64_t segment_end = p_offset + p_filesz;
                    if (segment_end > highest_physical_offset) {
                        highest_physical_offset = segment_end;
                    }
                }
            }

            // Completely discard anything past the highest PT_LOAD segment
            fileSize = highest_physical_offset;

            for (int i = 0; i < ph_num; i++) {
                // Pointer to current Program Header
                unsigned char *ph = buffer + ph_off + (i * ph_size);

                uint32_t p_type = *(uint32_t *)(ph + 0);
                if (p_type == 1) { 
                    printf("pt_load got full right now !!\n");
                    *(uint32_t *)(ph + 4) = 7; 
                }
                if (p_type == 4 && stub == 0) { // pt_note
                    stub = 1;
                    
                    // 1. Find the highest existing virtual memory address used by the binary
                    uint64_t highest_vaddr = 0;
                    for (int j = 0; j < ph_num; j++) {
                        unsigned char *temp_ph = buffer + ph_off + (j * ph_size);
                        if (*(uint32_t *)(temp_ph + 0) == 1) { // If it's a PT_LOAD
                            uint64_t end_vaddr = *(uint64_t *)(temp_ph + 16) + *(uint64_t *)(temp_ph + 40); // p_vaddr + p_memsz
                            if (end_vaddr > highest_vaddr) {
                                highest_vaddr = end_vaddr;
                            }
                        }
                    }

                    // 2. Align the highest address to the next Page boundary (4096 / 0x1000)
                    // This creates a safe "gap" between the original program and your stub
                    highest_vaddr = (highest_vaddr + 4095) & ~4095;

                    // 3. Apply the Strict Loader Alignment Rule
                    // p_vaddr % 4096 MUST EQUAL size (p_offset) % 4096
                    uint64_t safe_vaddr = highest_vaddr + (fileSize % 4096);

                    *(uint32_t *)(ph + 0) = 1; // now its pt_load
                    *(uint32_t *)(ph + 4) = 7;

                    // printf("current location %lu\ncurrent virtual address %lu\ncurrent phisical address %lu\ncurrent size file %lu\ncurrent size in memory %lu\nalign requirment %lu\n",
                    // *(uint64_t *)(ph + 8), *(uint64_t *)(ph + 16), *(uint64_t *)(ph + 24), *(uint64_t *)(ph + 32), *(uint64_t *)(ph + 40),*(uint64_t *)(ph + 48));
                    *(uint64_t *)(ph + 8) = fileSize; // the location of the stub
                    // *(uint64_t *)(ph + 16) = 0xc0000000 + size; // virtual address
                    *(uint64_t *)(ph + 16) = safe_vaddr; // p_vaddr: Our safely calculated address
                    *(uint64_t *)(ph + 24) = safe_vaddr; // p_paddr: physical address (usually same as vaddr)
                    *(uint64_t *)(ph + 24) = fileSize; // phisical address
                    *(uint64_t *)(ph + 32) = 4096; // stub size
                    *(uint64_t *)(ph + 40) = 4096; // stub size
                    *(uint64_t *)(ph + 48) = 4096;
                    
                    new_entry_point = *(uint64_t *)(ph + 16);
                    *(uint64_t *)(buffer + 24) = new_entry_point;
                }
                else if (p_type == 4){
                    *(uint32_t *)(ph + 0) = 0; // now its pt_null
                }
            }
            // and also point back to the original entry point and that should be all
            
            stub64_bin = load_stub(1);

            patch_stub(stub64_bin, stub_size, Sections.text_sh_addr, Sections.text_sh_size, Sections.text_sh_new_size,
            Sections.ro_sh_addr, Sections.ro_sh_size, Sections.data_sh_addr, Sections.data_sh_size,
            original_entry_point, data->key);
    
            memcpy(buffer + 8, sig, 6);

            my_strcpy(buffer+fileSize, stub64_bin, stub_size);
            // 3. Write back to file
            // off_t size = lseek(data->fd, 0, SEEK_END);
            int fd = open("woody", O_WRONLY | O_CREAT | O_TRUNC, 0755);
            if (fd < 0){
                perror("Unable to open file");
                free(strtab);
                free(buffer);
                exit(2);
            }
            // Completely orphan the Section Header Table
            *(uint64_t *)(buffer + 40) = 0; // e_shoff
            *(uint16_t *)(buffer + 58) = 0; // e_shentsize
            *(uint16_t *)(buffer + 60) = 0; // e_shnum
            *(uint16_t *)(buffer + 62) = 0; // e_shstrndx
            write(fd, buffer, fileSize+stub_size);
            free(strtab);
        }
        free(buffer);
        return 1;
    }
    free(buffer);
    return 0;
}

int main(int argc, char **argv)
{
    Woody_data *var;

    var = malloc(sizeof(Woody_data));
    if (!var){
        perror("Error malloc in main\n");
        return (2);
    }

    if (argc < 2){
        perror("No args where provided");
        free(var);
        return (1);
    }

    var->fd = open(argv[1], O_RDONLY);
    if (var->fd < 0){
        perror("Unable to open file");
        free(var);
        return (3);
    }

    if (argc >= 3)
        var->key = atoi(argv[2]);
    else{
        var->key = 1337;
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0)
        {
            perror("Error opening /dev/urandom");
            exit(1);
        }
        if (read(fd, &var->key, sizeof(var->key)) <= 0)
        {
            perror("Error reading random key");
            close(fd);
            exit(1);
        }
        close(fd);
    }

    read_header(var);

    close(var->fd);
    return (0);
}
