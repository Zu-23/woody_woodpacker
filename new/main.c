#include "./woody.h"
unsigned char sig[7] = "meljira";
uint64_t new_entry_point;
// uint64_t new_ventry_point;
int stub = 0;

void encrypt_section(unsigned char *buffer, uint64_t offset, uint64_t size, uint32_t key) {
    unsigned char *key_bytes = (unsigned char *)&key;
    
    for (size_t i = offset; i < offset+size; i++) {
        buffer[i] ^= key_bytes[i % 4]; 
    }
}

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

void patch_stub(unsigned char *stub, size_t len, uint64_t text_va, uint64_t text_sz, 
                uint64_t ro_va, uint64_t ro_sz, uint64_t data_va, uint64_t data_sz, 
                uint64_t oep, uint32_t key) {
    printf("text=[%lx] p_dist=[%lx]\n", text_va, oep - new_entry_point);
    for (size_t i = 0; i < len - 8; i++) {
        uint64_t *ptr = (uint64_t *)&stub[i];
        // We need the DISTANCE from stub to section
        if (*ptr == 0xAAAAAAAAAAAAAAA1){
            printf("0xAAAAAAAAAAAAAAA1: %lx\n", new_entry_point - text_va);
            *ptr = new_entry_point - text_va;
        }
        else if (*ptr == 0xAAAAAAAAAAAAAAA2){
            printf("0xAAAAAAAAAAAAAAA2: %lx\n", new_entry_point - ro_va);
            *ptr = (ro_va == 0) ? 0 : new_entry_point - ro_va;  
        }
        else if (*ptr == 0xAAAAAAAAAAAAAAA3){
            printf("0xAAAAAAAAAAAAAAA3: %lx\n", new_entry_point - data_va);
            *ptr = (data_va == 0) ? 0 : new_entry_point - data_va;
        }
        else if (*ptr == 0xBBBBBBBBBBBBBBB1) *ptr = text_sz;
        else if (*ptr == 0xBBBBBBBBBBBBBBB2) *ptr = ro_sz;
        else if (*ptr == 0xBBBBBBBBBBBBBBB3) *ptr = data_sz;
        else if (*ptr == 0xCCCCCCCCCCCCCCCC){
            printf("replace the oep %lx\n", oep-new_entry_point);
            *ptr = oep - new_entry_point;
        } 
        else if (*(uint32_t *)ptr == 0xDDDDDDDD) *(uint32_t *)ptr = key;
    }
}

int read_header(Woody_data *data){
    unsigned char *buffer;

    buffer = NULL;
    off_t size = lseek(data->fd, 0, SEEK_END);
    buffer = malloc(size+4096);
    if (!buffer){
        perror("Error malloc in check_magic_number\n");
        return (2);
    }
    lseek(data->fd, 0, SEEK_SET);
    int size2 = read(data->fd, buffer, size);
    if (size2 < 0){
        perror("Error read failed in check_magic_number\n");
        free(buffer);
        return (4);
    }

    
    if (buffer[0] == 0x7f && buffer[1] == 'E' && buffer[2] == 'L' && buffer[3] == 'F'){ // .ELF
        if (!my_strncmp(buffer+8, sig, 6)){
            // its already packed (:
            return 0;
        }
        if (buffer[4] == 1){
            Elf32_Ehdr *elfHeader = malloc(sizeof(Elf32_Ehdr));
            if (!elfHeader){
                perror("Error malloc in check_magic_number\n");
                free(buffer);
                return (2);
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
                return (2);
            }

            data->elf64_hdr = elfHeader;
            data->elf64_hdr->e_ident[0] = 1;
            data->elf64_hdr->e_machine = 2;
            // let me save my original entry point
            data->elf64_hdr->e_entry = *(uint64_t *)(buffer + 24);
            original_entry_point = data->elf64_hdr->e_entry;

            // now i will find the pt_note and convert it to pt_load

            uint16_t ph_num = *(uint16_t *)(buffer + 56);
            printf("Number of Program Headers: %d\n", ph_num);

            data->elf64_hdr->e_phoff = *(uint64_t *)(buffer + 32);
            uint64_t ph_off = data->elf64_hdr->e_phoff;
            printf("Program Headers Offset: %lu\n", ph_off);

            uint16_t ph_size = *(uint16_t *)(buffer + 54);
            printf("number of segments: %hu\n", ph_num);
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
                    
                    *(uint32_t *)(ph + 0) = 1; // now its pt_load
                    *(uint32_t *)(ph + 4) = 7;

                    *(uint64_t *)(ph + 8) = size; // the location of the stub
                    *(uint64_t *)(ph + 16) = 0xc0000000 + size; // virtual address
                    *(uint64_t *)(ph + 24) = 0xc0000000 + size; // phisical address
                    *(uint64_t *)(ph + 32) = stub_size; // stub size
                    *(uint64_t *)(ph + 40) = stub_size; // stub size
                    *(uint64_t *)(ph + 48) = 4096;
                    
                    new_entry_point = *(uint64_t *)(ph + 16);
                    printf("new entry point address: %lx\n", new_entry_point);
                }
            }
            data->elf64_hdr->e_shoff = *(uint64_t *)(buffer + 40);

            uint16_t section_header_size = *(uint16_t *)(buffer + 58);
            printf("size of section header: %d\n", section_header_size);
            
            uint16_t num_sections = *(uint16_t *)(buffer + 60);
            printf("Number of Sections: %d\n", num_sections);

            uint16_t string_table_index = *(uint16_t *)(buffer + 62);
            printf("offset of string table: %d\n", string_table_index);

            uint64_t strtable_header_pos = data->elf64_hdr->e_shoff + (string_table_index * section_header_size);
            
            unsigned char sh_entry[64]; // buffer for one section header
            
            lseek(data->fd, strtable_header_pos, SEEK_SET);
            read(data->fd, sh_entry, 64);

            // get file offset of string table (sh_offset is at +24 or 0x18 in 64-bit SH)
            uint64_t strtab_file_offset = *(uint64_t *)(sh_entry + 24);
            uint64_t strtab_size = *(uint64_t *)(sh_entry + 32); // sh_size at +32

            char *strtab = malloc(strtab_size);
            lseek(data->fd, strtab_file_offset, SEEK_SET);
            read(data->fd, strtab, strtab_size);

            uint64_t sh_table_start = data->elf64_hdr->e_shoff;

            sections Sections;
            Sections.text = 0;
            Sections.data = 0;
            Sections.rodata = 0;

            for (int i = 0; i < num_sections; i++) {
                // Read Section Header i
                lseek(data->fd, sh_table_start + (i * section_header_size), SEEK_SET);
                read(data->fd, sh_entry, 64);

                uint32_t name_idx = *(uint32_t *)(sh_entry + 0);
                char *name = strtab + name_idx;

                // Check if it is .text or .data or .rodata
                if (!strcmp(name, ".text")) {
                    Sections.text = 1;
                    Sections.textPAddress = *(uint64_t *)(sh_entry + 8);
                    Sections.textAddress = *(uint64_t *)(sh_entry + 16);
                    Sections.textSize  = *(uint64_t *)(sh_entry + 32);
                    printf("text: %lx %lx %lx\n", Sections.textPAddress, Sections.textAddress, Sections.textSize);

                    printf("Found %s at offset 0x%lx size 0x%lx\n", name, Sections.textAddress, Sections.textSize);
                    // encrypt_section(buffer, Sections.textAddress, Sections.textSize, data->key);
                }
                else if (!strcmp(name, ".data")) {
                    Sections.data = 1;
                    Sections.dataPAddress = *(uint64_t *)(sh_entry + 8);
                    Sections.dataAddress = *(uint64_t *)(sh_entry + 16);
                    Sections.dataSize   = *(uint64_t *)(sh_entry + 32);
                    printf(".data: %lx %lx %lx\n", Sections.dataPAddress, Sections.dataAddress, Sections.dataSize);

                    printf("Found %s at offset 0x%lx size 0x%lx\n", name, Sections.dataAddress, Sections.dataSize);
                    // encrypt_section(buffer, Sections.dataAddress, Sections.dataSize, data->key);
                }
                else if (!strcmp(name, ".rodata")) {
                    Sections.rodata = 1;
                    Sections.roPAddress = *(uint64_t *)(sh_entry + 8);
                    Sections.roAddress = *(uint64_t *)(sh_entry + 16);
                    Sections.roSize    = *(uint64_t *)(sh_entry + 32);
                    printf("rodata: %lx %lx %lx\n", Sections.roPAddress, Sections.roAddress, Sections.roSize);

                    printf("Found %s at offset 0x%lx size 0x%lx\n", name, Sections.roAddress, Sections.roSize);
                    // encrypt_section(buffer, Sections.roAddress, Sections.roSize, data->key);
                }
                // else if (!strcmp(name, ".symtab ")) {
                //     Sections.symtab = 1;
                //     Sections.symtabAddress = *(uint64_t *)(sh_entry + 16);
                //     Sections.symtabSize    = *(uint64_t *)(sh_entry + 32);
                //     printf("Found %s at offset 0x%lx size 0x%lx\n", name, Sections.symtabAddress, Sections.symtabSize);
                //     encrypt_section(buffer, Sections.symtabAddress, Sections.symtabSize, data->key);
                // }
                // else if (!strcmp(name, ".comment")) {
                //     Sections.comment = 1;
                //     Sections.commentAddress = *(uint64_t *)(sh_entry + 16);
                //     Sections.commentSize    = *(uint64_t *)(sh_entry + 32);

                //     printf("Found %s at offset 0x%lx size 0x%lx\n", name, Sections.commentAddress, Sections.commentSize);
                //     encrypt_section(buffer, Sections.commentAddress, Sections.commentSize, data->key);
                // }
            }
            // and also point back to the original entry point and that should be all
            *(uint64_t *)(buffer + 24) = new_entry_point;
            // now i need to update my stub address to point to key and adress and size of sections it should decrypt
            patch_stub(stub64_bin, stub_size, Sections.textAddress, Sections.textSize, 
            Sections.roAddress, Sections.roSize, Sections.dataAddress, Sections.dataSize, 
            original_entry_point, data->key);
            // ofc i will need to add a signature so i don't encrypt more then 1 time
            memcpy(buffer + 8, sig, 6);
            // and later on of course i need to add the compress algo

            // append the stub to the buffer
            my_strcpy(buffer+size, stub64_bin, stub_size);
            // 3. Write back to file
            off_t size = lseek(data->fd, 0, SEEK_END);
            int fd = open("woody", O_WRONLY | O_CREAT | O_TRUNC, 0755);
            if (fd < 0){
                perror("Unable to open file");
                free(strtab);
                free(buffer);
                exit(2);
            }
            write(fd, buffer, size+stub_size);
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
    else
        var->key = 1337;

    read_header(var);

    close(var->fd);
    return (0);
}
