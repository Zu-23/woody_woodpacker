#include "./woody.h"

void encrypt_section(unsigned char *buffer, uint64_t offset, uint64_t size) {
    for (uint64_t i = offset; i < offset+size; i++) {
        buffer[i] ^= 0x42; 
    }
}

int read_header(Woody_data *data){
    unsigned char *buffer;

    buffer = NULL;
    off_t size = lseek(data->fd, 0, SEEK_END);
    buffer = malloc(size);
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

    elf_header *elfHeader = malloc(sizeof(elf_header));
    if (!elfHeader){
        perror("Error malloc in check_magic_number\n");
        free(buffer);
        return (2);
    }

    data->elfHeader = elfHeader;
    // puts("aaaaaaaaaaaaaaaaaa");
    // printf("%02x %02x %02x\n", buffer[0], buffer[1], buffer[2], buffer[3]);
    if (buffer[0] == 0x7f && buffer[1] == 'E' && buffer[2] == 'L' && buffer[3] == 'F'){ // .ELF
        data->elfHeader->magic = 1;
        if (buffer[4] == 1){
            data->elfHeader->arch = 1;
            data->elfHeader->entry_offset = *(unsigned int *)(buffer + 24);
        }
        else if (buffer[4] == 2){ //finish this first
            // puts("everything good\n");
            data->elfHeader->arch = 2;
            data->elfHeader->entry_offset = *(unsigned long long *)(buffer + 24);
            data->elfHeader->header_table_offset = *(unsigned long long *)(buffer + 32);
            data->elfHeader->section_header_table_offset = *(unsigned long long *)(buffer + 40);
            
            printf("%llu\n", data->elfHeader->entry_offset);
            printf("Program Entry Point: 0x%llx\n", data->elfHeader->entry_offset);
            printf("Program Header Table Offset: 0x%llx\n", data->elfHeader->header_table_offset);
            printf("Program Sectin Header Table Offset: 0x%llx\n", data->elfHeader->section_header_table_offset);

            uint16_t ph_num = *(uint16_t *)(buffer + 56);
            printf("Number of Program Headers: %d\n", ph_num);

            uint16_t section_header_size = *(uint16_t *)(buffer + 58);
            printf("size of section header: %d\n", section_header_size);
            
            uint16_t num_sections = *(uint16_t *)(buffer + 60);
            printf("Number of Sections: %d\n", num_sections);

            uint16_t string_table_index = *(uint16_t *)(buffer + 62);
            printf("offset of string table: %d\n", string_table_index);

            uint64_t strtable_header_pos = data->elfHeader->section_header_table_offset + 
                                        (string_table_index * section_header_size);
            
            unsigned char sh_entry[64]; // buffer for one section header
            
            lseek(data->fd, strtable_header_pos, SEEK_SET);
            read(data->fd, sh_entry, 64);

            // get file offset of string table (sh_offset is at +24 or 0x18 in 64-bit SH)
            uint64_t strtab_file_offset = *(uint64_t *)(sh_entry + 24);
            uint64_t strtab_size = *(uint64_t *)(sh_entry + 32); // sh_size at +32

            char *strtab = malloc(strtab_size);
            lseek(data->fd, strtab_file_offset, SEEK_SET);
            read(data->fd, strtab, strtab_size);

            uint64_t sh_table_start = data->elfHeader->section_header_table_offset;

            for (int i = 0; i < num_sections; i++) {
                // Read Section Header i
                lseek(data->fd, sh_table_start + (i * section_header_size), SEEK_SET);
                read(data->fd, sh_entry, 64);

                // Get Name Index (sh_name @ 0x00)
                uint32_t name_idx = *(uint32_t *)(sh_entry + 0);
                
                // Get Section Name
                char *name = strtab + name_idx;

                // Check if it is .text or .data or .rodata
                if (!strcmp(name, ".text") || !strcmp(name, ".data") || !strcmp(name, ".rodata")) {
                    uint64_t sh_offset = *(uint64_t *)(sh_entry + 24); // sh_offset
                    uint64_t sh_size   = *(uint64_t *)(sh_entry + 32); // sh_size

                    printf("Found %s at offset 0x%lx size 0x%lx\n", name, sh_offset, sh_size);
                    
                    // CALL ENCRYPTION
                    encrypt_section(buffer, sh_offset, sh_size);
                }
            }

            // 1. We need to make the segments WRITABLE so the stub can decrypt .text and .rodata
            uint64_t ph_off = data->elfHeader->header_table_offset;
            // uint16_t ph_num = *(uint16_t *)(buffer + 56);
            uint16_t ph_size = *(uint16_t *)(buffer + 54); // e_phentsize
            printf("number of segments: %d\n", ph_num);
            for (int i = 0; i < ph_num; i++) {
                // Pointer to current Program Header
                unsigned char *ph = buffer + ph_off + (i * ph_size);
                
                // Check if it is a LOAD segment (p_type == 1)
                uint32_t p_type = *(uint32_t *)(ph + 0);
                
                if (p_type == 1) { // PT_LOAD
                    // Get current flags (p_flags at offset 4)
                    uint32_t flags = *(uint32_t *)(ph + 4);
                    printf("Current permission 0x%x\n", flags);
                    // Add Write Permission (PF_W = 2)
                    // We OR it (|) so we don't lose Read/Execute permissions
                    *(uint32_t *)(ph + 4) = flags | 2; 
                    
                    printf("Segment %d: Added Write Flag (New Flags: 0x%x)\n", i, flags | 2);
                }
            }

            // 3. Write back to file
            off_t size = lseek(data->fd, 0, SEEK_END);
            int fd = open("woody", O_WRONLY | O_CREAT | O_TRUNC, 0755);
            if (fd < 0){
                perror("Unable to open file");
                free(strtab);
                free(buffer);
                exit(2);
            }
            write(fd, buffer, size);
            free(strtab);
        }
        free(buffer);
        return 1;
    }
    free(buffer);
    return 0;
}

void handle32_elf(){
    printf("still need to do work 32\n");
}

void handle64_elf(){
    printf("still need to do work 64\n");
}

void handle_elf(Woody_data *data){
    if (data->elfHeader->arch == 1){
        handle32_elf();
    }
    else if (data->elfHeader->arch == 2)
        handle64_elf();
    else
        exit(5);
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

    int type = read_header(var);
    if (type == 1)
        handle_elf(var);
    // puts("all good");
    // else if (type = 2)
    //     handle_pe(var);

    // check_elf(var);
    // find_text_segment(var);
    // find_cave(var);
    // read_stub_and_patch(var);
    // create_woody(var);

    close(var->fd);
    return (0);
}

