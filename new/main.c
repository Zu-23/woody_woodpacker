#include "./woody.h"
unsigned char sig[7] = "meljira";
uint64_t new_entry_point;
int stub = 0;

void compress_algo(unsigned char *src, size_t src_sz, unsigned char *dest, size_t *dest_sz){
    size_t i = 0;
    size_t j = 0;

    while (i < src_sz) {
        unsigned char count = 1;
        while (i + 1 < src_sz && src[i] == src[i+1] && count < 255) {
            count++;
            i++;
        }
        dest[j++] = count;
        dest[j++] = src[i++];
    }
    *dest_sz = j;
}

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

void patch_stub(unsigned char *stub, size_t len, uint64_t text_va, uint64_t text_sz, 
                uint64_t ro_va, uint64_t ro_sz, uint64_t data_va, uint64_t data_sz,
                 uint64_t oep, uint64_t key) {
    printf("text=[%lx] p_dist=[%lx]\n", text_va, oep - new_entry_point);
    for (size_t i = 0; i < len - 8; i++) {
        uint64_t *ptr = (uint64_t *)&stub[i];\
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
                else if (p_type == 4){
                    *(uint32_t *)(ph + 0) = 0; // now its pt_null
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
            Sections.text_sh_size = 0;
            Sections.ro_sh_size = 0;
            Sections.data_sh_size = 0;

            for (int i = 0; i < num_sections; i++) {
                lseek(data->fd, sh_table_start + (i * section_header_size), SEEK_SET);
                read(data->fd, sh_entry, 64);

                uint32_t name_idx = *(uint32_t *)(sh_entry);
                char *name = strtab + name_idx;

                // printf("text: %s %x %x %lx %lx %lx %x %x %lx %lx\n", strtab+*(uint32_t *)(sh_entry), *(uint32_t *)(sh_entry+4),
                // *(uint32_t *)(sh_entry+8), *(uint64_t *)(sh_entry+0x10), *(uint64_t *)(sh_entry+0x18),
                // *(uint64_t *)(sh_entry+0x20), *(uint32_t *)(sh_entry+0x28), *(uint32_t *)(sh_entry+0x2c),
                // *(uint64_t *)(sh_entry+0x30), *(uint64_t *)(sh_entry+0x38));
                if (!strcmp(name, ".text")) {
                    Sections.text_sh_addr = *(uint64_t *)(sh_entry + 0x10);
                    Sections.text_sh_offset = *(uint64_t *)(sh_entry + 0x18);
                    Sections.text_sh_size  = *(uint64_t *)(sh_entry + 0x20);
                    printf("text: %lx %lx %lx\n", Sections.text_sh_addr, Sections.text_sh_offset, Sections.text_sh_size);

                    printf("Found %s at offset 0x%lx size 0x%lx\n", name, Sections.text_sh_offset, Sections.text_sh_size);
                    encrypt_section(buffer, Sections.text_sh_offset, Sections.text_sh_size, data->key);
                }
                else if (!strcmp(name, ".rodata")) {
                    Sections.ro_sh_addr = *(uint64_t *)(sh_entry + 0x10);
                    Sections.ro_sh_offset = *(uint64_t *)(sh_entry + 0x18);
                    Sections.ro_sh_size    = *(uint64_t *)(sh_entry + 0x20);
                    printf("rodata: %lx %lx %lx\n", Sections.ro_sh_addr, Sections.ro_sh_offset, Sections.ro_sh_size);
                    
                    printf("Found %s at offset 0x%lx size 0x%lx\n", name, Sections.ro_sh_offset, Sections.ro_sh_size);
                    encrypt_section(buffer, Sections.ro_sh_offset, Sections.ro_sh_size, data->key);
                }
                else if (!strcmp(name, ".data")) {
                    Sections.data_sh_addr = *(uint64_t *)(sh_entry + 0x10);
                    Sections.data_sh_offset = *(uint64_t *)(sh_entry + 0x18);
                    Sections.data_sh_size    = *(uint64_t *)(sh_entry + 0x20);
                    printf("rodata: %lx %lx %lx\n", Sections.data_sh_addr, Sections.data_sh_offset, Sections.data_sh_size);
                    
                    printf("Found %s at offset 0x%lx size 0x%lx\n", name, Sections.data_sh_offset, Sections.data_sh_size);
                    encrypt_section(buffer, Sections.data_sh_offset, Sections.data_sh_size, data->key);
                }
            }
            // and also point back to the original entry point and that should be all
            *(uint64_t *)(buffer + 24) = new_entry_point;
            // now i need to update my stub address to point to key and adress and size of sections it should decrypt
            stub64_bin = load_stub(1);
            patch_stub(stub64_bin, stub_size, Sections.text_sh_addr, Sections.text_sh_size, 
            Sections.ro_sh_addr, Sections.ro_sh_size, Sections.data_sh_addr, Sections.data_sh_size,
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
