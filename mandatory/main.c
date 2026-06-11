#include "woody.h"

unsigned char sig[8] = "mel-jira";
uint64_t new_entry_point;
int stub = 0;
unsigned char *stub64_bin;
int stub_size = 0;

void ft_perror(const char *errorMsg){
    while (*errorMsg){
        write(2, &*errorMsg++, 1);
    }
}

static	void	ft_printHex(uint64_t nbr)
{
	char	*lowerhex;

	lowerhex = "0123456789ABCDEF";
	if (nbr > 15)
		ft_printHex(nbr / 16);
    write(1, &lowerhex[nbr % 16], 1);
}

void ft_print(const char *str){
    while (*str){
        write(1, &*str++, 1);
    }
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

void encrypt_section(unsigned char *buffer, uint64_t offset, uint64_t size, uint64_t key) {
    for (size_t i = offset; i < offset+size; i++)
    {
        ((unsigned char *)buffer)[i] ^= (unsigned char)(key & 0xFF);
        key = (key >> 8) | (key << 56);
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

void patch_stub(unsigned char *stub, size_t len, uint64_t text_va, uint64_t text_sz,
    uint64_t ro_va, uint64_t ro_sz, uint64_t data_va, uint64_t data_sz, uint64_t oep, uint64_t key) {
    for (size_t i = 0; i < len - 8; i++) {
        uint64_t *ptr = (uint64_t *)&stub[i];
        if (*ptr == 0xAAAAAAAAAAAAAAA1) *ptr = new_entry_point - text_va;
        else if (*ptr == 0xAAAAAAAAAAAAAAA2) *ptr = (ro_sz == 0) ? 0 : new_entry_point - ro_va; 
        else if (*ptr == 0xAAAAAAAAAAAAAAA3) *ptr = (data_sz == 0) ? 0 : new_entry_point - data_va;
        else if (*ptr == 0xBBBBBBBBBBBBBBB1) *ptr = text_sz;
        else if (*ptr == 0xBBBBBBBBBBBBBBB2) *ptr = ro_sz;
        else if (*ptr == 0xBBBBBBBBBBBBBBB3) *ptr = data_sz;
        else if (*ptr == 0xCCCCCCCCCCCCCCCC) *ptr = new_entry_point - oep;
        else if (*(uint64_t *)ptr == 0xDDDDDDDDDDDDDDD1) *(uint64_t *)ptr = key;
    }
}

int read_header(Woody_data *data){
    unsigned char *buffer;
    
    buffer = NULL;
    off_t fileSize = lseek(data->fd, 0, SEEK_END);
    buffer = malloc(fileSize+4096);
    if (!buffer){
        ft_perror("Error malloc\n");
        return (2);
    }
    lseek(data->fd, 0, SEEK_SET);
    int size2 = read(data->fd, buffer, fileSize);
    if (size2 < 0){
        ft_perror("Error read failed\n");
        free(buffer);
        return (4);
    }

    if (buffer[0] == 0x7f && buffer[1] == 'E' && buffer[2] == 'L' && buffer[3] == 'F'){ // .ELF
        if (buffer[8] == 0x6d && buffer[9] == 0x65 && buffer[10] == 0x6c && buffer[11] == 0x2d &&
            buffer[12] == 0x6a && buffer[13] == 0x69 && buffer[14] == 0x72 && buffer[15] == 0x61){
            ft_perror("this is a packed binary by mel-jira packer(:\n");
            exit(0);
        }
        if (buffer[4] == 2){
            ft_print("key_value: ");
            ft_printHex(data->key);
            ft_print("\n");

            Elf64_Ehdr *elfHeader = malloc(sizeof(Elf64_Ehdr));
            if (!elfHeader){
                ft_perror("Error malloc in check_magic_number\n");
                free(buffer);
                exit(2);
            }
            // 1. Just cast the buffer directly, no malloc needed!
            Elf64_Ehdr *ehdr = (Elf64_Ehdr *)buffer;
            data->elf64_hdr = ehdr;

            uint64_t original_entry_point = ehdr->e_entry;

            // 2. Fixed String Table Calculation (using e_shentsize)
            unsigned char *strtab_hdr = buffer + ehdr->e_shoff + (ehdr->e_shstrndx * ehdr->e_shentsize);
            Elf64_Shdr *strtab_shdr = (Elf64_Shdr *)strtab_hdr; // Cast to struct!

            uint64_t strtab_file_offset = strtab_shdr->sh_offset;
            uint64_t strtab_size = strtab_shdr->sh_size;

            char *strtab = malloc(strtab_size);
            lseek(data->fd, strtab_file_offset, SEEK_SET);
            read(data->fd, strtab, strtab_size);

            sections Sections;
            Sections.text_sh_size = 0;
            Sections.ro_sh_size = 0;
            Sections.data_sh_size = 0;

            for (int i = 0; i < ehdr->e_shnum; i++) {

                unsigned char *sh_entry = buffer + ehdr->e_shoff + (i * ehdr->e_shentsize);
                uint32_t name_idx = *(uint32_t *)(sh_entry);
                char *name = strtab + name_idx;

                if (!strcmp(name, ".text")) {
                    Sections.text_sh_addr = *(uint64_t *)(sh_entry + 0x10);
                    Sections.text_sh_offset = *(uint64_t *)(sh_entry + 0x18);
                    Sections.text_sh_size  = *(uint64_t *)(sh_entry + 0x20);
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

            for (int i = 0; i < ehdr->e_phnum; i++) {
                Elf64_Phdr *ph = (Elf64_Phdr *)(buffer + ehdr->e_phoff + (i * ehdr->e_phentsize));

                if (ph->p_type  == 1) {
                    ph->p_flags = 7; 
                }
                if (ph->p_type  == 4 && stub == 0) { // pt_note
                    stub = 1;
                    
                    // 1. Find the highest existing virtual memory address used by the binary
                    uint64_t highest_vaddr = 0;
                    for (int j = 0; j < ehdr->e_phnum; j++) {
                        Elf64_Phdr *temp_ph = (Elf64_Phdr *)(buffer + ehdr->e_phoff + (j * ehdr->e_phentsize));
                        if (temp_ph->p_type == 1) { // If it's a PT_LOAD
                            uint64_t end_vaddr = temp_ph->p_vaddr + temp_ph->p_memsz;
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

                    ph->p_type = 1; // now its pt_load
                    ph->p_flags = 7;
                    ph->p_offset = fileSize; // the location of the stub
                    
                    ph->p_vaddr = safe_vaddr; // p_vaddr: Our safely calculated address
                    ph->p_paddr = safe_vaddr; // p_paddr: physical address (usually same as vaddr)
                    ph->p_paddr = fileSize; // phisical address
                    ph->p_filesz = 4096; // stub size
                    ph->p_memsz = 4096; // stub size
                    ph->p_align = 4096;
                    
                    new_entry_point = ph->p_vaddr;
                    *(uint64_t *)(buffer + 24) = new_entry_point;
                }
                else if (ph->p_type  == 4){
                    *(uint32_t *)(ph + 0) = 0; // now its pt_null
                }
            }
            
            stub64_bin = load_stub(1);

            patch_stub(stub64_bin, stub_size, Sections.text_sh_addr, Sections.text_sh_size,
            Sections.ro_sh_addr, Sections.ro_sh_size, Sections.data_sh_addr, Sections.data_sh_size,
            original_entry_point, data->key);
    
            my_strcpy(buffer + 8, sig, 8);

            my_strcpy(buffer+fileSize, stub64_bin, stub_size);
            // 3. Write back to file
            int fd = open("woody", O_WRONLY | O_CREAT | O_TRUNC, 0755);
            if (fd < 0){
                ft_perror("Unable to open file");
                free(strtab);
                free(buffer);
                exit(2);
            }
            write(fd, buffer, fileSize+stub_size);
            free(strtab);
        }
        else {
            ft_perror("File architecture not suported. x86_64 only\n");
        }
        free(buffer);
        return 1;
    }
    else{
        ft_perror("ELF x86_64 Only\n");
    }
    free(buffer);
    return 0;
}

int main(int argc, char **argv)
{
    Woody_data *var;

    var = malloc(sizeof(Woody_data));
    if (!var){
        ft_perror("Error malloc in main\n");
        return (2);
    }

    if (argc < 2){
        ft_perror("No args where provided");
        free(var);
        return (1);
    }

    var->fd = open(argv[1], O_RDONLY);
    if (var->fd < 0){
        ft_perror("Unable to open file");
        free(var);
        return (3);
    }

    if (argc >= 3)
        var->key = atoi(argv[2]);
    else{
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0)
        {
            ft_perror("Error opening /dev/urandom");
            exit(1);
        }
        if (read(fd, &var->key, sizeof(var->key)) <= 0)
        {
            ft_perror("Error reading random key");
            close(fd);
            exit(1);
        }
        close(fd);
    }

    read_header(var);

    close(var->fd);
    return (0);
}
