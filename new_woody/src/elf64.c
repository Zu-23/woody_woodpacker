#include "../woody.h" 

void load_stub(t_woody *env)
{
    int stub_fd = open("stubs/stub_elf64.bin", O_RDONLY);
    if (stub_fd < 0)
    {
        perror("Error opening stub.bin");
        exit(1);
    }
    env->stub_size = lseek(stub_fd, 0, SEEK_END);
    env->stub = mmap(NULL, env->stub_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, stub_fd, 0);
    close(stub_fd);
    if (env->stub == MAP_FAILED)
    {
        perror("Error mapping stub");
        exit(1);
    }
}

int check_magic_elf64(void *file_data)
{
    unsigned char *magic = (unsigned char *)file_data;

    if (magic[EI_MAG0] == ELFMAG0 &&
        magic[EI_MAG1] == ELFMAG1 &&
        magic[EI_MAG2] == ELFMAG2 &&
        magic[EI_MAG3] == ELFMAG3 &&
        magic[EI_CLASS] == ELFCLASS64)
    {
        return 1;
    }
    return 0;
}

int parse_elf64(t_woody *env)
{
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)env->file_data;
    Elf64_Phdr *phdr = (Elf64_Phdr *)((unsigned char *)env->file_data + ehdr->e_phoff);
    env->elf_hdr.spec.elf64.ehdr = ehdr;
    env->elf_hdr.spec.elf64.phdr = phdr;
    for (int i = 0; i < ehdr->e_phnum; i++)
    {
        if (phdr[i].p_type == PT_LOAD && (phdr[i].p_flags & PF_X))
        {
            env->elf_hdr.text_index = i;
            break;
        }
    }
    load_stub(env);
    return 1;
}

size_t find_cave_elf64(t_woody *env, size_t stub_size) // returns offset of cave
{
    int ndx = env->elf_hdr.text_index;
    Elf64_Phdr *phdr = env->elf_hdr.spec.elf64.phdr;
    size_t end_of_code = phdr[ndx].p_offset + phdr[ndx].p_filesz;
    size_t available_padding = phdr[ndx + 1].p_offset - end_of_code;

    if (available_padding >= stub_size)
        return end_of_code;
    else
    {
        perror("Not enough space for stub");
        exit(1);
    }
    return 0;
}



void patch_stub_64(t_woody *env, uint64_t old_entry, uint64_t new_entry, uint32_t p_encrypt_size)
{
    uint32_t p_dist = (uint32_t)(new_entry - old_entry);
    uint64_t p_key = env->key;
    
    // Changed to - 8 to safely write a 64-bit key
    for (size_t i = 0; i < env->stub_size - 8; i++) 
    {
        uint32_t *ptr = (uint32_t *)(env->stub + i);
        if (*ptr == 0x11111111)
            *ptr = p_dist;
        else if (*ptr == 0x22222222)
            *ptr = p_encrypt_size; // Now uses the passed parameter!
        else if (*ptr == 0xAAAAAAAA)
            *ptr = (uint32_t)(old_entry - (new_entry + i + 4));
        else if (*ptr == 0x33333333)
        {
            uint64_t *ptr64 = (uint64_t *)(env->stub + i);
            if (*ptr64 == 0x3333333333333333) 
                *ptr64 = p_key;
        }
    }
}


void encrypt_rotate_64(void *data, size_t len, uint64_t key)
{
    for (size_t i = 0; i < len; i++)
    {
        ((unsigned char *)data)[i] ^= (unsigned char)(key & 0xFF);
        key = (key >> 8) | (key << 56);
    }
}

int inject_elf64(t_woody *env, size_t cave_offset)
{
    Elf64_Ehdr *ehdr = env->elf_hdr.spec.elf64.ehdr;
    Elf64_Phdr *phdr = env->elf_hdr.spec.elf64.phdr;
    int ndx = env->elf_hdr.text_index;

    uint64_t original_size = phdr[ndx].p_filesz;
    uint64_t old_entry = ehdr->e_entry;
    uint64_t new_entry = phdr[ndx].p_vaddr + phdr[ndx].p_filesz;
    ehdr->e_entry = new_entry;

    uint64_t entry_file_offset = phdr[ndx].p_offset + (old_entry - phdr[ndx].p_vaddr);

    void *code_seg_location = (unsigned char *)env->file_data + entry_file_offset;
    uint64_t encrypt_size = original_size - (old_entry - phdr[ndx].p_vaddr);
    encrypt_rotate_64(code_seg_location, encrypt_size, env->key);

    phdr[ndx].p_filesz += env->stub_size;
    phdr[ndx].p_memsz += env->stub_size;
    phdr[ndx].p_flags |= PF_W; 

    patch_stub_64(env, old_entry, new_entry, (uint32_t)encrypt_size);
    memcpy((unsigned char *)env->file_data + cave_offset, env->stub, env->stub_size);
    return (1);
}

const t_type_handler elf64_type = {
    .check_magic = check_magic_elf64,
    .parse_headers = parse_elf64,
    .find_cave = find_cave_elf64,
    .inject = inject_elf64,
    .format_name = "ELF 64-bit"};