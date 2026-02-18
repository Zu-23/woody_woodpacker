#include "../woody.h"

uint32_t get_encrypt_size(Woody_data *var)
{
    long entry_offset;
    long end_offset;
    uint32_t encrypt_size;
    if (var->is_32bit)
    {
        entry_offset = var->spec.elf32.ehdr->e_entry;
        end_offset = var->phdr.text_segment32->p_offset + var->phdr.text_segment32->p_filesz;
        encrypt_size = (uint32_t)(end_offset - entry_offset);
    }
    else
    {
        entry_offset = var->spec.elf64.ehdr->e_entry;
        end_offset = var->phdr.text_segment64->p_offset + var->phdr.text_segment64->p_filesz;
        encrypt_size = (uint32_t)(end_offset - entry_offset);
    }
    return (encrypt_size);
}

uint32_t get_distance(Woody_data *var)
{
    long stub_start_vaddr;
    long entry_vaddr;
    uint32_t distance;
    if (var->is_32bit)
    {
        stub_start_vaddr = var->phdr.text_segment32->p_vaddr + var->phdr.text_segment32->p_filesz;
        entry_vaddr = var->spec.elf32.ehdr->e_entry;
        distance = (uint32_t)(stub_start_vaddr - entry_vaddr);
    }
    else
    {
        stub_start_vaddr = var->phdr.text_segment64->p_vaddr + var->phdr.text_segment64->p_filesz;
        entry_vaddr = var->spec.elf64.ehdr->e_entry;
        distance = (uint32_t)(stub_start_vaddr - entry_vaddr);
    }
    return (distance);
}

void read_stub_and_patch32(Woody_data *var)
{
    var->p_key = 0x33333333 ;
    uint32_t encrypt_size = get_encrypt_size(var);
    uint32_t distance = get_distance(var);
    uint64_t old_entry = var->spec.elf32.ehdr->e_entry;
    uint64_t new_entry = var->phdr.text_segment32->p_vaddr + var->phdr.text_segment32->p_filesz;
    int stub_fd = open("stub32.bin", O_RDONLY);

    if (stub_fd < 0)
    {
        perror("Error opening stub.bin");
        exit(1);
    }
    if ((var->stub = malloc(1000))== NULL)
    {
        perror("Error malloc in read_strub\n");
        exit(1);
    }
    if ((var->stub_len = read(stub_fd, var->stub, 1000)) == -1)
    {
        perror("Error reading stub len\n");
        exit(1);
    }
    close(stub_fd);
    printf("stub len %d\ncave size %d\n", var->stub_len, var->cave_size);
    if (var->stub_len > var->cave_size)
    {
        perror("Stub too big for cave!\n");
        exit(1);
    }
    for (int i = 0; i <= var->stub_len - 4; i++)
    {
        uint32_t val = *(uint32_t *)&var->stub[i];

        if (val == var->p_jmp)
            *(int *)&var->stub[i] = (int)(old_entry - (new_entry + i + 4));
        else if (val == var->p_dist)
            *(uint32_t *)&var->stub[i] = distance;
        else if (val == var->p_size)
            *(uint32_t *)&var->stub[i] = encrypt_size;
        else if (val == var->p_key)
        {
            *(uint32_t *)&var->stub[i] = var->key;
            printf("key %u\n", *(uint32_t *)&var->stub[i]);
            // printf("val of key %ld\n", var->key);
            exit(1);
        }
    }
}

void read_stub_and_patch(Woody_data *var)
{
    if (var->is_32bit)
        read_stub_and_patch32(var);
    else
    {
        var->p_jmp = 0xAAAAAAAA;
        var->p_dist = 0x11111111;
        var->p_size = 0x22222222;
        var->p_key = 0x1122334455667788;
        uint32_t encrypt_size = get_encrypt_size(var);
        uint32_t distance = get_distance(var);
        uint64_t old_entry = var->spec.elf64.ehdr->e_entry;
        uint64_t new_entry = var->phdr.text_segment64->p_vaddr + var->phdr.text_segment64->p_filesz;
        int stub_fd = open("stub.bin", O_RDONLY);

        if (stub_fd < 0)
        {
            perror("Error opening stub.bin");
            exit(1);
        }
        if ((var->stub = malloc(1000)) == NULL)
        {
            perror("Error malloc in read_strub\n");
            exit(1);
        }
        if ((var->stub_len = read(stub_fd, var->stub, 1000)) == -1)
        {
            perror("Error reading for stub len\n");
            exit(1);
        }
        close(stub_fd);
        if (var->stub_len > var->cave_size)
        {
            perror("Stub too big for cave!\n");
            exit(1);
        }
        for (int i = 0; i <= var->stub_len - 4; i++)
        {
            uint32_t val = *(uint32_t *)&var->stub[i];

            if (val == var->p_jmp)
                *(int *)&var->stub[i] = (int)(old_entry - (new_entry + i + 4));
            else if (val == var->p_dist)
                *(uint32_t *)&var->stub[i] = distance;
            else if (val == var->p_size)
                *(uint32_t *)&var->stub[i] = encrypt_size;
        }
        for (int i = 0; i <= var->stub_len - 8; i++)
        {
            uint64_t val = *(uint64_t *)&var->stub[i];
            if (val == var->p_key)
                *(uint64_t *)&var->stub[i] = var->key;
        }
    }
        printf("..f.\n");

}