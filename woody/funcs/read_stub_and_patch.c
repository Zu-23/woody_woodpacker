#include "../woody.h"

uint32_t get_encrypt_size(struct Woody_data *var)
{
    long entry_offset = var->header->e_entry;
    long end_offset = var->text_segment->p_offset + var->text_segment->p_filesz;
    uint32_t encrypt_size = (uint32_t)(end_offset - entry_offset);
    return (encrypt_size);
}

uint32_t get_distance(struct Woody_data *var)
{
    long stub_start_vaddr = var->text_segment->p_vaddr + var->text_segment->p_filesz;
    long entry_vaddr = var->header->e_entry;
    uint32_t distance = (uint32_t)(stub_start_vaddr - entry_vaddr);
    return (distance);
}

void read_stub_and_patch(struct Woody_data *var)
{
    uint32_t p_jmp = 0xAAAAAAAA;
    uint32_t p_dist = 0x11111111;
    uint32_t p_size = 0x22222222;
    uint64_t p_key = 0x1122334455667788;
    uint32_t encrypt_size = get_encrypt_size(var);
    uint32_t distance = get_distance(var);
    uint64_t old_entry = var->header->e_entry;
    uint64_t new_entry = var->text_segment->p_vaddr + var->text_segment->p_filesz;
    var->key = generate_64bit_key();
    int stub_fd = open("stub.bin", O_RDONLY);

    if (stub_fd < 0)
    {
        perror("Error opening stub.bin");
        exit(1);
    }
    var->stub = malloc(1000);
    var->stub_len = read(stub_fd, var->stub, 1000);
    close(stub_fd);
    if (var->stub_len > var->cave_size)
    {
        perror("Stub too big for cave!\n");
        exit(1);
    }
    for (int i = 0; i <= var->stub_len - 4; i++)
    {
        uint32_t val = *(uint32_t *)&var->stub[i];

        if (val == p_jmp)
            *(int *)&var->stub[i] = (int)(old_entry - (new_entry + i + 4));
        else if (val == p_dist)
            *(uint32_t *)&var->stub[i] = distance;
        else if (val == p_size)
            *(uint32_t *)&var->stub[i] = encrypt_size;
    }
    for (int i = 0; i <= var->stub_len - 8; i++)
    {
        uint64_t val = *(uint64_t *)&var->stub[i];
        if (val == p_key)
            *(uint64_t *)&var->stub[i] = var->key;
    }
}