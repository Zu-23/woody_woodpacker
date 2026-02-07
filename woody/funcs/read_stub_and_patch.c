#include "../woody.h"

void read_stub_and_patch(struct Woody_data *var)
{
    int stub_fd = open("stub.bin", O_RDONLY);
    if (stub_fd < 0)
    {
        perror("Error opening stub.bin");
        exit(1);
    }
    var->stub = malloc(512);
    var->stub_len = read(stub_fd, var->stub, 512);
    close(stub_fd);
    if (var->stub_len > var->cave_size)
    {
        perror("Stub too big for cave!\n");
        exit(1);
    }
    uint32_t p_jmp = 0xAAAAAAAA;
    uint32_t p_dist = 0x11111111;
    uint32_t p_size = 0x22222222;
    long entry_offset = var->header->e_entry;
    long end_offset = var->text_segment->p_offset + var->text_segment->p_filesz;
    uint32_t encrypt_size = (uint32_t)(end_offset - entry_offset);
    long stub_start_vaddr = var->text_segment->p_vaddr + var->text_segment->p_filesz;
    long entry_vaddr = var->header->e_entry;
    uint32_t distance = (uint32_t)(stub_start_vaddr - entry_vaddr);
    uint64_t old_entry = var->header->e_entry;
    uint64_t new_entry = var->text_segment->p_vaddr + var->text_segment->p_filesz;
    for (int i = 0; i <= var->stub_len - 4; i++)
    {
        uint32_t val = *(uint32_t *)&var->stub[i];

        if (val == p_jmp)
        {
            *(int *)&var->stub[i] = (int)(old_entry - (new_entry + i + 4));
        }
        else if (val == p_dist)
        {
            *(uint32_t *)&var->stub[i] = distance;
        }
        else if (val == p_size)
        {
            *(uint32_t *)&var->stub[i] = encrypt_size;
        }
    }
}