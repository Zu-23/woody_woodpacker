#include "../woody.h"
void check_elf(struct Woody_data *var)
{
    var->header = malloc(sizeof(Elf64_Ehdr));
    if (read(var->fd, var->header, sizeof(Elf64_Ehdr)) == -1)
    {
        perror("Read error");
        exit(1);
    }
    if (var->header->e_ident[EI_MAG0] != 0x7f || var->header->e_ident[EI_MAG1] != 'E' || var->header->e_ident[EI_CLASS] != ELFCLASS64)
    {
        perror("Not a valid ELF");
        exit(1);
    }
}
