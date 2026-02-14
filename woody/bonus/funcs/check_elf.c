#include "../woody.h"

void check_elf32(Woody_data *var)
{
    free(var->spec.elf64.ehdr);
    if ((lseek(var->fd, 0, SEEK_SET)) == -1)
    {
        perror("Error lseek for check_elf32\n");
        exit(1);
    }
    if ((var->spec.elf32.ehdr = malloc(sizeof(Elf32_Ehdr))) == NULL)
    {
        perror("Error malloc in check_el32\n");
        exit(1);
    }

    printf("elf 32 treated\n");
    if ((read(var->fd, var->spec.elf32.ehdr, sizeof(Elf32_Ehdr))) == -1)
    {
        perror("Read error");
        exit(1);
    }
}

void check_elf(Woody_data *var)
{
    if ((var->spec.elf64.ehdr = malloc(sizeof(Elf64_Ehdr))) == NULL)
    {
        perror("Error malloc in check_elf\n");
        exit(1);
    }
    if ((read(var->fd, var->spec.elf64.ehdr, sizeof(Elf64_Ehdr))) == -1)
    {
        perror("Read error");
        exit(1);
    }
    if (var->spec.elf64.ehdr->e_ident[EI_MAG0] != 0x7f || var->spec.elf64.ehdr->e_ident[EI_MAG1] != 'E')
    {
        perror("Not a valid ELF");
        exit(1);
    }
    if (var->spec.elf64.ehdr->e_ident[EI_CLASS] == ELFCLASS32)
    {
        var->is_32bit = ELFCLASS32;
        check_elf32(var);
    }
    else
        var->is_32bit = 0;
}
