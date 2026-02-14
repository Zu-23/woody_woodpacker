#include "../woody.h"

void find_text_segment32(Woody_data *var)
{
    int ph_num = var->spec.elf32.ehdr->e_phnum;
    if ((lseek(var->fd, var->spec.elf32.ehdr->e_phoff, SEEK_SET)) == -1)
    {
        perror("Error lseek in find_text_segment32\n");
        exit(1);
    }
    if ((var->spec.elf32.phdr = malloc(sizeof(Elf32_Phdr) * ph_num)) == NULL)
    {
        perror("Error malloc in find_text_segment32\n");
        exit(1);
    }
    if ((read(var->fd, var->spec.elf32.phdr, sizeof(Elf32_Phdr) * ph_num)) == -1)
    {
        perror("Error reading for phdr32");
        exit(1);
    }
    for (int i = 0; i < ph_num; i++)
    {
        if (var->spec.elf32.phdr[i].p_type == PT_LOAD && (var->spec.elf32.phdr[i].p_flags & (PF_X | PF_R)) == (PF_X | PF_R))
        {
            var->phdr.text_segment32 = &var->spec.elf32.phdr[i];
            var->text_index = i;
            printf("text seg32 indx %d\n", var->text_index);
            break;
        }
    }
}

void find_text_segment(Woody_data *var)
{
    if (var->is_32bit)
        find_text_segment32(var);
    else
    {
        int ph_num = var->spec.elf64.ehdr->e_phnum;
        if ((lseek(var->fd, var->spec.elf64.ehdr->e_phoff, SEEK_SET)) == -1)
        {
            perror("Error lseek in find_text_segment64\n");
            exit(1);
        }
        if ((var->spec.elf64.phdr = malloc(sizeof(Elf64_Phdr) * ph_num)) == NULL)
        {
            perror("Error malloc in find_text_segment64\n");
            exit(1);
        }
        if ((read(var->fd, var->spec.elf64.phdr, sizeof(Elf64_Phdr) * ph_num)) == -1)
        {
            perror("Error reading for phdr64\n");
            exit(1);
        }
        for (int i = 0; i < ph_num; i++)
        {
            if (var->spec.elf64.phdr[i].p_type == PT_LOAD && (var->spec.elf64.phdr[i].p_flags & (PF_X | PF_R)) == (PF_X | PF_R))
            {
                var->phdr.text_segment64 = &var->spec.elf64.phdr[i];
                var->text_index = i;
                break;
            }
        }
    }
}