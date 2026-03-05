#include "../woody.h"
void find_text_segment(struct Woody_data *var)
{
    int ph_num = var->header->e_phnum;
    lseek(var->fd, var->header->e_phoff, SEEK_SET);
    var->p_header = malloc(sizeof(Elf64_Phdr) * ph_num);
    read(var->fd, var->p_header, sizeof(Elf64_Phdr) * ph_num);
    for (int i = 0; i < ph_num; i++)
    {
        if (var->p_header[i].p_type == PT_LOAD && (var->p_header[i].p_flags     // Security check: Is the file even big enough to hold an ELF header?
)
        {
            var->text_segment = &var->p_header[i];
            var->text_index = i;
            break;
        }
    }
}