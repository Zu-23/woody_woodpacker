#include "../woody.h"


void find_cave32(Woody_data *var)
{
    var->after_text_segment_offset = var->spec.elf32.phdr[var->text_index + 1].p_offset;
    var->cave_start_offset = var->phdr.text_segment32->p_offset + var->phdr.text_segment32->p_filesz;
    var->cave_size = var->after_text_segment_offset - var->cave_start_offset;
}

void find_cave(Woody_data *var)
{
    if (var->is_32bit)
        find_cave32(var);
    else
    {
        var->after_text_segment_offset = var->spec.elf64.phdr[var->text_index + 1].p_offset;
        var->cave_start_offset = var->phdr.text_segment64->p_offset + var->phdr.text_segment64->p_filesz;
        var->cave_size = var->after_text_segment_offset - var->cave_start_offset;
    }
}