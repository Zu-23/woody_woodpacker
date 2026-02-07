#include "../woody.h"
void find_cave(struct Woody_data *var)
{
    var->after_text_segment_offset = var->p_header[var->text_index + 1].p_offset;
    var->cave_start_offset = var->text_segment->p_offset + var->text_segment->p_filesz;
    var->cave_size = var->after_text_segment_offset - var->cave_start_offset;
}