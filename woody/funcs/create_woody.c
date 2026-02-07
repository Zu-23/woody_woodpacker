#include "../woody.h"
void create_woody(struct Woody_data *var)
{
    char *new_elf_file;
    Elf64_Ehdr *new_elf_header;
    Elf64_Phdr *new_p_header;

    var->file_size = lseek(var->fd, 0, SEEK_END);
    new_elf_file = malloc(var->file_size);
    lseek(var->fd, 0, SEEK_SET);
    read(var->fd, new_elf_file, var->file_size);
    new_elf_header = (Elf64_Ehdr *)new_elf_file;
    new_elf_header->e_entry = var->text_segment->p_vaddr + var->text_segment->p_filesz;
    new_p_header = (Elf64_Phdr *)(new_elf_file + new_elf_header->e_phoff);
    int idx = var->text_index;
    new_p_header[idx].p_filesz += var->stub_len;
    new_p_header[idx].p_memsz += var->stub_len;
    new_p_header[idx].p_flags |= PF_W;
    long entry_offset = var->header->e_entry;

    long end_offset = var->text_segment->p_offset + var->text_segment->p_filesz;

    size_t target_size = end_offset - entry_offset;
    char *target_data = new_elf_file + entry_offset;

    if (target_size > 0 && target_size < (size_t)var->file_size)
        encrypt_simple_xor(target_data, target_size);
    int new_elf_fd = open("woody", O_WRONLY | O_CREAT | O_TRUNC, 0755);
    write(new_elf_fd, new_elf_file, var->cave_start_offset);
    write(new_elf_fd, var->stub, var->stub_len);
    write(new_elf_fd, new_elf_file + var->cave_start_offset + var->stub_len,
          var->file_size - (var->cave_start_offset + var->stub_len));
    close(new_elf_fd);
}