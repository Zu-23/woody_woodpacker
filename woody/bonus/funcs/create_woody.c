#include "../woody.h"


void set_size(Elf64_Phdr *p_header, Woody_data *var)
{
    int idx = var->text_index;
    p_header[idx].p_filesz += var->stub_len;
    p_header[idx].p_memsz += var->stub_len;
    p_header[idx].p_flags |= PF_W;
}

char *create_new_file(Woody_data *var)
{
    char *new_elf_file;

    var->file_size = lseek(var->fd, 0, SEEK_END);
    new_elf_file = malloc(var->file_size);
    lseek(var->fd, 0, SEEK_SET);
    read(var->fd, new_elf_file, var->file_size);
    return (new_elf_file);
}

void create_woody(Woody_data *var)
{
    char *new_elf_file;
    Elf64_Ehdr *new_elf_header;
    Elf64_Phdr *new_p_header;

    new_elf_file = create_new_file(var);
    new_elf_header = (Elf64_Ehdr *)new_elf_file;
    new_elf_header->e_entry = var->phdr.text_segment64->p_vaddr + var->phdr.text_segment64->p_filesz;
    new_p_header = (Elf64_Phdr *)(new_elf_file + new_elf_header->e_phoff);
    set_size(new_p_header, var);
    long entry_offset = var->spec.elf64.ehdr->e_entry;
    long end_offset = var->phdr.text_segment64->p_offset + var->phdr.text_segment64->p_filesz;
    size_t target_size = end_offset - entry_offset;
    char *target_data = new_elf_file + entry_offset;
    if (target_size > 0 && target_size < (size_t)var->file_size)
        encrypt_rotate_64(target_data, target_size, var->key);
    int new_elf_fd = open("woody", O_WRONLY | O_CREAT | O_TRUNC, 0755);
    write(new_elf_fd, new_elf_file, var->cave_start_offset);
    write(new_elf_fd, var->stub, var->stub_len);
    write(new_elf_fd, new_elf_file + var->cave_start_offset + var->stub_len,
          var->file_size - (var->cave_start_offset + var->stub_len));
    close(new_elf_fd);
    printf("key_value: %ld\n", var->key);
}
