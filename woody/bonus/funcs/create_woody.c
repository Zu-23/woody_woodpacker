#include "../woody.h"

void write_to_woody(Woody_data *var, char *new_elf_file)
{
    int new_elf_fd;

    if ((new_elf_fd = open("woody", O_WRONLY | O_CREAT | O_TRUNC, 0755)) == -1)
    {
        perror("Error open in write_to_woody");
        exit(1);
    }
    write(new_elf_fd, new_elf_file, var->cave_start_offset);
    write(new_elf_fd, var->stub, var->stub_len);
    write(new_elf_fd, new_elf_file + var->cave_start_offset + var->stub_len,
          var->file_size - (var->cave_start_offset + var->stub_len));
    close(new_elf_fd);
}

void set_size(void *p_header, Woody_data *var)
{
    int idx = var->text_index;
    if (var->is_32bit)
    {
        Elf32_Phdr *phdr32 = (Elf32_Phdr *)p_header;
        phdr32[idx].p_filesz += var->stub_len;
        phdr32[idx].p_memsz += var->stub_len;
        phdr32[idx].p_flags |= PF_W;
    }
    else
    {
        Elf64_Phdr *phdr64 = (Elf64_Phdr *)p_header;
        phdr64[idx].p_filesz += var->stub_len;
        phdr64[idx].p_memsz += var->stub_len;
        phdr64[idx].p_flags |= PF_W;
    }
}

char *create_new_file(Woody_data *var)
{
    char *new_elf_file;

    if ((var->file_size = lseek(var->fd, 0, SEEK_END)) == -1)
    {
        perror("Error lseek in create_new_file\n");
        exit(1);
    }
    if ((new_elf_file = malloc(var->file_size)) == NULL)
    {
        perror("Error malloc in create_new_file\n");
        exit(1);
    }
    if (lseek(var->fd, 0, SEEK_SET) == -1)
    {
        perror("Error lseek for new file\n");
        exit(1);
    }
    if ((read(var->fd, new_elf_file, var->file_size)) == -1)
    {
        perror("Error reading new file\n");
        exit(1);
    }
    return (new_elf_file);
}

char* create_woody32(Woody_data *var)
{
    Elf32_Ehdr *new_elf_header;
    Elf32_Phdr *new_p_header;
    char *new_elf_file;

    new_elf_file = create_new_file(var);
    new_elf_header = (Elf32_Ehdr *)new_elf_file;
    new_elf_header->e_entry = var->phdr.text_segment32->p_vaddr + var->phdr.text_segment32->p_filesz;
    new_p_header = (Elf32_Phdr *)(new_elf_file + new_elf_header->e_phoff);
    set_size(new_p_header, var);
    long entry_offset = var->spec.elf64.ehdr->e_entry;
    long end_offset = var->phdr.text_segment32->p_offset + var->phdr.text_segment32->p_filesz;
    size_t target_size = end_offset - entry_offset;
    char *target_data = new_elf_file + entry_offset;
    if (target_size > 0 && target_size < (size_t)var->file_size)
        encrypt_rotate_32(target_data, target_size, var->key);
    return (new_elf_file);
}

void create_woody(Woody_data *var)
{
    char *new_elf_file;
    if (var->is_32bit)
        new_elf_file = create_woody32(var);
    else
    {
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
    }
    write_to_woody(var, new_elf_file);
}
