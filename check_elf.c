#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>


struct Woody_data
{
    int fd;
    Elf64_Ehdr *header;
    Elf64_Phdr *p_header;
    Elf64_Phdr *text_segment;
    int text_index;
    int stub_len;
    int cave_size;
    long cave_start_offset;
    long after_text_segment_offset;
    long file_size;
    char *stub;
};


void check_elf(struct Woody_data *var);
void find_cave(struct Woody_data *var);
void find_text_segment(struct Woody_data *var);
void read_stub_and_patch(struct Woody_data *var);
void create_woody(struct Woody_data *var);


int main(int argc, char **argv)
{
    struct Woody_data *var;

    var = malloc(sizeof(struct Woody_data));
    if (argc < 2)
    {
        perror("No ELF provided");
        return (1);
    }
    var->fd = open(argv[1], O_RDONLY);
    if (var->fd < 0)
    {
        perror("Unable to open file");
        return (1);
    }
    check_elf(var);
    find_text_segment(var);
    find_cave(var);
    read_stub_and_patch(var);
    create_woody(var);
    close(var->fd);
    return 0;
}

void check_elf(struct Woody_data *var)
{
    var->header = malloc(sizeof(Elf64_Ehdr));
    if (read(var->fd, var->header, sizeof(Elf64_Ehdr)) == -1)
    {
        perror("error while reading\n");
        exit(1);
    }
    if (var->header->e_ident[EI_MAG0] == 0x7f && var->header->e_ident[EI_MAG1] == 'E' && var->header->e_ident[EI_CLASS] == ELFCLASS64)
        printf("ELF is correct\n");
    else
    {
        perror("not valid\n");
        exit(1);
    }
}

void find_text_segment(struct Woody_data *var)
{
    int ph_num;
    ph_num = var->header->e_phnum;
    lseek(var->fd, var->header->e_phoff, SEEK_SET);
    var->p_header = malloc(sizeof(Elf64_Phdr) * ph_num);
    read(var->fd, var->p_header, sizeof(Elf64_Phdr) * ph_num);
    for (int i = 0; i < ph_num; i++)
    {
        if (var->p_header[i].p_type == PT_LOAD && (var->p_header[i].p_flags & (PF_X | PF_R)) == (PF_X | PF_R))
        {
            var->text_segment = &var->p_header[i];
            var->text_index = i;
            break;
        }
    }
}

void find_cave(struct Woody_data *var)
{
    var->after_text_segment_offset = var->p_header[var->text_index + 1].p_offset;
    var->cave_start_offset = var->text_segment->p_offset + var->text_segment->p_filesz;
    var->cave_size = var->after_text_segment_offset - var->cave_start_offset;
    printf("cave size is %d\n", var->cave_size);
}

void read_stub_and_patch(struct Woody_data *var)
{
    int stub_fd;
    uint64_t old_entry;
    uint64_t new_entry;

    old_entry = var->header->e_entry;
    new_entry = var->text_segment->p_vaddr + var->text_segment->p_filesz;
    stub_fd = open("stub.bin", O_RDONLY);
    if (stub_fd < 0)
    {
        perror("error opening stub.bin\n");
        exit(1);
    }
    var->stub = malloc(sizeof(char) * 512);
    var->stub_len = read(stub_fd, var->stub, 512);
    close(stub_fd);
    if (var->stub_len > var->cave_size)
    {
        printf("stub too big");
        exit(1);
    }
    for (int i = 0; i < var->stub_len - 4; i++)
    {
        if (*(unsigned int *)&var->stub[i] == 0xAAAAAAAA)
        {
            *(int *)&var->stub[i] = (int)(old_entry - (new_entry + i + 4));
            break;
        }
    }
}



void create_woody(struct Woody_data *var)
{
    char *new_elf_file;
    Elf64_Ehdr *new_elf_header;
    Elf64_Phdr *new_p_header;
    int text_index;
    
    var->file_size = lseek(var->fd, 0, SEEK_END);
    new_elf_file = malloc(var->file_size);
    lseek(var->fd, 0, SEEK_SET);         
    read(var->fd, new_elf_file, var->file_size);
    new_elf_header = (Elf64_Ehdr *)new_elf_file;
    new_elf_header->e_entry = var->text_segment->p_vaddr + var->text_segment->p_filesz;
    new_p_header = (Elf64_Phdr *) (new_elf_file + new_elf_header->e_phoff);
    text_index = var->text_index;
    new_p_header[text_index].p_filesz += var->stub_len;
    if (new_p_header[text_index].p_memsz < new_p_header[text_index].p_filesz)
        new_p_header[text_index].p_memsz += var->stub_len;
    int new_elf_fd = open("woody", O_WRONLY | O_CREAT | O_TRUNC, 0755);
    write(new_elf_fd,  new_elf_file, var->cave_start_offset);
    write(new_elf_fd, var->stub, var->stub_len);
    write(new_elf_fd, new_elf_file + var->cave_start_offset + var->stub_len, var->file_size - (var->cave_start_offset + var->stub_len));

    printf("Infection successful. New entry point: 0x%lx\n", var->text_segment->p_vaddr + var->text_segment->p_filesz);

}