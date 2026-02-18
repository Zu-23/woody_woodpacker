#include "./woody.h"


int main(int argc, char **argv)
{
    Woody_data *var;

    if (NULL == (var = malloc(sizeof(Woody_data))))
    {
        perror("Error malloc in main\n");
        exit(1);
    }
    if (argc < 2)
    {
        perror("No ELF provided");
        return (1);
    }
    else if (argc == 3)
        var->key = atoi(argv[2]); //dont forget to use libft atoi
    else if (argc == 2)
        var->key = generate_64bit_key();
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
    return (0);
}

