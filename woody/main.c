#include "./woody.h"




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

