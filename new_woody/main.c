#include "woody.h"
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

extern const t_type_handler elf64_type;

const t_type_handler *types[] = {
    &elf64_type,
    NULL
};

uint64_t generate_key(int argc, char **argv)
{
    uint64_t key = 0;
    if (argc == 3)
    {
        if (!ft_atoierr(argv[2], &key))
        {
            perror("Invalid key provided");
            exit(1);
        }
        return (key);
    }
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
    {
        perror("Error opening /dev/urandom");
        exit(1);
    }
    if (read(fd, &key, sizeof(key)) != sizeof(key))
    {
        perror("Error reading random key");
        close(fd);
        exit(1);
    }
    close(fd);
    return key;
}

int map_target_file(const char *filename, t_woody *env)
{
    int fd = open(filename, O_RDONLY);
    if (fd < 0)
    {
        perror("Error opening file");
        return 0;
    }
    env->file_size = lseek(fd, 0, SEEK_END);
    env->file_data = mmap(NULL, env->file_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    close(fd);
    if (env->file_data == MAP_FAILED)
    {
        perror("Error mapping file");
        return 0;
    }
    return 1;
}

int save_woody_file(t_woody *env)
{

    int fd = open("woody", O_CREAT | O_TRUNC | O_WRONLY, 0755);
    if (fd < 0)
    {
        perror("Error creating 'woody' file");
        return 1;
    }

    if (write(fd, env->file_data, env->file_size) != (ssize_t)env->file_size)
    {
        perror("Error writing to 'woody' file");
        close(fd);
        return 1;
    }
    else
        printf("Successfully created 'woody'!\n");
    close(fd);
    return 0;
}



int main(int argc, char **argv)
{
    if (argc != 2)
    {
        perror("Usage: ./woody <target_binary> [encryption_key]");
        return 1;
    }
    t_woody env = {0};
    if (!map_target_file(argv[1], &env))
        return 1;
    env.key = generate_key(argc, argv);

    for (int i = 0; types[i] != NULL; i++)
    {
        if (types[i]->check_magic(env.file_data))
        {
            env.handler = (t_type_handler *)types[i];
            break;
        }
    }

    if (!env.handler)
    {
        perror("Unsupported file format");
        munmap(env.file_data, env.file_size);
        exit(1);
    }
    size_t cave_offset = 0;

    if (env.handler->parse_headers(&env))
    {
        cave_offset = env.handler->find_cave(&env, env.stub_size);

        if (cave_offset > 0)
        {
            env.handler->inject(&env, cave_offset);
            if (save_woody_file(&env))
            {
                perror("Error creating woody file");
                munmap(env.file_data, env.file_size);
                exit(1);
            }
        }
    }
    munmap(env.file_data, env.file_size);

    return 0;
}