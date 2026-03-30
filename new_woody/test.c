#include<stdio.h>
#include<stdlib.h>

int main()
{
    int s[5] = {1, 2, 3, 4, 5};
    void *ptr = s;

  printf("Value at ptr: %d\n", *(int*)((char*)ptr + sizeof(int))); // Should print 2
    return 0;
}


// void find_exec_segment_paddings(void *map_ptr)
// {
//     Elf64_Ehdr *ehdr = (Elf64_Ehdr *)map_ptr;
//     Elf64_Phdr *phdr = (Elf64_Phdr *)((uint8_t *)map_ptr + ehdr->e_phoff);

//     for (int i = 0; i < ehdr->e_phnum; i++)
//     {
//         if (phdr[i].p_type == PT_LOAD && (phdr[i].p_flags & PF_X))
//         {
//             uint64_t seg_start = phdr[i].p_offset;
//             uint64_t seg_end = phdr[i].p_offset + phdr[i].p_filesz;
//             unsigned char *seg_data = (unsigned char *)map_ptr + seg_start;
//             size_t i = 0;
//             size_t chain = 0;
//             size_t padding_count = 0;
//             while (i < seg_end - seg_start)
//             {
//                 if (seg_data[i] == 0x00)
//                     padding_count = i;
//                 else
//                     i++;
//                 while (seg_data[i] == 0x00)
//                 {
//                     i++;
//                     chain++;
//                 }
//                 if (chain > 4)
//                 {
//                     uint64_t found_offset = seg_start + padding_count;
//                     const char *name = get_section_name(ehdr, found_offset, map_ptr);
//                     printf("Padding: %ld bytes | Offset: 0x%lx | Location: [%s]\n",
//                            chain, found_offset, name);
//                 }
//                 chain=0;
//             }
//         }
//     }
// }