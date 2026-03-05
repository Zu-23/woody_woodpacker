#include<stdio.h>
#include<stdlib.h>

int main()
{
    int s[5] = {1, 2, 3, 4, 5};
    void *ptr = s;

  printf("Value at ptr: %d\n", *(int*)((char*)ptr + sizeof(int))); // Should print 2
    return 0;
}