#include<stdio.h>


int main()
{
   long key = 999999999999999;
   unsigned int uint_key = (unsigned int)key;
   printf("%ld\n",key);
   printf("%u\n", uint_key);
}