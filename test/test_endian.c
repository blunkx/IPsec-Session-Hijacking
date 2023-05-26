#include <stdio.h>
typedef union
{
    unsigned long l;
    unsigned char c[4];
} EndianTest;
int main()
{
    EndianTest et;
    et.l = 0x12345678;
    printf("Endian: ");
    if (et.c[0] == 0x78 && et.c[1] == 0x56 && et.c[2] == 0x34 && et.c[3] == 0x12)
    {
        printf("Little Endian");
    }
    else if (et.c[0] == 0x12 && et.c[1] == 0x34 && et.c[2] == 0x56 && et.c[3] == 0x78)
    {
        printf("Big Endian");
    }
    else
    {
        printf("Unknown Endian");
    }
    printf("\n");
    return 0;
}