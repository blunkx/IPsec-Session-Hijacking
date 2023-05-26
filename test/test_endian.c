#include <stdio.h>
#include <stdint.h>

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

uint32_t endian_trans(uint32_t src)
{
    uint32_t b0, b1, b2, b3;
    b0 = (src & 0x000000ff) << 24u;
    b1 = (src & 0x0000ff00) << 8u;
    b2 = (src & 0x00ff0000) >> 8u;
    b3 = (src & 0xff000000) >> 24u;
    return b0 | b1 | b2 | b3;
}