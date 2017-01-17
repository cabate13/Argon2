#include "blake2b.h"

// Test main

int main(int argc, char const *argv[])
{
        unsigned char data[1200] = {'a','b','c'};
        memset(data+3,0x13,1197);
        unsigned char digest[64];

        size_t nn = 64;
        size_t ll = 1197;

        blake2b(digest,nn,data,ll,NULL,0);

        printf("digest:\n");
        for(int i = 0;i<nn;i++)
                printf("%02X ",digest[i]);
        printf("\n");

        return 0;
}
