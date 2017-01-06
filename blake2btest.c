#include "blake2b.h"

// Test main

int main(int argc, char const *argv[])
{
        unsigned char data[3] = {'a','b','c'};
        unsigned char digest[64];

        size_t nn = 64;
        size_t ll = 3;

        blake2b(digest,nn,data,ll,NULL,0);

        printf("digest:\n");
        for(int i = 0;i<nn;i++)
                printf("%02X ",digest[i]);
        printf("\n");

        return 0;
}