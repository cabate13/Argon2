#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include "Argon2_compression.h"
#include "blake2b.h"

int main(void)
{
        uint64_t X[128];
        uint64_t Y[128];
        uint64_t result[128];

        memset(X,0x12,128*sizeof(uint64_t));
        memset(Y,0x13,128*sizeof(uint64_t));

        CompressionFunctionG(X, Y, result);

        printf("A2CT:: Compression of 0x12 and 0x13:\n");
        for(int i = 0; i<128;i++){

            printf("%016llX ",result[i]);

        }
        printf("\n");

        uint64_t digest[4];

        Hprime((uint8_t*)X, 1024, 4*64, (uint8_t*)digest);

        printf("A2CT:: Hash H' of 0x12:\n");
        for(int i = 0;i<4;i++){

            printf("%016llX ",digest[i]);

        }
        printf("\n");

        return 0;
}

