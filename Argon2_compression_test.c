#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include "Argon2_compression.h"
#include "blake2b.h"

const uint8_t HprimeInput[72] = {0xB8, 0x81, 0x97, 0x91, 0xA0, 0x35, 0x96, 0x60,
                                 0xBB, 0x77, 0x09, 0xC8, 0x5F, 0xA4, 0x8F, 0x04, 
                                 0xD5, 0xD8, 0x2C, 0x05, 0xC5, 0xF2, 0x15, 0xCC, 
                                 0xDB, 0x88, 0x54, 0x91, 0x71, 0x7C, 0xF7, 0x57, 
                                 0x08, 0x2C, 0x28, 0xB9, 0x51, 0xBE, 0x38, 0x14, 
                                 0x10, 0xB5, 0xFC, 0x2E, 0xB7, 0x27, 0x40, 0x33, 
                                 0xB9, 0xFD, 0xC7, 0xAE, 0x67, 0x2B, 0xCA, 0xAC, 
                                 0x5D, 0x17, 0x90, 0x97, 0xA4, 0xAF, 0x31, 0x09, 
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};


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
        uint8_t digest1[1024];

        // Hprime((uint8_t*)X, 1024, 4*64, (uint8_t*)digest);

        // printf("A2CT:: Hash H' of 0x12:\n");
        // for(int i = 0;i<4;i++){

        //     printf("%016llX ",digest[i]);

        // }
        // printf("\n");

        for(int i = 1;i<1025;i++)
        Hprime((uint8_t*)HprimeInput, 72, i, digest1);

        return 0;
}

