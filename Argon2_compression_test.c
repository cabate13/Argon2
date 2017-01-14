#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include "Argon2_matrix.h"
//#include "Argon2_compression.h"
//#include "blake2b.h"
//#include "SomeUtilityFunctions.h"


void XOR128(uint64_t* X, uint64_t* Y, uint64_t* res, int n)
{
    for(int i=0; i<n; i++)
    {
        res[i] = X[i] ^ Y[i];
    }
}

int main(void)
{
        Argon2_block block;

        for (int i = 0; i < 1024; ++i)
        {
            block.content[i] = 1;
        }

        XOR128((uint64_t*)block.content, (uint64_t*)block.content, (uint64_t*)block.content, 128);

        for (int i = 0; i < 1024; ++i)
        {
            printf("%02X\n", block.content[i]);
        }

        return 0;
}

