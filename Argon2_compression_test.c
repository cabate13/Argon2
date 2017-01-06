#include <stdio.h>
#include <stdint.h>
#include "Argon2_compression.h"
#include "blake2b.h"

int main(void)
{

        /*      
        uint128_t S[8];

        for (int i = 0; i < 8; ++i)
        {
                S[i].left = 4294967297 +i;
                printf("%lu\n", S[i].left);
                S[i].right = 4294967299 + 10*i;
                printf("%lu\n", S[i].right);
        }

        printf("\n\n");
        P((uint128_t*) &S);

        for (int i = 0; i < 8; ++i)
        {
                printf("%lu\n", S[i].left);
                printf("%lu\n", S[i].right);
        }       
        */

        uint128_t X[64];
        uint128_t Y[64];

        for (int i = 0; i < 64; ++i)
        {
                X[i].left = 1;
                Y[i].right = 0;
                X[i].right = 0;
                Y[i].left = 0;
        }

        
        uint128_t T[64];

        for (int i = 0; i < 64; ++i)
        {
                
                T[i].left = 0;
                T[i].right = 0;

        }

        printf("FINE\n");

        CompressionFunctionG(X,Y,T);

        
        for (int i = 0; i < 64; ++i)
        {
                
                uint64_t d = (*(T+i)).left;
                uint64_t t = (*(T+i)).right;

                printf("%016llX | %016llX\n", t, d);
        }
        
        return 0;
}