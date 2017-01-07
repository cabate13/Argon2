#include <stdio.h>
#include <stdint.h>
#include "Argon2_compression.h"
#include "blake2b.h"
//#include "SomeUtilityFunctions.h"




int main(void)
{

        uint128_t X[64];
        uint128_t Y[64];

        for (int i = 0; i < 64; ++i)
        {
            X[i].left =  4294967297 +i;
            Y[i].left =  429496729 + 2*i;
            X[i].right = Y[i].left;
            Y[i].right = X[i].left;
        }

        uint128_t* res;
        res = (uint128_t*) malloc(16*64);

        CompressionFunctionG(X,Y,res);

        printf("res: \n");
        for(int i = 0;i<64;i++)
            printf("%016lX | %016lX \n", res[i].right, res[i].left);
        printf("\n");
        free(res);

        return 0;
}

