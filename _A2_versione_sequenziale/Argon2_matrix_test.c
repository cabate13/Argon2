#include <stdio.h>
#include "Argon2_matrix.h"

int main(){

        Argon2_matrix matrix;
        Argon2_matrix_init(8,1,&matrix);
        Argon2_block block;
        memset(&(block.content),0xFF,1024);

        for(uint32_t j = 0;j<8;j++)
                Argon2_matrix_fill_block(0,j,&matrix,&block);

        memset(&(block.content),0,1024);


        for(uint32_t j = 0;j<8;j++){
                Argon2_matrix_get_block(0,j,&block,&matrix);
                for(int i = 0;i<16;i++)
                        printf("%01X",block.content[i]);
                printf("\n");
        }

        Argon2_indexing_arguments arg;

        arg.r = 2;
        arg.l = 0;
        arg.c = 2048;
        arg.m = 8*1024;
        arg.s = 2;
        arg.t = 12;
        arg.x = 1;
        arg.i = 0;
        arg.counter = 0;

        printf("Retrieved indeces [Argon2i]: %016llX\n", Argon2_indexing(&arg,&matrix));

        arg.r = 2;
        arg.l = 0;
        arg.c = 6;
        arg.m = 8;
        arg.s = 0;
        arg.t = 12;
        arg.x = 0;
        arg.i = 0;
        arg.counter = 0;

        printf("Retrieved indeces [Argon2d]: %016llX\n", Argon2_indexing(&arg,&matrix));

        return 0;

}