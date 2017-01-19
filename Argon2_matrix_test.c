#include <stdio.h>
#include "Argon2_matrix.h"

int main(){

        Argon2_global_workspace matrix;
        Argon2_global_workspace_init(8,1,3,1,&matrix);
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

        Argon2_local_workspace arg;

        arg.l = 0;
        arg.c = 2048;
        arg.i = 0;
        arg.counter = 0;

        printf("Retrieved indeces [Argon2i]: %016llX\n", Argon2_indexing(&matrix,&arg));


        arg.l = 0;
        arg.c = 6;
        arg.i = 0;
        arg.counter = 0;

        printf("Retrieved indeces [Argon2d]: %016llX\n", Argon2_indexing(&matrix,&arg));

        return 0;

}