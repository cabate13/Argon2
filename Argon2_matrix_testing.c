#include <stdio.h>
#include "Argon2_matrix.h"

int main(){

        Argon2_matrix matrix;
        Argon2_matrix* ptr = &matrix;
        Argon2_matrix_init(8,1,&matrix);
        Argon2_block block;
        memset(&(block.content),0x12,1024);

        for(uint32_t j = 0;j<8;j++)
                Argon2_matrix_fill_block(0,j,&matrix,&block);

        memset(&(block.content),0,1024);


        for(uint32_t j = 0;j<8;j++){
                Argon2_matrix_get_block(0,j,&block,&matrix);
                for(int i = 0;i<16;i++)
                        printf("%01X",block.content[i]);
                printf("\n");
        }

        Argon2_matrix_free(&matrix);

        return 0;

}