#include "Argon2_matrix.h"
#include "Argon2_compression.h"

// Initializes the matrix and sets its parameters
int Argon2_matrix_init(uint32_t m, uint32_t p, Argon2_matrix* B){

        if(p == 0 || p > 0xFFFFFF || m < 8*p || B->matrix != NULL)
                return 1;

        B->p = p;
        B->m = (m/(4*p))*4*p;
        B->q = m/p;

        B->matrix = (uint8_t*)malloc(m*1024);

        return 0;

}

// Fills the block in position (i,j) in the Argon2 matrix B with the content of the source block
int Argon2_matrix_fill_block(uint32_t i, uint32_t j, Argon2_matrix* dst, Argon2_block* src){

        if(i > (dst->p - 1) || j > (dst->q - 1))
                return 1;

        memcpy((dst->matrix)+1024*(j+dst->q*i),src->content,1024);
        return 0;

}

// Gets the block in position (i,j) in the Argon2 matrix B, storing the content in the dst block
int Argon2_matrix_get_block(uint32_t i, uint32_t j, Argon2_block* dst, Argon2_matrix* src){

        if(i > (src->p - 1) || j > (src->q - 1))
                return 1;

        memcpy(dst->content,(src->matrix)+1024*(j+src->q*i),1024);
        return 0;

}

// GC
void Argon2_matrix_free(Argon2_matrix* B){

        B->m = 0;
        B->p = 0;
        B->q = 0;
        free(B->matrix);
        B->matrix = NULL;

}

// Generates J1, J2 as specified in Argon2d
uint32_t* Argon2d_generate_values(Argon2_matrix* B, uint32_t i, uint32_t j){

        Argon2_block buffer;
        uint32_t J[2];
        if(Argon2_matrix_get_block(i,j-1,buffer,B))
                printf("Warning: invalid indeces, reading random bytes from RAM");
        memcpy(J,buffer->content,8);

}

// Generates 128 pairs (J1,J2) t.b.u. in the data independent indexing function
void Argon2i_generate_values(Argon2_indexing_arguments* arg, uint32_t* pairs){

        uint128_t zeros[64];
        uint128_t input[64];
        uint128_t result[64];

        for(int i = 0;i<64;i++){
                zeros[i].left = 0;
                zeros[i].right = 0;
        }

        input[0].left = arg->r;
        input[0].right = arg->l;
        input[1].left = arg->s;
        input[1].right = arg->m;
        input[2].left = arg->t;
        input[2].right = arg->x;
        input[3].left = arg->i;
        input[3].right = 0;
        for(int i = 4;i<64;i++){
                input[i].left = 0;
                input[i].right = 0;
        }


        CompressionFunctionG(zeros, input, result);
        CompressionFunctionG(zeros, result, result);

        for(int i = 0;i<64;i++){
                pairs[2*i] = result[i].left;
                pairs[2*i+1] = result[i].right;
        }
}

void Argon2_indexing_mapping(Argon2_indexing_arguments* arg; Argon2_matrix* B, uint32_t* J){

        uint32_t l;
        if(arg->r == 0 && arg->s == 0)
                l = arg->l;
        else
                l = J[1] % B->p;



}

void Argon2d_indexing(Argon2_matrix* B){

}


