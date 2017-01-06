#include "Argon2_matrix.h"

int Argon2_matrix_init(uint32_t m, uint32_t p, Argon2_matrix* B){

        if(p == 0 || p > 0xFFFFFF || m < 8*p )
                return 1;

        B->p = p;
        B->m = (m/(4*p))*4*p;
        B->q = m/p;

        B->matrix = (uint8_t*)malloc(m*1024);

        return 0;

};

int Argon2_matrix_fill_block(uint32_t i, uint32_t j, Argon2_matrix* dst, Argon2_block* src){

        if(i > (dst->p - 1) || j > (dst->q - 1))
                return 1;

        memcpy((dst->matrix)+1024*(j+dst->q*i),src->content,1024);
        return 0;

};

int Argon2_matrix_get_block(uint32_t i, uint32_t j, Argon2_block* dst, Argon2_matrix* src){

        if(i > (src->p - 1) || j > (src->q - 1))
                return 1;

        memcpy(dst->content,(src->matrix)+1024*(j+src->q*i),1024);
        return 0;

};

void Argon2_matrix_free(Argon2_matrix* B){

        B->m = 0;
        B->p = 0;
        B->q = 0;
        free(B->matrix);
        B->matrix = NULL;

};