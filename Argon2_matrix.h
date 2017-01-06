// Creates and manages the matrix B

#if !defined A2_MATRIX
#define A2_MATRIX

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

typedef struct{

        uint8_t content[1024];

}Argon2_block;

typedef struct{

        uint8_t* matrix;
        uint32_t m;
        uint32_t p;
        uint32_t q;

}Argon2_matrix;

int Argon2_matrix_init(uint32_t m, uint32_t p, Argon2_matrix* B);

int Argon2_matrix_fill_block(uint32_t i, uint32_t j, Argon2_matrix* dst, Argon2_block* src);

int Argon2_matrix_get_block(uint32_t i, uint32_t j, Argon2_block* dst, Argon2_matrix* src);

void Argon2_matrix_free(Argon2_matrix* B);

#endif