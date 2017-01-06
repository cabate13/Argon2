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

// arguments for the data-independent indexing function
typedef struct{

        uint64_t r;
        uint64_t l;
        uint64_t m;
        uint64_t s;
        uint64_t t;
        uint64_t i;

}Argon2i_indexing_arguments;

// Initializes the matrix and sets its parameters
int Argon2_matrix_init(uint32_t m, uint32_t p, Argon2_matrix* B);

// Fills the block in position (i,j) in the Argon2 matrix B with the content of the source block
int Argon2_matrix_fill_block(uint32_t i, uint32_t j, Argon2_matrix* dst, Argon2_block* src);

// Gets the block in position (i,j) in the Argon2 matrix B, storing the content in the dst block
int Argon2_matrix_get_block(uint32_t i, uint32_t j, Argon2_block* dst, Argon2_matrix* src);

// GC
void Argon2_matrix_free(Argon2_matrix* B);

#endif