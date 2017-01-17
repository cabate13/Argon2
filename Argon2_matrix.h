// Creates and manages the matrix B

#if !defined A2_MATRIX
#define A2_MATRIX

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "blake2b.h"

typedef struct{

        uint8_t content[1024];

}Argon2_block;

typedef struct{

        uint8_t* matrix;
        uint32_t m;
        uint32_t p;
        uint32_t q;
        uint32_t segment_length;

}Argon2_matrix;

// arguments for the data-independent indexing function
typedef struct{

        // pass number
        uint64_t r;
        // lane number
        uint64_t l;
        // column number
        uint64_t c;
        // total memory blocks
        uint64_t m;
        // slice number
        uint64_t s;
        // total passes
        uint64_t t;
        // type number
        uint64_t x;
        // counter [reset for every segment]
        uint64_t i;
        // place to save the 128 pairs in argon2i
        uint64_t pairs[128];
        // used pairs counter
        uint64_t counter;

}Argon2_indexing_arguments;

// Initializes the arguments for Argon2 indexing
void Argon2_indexing_arguments_init(Argon2_indexing_arguments* args, uint32_t m, uint32_t t, uint32_t x);

// Initializes the matrix and sets its parameters
int Argon2_matrix_init(uint32_t m, uint32_t p, Argon2_matrix* B);

// Fills the block in position (i,j) in the Argon2 matrix B with the content of the source block
int Argon2_matrix_fill_block(uint32_t i, uint32_t j, Argon2_matrix* dst, Argon2_block* src);

// Gets the block in position (i,j) in the Argon2 matrix B, storing the content in the dst block
int Argon2_matrix_get_block(uint32_t i, uint32_t j, Argon2_block* dst, Argon2_matrix* src);

// GC
void Argon2_matrix_free(Argon2_matrix* B);

// Indexing function
/* Per avere la coppia di indici dell'indexing
Poni ip l'uint64 che ti butta Argon indexing
j = ip && 0x00000000FFFFFFFF
i = ip » 32
*/
uint64_t Argon2_indexing(Argon2_indexing_arguments* arg, Argon2_matrix* B);

#endif