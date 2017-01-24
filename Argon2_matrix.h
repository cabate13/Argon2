#include "Argon2_compression.h"

#if !defined A2_MATRIX
#define A2_MATRIX

typedef struct{

        uint8_t content[1024];

}Argon2_block;

typedef struct{

        uint8_t* matrix;
        // degree of parallelism
        uint32_t p;
        // number of columns in the matrix
        uint32_t q;
        // pass number
        uint64_t r;
        // Total memory blocks
        uint64_t m;
        // Slice number
        uint64_t s;
        // total passes number
        uint64_t t;
        // type number
        uint64_t x;
        uint32_t segment_length;
	// S-Box for Argon2ds
	uint64_t* S;

}Argon2_global_workspace;

// arguments for the data-independent indexing function
typedef struct{

        // lane number
        uint64_t l;
        // column number
        uint64_t c;
        // counter [reset for every segment]
        uint64_t i;
        // place to save the 128 pairs in argon2i
        uint64_t pairs[128];
        // used pairs counter
        uint64_t counter;

}Argon2_local_workspace;

// Initializes the matrix and sets global parameters
int Argon2_global_workspace_init(uint32_t m, uint32_t p, uint32_t t, uint32_t x, Argon2_global_workspace* B);

// Fills the block in position (i,j) in the Argon2 matrix B with the content of the source block
int Argon2_matrix_fill_block(uint32_t i, uint32_t j, Argon2_global_workspace* dst, Argon2_block* src);

// Gets the block in position (i,j) in the Argon2 matrix B, storing the content in the dst block
int Argon2_matrix_get_block(uint32_t i, uint32_t j, Argon2_block* dst, Argon2_global_workspace* src);

// Indexing function
uint64_t Argon2_indexing(Argon2_global_workspace* B, Argon2_local_workspace* arg);

// Safely free memory allocated for the matrix
void Argon2_global_workspace_free(Argon2_global_workspace* B);

#endif
