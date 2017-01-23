#include "Argon2_matrix.h"

#if !defined A2_BODY

#define A2_BODY

typedef struct{

        // Message P and its size = [0 .. 2^32-1]
        uint8_t* P;
        uint32_t size_P;
        // Nonce S and its size = [8 .. 2^32-1]
        uint8_t* S;
        uint32_t size_S;
        // Degree of parallelization [1 .. 2^24-1]
        uint32_t p;
        // Tag length 
        uint32_t tau;
        // Total number of memory blocks
        uint32_t m;
        // Number of steps
        uint32_t t;
        // Version byte, default = 0x13
        uint32_t v;
        // Key K and its size = [0 .. 2^32]
        uint8_t* K;
        uint32_t size_K;
        // Associated data X and its size = [0..2^32]
        uint8_t* X;
        uint32_t size_X;
        // Type value
        uint32_t y;

}Argon2_arguments;

void Argon2(Argon2_arguments* args, uint8_t* tag);

#endif