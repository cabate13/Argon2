// Argon2 v1.3 : PHC release
//
//      C implementation of the Argon2 memory hard function for password hashing and others applications
//
//      Credits to:  Alex Biryukov, Daniel Dinu and Dimitry Khovratovich
//

#if !defined A2_BODY

#define A2_BODY
#define H0_LENGTH 64

#include "Argon2_matrix.h"

/*
 * Contains the parameters necessary for Argon2
 */
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

/*
 * Argon2 main function, initializes the global environment, performs computations and stores the output in tag 
 */
void Argon2(Argon2_arguments* args, uint8_t* tag);

#endif
