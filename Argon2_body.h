/**
* @file
* Interface for Argon2
*/
#if !defined A2_BODY
#define A2_BODY

/// @def H0_LENGTH
///      length of the initial seed for first block computation
#define H0_LENGTH 64

#include "Argon2_matrix.h"

/**
 * @struct
 * Contains all the parameters necessary for Argon2
 */
typedef struct{

        // Message P and its size = [0 .. 2^32-1]
        uint8_t* P;
        uint32_t size_P;
        //! Nonce S 
        uint8_t* S;
        //! nonce size, in [8 .. 2^32-1]
        uint32_t size_S;
        //! Degree of parallelization, in [1 .. 2^24-1]
        uint32_t p;
        //! Tag length 
        uint32_t tau;
        //! Total number of memory blocks
        uint32_t m;
        //! Number of steps
        uint32_t t;
        //! Version byte, default = 0x13
        uint32_t v;
        //! Key K 
        uint8_t* K;
        //! Key size, in [0 .. 2^32]
        uint32_t size_K;
        //! Associated data X 
        uint8_t* X;
        //! Associated data size, in [0..2^32]
        uint32_t size_X;
        //! Type value, defining the version of Argon2 : 0 = d , 1 = i , 2 = id , 4 = ds
        uint32_t y;

}Argon2_arguments;

/**
 * @fn void Argon2(Argon2_arguments* args, uint8_t* tag)
 * Initializes the global environment, performs computations and stores the output in tag 
 * @param args pointer to the arguments for Argon2 to be inizialized 
 * @param tag  pointer to the tag
 */
void Argon2(Argon2_arguments* args, uint8_t* tag);

#endif
