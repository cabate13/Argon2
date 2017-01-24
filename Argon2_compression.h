// Argon2 v1.3 : PHC release
//
//      C implementation of the Argon2 memory hard function for password hashing and others applications
//
//      Credits to:  Alex Biryukov, Daniel Dinu and Dimitry Khovratovich
//

#if !defined A2_COMPRESSION

#define A2_COMPRESSION
#define A2D 0
#define A2I 1
#define A2ID 2
#define A2DS 4

#include "Blake2b.h"

/*
 * Takes the block of position (0,0) and initializes the S-Box S for Argon2ds
 */
void S_Box_Inizialization(uint64_t* block_00, uint64_t* S);

/*
* Argon2 compression function, takes two blocks X and Y and compresses the into one block stored in result
* The last two arguments are the S-Box to be used in Argon2ds [type == 4]
*/
void A2_G(const uint64_t* X, const uint64_t* Y, uint64_t* result, uint64_t* S, uint8_t type);

/*
* Multi-length hash function, based on Blake2b, tau is the lenght of the digest
*/ 
void H_prime(uint8_t*X, uint32_t sizeX, uint32_t tau, uint8_t* digest);

/*
* utility function it performs the XOR coordinatewise between two arrays
*/
void XOR_128(const uint64_t* X, const uint64_t* Y, uint64_t* res);

#endif

/*
 * Outputs the 32-LSB of an uint64_t
 */
#if !defined TRUNC_32
// Truncation of the 32 lsb of a uint64_t, without changing its type
#define TRUNC_32(m) (m & 0x00000000FFFFFFFF)
#endif
