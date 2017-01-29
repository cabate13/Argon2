/**
* @file
* Interface for the compression process in Argon2
*/
#if !defined A2_COMPRESSION


#define A2_COMPRESSION

/// @def A2D
/// type number for Argon2d
#define A2D 0
/// @def A2I
/// type number for Argon2i
#define A2I 1
/// @def A2ID
/// type number for Argon2id
#define A2ID 2
/// @def A2DS
/// type number for Argon2ds
#define A2DS 4

#include "Blake2b.h"

/**
 * @fn void S_Box_Inizialization(uint64_t* block_00, uint64_t* S)
 * Takes the block at position (0,0) and initializes the S-Box S for Argon2ds
 * @param block_00   pointer to the block in position [0,0] of the matrix B
 * @param S          pointer to the image of the S box 
 */
void S_Box_Inizialization(uint64_t* block_00, uint64_t* S);

/**
 * @fn void A2_G(const uint64_t* X, const uint64_t* Y, uint64_t* result, uint64_t* S, uint8_t type)
 * Compression functions of Argon2  G : (X,Y) -> R = X ^ Y -> Q -> Z -> Z ^ R
 * @param X         pointer to the first input of the compression function
 * @param Y         pointer to the second input of the compression function
 * @param result    pointer to the result of the compression function
 * @param S         pointer to the image of the S box 
 * @param type      version of Argon2 to be used
 */
void A2_G(const uint64_t* X, const uint64_t* Y, uint64_t* result, uint64_t* S, uint8_t type);

/**
* @fn void H_prime(uint8_t*X, uint32_t sizeX, uint32_t tau, uint8_t* digest)
* Variable-lenght hash function based on Blake2b
* tau is the lenght of the digest
* @param X         pointer to the input of Argon2 hash function 
* @param sizex     size of the input
* @param tau       length of the digest
* @param digest    pointer to the resulting digest
*/ 
void H_prime(uint8_t*X, uint32_t sizeX, uint32_t tau, uint8_t* digest);

/**
* @fn void XOR_128(const uint64_t* X, const uint64_t* Y, uint64_t* res)
* Utility function performing the componentwise xor of two arrays
* @param X      pointer to the first input array
* @param Y      pointer to the second input array
* @param res    pointer to the result of the xor
*/
void XOR_128(const uint64_t* X, const uint64_t* Y, uint64_t* res);

#endif

#if !defined TRUNC_32
/// @def
/// The 32-LSB of an uint64_t
#define TRUNC_32(m) (m & 0x00000000FFFFFFFF)
#endif
