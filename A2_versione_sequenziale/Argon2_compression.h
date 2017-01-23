#if !defined A2_COMPRESSION

#define A2_COMPRESSION

#include "Blake2b.h"

/*
* New version of a compression function working with uint64_t
*/
void A2_G(uint64_t* X, uint64_t* Y, uint64_t* result);

/*
* Multi-length hash function, based on Blake2b, tau is the lenght of the digest
*/ 
void H_prime(uint8_t*X, uint32_t sizeX, uint32_t tau, uint8_t* digest);

/*
* utility function it performs the XOR coordinatewise between two arrays
*/
void XOR_128(uint64_t* X, uint64_t* Y, uint64_t* res);

#endif

#if !defined TRUNC_32
// Truncation of the 32 lsb of a uint64_t, without changing its type
#define TRUNC_32(m) (m & 0x00000000FFFFFFFF)
#endif
