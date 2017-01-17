#if !defined A2_COMPRESSION

#define A2_COMPRESSION

#include "blake2b.h"


/*
* New version of a compression function working with uint64_t
*/
void CompressionFunctionG(uint64_t* X, uint64_t* Y, uint64_t* result);

/*
* Multi-length hash function, based on Blake2b, tau is the lenght of the digest
*/ 
void Hprime(uint8_t*X, uint32_t sizeX, uint32_t tau, uint8_t* digest);

/*
* utility function it performs the XOR coordinatewise between two arrays
*/
void XOR_128(uint64_t* X, uint64_t* Y, uint64_t* res);

#endif
