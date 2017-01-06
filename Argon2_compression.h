#if !defined A2_COMPRESSION

#define A2_COMPRESSION

#include "blake2b.h"

void CompressionFunctionG(uint128_t X[64], uint128_t Y[64], uint128_t* result);

void Hprime(uint8_t*X, uint32_t sizeX, uint32_t tau, uint8_t* digest);

#endif
