#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "blake2b.h"
#include "Argon2_compression.h"
#include "SomeUtilityFunctions.h"

/*
* Function G in Blake2b (see pages 18 - 19) it is the core function for the permutation
*/
void CoreG(uint64_t* a, uint64_t* b, uint64_t* c, uint64_t* d);

/*
* Rund function of Blake2b (it should be a permutation but does not look like...)
* it takes in input the address of the array cointaining v_0... v_15
*/
void P(uint64_t* S);

/*
* New version of a compression function working with uint64_t
*/
void CompressionFunctionG(uint64_t* X, uint64_t* Y, uint64_t* result);


/*
* utility function it performs the XOR coordinatewise between two arrays
*/
void XOR128(uint64_t* X, uint64_t* Y, uint64_t*, int n);

// Rotational right shift of a 64-bit array [controlla che non sia già stato definito, per esempio
// importando blake2b]
#ifndef ROT_SHIFT
#define ROT_SHIFT(array,offset) (((array) >> (offset)) ^ ((array) << (64 - (offset))))
#endif
