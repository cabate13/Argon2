// Blake2b implementation
//
//      C implementation of the blake2b multi-length hash function
//      and its round function.
//      
//      Credits to:  Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn, and Christian Winnerlein
//


#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#if !defined BLAKE2B
#define BLAKE2B

// Blake2b hash function function
void blake2b( uint8_t* digest, size_t digest_size, uint8_t* data, uint64_t data_size);

#endif

// Utility functions used troughout the whole executable
#if !defined ERROR
#define ERROR(msg) {puts((char*)msg); exit(1);}
#endif
#if !defined ROT_SHIFT
#define ROT_SHIFT(array,offset) (((array) >> (offset)) ^ ((array) << (64 - (offset))))
#endif
