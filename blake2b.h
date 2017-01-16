// Blake2b implementation
//
//      C implementation of the blake2b multi-length hash function
//      and its round function.
//      
//      Credits to:  Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn, and Christian Winnerlein
//
//  Notation and function names are used accordingly to this independent IETF submission:
//  https://tools.ietf.org/html/rfc7693
//
//  Credits to: M-J. Saarinen, Ed.
//

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if !defined BLAKE2B

#define BLAKE2B

// Blake2b hash function function
void blake2b( void* digest, size_t nn, void* data, size_t ll, void* key, size_t kk);

#endif