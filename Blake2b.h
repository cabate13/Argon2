/**
 * @file Blake2b.h
 * Interface for the blake2b hash function
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#if !defined BLAKE2B
#define BLAKE2B

/*
 * @fn void blake2b( uint8_t* digest, size_t digest_size, uint8_t* data, uint64_t data_size)
 * Simplified version of the blake2b hash function. It divides the input data into blocks and then proceeds to repeatedly 
 * compress them, xoring the result in h, an array of 64 bytes, then outputs the required amount of bytes from it.
 * Unlike the original blake2b, this version does not accept a key, since it is unnecessary for Argon2 computation.
 * @param digest        an array to store the digest
 * @param digest_size   the number of required output bytes
 * @param data          the input data to compress
 * @param data_size     the size of said data, expressed in number of bytes
 */
void blake2b( uint8_t* digest, size_t digest_size, uint8_t* data, uint64_t data_size);

#endif

#if !defined ERROR
/// @def ERROR 
/// An utility function, used to print an error to std out and terminate the program
#define ERROR(msg) {puts((char*)msg); exit(1);}
#endif
#if !defined ROT_SHIFT
/// @def ROT_SHIFT 
/// An utility function, used to apply a rotational right shift of 'offset' positions to an array
#define ROT_SHIFT(array,offset) (((array) >> (offset)) ^ ((array) << (64 - (offset))))
#endif
