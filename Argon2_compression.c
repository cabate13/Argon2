#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "blake2b.h"
#include "Argon2_compression.h"

#ifndef ROT_SHIFT
// Rotational right shift of a 64-bit array
#define ROT_SHIFT(array,offset) (((array) >> (offset)) ^ ((array) << (64 - (offset))))
#endif 

#if !defined TRUNC_32
// Truncation of the 32 lsb of a uint64_t, without changing its type
#define TRUNC_32(m) (m & 0x00000000FFFFFFFF)
#endif

#define PRINT_MATRIX(m) {for(int k = 0; k < 8; k++){for(int cl = 0;cl<16;cl++)printf("%016llX ",m[k*16+cl]);printf("\n");}printf("\n");}
#define PRINT_ARRAY(v) {for(int k = 0;k<16;k++)printf("%016llX ",v[k]);printf("\n");}

void XOR_128(uint64_t* X, uint64_t* Y, uint64_t* res){

    for(int i = 0; i<128; ++i)
        res[i] = X[i]^Y[i];

}

/*
* Slightly modified version of the function G in Blake2b (see pages 18 - 19) 
* It is the core function for the permutation P
*/
void CoreG(uint64_t* a, uint64_t* b, uint64_t* c, uint64_t* d)
{
	*a = *a + *b + 2*TRUNC_32(*a)*TRUNC_32(*b);
	*d = ROT_SHIFT(*d ^ *a, 32);
	*c = *c + *d + 2*TRUNC_32(*c)*TRUNC_32(*d);
	*b = ROT_SHIFT(*b ^ *c, 24);
	*a = *a + *b + 2*TRUNC_32(*a)*TRUNC_32(*b);
	*d = ROT_SHIFT(*d ^ *a, 16);
	*c = *c + *d + 2*TRUNC_32(*c)*TRUNC_32(*d);
	*b = ROT_SHIFT(*b ^ *c, 63);
}

/*
* Slightly modified version of round function of Blake2b 
* it takes in input the address of the array cointaining v_0... v_15
*/
void P(uint64_t* S)
{

	CoreG( S + 0, S + 4, S +  8, S + 12);
	CoreG( S + 1, S + 5, S +  9, S + 13);
	CoreG( S + 2, S + 6, S + 10, S + 14);
	CoreG( S + 3, S + 7, S + 11, S + 15);
	CoreG( S + 0, S + 5, S + 10, S + 15);
	CoreG( S + 1, S + 6, S + 11, S + 12);
	CoreG( S + 2, S + 7, S +  8, S + 13);
	CoreG( S + 3, S + 4, S +  9, S + 14);

}

void CompressionFunctionG(uint64_t* X, uint64_t* Y, uint64_t* result)
{

        //the first XOR
        uint64_t R[128];
        XOR_128(X,Y,R);

        // Compute P on the rows of Q
        uint64_t Q[128];
        memcpy(Q,R,sizeof(R));
        for (int i = 0; i < 8; ++i)
        	P(Q+16*i);

        // Compute P on the columns of Q
        uint64_t array[16];
        for (int i = 0; i < 8; ++i)
        {
        	for (int j = 0; j < 8; ++j)
        	{
        		array[2*j] = Q[16*j+2*i];
        		array[2*j+1] = Q[16*j+1+2*i];
        	}

        	P(array);

        	for (int j=0; j<8; ++j)
        	{
        		Q[16*j+2*i] = array[2*j];
        		Q[16*j+1+2*i] = array[2*j+1];
        	}

        }

       	XOR_128(Q,R,result);

}

void Hprime(uint8_t*X, uint32_t sizeX, uint32_t tau, uint8_t* digest)
{

        // tau || X
        uint8_t* tauCatX;
        tauCatX = (uint8_t*) malloc(sizeX+4);
        memcpy(tauCatX, &tau, 4);
        memcpy(tauCatX+4, X, sizeX);

        //digest depends on the value of tau
        if(tau <= 64)
                blake2b(digest,tau,tauCatX,sizeX+4, NULL, 0);

        else
        {
                uint32_t r = tau/32 + (tau%32 != 0) - 2;
                uint8_t V[64];

                //apply blake2b to tau||X to find V_1
                blake2b(V,64,tauCatX, sizeX+4, NULL,0);
                memcpy(digest, V, 32);

                // Compute V_(i+1) = blake2b(V_i)
                // Copy the first 32 bits of V_i+1 to the digest
                for (int i = 1; i < r; ++i)
                {
                        blake2b(V,64,V,64, NULL,0);
                        memcpy(digest+i*32, V, 32);

                }

                blake2b(V, tau-32*r, V,64, NULL,0);
                memcpy(digest+r*32,V, tau-32*r);

        }
             
        //free memory
        free(tauCatX);   
        
}

