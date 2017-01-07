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
void MyPermutation(uint64_t* S);

/*
* starting from an array of 8 blocks of 16 bytes get the corresnponding matrix and then apply MyPermutation
*/
void P(uint128_t* S);

// Rotational right shift of a 64-bit array [controlla che non sia già stato definito, per esempio
// importando blake2b]
#ifndef ROT_SHIFT
#define ROT_SHIFT(array,offset) (((array) >> (offset)) ^ ((array) << (64 - (offset))))
#endif

void CoreG(uint64_t* a, uint64_t* b, uint64_t* c, uint64_t* d)
{

	uint64_t al = (uint32_t)(*a);
	uint64_t bl = (uint32_t)(*b);
	uint64_t cl = (uint32_t)(*c);
	uint64_t dl = (uint32_t)(*d);

	*a = *a + *b + 2*al*bl;
	*d = ROT_SHIFT(*d ^ *a, 32);
	*c = *c + *d + 2*cl*dl;
	*b = ROT_SHIFT(*b ^ *c, 24);
	*a = *a + *b + 2*al*bl;
	*d = ROT_SHIFT(*d ^ *a, 16);
	*c = *c + *d + 2*cl*dl;
	*b = ROT_SHIFT(*b ^ *c, 63);
}

void MyPermutation(uint64_t* S)
{

	CoreG( S    , S + 4, S +  8, S + 12);
	CoreG( S + 1, S + 5, S +  9, S + 13);
	CoreG( S + 2, S + 6, S + 10, S + 14);
	CoreG( S + 3, S + 7, S + 11, S + 15);
	CoreG( S + 0, S + 5, S + 10, S + 15);
	CoreG( S + 1, S + 6, S + 11, S + 12);
	CoreG( S + 2, S + 7, S +  8, S + 13);
	CoreG( S + 3, S + 4, S +  9, S + 14);
}

void P(uint128_t* T)
{
        uint64_t MyT[16];

        for (int i = 0; i < 8; ++i)
        {
                MyT[2*i] = T[i].left;
                MyT[2*i+1] = T[i].right;
        }
        
        MyPermutation(MyT);

        for (int i = 0; i < 8; ++i)
        {
                T[i].left = MyT[2*i];
                T[i].right = MyT[2*i+1];
        }

}


void CompressionFunctionG(uint128_t X[64], uint128_t Y[64], uint128_t* result)
{

        //the first XOR
        uint128_t R[64];
        XOR(X,Y,R,64);

        //build the square matrix Q
        uint128_t** Q;
        Q = matrixMalloc(Q,8,8);
        arrayToMatrix(R,Q,8,8);

        for (int i = 0; i < 8; i++)
        {
                P(Q[i]);
        }

        //build the square matrix Z
        uint128_t** Z = transpose(Q,8,8);

        //free memory used for Q
        matrixFree(Q,8);

        for (int i = 0; i < 8; i++)
        {
               P(Z[i]);
        }

        //reguard Z as an array to perform XOR with R
        uint128_t Zarray[64];
        matrixToArray(Z,Zarray,8,8);

        //free memory used for Z
        matrixFree(Z,8);

        //XOR with R
        XOR(Zarray, R, result,64);

}


void Hprime(uint8_t*X, uint32_t sizeX, uint32_t tau, uint8_t* digest)
{

        // tau || X
        uint8_t* tauCatX;
        tauCatX = (uint8_t*) malloc( sizeof(uint8_t)*(sizeX+4));
        memcpy(tauCatX, &tau, 4);
        memcpy(tauCatX, X, sizeX);

        //digest depends on the value of tau
        if(tau <= 64)
        {
                blake2b(digest,tau,tauCatX,sizeX+4, digest, 0);

                //free memory
                free(tauCatX);
        }
        

        else
        {
                uint32_t r = tau/32 + (tau%32 != 0);

                uint8_t* V;     

                //apply blake2b 
                blake2b(V,64,tauCatX, sizeX+4, digest,0);

                //free memory
                free(tauCatX);

                //and add the first 32 bytes to the digest
                memcpy(digest, V, 32);

                for (int i = 1; i <= r; ++i)
                {
                        blake2b(V,64,V,64, digest,0);
                        memcpy(digest+i, V, 32);
                }

                blake2b(V, tau-32*r, V,64, digest,0);
                memcpy(digest+r+1,V, tau-32*r);
        }
             
        //free memory
        free(tauCatX);   
        
}