#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "blake2b.h"
#include "Argon2_compression.h"

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

/*
*  Compression Function of Argon2
*/
void CompressionFunctionG(uint128_t X[64], uint128_t Y[64], uint128_t* result);

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
        uint128_t S[8]; 

        for (int i = 0; i < 8; ++i)
        {
                S[i] = *(T+i);
        }

        uint64_t MyS[16];

        for (int i = 0; i < 8; ++i)
        {
                MyS[2*i] = S[i].left;
                MyS[2*i+1] = S[i].right;
        }
        
        MyPermutation(MyS);

        for (int i = 0; i < 8; ++i)
        {
                S[i].left = MyS[2*i];
                S[i].right = MyS[2*i+1];
        }

        *T = *S;

}


void CompressionFunctionG(uint128_t X[64], uint128_t Y[64], uint128_t* result)
{

        //the first XOR
        uint128_t R[64];

        XOR(X,Y,R,64);

        //now we build the square matrix Q
        uint128_t Q[8][8];

        for (int i = 0; i < 8; i++)
        {
                for (int j= 0; j < 8; j++)
                {
                        Q[i][j] = R[j+8*i];
                }

                //and apply P to each row of Q
                P(Q[i]);
        }


        //now compute the tansopose of Q and apply P to its rows
        uint128_t Z[8][8];

        for (int i = 0; i < 8; i++)
        {
                for (int j = 0; j < 8; j++)
                {
                        Z[i][j] = Q [j][i];
                }

                P(Z[i]);
        }       

        //reguard Z as an array to perform XOR with R
        uint128_t myZ[64];

        for (int i = 0; i < 8; i++)
        {
                for (int j = 0; j < 8; j++)
                {
                        myZ[j+8*i] = Z[i][j];
                }
                
        }

        //XOR with R
        XOR(myZ, R, result,64);

}
