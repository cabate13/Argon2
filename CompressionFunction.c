#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "blake2b.h"
#include "Argon2_compression.h"
#include "SomeUtilityFunctions.h"


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

void P(uint64_t* S)
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

void XOR128(uint64_t* X, uint64_t* Y, uint64_t* res, int n)
{
	for(int i=0; i<n; i++)
	{
		res[i] = X[i] ^ Y[i];
	}
}

void CompressionFunctionG(uint64_t* X, uint64_t* Y, uint64_t* result)
{

        //the first XOR
        uint64 R[128];
        XOR128(X,Y,R,128);

        uint64_t Q[128] = R;
        
        //the generic Row of Q to which we will apply P
        uint64_t array[16];

        for (int i = 0; i < 8; ++i)
        {
        	memcpy(array, Q + 16*i, sizeof(uint64_t)*16);
        	P(array);
        	memcpy(Q+ 16*i, array, sizeof(uint64_t)*16);
        }

        // now build Z
        uint64_t Z[128];

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
        		Z[16*j+2*i] = array[2*j];
        		Z[16*j+1+2*i] = array[2*j+1];
        	}

        }

       	XOR128(Z,R,result);

}

