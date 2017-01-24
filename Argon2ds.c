#include "Argon2ds.h"

void F(uint64_t* X)
{
	for (int i = 0; i < 8; ++i) 
	{
		P(X+16*i);
	}
}

void S_Box_Inizialization(uint8_t* Block00Content, uint64_t* S)
{
	for (int i = 0; i < 8 ; ++i)
	{
		F((uint64_t*)Block00Content);
        F((uint64_t*)Block00Content);
		memcpy(S+128*i, Block00Content, 128*sizeof(uint64_t)); 
	}
}

uint64_t Tau(uint64_t W, uint64_t* S)
{
    uint64_t y;
    uint64_t z;

	for (int i = 0; i < 96; ++i)
	{
		y = S[W & 0x1FF]; // i primi 9 bit di W
		z = S[512 + ((W >> 32) & 0x1FF)]; // i bit da 32 a 40 di W

		W = (((W & 0x00000000FFFFFFFF)*(W >> 32)) +  y) ^ z;

	}

    return W;
}


void A2ds_Compression(uint64_t* R, uint64_t* Z, uint64_t* S)
{

    uint64_t W;
    W = R[0] ^ R[127]; 

    W = Tau(W,S);

    Z[0] += W;

    Z[126] +=  W;
    Z[127] += (W<<32);                 
 
}


