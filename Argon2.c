#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include "blake2b.h"

/*
* Utility function that performs the Xor between two arrays of uint128_t of the same length
*/
void XOR(uint128_t* X, uint128_t* Y, uint128_t* xored, int n);

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


// a Test
int main(void)
{

	/*	
	uint128_t S[8];

	for (int i = 0; i < 8; ++i)
	{
		S[i].left = 4294967297 +i;
		printf("%lu\n", S[i].left);
		S[i].right = 4294967299 + 10*i;
		printf("%lu\n", S[i].right);
	}

	printf("\n\n");
	P((uint128_t*) &S);

	for (int i = 0; i < 8; ++i)
	{
		printf("%lu\n", S[i].left);
		printf("%lu\n", S[i].right);
	}	
	*/

	uint128_t X[64];
	uint128_t Y[64];

	for (int i = 0; i < 64; ++i)
	{
		X[i].left = 1;
		Y[i].right = 0;
		X[i].right = 0;
		Y[i].left = 0;
	}

	
	uint128_t T[64];

	for (int i = 0; i < 64; ++i)
	{
		
		T[i].left = 0;
		T[i].right = 0;

	}

	printf("FINE\n");

	CompressionFunctionG(X,Y,T);

	
	for (int i = 0; i < 64; ++i)
	{
		
		uint64_t d = (*(T+i)).left;
		uint64_t t = (*(T+i)).right;

		printf("%016llX | %016llX\n", t, d);
	}
	
 	return 0;
}

// Utility function, XOR of two uint128_t*

void XOR(uint128_t* X, uint128_t* Y, uint128_t* xored, int n)
{

        for (int i = 0; i < n; i++)
        {
                (*(xored+i)).left = ((*(X+i)).left) ^ ((*(Y+i)).left);
                (*(xored+i)).right = ((*(X+i)).right) ^ ((*(Y+i)).right);
        }

}

// Rotational right shift of a 64-bit array [controlla che non sia già stato definito, per esempio
// importando blake2b]
#ifndef ROT_SHIFT
#define ROT_SHIFT(array,offset) (((array) >> (offset)) ^ ((array) << (64 - (offset))))
#endif

// questa va cambiata un po'. Mi pare di capire che questa sia quella costruita 
// sulla funzione di round di blake2b, comunque visto che ha un paio di differenze è inutile stare lì a 
// usare quella che si usa in b2b vera e propria. è possibile, ma sarebbe orrendo e poco leggibile il codice.
// Detto ciò, se vogliamo tenere a mano spazio [20 righe scarse di codice] si può fare. Comunque qua sotto 
// il problema sono gli shift, che devono essere rotational [qua conviene importare quello definito in blake2b,
// si chiama ROT_SHIFT(array,offset) := (array >> offset) ^ (array << (64-offset)) <- visto che stiamo lavorando
// a 64 bit ] mentre tu li fai semplici. 
// In più i vari al,bl,.. devono essere a 64 bit, se no vanno in overflow quando provi a moltiplicarli sotto
// e visto che siamo in little endian basta fare un cast
void CoreG(uint64_t* a, uint64_t* b, uint64_t* c, uint64_t* d)
{
	// uint32_t al = (*a>>32) & 0xffffffff;
	// uint32_t bl = (*b>>32) & 0xffffffff;
	// uint32_t cl = (*c>>32) & 0xffffffff;
	// uint32_t dl = (*d>>32) & 0xffffffff;
	// Sia
	uint64_t al = (uint32_t)(*a);
	uint64_t bl = (uint32_t)(*b);
	uint64_t cl = (uint32_t)(*c);
	uint64_t dl = (uint32_t)(*d);

	// *a = *a + *b + 2*al*bl;
	// *d = (*d ^ *a) >> 32;
	// *c = *c + *d + 2*cl*dl;
	// *b = (*b ^ *c) >> 24;
	// *a = *a + *b + 2*al*bl;
	// *d = (*d ^ *a) >> 16;
	// *c = *c + *d + 2*cl*dl;
	// *b = (*b ^ *c) >> 63;
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
	// Li stai castando nello stesso tipo di dato che già sono
	// CoreG((uint64_t*)S, (uint64_t*)(S+4), (uint64_t*)(S+8), (uint64_t*)(S+12));
	// CoreG((uint64_t*)(S+1), (uint64_t*)(S+5),(uint64_t*)(S+9),(uint64_t*)(S+13));
	// CoreG((uint64_t*)(S+2), (uint64_t*)(S+6), (uint64_t*)(S+10), (uint64_t*)(S+14));
	// CoreG((uint64_t*)(S+3), (uint64_t*)(S+7), (uint64_t*)(S+11), (uint64_t*)(S+15));
	// CoreG((uint64_t*)S, (uint64_t*)(S+5), (uint64_t*)(S+10), (uint64_t*)(S+15));
	// CoreG((uint64_t*)(S+1), (uint64_t*)(S+6), (uint64_t*)(S+11), (uint64_t*)(S+12));
	// CoreG((uint64_t*)(S+2), (uint64_t*)(S+7), (uint64_t*)(S+8), (uint64_t*)(S+13));
	// CoreG((uint64_t*)(S+3), (uint64_t*)(S+4), (uint64_t*)(S+9), (uint64_t*)(S+14));
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