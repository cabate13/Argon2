#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Argon2_compression.h"
#include "Argon2_matrix.h"


//è la funzione principale di A2_G (almeno secondo l'interpretazione di Carmine delle specifiche di Argon2ds)
// semplicemente calcola P(X_0,..X_8),.., P(X_56,..X_63)
void F(uint64_t* X);

/*
* Permutazione S (S-box). Definiamo S fornendone la tavola degli output (i.e. l'immagine di S) che è un array uint8_t [1024]
* prende in input B[0][0].content e S e inizializza S alla S-box richiesta.
* NOTA: passare una copia di B[0][0].content perchè ne andiamo a modificare il contenuto
*/
void S_Box_Inizialization(uint8_t* Block00Content, uint8_t* S);

/*
* Funzione Tau
*/
void Tau(uint8_t* W, uint8_t* S, uint8_t* tauW);

/*
* Funzione di compressione per Argon2ds
*/
void A2ds_Compression(uint64_t* X, uint64_t* Y, uint64_t* result, uint8_t* Block00Content);


void F(uint64_t* X)
{
	for (int i = 0; i < 8; ++i) 
	{
		P(X);
	}
}

void S_Box_Inizialization(uint8_t* Block00Content, uint8_t* S)
{
	for (int i = 0; i < 16 ; ++i)
	{
		F(Block00Content);

		if(i%2) //"after each two iterations we use the entire 1024 byte value and initialize 128 lookupvalues" io l'ho intesa così
		{
			memcpy(S+128*(i/2), Block00Content, 128); 
		}
	}
}

void Tau(uint8_t* W, uint8_t* S, uint8_t* tauW)
{
	memcpy(tauW,W,8);

	uint64_t temp1;
	uint64_t temp2;

	for (int i = 0; i < 96; ++i)
	{
		uint8_t y = S[tauW[0]]; //W[0] sono i primi 8 bit di W
		uint8_t z = S[512 + tauW[4]] //W[4] sono i bit da 32 a 40 di W


		memcpy(temp1, tauW, 4);
		memcpy(temp2, tauW+4,4);

		*tauW = (temp1 * temp2) + (uint64_t) y;

		*tauW ^= (uint64_t) z; 

	}

}


void A2ds_Compression(uint64_t* X, uint64_t* Y, uint64_t* result, uint8_t* Block00Content)
{

	uint64_t R[128];                        // XOR of the two input arrays to compute
    XOR_128(X,Y,R);                         // the working matrix R, which is seen as a 
                                            // 8x8 matrix of elements uint64_t[2]

    uint64_t Q[128];                        // Stores R in Q for future computation
    memcpy(Q,R,sizeof(R));

    for (int i = 0; i < 8; ++i)             // Applies the permutation P to Q row-wise
    	P(Q+16*i);

    uint64_t column[16];                    // Applies the permutation P to Q column-wise:
    for (int i = 0; i < 8; ++i){

    	for (int j = 0; j < 8; ++j) 
    	{                                      
    	    column[2*j] = Q[16*j+2*i];      // Computes the i-th column of Q and stores        
    		column[2*j+1] = Q[16*j+1+2*i];  // it in 'column'
    	}

    	P(column);                           // Applies P 

        for (int j=0; j<8; ++j){
    		Q[16*j+2*i] = column[2*j];       // Writes the result in the correct position
    		Q[16*j+1+2*i] = column[2*j+1];
    	}

    //2ds part
    uint8_t* S = (uint8_t*) calloc(1024,sizeof(uint8_t));
    S_Box_Inizialization(Block00Content, S);

    uint8_t* W= (uint8_t*) malloc(sizeof(uint8_t)*8);
    W = R[0] ^ R[127]; 

    Tau(W,S,W);

    Q[0] += (uint64_t) W;
    Q[127] += (uint64_t) (W<<32);

   	XOR_128(Q,R,result);                     // Performs the final XOR

}


