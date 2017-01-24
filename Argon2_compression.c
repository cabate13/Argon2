// Argon2 v1.3 : PHC release
//
//      C implementation of the Argon2 memory hard function for password hashing and others applications
//
//      Credits to:  Alex Biryukov, Daniel Dinu and Dimitry Khovratovich
//

#include "Argon2_compression.h"

void XOR_128(const uint64_t* X, const uint64_t* Y, uint64_t* res){

    for(int i = 0; i<128; ++i)
        res[i] = X[i]^Y[i];

}

/*
* Slightly modified version of the function B2B_G in Blake2b  
* It is the core function for the permutation P
*/
void Core_G(uint64_t* a, uint64_t* b, uint64_t* c, uint64_t* d){

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
* it takes as input the address of an array cointaining 16 uint64_t
*/
void P(uint64_t* S){

	Core_G( S + 0, S + 4, S +  8, S + 12);
	Core_G( S + 1, S + 5, S +  9, S + 13);
	Core_G( S + 2, S + 6, S + 10, S + 14);
	Core_G( S + 3, S + 7, S + 11, S + 15);
	Core_G( S + 0, S + 5, S + 10, S + 15);
	Core_G( S + 1, S + 6, S + 11, S + 12);
	Core_G( S + 2, S + 7, S +  8, S + 13);
	Core_G( S + 3, S + 4, S +  9, S + 14);

}

/*
 * Round function for the S-Box initialization Argon2ds
 */
#define A2DS_F {for (int k = 0; k < 8; ++k) P(block_00+16*k);}

void S_Box_Inizialization(uint64_t* block_00, uint64_t* S){

    for (int i = 0; i < 8 ; ++i)
    {
        A2DS_F;
        A2DS_F;
        memcpy(S+128*i, block_00, 128*sizeof(uint64_t)); 
    }

}
/*
 * Scrambles W using the S-Box S
 */
uint64_t Tau(uint64_t W, uint64_t* S){

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
/*
 * Further scrambling using the S-Box, takes R and Z as described in A2_G
 */
void A2DS_compression(uint64_t* R, uint64_t* Z, uint64_t* S){

    uint64_t W;
    W = R[0] ^ R[127]; 

    W = Tau(W,S);

    Z[0] += W;

    Z[126] +=  W;
    Z[127] += (W<<32);                 
 
}

/*
 * Main compression functions of Argon2, takes as input
 * two arrays of 1024 bytes and compresses them into one array
 * of 1024 bytes.
 */
void A2_G(const uint64_t* X, const uint64_t* Y, uint64_t* result, uint64_t* S, uint8_t type){

    uint64_t R[128];                        // XOR of the two input arrays to compute
    XOR_128(X,Y,R);                         // the working matrix R, which is seen as a 
                                            // 8x8 matrix of elements uint64_t[2]
    uint64_t Q[128];                        // Stores R in Q for future computation
    memcpy(Q,R,sizeof(R));

    for (int i = 0; i < 8; ++i)             // Applies the permutation P to Q row-wise
    	P(Q+16*i);

    uint64_t column[16];                    // Applies the permutation P to Q column-wise:
    for (int i = 0; i < 8; ++i){

    	for (int j = 0; j < 8; ++j){

    	    column[2*j] = Q[16*j+2*i];      // Computes the i-th column of Q and stores        
    		column[2*j+1] = Q[16*j+1+2*i];  // it in 'column'

    	}

    	P(column);                           // Applies P 

        for (int j=0; j<8; ++j){

    		Q[16*j+2*i] = column[2*j];       // Writes the result in the correct position
    		Q[16*j+1+2*i] = column[2*j+1];

    	}

    }

    if(type == A2DS)
        A2DS_compression(R, Q, S);

   	XOR_128(Q,R,result);                     // Performs the final XOR

}

/*
 * Multi-lenght hash function based on Blake2b. 
 */
void H_prime(uint8_t*X, uint32_t sizeX, uint32_t tau, uint8_t* digest){

    // Compute tau || X
    uint8_t* t_cat_X;
    t_cat_X = (uint8_t*) malloc(sizeX+4);
    memcpy(t_cat_X, &tau, 4);
    memcpy(t_cat_X+4, X, sizeX);

    if(tau <= 64)
            blake2b(digest,tau,t_cat_X,sizeX+4);            // If tau <= 64, blake2b is enough

    else{                                                   // Otherwise, we use repeated evaluations of Blake2b

            uint32_t r = tau/32 + (tau%32 != 0) - 2;        //  Compute the required evaluations
            uint8_t V[64];

            blake2b(V,64,t_cat_X, sizeX+4);                 //  Apply blake2b to tau||X to compute V_1
            memcpy(digest, V, 32);

            for (int i = 1; i < r; ++i){

                    blake2b(V,64,V,64);                     //  Compute V_(i+1) = blake2b(V_i)
                    memcpy(digest+i*32, V, 32);             //  Copy the first 32 bits of V_i+1 to the digest
            
            }

            blake2b(V, tau-32*r, V,64);                     //  Compute the last block required, which has different length 
            memcpy(digest+r*32,V, tau-32*r);                //  Copy it to the digest until the desired length is reached

    }
         
    //free memory
    free(t_cat_X);   
        
}

