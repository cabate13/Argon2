/**
* @file 
* Compression function of Argon2. It is built upon the function P taken from Blake2b
*/
#include "Argon2_compression.h"

/*
* @fn void XOR_128(const uint64_t* X, const uint64_t* Y, uint64_t* res)
* Utility function performing the componentwise xor of two arrays
* @param X      pointer to the first input array
* @param Y      pointer to the second input array
* @param res    pointer to the result of the xor
*/
void XOR_128(const uint64_t* X, const uint64_t* Y, uint64_t* res){

    for(int i = 0; i<128; ++i)
        res[i] = X[i]^Y[i];

}

/** 
*    @fn void Core_G(uint64_t* a, uint64_t* b, uint64_t* c, uint64_t* d)
*   Slightly modified version of the function B2B_G in Blake2b  
*   It is the core function for the permutation P
*   @param a    pointer to one of the input of the core of the round function of Blake2b
*   @param b    pointer to one of the input of the core of the round function of Blake2b
*   @param c    pointer to one of the input of the core of the round function of Blake2b
*   @param d    pointer to one of the input of the core of the round function of Blake2b
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

/**
* @fn void P(uint64_t* S)
* Slightly modified version of round function of Blake2b 
* it takes as input the address of an array cointaining 16 uint64_t
* @param S  pointer to input of the round function of Blake2b
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

void A2DS_F(uint64_t* Q){

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

}

/*
* @fn void S_Box_Inizialization(uint64_t* block_00, uint64_t* S)
* Inizialization of the S-box for the 2ds version
* @param block_00   pointer to the block in position [0,0] of the matrix B
* @param S          pointer to the image of the S box 
*/
void S_Box_Inizialization(uint64_t* block_00, uint64_t* S){

    uint64_t seed[A2_MATRIX_BLOCK_LENGTH/sizeof(uint64_t)];
    memcpy(seed,block_00,A2_MATRIX_BLOCK_LENGTH);
    for (int i = 0; i < 8 ; ++i)
    {
        A2DS_F(seed);
        A2DS_F(seed);
        memcpy(S+(A2_MATRIX_BLOCK_LENGTH/sizeof(uint64_t))*i, seed, A2_MATRIX_BLOCK_LENGTH); 
    }

}

/**
 * @fn uint64_t Tau(uint64_t W, uint64_t* S)
 * 64-bit transformation involved in the 2ds version
 * @param W          64-bit word
 * @param S          pointer to the image of the S box   
 */
uint64_t Tau(uint64_t W, uint64_t* S){

    uint64_t y;
    uint64_t z;

    for (int i = 0; i < 96; ++i){
        
        y = S[W & 0x1FF];                   // i primi 9 bit di W
        z = S[512 + ((W >> 32) & 0x1FF)];   // i bit da 32 a 40 di W

        W = (((W & 0x00000000FFFFFFFF)*(W >> 32)) +  y) ^ z;

    }

    return W;
}

/**
 * @fn void A2DS_compression(uint64_t* R, uint64_t* Z, uint64_t* S)
 * Extra computation required in the compression function for the 2ds version
 * @param R     pointer to R defined in the compression function
 * @param Z     pointer to Z defined in the compression function
 * @param S     pointer to the image of the S box
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
 * @fn void A2_G(const uint64_t* X, const uint64_t* Y, uint64_t* result, uint64_t* S, uint8_t type)
 * Compression functions of Argon2  G : (X,Y) -> R = X ^ Y -> Q -> Z -> Z ^ R. 
 * @param X         pointer to the first input of the compression function
 * @param Y         pointer to the second input of the compression function
 * @param result    pointer to the result of the compression function
 * @param S         pointer to the image of the S box 
 * @param type      version of Argon2 to be used
 */
void A2_G(const uint64_t* X, const uint64_t* Y, uint64_t* result, uint64_t* S, uint8_t type){

    uint64_t R[A2_MATRIX_BLOCK_LENGTH/8];   // XOR of the two input arrays to compute
    XOR_128(X,Y,R);                         // the working matrix R, which is seen as a 
                                            // 8x8 matrix of elements uint64_t[2]
    uint64_t Q[A2_MATRIX_BLOCK_LENGTH/8];   // Stores R in Q for future computation
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
 * @fn void H_prime(uint8_t*X, uint32_t size_X, uint32_t tau, uint8_t* digest)
 * Variable-lenght hash function based on Blake2b. 
 * @param X         pointer to the input of Argon2 hash function 
 * @param size_X     size of the input
 * @param tau       length of the digest
 * @param digest    pointer to the resulting digest
 */
void H_prime(uint8_t*X, uint32_t size_X, uint32_t tau, uint8_t* digest){

    // Compute tau || X
    uint8_t* t_cat_X;
    t_cat_X = (uint8_t*) malloc(size_X+4);
    memcpy(t_cat_X, &tau, 4);
    memcpy(t_cat_X+4, X, size_X);

    if(tau <= 64)
            blake2b(digest,tau,t_cat_X,size_X+4);           // If tau <= 64, blake2b is enough

    else{                                                   // Otherwise, we use repeated evaluations of Blake2b

            uint32_t r = tau/32 + (tau%32 != 0) - 2;        //  Compute the required evaluations
            uint8_t V[64];

            blake2b(V,64,t_cat_X, size_X+4);                 //  Apply blake2b to tau||X to compute V_1
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

