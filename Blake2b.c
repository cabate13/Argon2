/**
* @file
* Ad hoc version of Blake2b 
*/

#include "Blake2b.h"

// Constants definition

//! @def length of a word
#define WORD_LENGTH 64  
//! @def number of rounds required     
#define ROUNDS_NUMER 12   
//! @def length of a block         
#define BLOCK_LENGTH 128 
//! @def dimension of the workspace     
#define WORKSPACE_LENGTH 8  

//! @def a type of a rotational shift
#define R1 32 
//! @def a type of a rotational shift    
#define R2 24
//! @def a type of a rotational shift
#define R3 16
//! @def a type of a rotational shift
#define R4 63

//! @var 
static const size_t SIGMA[12][16] = {
   { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
   { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
   { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
   { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
   { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
   { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
   { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
   { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
   { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
   { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
   { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
   { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
};

static const uint64_t IV[8] = { 
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
};

// B2B_G [mixing function]

void B2B_G(uint64_t* v, int a, int b, int c, int d, uint64_t x, uint64_t y){

    v[a] = v[a] + v[b] + x;
    v[d] = ROT_SHIFT((v[d]^v[a]) , R1);
    v[c] = v[c] + v[d];
    v[b] = ROT_SHIFT((v[b]^v[c]) , R2);
    v[a] = v[a] + v[b] + y;
    v[d] = ROT_SHIFT((v[d]^v[a]) , R3);
    v[c] = v[c] + v[d];
    v[b] = ROT_SHIFT((v[b]^v[c]) , R4);
}

/*
 * Main compression function of Blake2b, takes as input a workspace uint64_t h[8],
 * a data buffer uint64_t m[16], a 128-bit precision counter and a flag to differentiate
 * the last data block.
 */

void B2B_F(uint64_t* h, uint64_t* m, uint64_t* t, int f ){

    // Initialize local work vectors
    uint64_t v[2*WORKSPACE_LENGTH];
    const size_t* s;
    memcpy(v,h,WORD_LENGTH);
    memcpy(v+WORKSPACE_LENGTH,IV,WORD_LENGTH);

    v[12] ^= t[0];
    v[13] ^= t[1];

    if(f)
            v[14] = ~v[14];

    // Mixing procedure
    for(int i = 0; i < ROUNDS_NUMER;i++){

        B2B_G( v, 0, 4,  8, 12, m[SIGMA[i][ 0]], m[SIGMA[i][ 1]] );
        B2B_G( v, 1, 5,  9, 13, m[SIGMA[i][ 2]], m[SIGMA[i][ 3]] );
        B2B_G( v, 2, 6, 10, 14, m[SIGMA[i][ 4]], m[SIGMA[i][ 5]] );
        B2B_G( v, 3, 7, 11, 15, m[SIGMA[i][ 6]], m[SIGMA[i][ 7]] );
        B2B_G( v, 0, 5, 10, 15, m[SIGMA[i][ 8]], m[SIGMA[i][ 9]] );
        B2B_G( v, 1, 6, 11, 12, m[SIGMA[i][10]], m[SIGMA[i][11]] );
        B2B_G( v, 2, 7,  8, 13, m[SIGMA[i][12]], m[SIGMA[i][13]] );
        B2B_G( v, 3, 4,  9, 14, m[SIGMA[i][14]], m[SIGMA[i][15]] );

    }

    // Write the result
    for(int i = 0; i < WORKSPACE_LENGTH; i++)
        h[i] = h[i] ^ v[i] ^ v[i+WORKSPACE_LENGTH];

}

/*
 * Blake2b hash function. Takes an uint8_t data[data_size] and outputs an uint8_t digest[digest_size] 
 */
void blake2b( uint8_t* digest, size_t digest_size, uint8_t* data, uint64_t data_size){

    // equivalent to ceil(data_size/BLOCK_LENGTH) + ceil(kk/BLOCK_LENGTH)
    size_t dd = (data_size/BLOCK_LENGTH) + (data_size%BLOCK_LENGTH!=0); 
    uint64_t h[WORKSPACE_LENGTH];
    uint64_t t[2];
    uint8_t buffer[BLOCK_LENGTH];
    
    t[0] = 0;
    t[1] = 0;
    memcpy(h,IV,WORD_LENGTH);
    h[0] = h[0] ^ 0x01010000 ^ digest_size;

    for(size_t block_counter = 0;block_counter < dd-1; block_counter++){                // Compress data, except last block:
            memcpy(buffer,data+BLOCK_LENGTH*block_counter,BLOCK_LENGTH);                // Load data block in buffer
            t[0]+=BLOCK_LENGTH;                                                         // Update data offset
            if(t[0]<BLOCK_LENGTH)                                                       // Manage carry
                    t[1]++;                                                 
            B2B_F(h,(uint64_t*)buffer,t,0);                                             // Apply compression
    }
                                                                                        // Compress last block:
    memcpy(buffer,data+(data_size/BLOCK_LENGTH)*BLOCK_LENGTH,data_size%BLOCK_LENGTH);   //  Load last block in buffer
    memset(buffer+(data_size%BLOCK_LENGTH),0,BLOCK_LENGTH-data_size%BLOCK_LENGTH);      //  Pad with zeros
    t[0]+=(data_size % BLOCK_LENGTH == 0) ? BLOCK_LENGTH : data_size%BLOCK_LENGTH;      //  Update data offset
    if(t[0]<(data_size%BLOCK_LENGTH))                                                   //  Manage carry
            t[1]++;  
    B2B_F(h,(uint64_t*)buffer,t,1);                                                     //  Apply compression 

    memcpy(digest,h,digest_size);                                                 // Output the required digest_size bytes

}


