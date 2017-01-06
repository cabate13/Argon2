// Blake2b implementation
//
//      C implementation of the blake2b multi-length hash function
//      and its round function.
//      
//      Credits to:  Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn, and Christian Winnerlein
//
//  Notation and function names are used accordingly to this independent IETF submission:
//  https://tools.ietf.org/html/rfc7693
//
//  Credits to: M-J. Saarinen, Ed.
//

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "blake2b.h"

// Constant definition

#define ww 64
#define r 12
#define bb 128
#define max_nn 64
#define mak_kk 64
#define R1 32
#define R2 24
#define R3 16
#define R4 63

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

// Functions prototypes

#define ERROR(msg) {puts((char*)msg); exit(1);}
#define ROT_SHIFT(array,offset) (((array) >> (offset)) ^ ((array) << (64 - (offset))))

// These should not be necessary, since this is a library
void B2B_G(uint64_t* work_vector, int a, int b, int c, int d, uint64_t x, uint64_t y);
void B2B_F(uint64_t* h, uint64_t* m, uint128_t t, int f );

// This should be included from blake2b.h
//void blake2b( void* digest, size_t nn, void* data, size_t ll, void* key, size_t kk);

// Utility function, XOR of two uint128_t*

void XOR(uint128_t* X, uint128_t* Y, uint128_t* xored, int n)
{

        for (int i = 0; i < n; i++)
        {
                (*(xored+i)).left = ((*(X+i)).left) ^ ((*(Y+i)).left);
                (*(xored+i)).right = ((*(X+i)).right) ^ ((*(Y+i)).right);
        }

}

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

// F [compression function]

void B2B_F(uint64_t* h, uint64_t* m, uint128_t t, int f ){
        // Initialize local work vectors
        uint64_t v[16];
        const size_t* s;
        memcpy(v,h,ww);
        memcpy(v+8,IV,ww);

        v[12] ^= t.left;
        v[13] ^= t.right;

        if(f)
                v[14] ^= 0xFFFFFFFFFFFFFFFF;

        // Mixing

        for(int i = 0; i < r;i++){

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
        for(int i = 0; i < 8; i++)
                h[i] = h[i] ^ v[i] ^ v[i+8];

}

// Initializes data and manages rounds

void blake2b( void* digest, size_t nn, void* data, size_t ll, void* key, size_t kk){

        // equivalent to ceil(ll/bb) + ceil(kk/bb)
        size_t dd = (ll/bb) + (ll%bb!=0) + (kk>0); 
        uint64_t h[8];
        uint128_t t;
        uint8_t buffer[bb];
        
        t.left = 0;
        t.right = 0;
        memcpy(h,IV,ww);
        h[0] = h[0] ^ 0x01010000 ^ (kk << 8) ^ nn;

        // Questa la lasciamo per ora, può essere utile in fase di sviluppo, poi gli errori dovrebbero
        // essere gestiti a monte quando si inizializza Argon2
        // Handle exceptions:
        if( nn<1 || nn > 64 || kk > 64 )
                ERROR("Parameters out of bounds.\n");
        if(ll>0 && data == NULL)
                ERROR("Missing data.\n");
        if(ll == 0){
                if(kk == 0){
                        puts("Warning: Unkeyed empty message.\n");
                        memset(buffer,0,bb);
                        t.left+=bb;
                        B2B_F(h,(uint64_t*)buffer,t,1);
                        memcpy(digest,h,nn);
                        return;
                }else
                        ERROR("Keyed empty message, unspecified behaviour.");

        }

        // Use the key, if any is given
        if(kk>0){
                memcpy(buffer,key,kk);          // Load key in buffer
                memset(buffer+kk,0,bb-kk);      // Pad key with zeros
                t.left+=bb;                       // Update data offset
                B2B_F(h,(uint64_t*)buffer,t,0);     // Apply compression
        }

        // Compress data, except last block
        for(size_t block_counter = 0;block_counter < dd-1; block_counter++){
                memcpy(buffer,data+bb*block_counter,bb);        // Load data block in buffer
                t.left+=bb;                                       // Update data offset
                if(t.left<bb)                                     // Manage carry
                        t.right++;                                 //
                B2B_F(h,(uint64_t*)buffer,t,0);                     // Apply compression
        }

        // Last block
        memcpy(buffer,data+ll/bb,ll%bb);        // Load last block in buffer
        memset(buffer+(ll%bb),0,bb-ll%bb);      // Pad with zeros
        t.left+=ll%bb;                            // Update data offset
        if(t.left<(ll%bb))                        // Manage carry
                t.right++;                         // 
        B2B_F(h,(uint64_t*)buffer,t,1);             // Apply compression

        // Output the required nn bytes
        memcpy(digest,h,nn);

}


