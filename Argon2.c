#include "Argon2_body.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define TEST_FOR_MEMORY_LEAKS 0

/*
Memory: 32 KiB, Iterations: 3, Parallelism: 4 lanes, Tag length: 32 bytes
Password[32]: 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 
Salt[16]: 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 
Secret[8]: 03 03 03 03 03 03 03 03 
Associated data[12]: 04 04 04 04 04 04 04 04 04 04 04 04 
*/

int main(){

        for(int i = 0;i<=100*TEST_FOR_MEMORY_LEAKS;i++){

        Argon2_arguments args;
        uint8_t P[32];
        uint8_t S[16];
        uint8_t K[8];
        uint8_t X[12];
        uint8_t tag[32];

        /*
        Argon2d test --- version 1.3

        Memory: 32 KiB, Iterations: 3, Parallelism: 4 lanes, Tag length: 32 bytes
        Password[32]: 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 
        Salt[16]: 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 
        Secret[8]: 03 03 03 03 03 03 03 03 
        Associated data[12]: 04 04 04 04 04 04 04 04 04 04 04 04 
        */
        memset(P,0x01,32);        
        memset(S,0x02,16);
        memset(K,0x03,8);
        memset(X,0x04,12);
        args.P = P;
        args.size_P = 32;
        args.S = S;
        args.size_S = 16;
        args.p = 4;
        args.tau = 32;
        args.m = 32; // 32 KiB
        args.t = 3;
        args.v = 0x13; 
        args.size_K = 8;
        args.K = K;
        args.X = X;
        args.size_X = 12;
        args.y = 0;

        Argon2(&args, tag);
        printf("Argon2d test: \n");
        printf("tag: ");
        for(int i = 0;i < args.tau; i++)
                printf("%02X ", tag[i]);
        printf("\n\n===============================\n\n");

        /*
        Argon2i test --- version 1.3

        Memory: 32 KiB, Iterations: 3, Parallelism: 4 lanes, Tag length: 32 bytes
        Password[32]: 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 
        Salt[16]: 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 
        Secret[8]: 03 03 03 03 03 03 03 03 
        Associated data[12]: 04 04 04 04 04 04 04 04 04 04 04 04 
        */

        args.y = 1;

        Argon2(&args, tag);
        printf("Argon2i test: \n");
        printf("tag: ");
        for(int i = 0;i < args.tau; i++)
                printf("%02X ", tag[i]);
        printf("\n\n===============================\n\n");

        /*
        Argon2id test --- version 1.3

        Memory: 32 KiB, Iterations: 3, Parallelism: 4 lanes, Tag length: 32 bytes
        Password[32]: 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 
        Salt[16]: 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 
        Secret[8]: 03 03 03 03 03 03 03 03 
        Associated data[12]: 04 04 04 04 04 04 04 04 04 04 04 04        
        */

        args.y = 2;

        Argon2(&args, tag);
        printf("Argon2id test: \n");
        printf("tag: ");
        for(int i = 0;i < args.tau; i++)
                printf("%02X ", tag[i]);
        printf("\n\n");

        }

}