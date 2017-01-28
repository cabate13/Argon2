// Argon2 v1.3 : PHC release
//      
//      C implementation of the Argon2 memory hard function for password hashing and others applications
//           
//      Credits to:  Alex Biryukov, Daniel Dinu and Dimitry Khovratovich
//

#include <stdlib.h>
#include <stdio.h>
#include "Argon2_body.h"

// definitions for input sanitizations
#define NO_INPUT_GIVEN 1
#define MALFORMED_INPUT 2
#define MISSING_PARAMETER 3
#define NON_VALID_INPUT_FILE 4
#define MALFORMED_INPUT_FILE 5
#define GENERATE_TEMPLATE 6
#define UNABLE_TO_WRITE_TEMPLATE 7
#define SUCCESS 0

/*
 * Test main, runs the four types of argon2 with the following inputs:
 *
 * Memory: 32 KiB, Iterations: 3, Parallelism: 4 lanes, Tag length: 32 bytes
 * Password[32]: 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 
 * Salt[16]: 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 
 * Secret[8]: 03 03 03 03 03 03 03 03 
 * Associated data[12]: 04 04 04 04 04 04 04 04 04 04 04 04 
 * 
 * and prints the resulting Tag
 */

int main(){

    Argon2_arguments args;
    uint8_t P[32];
    uint8_t S[16];
    uint8_t K[8];
    uint8_t X[12];
    uint8_t tag[32];

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

    args.m = 64;
    args.p = 5;

    Argon2(&args, tag);
    printf("Argon2d test: \n");
    printf("tag: ");
    for(int i = 0;i < args.tau; i++)
            printf("%02X ", tag[i]);
    printf("\n\n===============================\n\n");

    args.y = 1;

    Argon2(&args, tag);
    printf("Argon2i test: \n");
    printf("tag: ");
    for(int i = 0;i < args.tau; i++)
            printf("%02X ", tag[i]);
    printf("\n\n===============================\n\n");

    args.y = 2;

    Argon2(&args, tag);
    printf("Argon2id test: \n");
    printf("tag: ");
    for(int i = 0;i < args.tau; i++)
            printf("%02X ", tag[i]);
    printf("\n\n===============================\n\n");

    args.y = 4;

    Argon2(&args, tag);
    printf("Argon2ds test: \n");
    printf("tag: ");
    for(int i = 0;i < args.tau; i++)
            printf("%02X ", tag[i]);
    printf("\n\n");

  /*
    //Samuele TEST p = 5 & m = 2600;

    args.y = 0;

    printf("\n\n===============================\n\n");
    printf("\n \n \n");
    printf("TEST con p=5 & m = 2600\n");
    printf("\n\n===============================\n\n");
    
    args.p = 5;
    args.m = 2600;

    Argon2(&args, tag);
    printf("Argon2d test: \n");
    printf("tag: ");
    for(int i = 0;i < args.tau; i++)
            printf("%02X ", tag[i]);
    printf("\n\n===============================\n\n");

    args.y = 1;

    Argon2(&args, tag);
    printf("Argon2i test: \n");
    printf("tag: ");
    for(int i = 0;i < args.tau; i++)
            printf("%02X ", tag[i]);
    printf("\n\n===============================\n\n");

    args.y = 2;

    Argon2(&args, tag);
    printf("Argon2id test: \n");
    printf("tag: ");
    for(int i = 0;i < args.tau; i++)
            printf("%02X ", tag[i]);
    printf("\n\n===============================\n\n");

    args.y = 4;

    Argon2(&args, tag);
    printf("Argon2ds test: \n");
    printf("tag: ");
    for(int i = 0;i < args.tau; i++)
            printf("%02X ", tag[i]);
    printf("\n\n");

    //Samuele TEST p = 4 & m = 65536;

    args.y = 0;

    printf("\n\n===============================\n\n");
    printf("\n \n \n");
    printf("TEST con p=4 & m = 65536\n");
    printf("\n\n===============================\n\n");
    
    args.p = 4;
    args.m = 65536;

    Argon2(&args, tag);
    printf("Argon2d test: \n");
    printf("tag: ");
    for(int i = 0;i < args.tau; i++)
            printf("%02X ", tag[i]);
    printf("\n\n===============================\n\n");

    args.y = 1;

    Argon2(&args, tag);
    printf("Argon2i test: \n");
    printf("tag: ");
    for(int i = 0;i < args.tau; i++)
            printf("%02X ", tag[i]);
    printf("\n\n===============================\n\n");

    args.y = 2;

    Argon2(&args, tag);
    printf("Argon2id test: \n");
    printf("tag: ");
    for(int i = 0;i < args.tau; i++)
            printf("%02X ", tag[i]);
    printf("\n\n===============================\n\n");

    args.y = 4;

    Argon2(&args, tag);
    printf("Argon2ds test: \n");
    printf("tag: ");
    for(int i = 0;i < args.tau; i++)
            printf("%02X ", tag[i]);
    printf("\n\n");
*/
}

