/**
 * @file test.c
 * Test for the correctness of our implementation, runs a test for different parameters, considered critical:                                           \n
 * (°) Simple test with p = 4 and m = 32;                                                                                                               \n
 * (°) Test for p = 5 and m = 2601, so that p does not divide m, and the segment length is enough to require a second pseudo-random generation
 * in Argon2i;                                                                                                                                          \n
 * (°) Test for p = 4 and m = 65536, to test fairly large amounts of memory used;                                                                       \n
 * (°) A final test using 4 GiB of memory, in order to test the memory handling.                                                                        \n
 * Remark: there are no available test vectors for the Argon2ds type using version 1.9, since it has not been implemented.                              \n
 * The fixed parameters for the test are:                                                                                                               \n
 * Iterations: 3, Tag length: 32 bytes                                                                                                                  \n
 * Password[32]: 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01                                        \n
 * Salt[16]: 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02                                                                                            \n
 * Secret[8]: 03 03 03 03 03 03 03 03                                                                                                                   \n
 * Associated data[12]: 04 04 04 04 04 04 04 04 04 04 04 04                                                                                             \n
 */

#include <stdlib.h>
#include <stdio.h>
#include "Argon2_body.h"

/// @var A2i_tags
/// The results for the Argon2i tests, computed with the official version.
uint8_t A2i_tags[3][32] = {

    {0xc8, 0x14, 0xd9, 0xd1, 0xdc, 0x7f, 0x37, 0xaa, 0x13, 0xf0, 0xd7, 0x7f, 0x24, 0x94, 0xbd, 0xa1, 0xc8, 0xde, 0x6b, 0x01, 0x6d, 0xd3, 0x88, 0xd2, 0x99, 0x52, 0xa4, 0xc4, 0x67, 0x2b, 0x6c, 0xe8},
    {0xdc, 0x22, 0x95, 0xaf, 0x5f, 0x5e, 0x9e, 0xce, 0x87, 0x25, 0x1c, 0x42, 0x72, 0x35, 0xbc, 0x25, 0xfc, 0x9f, 0x60, 0x4a, 0xbd, 0x77, 0xdc, 0x4a, 0x70, 0x57, 0x60, 0xa2, 0x93, 0xfb, 0x4b, 0xed},
    {0x80, 0xf2, 0x82, 0x95, 0xc9, 0x74, 0xad, 0x00, 0x6d, 0x74, 0x97, 0x01, 0xdc, 0x38, 0xf1, 0x62, 0xb0, 0xee, 0x11, 0x8b, 0xd7, 0xb9, 0x07, 0x43, 0x37, 0x9e, 0xb7, 0xc0, 0x78, 0xce, 0x95, 0xdc}


};

/// @var A2d_tags
/// The results for the Argon2d tests, computed with the official version.
uint8_t A2d_tags[3][32] = {

    {0x51, 0x2b, 0x39, 0x1b, 0x6f, 0x11, 0x62, 0x97, 0x53, 0x71, 0xd3, 0x09, 0x19, 0x73, 0x42, 0x94, 0xf8, 0x68, 0xe3, 0xbe, 0x39, 0x84, 0xf3, 0xc1, 0xa1, 0x3a, 0x4d, 0xb9, 0xfa, 0xbe, 0x4a, 0xcb},
    {0xf3, 0x17, 0x84, 0x0d, 0x31, 0x43, 0xfe, 0xdb, 0x5c, 0x91, 0x6c, 0xc5, 0x90, 0x51, 0x66, 0x60, 0xf6, 0x83, 0x08, 0x46, 0x38, 0x32, 0xe6, 0x20, 0xc3, 0xb0, 0x1e, 0x57, 0x7e, 0x27, 0x6b, 0xdd},
    {0xba, 0x79, 0xe5, 0x47, 0x42, 0x5e, 0xb4, 0x7b, 0xd7, 0x7c, 0x22, 0x51, 0xd4, 0xdf, 0x02, 0x9c, 0x32, 0xc5, 0xc5, 0xf7, 0x76, 0x92, 0xc7, 0x84, 0xeb, 0xc1, 0x1b, 0x8f, 0xe7, 0x8a, 0xb5, 0x09}

};

/// @var A2id_tags
/// The results for the Argon2id tests, computed with the official version.
uint8_t A2id_tags[3][32] = {

    {0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53, 0xc9, 0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01, 0xe6, 0x59},
    {0xe8, 0x00, 0xa4, 0x0d, 0x4f, 0xde, 0x5b, 0x25, 0x53, 0x5e, 0x5c, 0xf7, 0x96, 0x05, 0xcc, 0x5c, 0x04, 0x3c, 0x4c, 0xc2, 0x69, 0x34, 0x2d, 0x80, 0x54, 0x07, 0x09, 0xd1, 0x74, 0xc1, 0xf9, 0xa5},
    {0x47, 0xa6, 0x77, 0xeb, 0xc6, 0x84, 0x12, 0xb8, 0xe1, 0x79, 0x49, 0xc9, 0x21, 0xfd, 0xca, 0x06, 0x53, 0x52, 0x11, 0x4f, 0xfb, 0x2a, 0x09, 0xee, 0xbe, 0x61, 0xad, 0xc4, 0x51, 0xee, 0xcf, 0x1e}

};

/// @var memory_test
/// The result for the test using 4 GiB of memory
uint8_t memory_test[32] = {0x1f, 0x92, 0x78, 0x12, 0xd1, 0x19, 0x30, 0x74, 0x2f, 0x9a, 0x54, 0x5b, 0x7a, 0xce, 0xaf, 0xc4, 0x64, 0xb8, 0x43, 0x9d, 0xb9, 0x06, 0x1b, 0x01, 0x28, 0x82, 0xeb, 0x87, 0xe8, 0xd9, 0x3a, 0xa9};

/** 
 * @fn int main()
 * Test main, initializes parametrs for the tests, launches them and prints the resulting Tag and whether the test has been successful.
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
    args.m = 32;
    args.t = 3;
    args.v = 0x13; 
    args.size_K = 8;
    args.K = K;
    args.X = X;
    args.size_X = 12;

    printf("===============================\n\n\n");
    printf("TEST: p = 4 & m = 32\n");
    printf("\n\n===============================\n\n");
    int test_counter = 0;

    args.y = 0;

    Argon2(&args, tag);
    printf("Argon2d test: \n");
    printf("tag: ");
    for(int i = 0;i < args.tau; i++)
            printf("%02X ", tag[i]);
    printf("\n");
    printf("kat: ");
    for(int i = 0;i < args.tau; i++)
        printf("%02X ", A2d_tags[test_counter][i]);
    if(!strncmp(A2d_tags[test_counter],tag,args.tau))
        printf("\nTest successful.");
    printf("\n\n===============================\n\n");

    args.y = 1;

    Argon2(&args, tag);
    printf("Argon2i test: \n");
    printf("tag: ");
    for(int i = 0;i < args.tau; i++)
            printf("%02X ", tag[i]);
    printf("\nkat: ");
    for(int i = 0;i < args.tau; i++)
        printf("%02X ", A2i_tags[test_counter][i]);
    if(!strncmp(A2i_tags[test_counter],tag,args.tau))
        printf("\nTest successful.");
    printf("\n\n===============================\n\n");

    args.y = 2;

    Argon2(&args, tag);
    printf("Argon2id test: \n");
    printf("tag: ");
    for(int i = 0;i < args.tau; i++)
        printf("%02X ", tag[i]);
    printf("\n");
    for(int i = 0;i < args.tau; i++)
        printf("%02X ", A2id_tags[test_counter][i]);
    if(!strncmp(A2id_tags[test_counter],tag,args.tau))
        printf("\nTest successful.");
    printf("\n\n===============================\n\n");

    args.y = 4;

    Argon2(&args, tag);
    printf("Argon2ds test: \n");
    printf("tag: ");
    for(int i = 0;i < args.tau; i++)
            printf("%02X ", tag[i]);
    printf("\n\n");

    //TEST p = 5 & m = 2601;
    printf("\n\n===============================\n\n\n");
    printf("TEST: p = 5 & m = 2601\n");
    printf("\n\n===============================\n\n");
    test_counter++;

    args.p = 5;
    args.m = 2601;
    
    args.y = 0;

    Argon2(&args, tag);
    printf("Argon2d test: \n");
    printf("tag: ");
    for(int i = 0;i < args.tau; i++)
            printf("%02X ", tag[i]);
    printf("\n");
    for(int i = 0;i < args.tau; i++)
        printf("%02X ", A2d_tags[test_counter][i]);
    if(!strncmp(A2d_tags[test_counter],tag,args.tau))
        printf("\nTest successful.");
    printf("\n\n===============================\n\n");

    args.y = 1;

    Argon2(&args, tag);
    printf("Argon2i test: \n");
    printf("tag: ");
    for(int i = 0;i < args.tau; i++)
            printf("%02X ", tag[i]);
    printf("\n");
    for(int i = 0;i < args.tau; i++)
        printf("%02X ", A2i_tags[test_counter][i]);
    if(!strncmp(A2i_tags[test_counter],tag,args.tau))
        printf("\nTest successful.");
    printf("\n\n===============================\n\n");

    args.y = 2;

    Argon2(&args, tag);
    printf("Argon2id test: \n");
    printf("tag: ");
    for(int i = 0;i < args.tau; i++)
            printf("%02X ", tag[i]);
    printf("\n");
    for(int i = 0;i < args.tau; i++)
        printf("%02X ", A2id_tags[test_counter][i]);
    if(!strncmp(A2id_tags[test_counter],tag,args.tau))
        printf("\nTest successful.");
    printf("\n\n===============================\n\n");

    args.y = 4;

    Argon2(&args, tag);
    printf("Argon2ds test: \n");
    printf("tag: ");
    for(int i = 0;i < args.tau; i++)
            printf("%02X ", tag[i]);
    printf("\n\n");

    //TEST p = 4 & m = 65536;

    printf("\n\n===============================\n\n\n");
    printf("TEST: p = 4 & m = 65536\n");
    printf("\n\n===============================\n\n");
    test_counter++;

    args.p = 4;
    args.m = 65536;

    args.y = 0;

    Argon2(&args, tag);
    printf("Argon2d test: \n");
    printf("tag: ");
    for(int i = 0;i < args.tau; i++)
            printf("%02X ", tag[i]);
    printf("\n");
    for(int i = 0;i < args.tau; i++)
        printf("%02X ", A2d_tags[test_counter][i]);
    if(!strncmp(A2d_tags[test_counter],tag,args.tau))
        printf("\nTest successful.");
    printf("\n\n===============================\n\n");

    args.y = 1;

    Argon2(&args, tag);
    printf("Argon2i test: \n");
    printf("tag: ");
    for(int i = 0;i < args.tau; i++)
            printf("%02X ", tag[i]);
    printf("\n");
    for(int i = 0;i < args.tau; i++)
        printf("%02X ", A2i_tags[test_counter][i]);
    if(!strncmp(A2i_tags[test_counter],tag,args.tau))
        printf("\nTest successful.");
    printf("\n\n===============================\n\n");

    args.y = 2;

    Argon2(&args, tag);
    printf("Argon2id test: \n");
    printf("tag: ");
    for(int i = 0;i < args.tau; i++)
            printf("%02X ", tag[i]);
        printf("\n");
    for(int i = 0;i < args.tau; i++)
        printf("%02X ", A2id_tags[test_counter][i]);
    if(!strncmp(A2id_tags[test_counter],tag,args.tau))
        printf("\nTest successful.");
    printf("\n\n===============================\n\n");

    args.y = 4;

    Argon2(&args, tag);
    printf("Argon2ds test: \n");
    printf("tag: ");
    for(int i = 0;i < args.tau; i++)
            printf("%02X ", tag[i]);
    printf("\n\n");
    

    printf("\n\n===============================\n\n");
    printf("TEST: p = 4 & m = 4 GiB\n");
    printf("\n\n===============================\n\n");

    args.m = 4096*1024;
    args.y = 1;

    Argon2(&args, tag);
    printf("Argon2i test: \n");
    printf("tag: ");
    for(int i = 0;i < args.tau; i++)
            printf("%02X ", tag[i]);
    printf("\nkat: ");
    for(int i = 0;i < args.tau; i++)
        printf("%02X ", memory_test[i]);
    if(!strncmp(memory_test,tag,args.tau))
        printf("\nTest successful.");
    printf("\n\n===============================\n\n");



}

