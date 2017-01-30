// Argon2 v1.3 : PHC release
//      
//      C implementation of the Argon2 memory hard function for password hashing and others applications
//           
//      Credits to:  Alex Biryukov, Daniel Dinu and Dimitry Khovratovich
//

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "Argon2_body.h"

const char* types[] = {"Argon2d","Argon2i","Argon2id","Argon2s"};

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
    args.tau = 32;
    args.m = 32;
    args.t = 3;
    args.v = 0x13; 
    args.size_K = 8;
    args.K = K;
    args.X = X;
    args.size_X = 12;

    // Fixed number of iterations: 3
    // Test for memory from 1 MiB to 4 GiB,
    // test for parallelism from 1 to 8 (doubling),
    // test for the four different types of Argon2

    uint32_t memory = 1024;

    for(int i = 0; i<13;i++){

        uint32_t parallelism = 1;

        for(int j = 0; j<4;j++){

                uint32_t type = 1;

                for(int k = 0; k<4; k++){

                        args.p = parallelism;
                        args.m = memory;
                        args.y = type/2;

                        clock_t begin = clock();
                        Argon2(&args,tag);
                        clock_t end = clock();
                        double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;

                        printf("%s, %u MiB, %u max threads: %lf seconds\n",types[k],memory/1024,parallelism,time_spent);

                        type *= 2;

                }

                parallelism *= 2;
                printf("\n");

        }

        memory *= 2;

    }

}

