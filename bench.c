/**
 * @file 
 * Benchmark for comparison with the official phc release of Argon2, it uses the same parameters used in the official phc implementation, in order to have a consistent test.
 */

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "Argon2_body.h"
/**
 * @def MEMORY_ROOF
 *      Defines the memory roof for benchmark, you should set it to 12 if you have less than 4 GiB of RAM
 *      Default value: 13
 */
#define MEMORY_ROOF 13

/// @var types
/// Used to store the names of Argon2 types for a nice formatted output
const char* types[] = {"Argon2d","Argon2i","Argon2id","Argon2ds"};

/**
 * @fn int main()
 * Performs the benchmark, in particular we use the same parameters used in the official benchmark:             \n
 * (°) Used memory: form 1 MiB up to 4 GiB;                                                                     \n
 * (°) Degree of parallelization: from 1 to 8;                                                                  \n
 * (°) All the four types of Argon2.                                                                            \n
 * @hidecallgraph
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
    args.tau = 32;
    args.m = 32;
    args.t = 3;
    args.v = 0x13; 
    args.size_K = 8;
    args.K = K;
    args.X = X;
    args.size_X = 12;

    uint32_t memory = 1024;

    for(int i = 0; i<MEMORY_ROOF;i++){

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

