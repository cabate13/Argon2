#include "Argon2_body.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

int main(){

        Argon2_arguments args;

        uint8_t P[32];
        memset(P,0x01,32);
        uint8_t S[16];
        memset(S,0x02,16);
        uint8_t K[8];
        memset(K,0x03,8);
        uint8_t X[12];
        memset(X,0x04,12);
        uint8_t tag[32];

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

        printf("tag: ");
        for(int i = 0;i < 16;i++)
                printf("%02X ", tag[i]);
        printf("\n");


}