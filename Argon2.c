#include <stdlib.h>
#include <stdio.h>

#include "Argon2_body.h"

#define TEST 0
#define TEST_FOR_MEMORY_LEAKS 0

// definitions for input sanitizations
#define NO_INPUT_GIVEN 1
#define MALFORMATED_INPUT 2
#define MISSING_PARAMETER 3
#define NON_VALID_INPUT_FILE 4
#define GENERATE_TEMPLATE 5
#define SUCCESS 0

// definitions for input consistency
#define PARAMETER_OUT_OF_BOUNDS 1
#define ILLEGAL_PAIR_P_M 2
#define ILLEGAL_TYPE 3

// Show purposes
#define PRINT_ARG_S {printf("Password: ");for(int i = 0;i<args.size_P;i++)printf("%c",args.P[i]);printf("\n");\
                     printf("Salt: ");for(int i = 0;i<args.size_S;i++)printf("%c",args.S[i]);printf("\n");\
                     printf("Secret: ");for(int i = 0;i<args.size_K;i++)printf("%c",args.K[i]);printf("\n");\
                     printf("Associated data: ");for(int i = 0;i<args.size_X;i++)printf("%c",args.X[i]);printf("\n");\
                     printf("tau: %u, p: %u, m: %u, t: %u, y: %u\n",args.tau, args.p, args.m, args.t, args.y);}

// Might set the man for argon2

const char* man = 
"*** Argon2 usage: ***\n\nInput from command line: [-K is the only optional argument]\n  ./Argon2 --C \n  -P <password>\n  -S <salt>\n  -X <associated data>\n  -p <parallelization degree>\n  -m <memory usage>\n  -t <total passes>\n  -v <type of Argon2>\n  -l <tag size>\n  [-K <secret size>]\n\nInput mode from file: [generate a template with ./Argon2 --T]\n  ./Argon2 --F <filename>\n\n";

/* *** Input sanitization ***
 * - Required input:
 *  (°) Password P and its size         (check_input_received[0-1])
 *  (°) Salt S and its size             (check_input_received[2-3])
 *  (°) Secret K and its size           (check_input_received[11-12])
 *  (°) Associated data X and its size  (check_input_received[4-5])
 *  (°) Tag size                        (check_input_received[10])
 *  (°) Degreee of parallelization      (check_input_received[6])
 *  (°) Total memory usage              (check_input_received[7])
 *  (°) Total passes                    (check_input_received[8])
 *  (°) version byte (?)                
 *  (°) type [0,1,2,4]                  (check_input_received[9])
 *
 * - Input formats:
 *  (°) --C : command line input
 *  (°) --F : file input
 *
 * - Mode 1: command line input:
 *  (°) --C
 *  (°) -P <password>
 *  (°) -S <salt>
 *  (°) [-K <secret>]
 *  (°) -X <associated data>
 *  (°) -p <degree of parallelization>
 *  (°) -m <total memory usage in KiB>
 *  (°) -t <total passes>
 *  (°) -v <type of Argon2>
 *  (°) -l <tag size>
 *
 * - Mode 2: file iput:
 *  (°) --F <filename>
 *  
 * - File format:
 *  (°) P_size: <password size>
 *  (°) P: <password>
 *  (°) S_size: <size of salt>
 *  (°) S: <salt>
 *  (°) K_size: <size of secret data>  // optional
 *  (°) K: <secret data>               // optional
 *  (°) X_size: <size of associated data>
 *  (°) X: <associated data>
 *  (°) p: <degree of parallelization>
 *  (°) m: <total memory usage in KiB>
 *  (°) t: <total passes>
 *  (°) v: <type of Argon2>
 *  (°) tau: <tag size>
 */

int sanitize_input(int argc, char* argv[], Argon2_arguments* args){

        // Check for the received arguments: order defined above
        uint8_t check_input_received[13];
        memset(check_input_received,0,13);

        // Check if any input is given
        if(argc == 1)
                return NO_INPUT_GIVEN;
        if((strlen(argv[1])!=3) || (argv[1][0]!='-') || (argv[1][1]!='-'))
                return MALFORMATED_INPUT;

        // Pick up the input mode flag
        switch (argv[1][2]){
        case 'C':{

                int i = 2;
                while(i<argc-1){

                        if((strlen(argv[i])!=2) || (argv[i][0]!='-'))
                                return MALFORMATED_INPUT;

                        switch(argv[i][1]){
                        case 'P':{
                                if(check_input_received[0])
                                        return MALFORMATED_INPUT;
                                args->P = argv[i+1];
                                args->size_P = strlen(argv[i+1]);
                                check_input_received[0] = 1;
                                check_input_received[1] = 1;
                        }break;
                        case 'S':{
                                if(check_input_received[2])
                                        return MALFORMATED_INPUT;                                
                                args->S = argv[i+1];
                                args->size_S = strlen(argv[i+1]);
                                check_input_received[2] = 1;
                                check_input_received[3] = 1;
                        }break;
                        case 'K':{
                                if(check_input_received[11])
                                        return MALFORMATED_INPUT;
                                args->K = argv[i+1];
                                args->size_K = strlen(argv[i+1]);
                                check_input_received[11] = 1;
                                check_input_received[12] = 1;
                        }break;
                        case 'X':{
                                if(check_input_received[4])
                                        return MALFORMATED_INPUT;
                                args->X = argv[i+1];
                                args->size_X = strlen(argv[i+1]);
                                check_input_received[4] = 1;
                                check_input_received[5] = 1;
                        }break;
                        case 'p':{
                                if(sscanf(argv[i+1],"%u",&(args->p))!=1 || check_input_received[6])
                                        return MALFORMATED_INPUT;
                                check_input_received[6]=1;
                        }break;
                        case 'm':{
                                if(sscanf(argv[i+1],"%llu",&(args->m))!=1 || check_input_received[7])
                                        return MALFORMATED_INPUT;
                                check_input_received[7]=1;
                        }break;
                        case 't':{
                                if(sscanf(argv[i+1],"%u",&(args->t))!=1 || check_input_received[8])
                                        return MALFORMATED_INPUT;
                                check_input_received[8]=1;
                        }break;
                        case 'v':{
                                if(sscanf(argv[i+1],"%u",&(args->y))!=1 || check_input_received[9])
                                        return MALFORMATED_INPUT;
                                check_input_received[9]=1;
                        }break;
                        case 'l':{
                                if(sscanf(argv[i+1],"%u",&(args->tau))!=1 || check_input_received[10])
                                        return MALFORMATED_INPUT;
                                check_input_received[10]=1;
                        }break;
                        default:
                                return MALFORMATED_INPUT;
                                break;

                        }
                        i+=2;
                }

                // Check if all arguments have been given:
                for(int i = 0; i < 11; i++){

                        if(!check_input_received[i])
                                return MISSING_PARAMETER;

                }
                if(!check_input_received[11] && !check_input_received[12]){

                        args->K = NULL;
                        args->size_K = 0;

                }



        }break; 
        case 'F':
                {

                        FILE* input_file;
                        input_file = fopen(argv[2],"r");
                        if(input_file == NULL)
                                return NON_VALID_INPUT_FILE;

                        printf("Read from file, TBI\n");
                        exit(0);

                }
                break; 
        case 'T':
                {
                printf("Not implemented yet.\n");
                return GENERATE_TEMPLATE;
                }break;
        default:
                return MALFORMATED_INPUT;
                break;
        }
                
        return SUCCESS;

}

int check_consistency(Argon2_arguments* args){

        if(args->size_S<8 || args->p > 0xFFFFFF || args->tau<4 )
                return PARAMETER_OUT_OF_BOUNDS;
        if(args->m < args->p*8)
                return ILLEGAL_PAIR_P_M;
        if(!((args->y == 0) || (args->y == 1) || (args->y == 2))) // When argon2ds is implemented, add args->y == 4
                return ILLEGAL_TYPE;
        return SUCCESS;
}

/*
Memory: 32 KiB, Iterations: 3, Parallelism: 4 lanes, Tag length: 32 bytes
Password[32]: 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 
Salt[16]: 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 
Secret[8]: 03 03 03 03 03 03 03 03 
Associated data[12]: 04 04 04 04 04 04 04 04 04 04 04 04 
*/

int main(int argc, char* argv[]){

        if(TEST){

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

        }else{

                Argon2_arguments args;
                
                int sanitization = sanitize_input(argc,argv,&args);

                switch(sanitization){
                        case NO_INPUT_GIVEN:
                                printf("%s",man);
                                break;
                        case MALFORMATED_INPUT:
                                printf("Error: Malformated input given.\n",man);
                                break;
                        case MISSING_PARAMETER:
                                printf("Error: Missing parameters.\n"); 
                                break;
                        case NON_VALID_INPUT_FILE:
                                printf("Error: Input file %s not found.\n", argv[2]);
                                break;

                        case GENERATE_TEMPLATE:
                                return 0;
                                break;
                        case SUCCESS:{

                                int consistency = check_consistency(&args);
                                sanitization+=consistency;
                                switch(consistency){

                                        case PARAMETER_OUT_OF_BOUNDS:
                                                printf("Error: parameters out of bounds.\n");
                                                break;
                                        case ILLEGAL_PAIR_P_M:
                                                printf("Error: Illegal pair (p,m). It must be 8*p < m < 2^32.\n");
                                                break;
                                        case ILLEGAL_TYPE:
                                                printf("Error: Undefined type for Argon2. Valid types:\nArgon2d:  0\nArgon2i:  1\nArgon2id: 2\n");
                                                break;
                                        case SUCCESS:{

                                                uint8_t* tag;
                                                tag = (uint8_t*)malloc(args.tau);
                                                Argon2(&args,tag);
                                                printf("Tag: 0x");
                                                for(int  i = 0;i<args.tau;i++)
                                                        printf("%02X",tag[i]);
                                                printf("\n");

                                                }
                                                break;
                                }

                        }
                }

                return (sanitization!= 0);
        }

}