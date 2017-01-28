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
#if defined TEST

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

        return 0;

}

#else

/* 
 * Actual implementation of Argon2 v1.3, wrapped in a main that handles input and correctly initializes arguments [hopefully]
 *
 * - Required input:
 *  (°) Password P and its size         (check_input_received[0-1])
 *  (°) Salt S and its size             (check_input_received[2-3])
 *  (°) Secret K and its size           (check_input_received[11-12])
 *  (°) Associated data X and its size  (check_input_received[4-5])
 *  (°) Tag size                        (check_input_received[10])
 *  (°) Degreee of parallelization      (check_input_received[6])
 *  (°) Total memory usage              (check_input_received[7])
 *  (°) Total passes                    (check_input_received[8])               
 *  (°) type [0,1,2,4]                  (check_input_received[9])
 *
 * - Input formats:
 *  (°) --C : command line input
 *  (°) --F : config file input -> more realistic use for password hashing, password and associatd data (exa. username, ..) defined at
 *            runtime, while other parameters are set in the database configuration.
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
 * - Mode 2: config file input:
 *  (°) --F <filename> -P <password> -X <associated data>
 *  
 * - File format:
 *  (°) S_size: <size of salt>
 *  (°) S: <salt>
 *  (°) K_size: <size of secret data>  // optional
 *  (°) K: <secret data>               // optional
 *  (°) p: <degree of parallelization>
 *  (°) m: <total memory usage in KiB>
 *  (°) t: <total passes>
 *  (°) v: <type of Argon2>
 *  (°) tau: <tag size>
 */

// Prints the arguments passed to Argon2
#define PRINT_ARG_S {printf("Password: ");for(int i = 0;i<args.size_P;i++)printf("%c",args.P[i]);printf("\n");\
                     printf("Salt: ");for(int i = 0;i<args.size_S;i++)printf("%c",args.S[i]);printf("\n");\
                     printf("Secret: ");for(int i = 0;i<args.size_K;i++)printf("%c",args.K[i]);printf("\n");\
                     printf("Associated data: ");for(int i = 0;i<args.size_X;i++)printf("%c",args.X[i]);printf("\n");\
                     printf("tau: %u, p: %u, m: %u, t: %u, y: %u\n",args.tau, args.p, args.m, args.t, args.y);}
const char* man = 
"*** Argon2 usage: ***\n\nInput from command line: [-K is the only optional argument]\n  ./Argon2 --C \n  -P <password>\n  -S <salt>\n  -X <associated data>\n  -p <parallelization degree>\n  -m <memory usage>\n  -t <total passes>\n  -v <type of Argon2>\n  -l <tag size>\n  [-K <secret>]\n\nInput from file: [generate a template with ./Argon2 --T]\n  ./Argon2 --F <filename> -P <password> -X <associated data>\n\n";
const char* template = 
"# This is a template for the Argon2 input file. Lines starting with # will be ignored\nS_size: <size of salt>\nS: <salt>\nK_size: <size of secret data>\nK: <secret data>\np: <degree of parallelization>\nm: <total memory usage in KiB>\nt: <total passes>\nv: <type of Argon2>\ntau: <tag size>";

// File input sanitization
int file_input_sanitization(int argc, char* argv[], Argon2_arguments* args, uint8_t* check_input_received){

        // Gets password and associated data from command line
        int i = 3;
        while(i<argc-1){
                if((strlen(argv[i])!=2) || (argv[i][0]!='-'))
                        return MALFORMED_INPUT;

                switch(argv[i][1]){
                        case 'P':{
                                if(check_input_received[0])
                                        return MALFORMED_INPUT;
                                args->P = argv[i+1];
                                args->size_P = strlen(argv[i+1]);
                                check_input_received[0] = 1;
                                check_input_received[1] = 1;
                        }break;
                        case 'X':{
                                if(check_input_received[4])
                                        return MALFORMED_INPUT;
                                args->X = argv[i+1];
                                args->size_X = strlen(argv[i+1]);
                                check_input_received[4] = 1;
                                check_input_received[5] = 1;
                        }break;
                        default:
                                return MALFORMED_INPUT;
                                break;

                }
                i+=2;

        }

        // Gets remaining arguments from input file

        FILE* input_file;
        input_file = fopen(argv[2],"r");
        if(input_file == NULL)
                return NON_VALID_INPUT_FILE;

        char buffer[1024];
        char* data_buffer;
        while(fgets(buffer,sizeof(buffer),input_file) != NULL){

                if(buffer[strlen(buffer)-1]!='\n')
                        return MALFORMED_INPUT_FILE;

                switch(buffer[0]){
                        case '#': 
                                break;
                        case 'S':{
                                if((sscanf(buffer,"S_size: %u",&(args->size_S))!=1) || check_input_received[2])
                                        return MALFORMED_INPUT_FILE; 
                                data_buffer = (uint8_t*)malloc(args->size_S+5); // One for the '\n' and one '\0'

                                if((fgets(data_buffer,args->size_S+5,input_file) == NULL) || (data_buffer[args->size_S+3] != '\n'))
                                        return MALFORMED_INPUT_FILE;
                                args->S = (uint8_t*)malloc(args->size_S);  // to free in the end!
                                memcpy(args->S,data_buffer+3,args->size_S);
                                check_input_received[2] =1;
                                check_input_received[3] =1;
                                free(data_buffer);
                        }break;
                        case 'K':{
                                if((sscanf(buffer,"K_size: %u",&(args->size_K))!=1)|| check_input_received[11])
                                        return MALFORMED_INPUT_FILE; 
                                data_buffer = (uint8_t*)malloc(args->size_K+5); // One for the '\n' and one '\0' and three for K: 

                                if((fgets(data_buffer,args->size_K+5,input_file) == NULL) || (data_buffer[args->size_K+3] != '\n'))
                                        return MALFORMED_INPUT_FILE;
                                args->K = (uint8_t*)malloc(args->size_K);  // to free in the end!
                                memcpy(args->K,data_buffer+3,args->size_K);
                                check_input_received[11] =1;
                                check_input_received[12] =1;
                                free(data_buffer);
                        }break;
                        case 'p':{
                                if((sscanf(buffer, "p: %u",&args->p) != 1)|| check_input_received[6])
                                        return MALFORMED_INPUT_FILE;
                                check_input_received[6] =1;
                        }break;
                        case 'm':{
                                if((sscanf(buffer, "m: %u",&args->m) != 1)|| check_input_received[7])
                                        return MALFORMED_INPUT_FILE;
                                check_input_received[7] =1;
                        }break;
                        case 't':{
                                if((sscanf(buffer, "t: %u",&args->t) != 1)|| check_input_received[8]){
                                        if((sscanf(buffer, "tau: %u",&args->tau) != 1)|| check_input_received[10])
                                                return MALFORMED_INPUT_FILE;
                                        check_input_received[10] =1;
                                        
                                }else
                                        check_input_received[8] =1;
                        }break;
                        case 'v':{
                                if((sscanf(buffer, "v: %u",&args->y) != 1)|| check_input_received[9])
                                        return MALFORMED_INPUT_FILE;
                                check_input_received[9] =1;
                        }break;

                }                        
                
        }

        for(int i = 0; i < 11; i++){

                if(!check_input_received[i]){
                        if(check_input_received[3])
                                free(args->S);
                        if(check_input_received[12])
                                free(args->K);
                        return MISSING_PARAMETER;
                }

        }

        if(!check_input_received[11] && !check_input_received[12])
                args->size_K = 0;

        return SUCCESS;

}

// Command line input sanitization
int command_line_input_sanitization(int argc, char* argv[], Argon2_arguments* args, uint8_t* check_input_received){

        int i = 2;
        while(i<argc-1){

                if((strlen(argv[i])!=2) || (argv[i][0]!='-'))
                        return MALFORMED_INPUT;

                switch(argv[i][1]){
                        case 'P':{
                                if(check_input_received[0])
                                        return MALFORMED_INPUT;
                                args->P = argv[i+1];
                                args->size_P = strlen(argv[i+1]);
                                check_input_received[0] = 1;
                                check_input_received[1] = 1;
                        }break;
                        case 'S':{
                                if(check_input_received[2])
                                        return MALFORMED_INPUT;                                
                                args->S = argv[i+1];
                                args->size_S = strlen(argv[i+1]);
                                check_input_received[2] = 1;
                                check_input_received[3] = 1;
                        }break;
                        case 'K':{
                                if(check_input_received[11])
                                        return MALFORMED_INPUT;
                                args->K = argv[i+1];
                                args->size_K = strlen(argv[i+1]);
                                check_input_received[11] = 1;
                                check_input_received[12] = 1;
                        }break;
                        case 'X':{
                                if(check_input_received[4])
                                        return MALFORMED_INPUT;
                                args->X = argv[i+1];
                                args->size_X = strlen(argv[i+1]);
                                check_input_received[4] = 1;
                                check_input_received[5] = 1;
                        }break;
                        case 'p':{
                                if(sscanf(argv[i+1],"%u",&(args->p))!=1 || check_input_received[6])
                                        return MALFORMED_INPUT;
                                check_input_received[6]=1;
                        }break;
                        case 'm':{
                                if(sscanf(argv[i+1],"%llu",&(args->m))!=1 || check_input_received[7])
                                        return MALFORMED_INPUT;
                                check_input_received[7]=1;
                        }break;
                        case 't':{
                                if(sscanf(argv[i+1],"%u",&(args->t))!=1 || check_input_received[8])
                                        return MALFORMED_INPUT;
                                check_input_received[8]=1;
                        }break;
                        case 'v':{
                                if(sscanf(argv[i+1],"%u",&(args->y))!=1 || check_input_received[9])
                                        return MALFORMED_INPUT;
                                check_input_received[9]=1;
                        }break;
                        case 'l':{
                                if(sscanf(argv[i+1],"%u",&(args->tau))!=1 || check_input_received[10])
                                        return MALFORMED_INPUT;
                                check_input_received[10]=1;
                        }break;
                        default:
                                return MALFORMED_INPUT;
                                break;

                }
                i+=2;
        }

        // Check if all arguments have been given:
        for(int i = 0; i < 11; i++){
                if(!check_input_received[i])
                        return MISSING_PARAMETER;

        }

        if(!check_input_received[11] && !check_input_received[12])
                args->size_K = 0;

        return SUCCESS;

}

// Checks the type of input provided (command line v.s. file) and calls the appropriate handler
int sanitize_input(int argc, char* argv[], Argon2_arguments* args){

        // Check for the received arguments: order defined above
        uint8_t check_input_received[13];
        memset(check_input_received,0,13);

        // Check if any input is given
        if(argc == 1)
                return NO_INPUT_GIVEN;
        if((strlen(argv[1])!=3) || (argv[1][0]!='-') || (argv[1][1]!='-'))
                return MALFORMED_INPUT;

        // Pick up the input mode flag
        switch (argv[1][2]){
        case 'C':{

                return command_line_input_sanitization(argc, argv, args, check_input_received);

        }break; 
        case 'F':{

                return file_input_sanitization(argc, argv, args, check_input_received);

        }break; 
        case 'T':{
                FILE* template_file = fopen("Argon2_template.txt","w");
                if(template_file == NULL)
                        return UNABLE_TO_WRITE_TEMPLATE;
                fprintf(template_file,"%s",template);
                return GENERATE_TEMPLATE;
        }break;
        default:
                return MALFORMED_INPUT;
                break;
        }

}

int main(int argc, char* argv[]){

        Argon2_arguments args;        
        int sanitization = sanitize_input(argc,argv,&args);
       
        switch(sanitization){
                case NO_INPUT_GIVEN:
                        printf("%s",man);
                        break;
                case MALFORMED_INPUT:
                        printf("Error: Malformed input given.\n");
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
                case UNABLE_TO_WRITE_TEMPLATE:
                        printf("Unable to write template, check to have writing rights.\n");
                        break;
                case MALFORMED_INPUT_FILE:
                        printf("Malformed configuration file.\n");
                        break; 
                case SUCCESS:{    
                        PRINT_ARG_S;                           
                        uint8_t* tag;
                        tag = (uint8_t*)malloc(args.tau);
                        Argon2(&args,tag);
                        printf("Tag: 0x");
                        for(int  i = 0;i<args.tau;i++)
                                printf("%02X",tag[i]);
                        printf("\n");

                        free(tag);

                        // Free memory if input is read from file
			if(argv[1][2] == 'F'){
	                        // Free memory
	                        if(args.size_K)
	                                free(args.K);
	                        if(args.size_S)
	                                free(args.S);
			}

                }

        }
        
        return (sanitization!= 0);

}

#endif
