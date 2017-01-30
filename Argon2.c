/** @file Argon2.c
 * 
 * Argon2 v1.3 : PHC release
 *     
 *      C implementation of the Argon2 memory hard function for password hashing and others applications
 *           
 *      Credits to:  Alex Biryukov, Daniel Dinu and Dimitry Khovratovich
 *
 * The actual implementation of Argon2 v1.3 is wrapped in a main that handles input and correctly initializes arguments \n
 *
 * - Required input:
 *  (°) Password P and its size         (check_input_received[0-1]) 		\n
 *  (°) Salt S and its size             (check_input_received[2-3]) 		\n
 *  (°) Secret K and its size           (check_input_received[11-12])		\n
 *  (°) Associated data X and its size  (check_input_received[4-5])			\n
 *  (°) Tag size                        (check_input_received[10])			\n
 *  (°) Degreee of parallelization      (check_input_received[6])			\n
 *  (°) Total memory usage              (check_input_received[7])			\n
 *  (°) Total passes                    (check_input_received[8]) 			\n              
 *  (°) type [0,1,2,4]                  (check_input_received[9])			\n
 *
 * - Input formats:\n
 *  (°) --C : command line input\n
 *  (°) --F : config file input -> more realistic use for password hashing, password and associatd data (exa. username, ..) defined at
 *            runtime, while other parameters are set in the database configuration. \n
 *
 * - Mode 1: command line input: 											\n
 *  (°) --C 																\n
 *  (°) -P <password>														\n
 *  (°) -S <salt>															\n
 *  (°) [-K <secret>]														\n
 *  (°) -X <associated data>												\n
 *  (°) -p <degree of parallelization>										\n
 *  (°) -m <total memory usage in KiB>										\n
 *  (°) -t <total passes>													\n
 *  (°) -v <type of Argon2>													\n
 *  (°) -l <tag size>														\n
 *
 * - Mode 2: config file input:												\n
 *  (°) --F <filename> -P <password> -X <associated data>					\n
 *  
 * - File format:															\n
 *  (°) S_size: <size of salt>												\n
 *  (°) S: <salt>															\n
 *  (°) K_size: <size of secret data>  // optional							\n
 *  (°) K: <secret data>               // optional							\n	
 *  (°) p: <degree of parallelization>										\n
 *  (°) m: <total memory usage in KiB>										\n
 *  (°) t: <total passes>													\n
 *  (°) v: <type of Argon2>													\n
 *  (°) tau: <tag size>
 */


#include <stdlib.h>
#include <stdio.h>
#include "Argon2_body.h"

/// @def NO_INPUT_GIVEN 
/// 	 no input is given 
#define NO_INPUT_GIVEN 1
/// @def MALFORMED_INPUT
///		 input is not given in the correct form
#define MALFORMED_INPUT 2
/// @def MISSING_PARAMETER
///		 one of the mandatory parameter is missing
#define MISSING_PARAMETER 3
/// @def NON_VALID_INPUT_FILE
///		 the input file is not valid
#define NON_VALID_INPUT_FILE 4
/// @def MALFORMED_INPUT_FILE
///		 the input file is not given in the correct form
#define MALFORMED_INPUT_FILE 5
/// @def GENERATE_TEMPLATE
///		 prints a templet for an Argon2 configuration file
#define GENERATE_TEMPLATE 6
/// @def UNABLE_TO_WRITE_TEMPLATE
///		 not possibile to print the template
#define UNABLE_TO_WRITE_TEMPLATE 7
/// @def SUCCESS
///		 all parameters have been given in input in the correct form, computation can start
#define SUCCESS 0

/// @def PRINT_ARG_S
///		 Prints the arguments passed to Argon2
#define PRINT_ARG_S {printf("Password: ");for(int i = 0;i<args.size_P;i++)printf("%c",args.P[i]);printf("\n");\
                     printf("Salt: ");for(int i = 0;i<args.size_S;i++)printf("%c",args.S[i]);printf("\n");\
                     printf("Secret: ");for(int i = 0;i<args.size_K;i++)printf("%c",args.K[i]);printf("\n");\
                     printf("Associated data: ");for(int i = 0;i<args.size_X;i++)printf("%c",args.X[i]);printf("\n");\
                     printf("tau: %u, p: %u, m: %u, t: %u, y: %u\n",args.tau, args.p, args.m, args.t, args.y);}

/// @var man
/// 	 manual given via std out when no input is guven
const char* man = 
"*** Argon2 usage: ***\n\nInput from command line: [-K is the only optional argument]\n  ./Argon2 --C \n  -P <password>\n  -S <salt>\n  -X <associated data>\n  -p <parallelization degree>\n  -m <memory usage>\n  -t <total passes>\n  -v <type of Argon2>\n  -l <tag size>\n  [-K <secret>]\n\nInput from file: [generate a template with ./Argon2 --T]\n  ./Argon2 --F <filename> -P <password> -X <associated data>\n\n";
/// @var template  
///  	 apposite template for the file input mode Argon2 configuration file 
const char* template = 
"# This is a template for the Argon2 input file. Lines starting with # will be ignored\nS_size: <size of salt>\nS: <salt>\nK_size: <size of secret data>\nK: <secret data>\np: <degree of parallelization>\nm: <total memory usage in KiB>\nt: <total passes>\nv: <type of Argon2>\ntau: <tag size>";

/**
*  @fn int file_input_sanitization(int argc, char* argv[], Argon2_arguments* args, uint8_t* check_input_received)
*  File input sanitization
*  @param argc  argc from the main 
*  @param argv  argv form the main 
*  @param args 	the argument for Argon2 to be inizialized
*  @param check_input_received argument used to check input was correctly inserted
*/
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
                                args->S = (uint8_t*)malloc(args->size_S);  // to free at the end!
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
                                args->K = (uint8_t*)malloc(args->size_K);  // to free at the end!
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

/**
*  @fn int command_line_input_sanitization(int argc, char* argv[], Argon2_arguments* args, uint8_t* check_input_received)
*  Command line input sanitization
*  @param argc 	from the main
*  @param argv	from the main
*  @param args 	the argument for Argon2 to be inizialized
*  @param check_input_received argument used to check input was correctly inserted
*/
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

/**
*	@fn int sanitize_input(int argc, char* argv[], Argon2_arguments* args)
*  	Checks the type of input provided (command line v.s. file) and calls the appropriate handler
*	@param argc  from the main
*  	@param argv	 from the main
*  	@param args  the argument for Argon2 to be inizialized
*/
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

/*
* 	@fn int main(int argc, char* argv[])
* 	Inizialization and error handling
*/
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
