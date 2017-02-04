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
 *  (°) Associated data X and its size  (check_input_received[9-10])	    \n
 *  (°) Degreee of parallelization      (check_input_received[4])			\n
 *  (°) Total memory usage              (check_input_received[5])			\n
 *  (°) Total passes                    (check_input_received[6]) 			\n              
 *  (°) type [0,1,2,4]                  (check_input_received[7])			\n
 *  (°) Tag size                        (check_input_received[8])           \n
 *
 * - Input formats:\n
 *  (°) --C : command line input\n
 *  (°) --F : config file input -> more realistic use for password hashing, password and associatd data (exa. username, ..) defined at
 *            runtime, while other parameters are set in the database configuration. \n
 *
 * - Mode 1: command line input: 											\n
 *  (°) --C 																\n
 *  (°) -P password														    \n
 *  (°) -S salt															    \n
 *  (°) [-K secret]														    \n
 *  (°) [-X associated data]												\n
 *  (°) -p degree of parallelization										\n
 *  (°) -m total memory usage in KiB										\n
 *  (°) -t total passes													    \n
 *  (°) -v type of Argon2													\n
 *  (°) -l tag size														    \n
 *
 * - Mode 2: config file input:												\n
 *  (°) --F filename -P password -S salt            					    \n
 *  
 * - File format:															\n
 *  (°) X_size: size of the associated data									\n
 *  (°) X: associated data													\n
 *  (°) K_size: size of secret data  // optional							\n
 *  (°) K: secret data               // optional							\n	
 *  (°) p: degree of parallelization										\n
 *  (°) m: total memory usage in KiB										\n
 *  (°) t: total passes													    \n
 *  (°) v: type of Argon2													\n
 *  (°) tau: tag size
 */


#include <stdlib.h>
#include <stdio.h>
#include "Argon2_body.h"

/// @def NO_INPUT_GIVEN 
/// 	 No input was given.
#define NO_INPUT_GIVEN 1
/// @def MALFORMED_INPUT
///		 Command line input was not given in the correct form.
#define MALFORMED_INPUT 2
/// @def MISSING_PARAMETER
///		 One of the mandatory parameter is missing.
#define MISSING_PARAMETER 3
/// @def NON_VALID_INPUT_FILE
///		 The input file could not be read.
#define NON_VALID_INPUT_FILE 4
/// @def MALFORMED_INPUT_FILE
///		 The input file is not given in the correct form.
#define MALFORMED_INPUT_FILE 5
/// @def GENERATE_TEMPLATE
///		 The template has been generated correctly.
#define GENERATE_TEMPLATE 6
/// @def UNABLE_TO_WRITE_TEMPLATE
///		 It was not possibile to print the template.
#define UNABLE_TO_WRITE_TEMPLATE 7
/// @def SUCCESS
///		 All parameters have been given in input in the correct form, so the computation of Argon2 can be started.
#define SUCCESS 0

/// @def PRINT_ARG_S
///		 Prints the arguments passed to Argon2.
#define PRINT_ARG_S {printf("Password: ");for(int i = 0;i<args.size_P;i++)printf("%c",args.P[i]);printf("\n");\
                     printf("Salt: ");for(int i = 0;i<args.size_S;i++)printf("%c",args.S[i]);printf("\n");\
                     printf("Secret: ");for(int i = 0;i<args.size_K;i++)printf("%c",args.K[i]);printf("\n");\
                     printf("Associated data: ");for(int i = 0;i<args.size_X;i++)printf("%c",args.X[i]);printf("\n");\
                     printf("tau: %u, p: %u, m: %u, t: %u, y: %u\n",args.tau, args.p, args.m, args.t, args.y);}

/// @def FREE_MEMORY_ON_BAD_INPUT
///      Frees eventually allocated memory if the input is incorrect.
#define FREE_MEMORY_ON_BAD_INPUT {if(check_input_received[10])free(args->S);if(check_input_received[12])free(args->K);}

/// @def TAKE_SCALAR_FROM_C_LINE
///      Takes a scalar from the command line argument and saves it in the correct position 'arg', then notes that it was taken as input.
#define TAKE_SCALAR_FROM_C_LINE(arg,i_arg){if(sscanf(argv[i+1],"%u",&arg)!=1 || check_input_received[i_arg])                       \
                                                return MALFORMED_INPUT; check_input_received[i_arg]=1;} 

/// @def TAKE_ARRAY_FROM_C_LINE
///      Takes an array from the command line argument, stores a pointer to it int arguments and notes it size, then notes that it was taken as input.
#define TAKE_ARRAY_FROM_C_LINE(array,size,i_arg){if(check_input_received[i_arg])return MALFORMED_INPUT;array = argv[i+1]; size = strlen(argv[i+1]);\
                                                 check_input_received[i_arg] = 1;check_input_received[i_arg+1] = 1;}

/// @def TAKE_SCALAR_FROM_FILE
///      Takes a scalar from configuration file.
#define TAKE_SCALAR_FROM_FILE(arg,type,i_arg){if((sscanf(buffer, type, &arg) != 1)|| check_input_received[i_arg])                       \
                                              {FREE_MEMORY_ON_BAD_INPUT;return MALFORMED_INPUT_FILE;}                                   \
                                              check_input_received[i_arg] = 1;}

/// @def TAKE_ARRAY_FROM_FILE
///      Takes an array from configuration file, in particular it reads the length of the array, then allocates the memory for it and proceeds
///      to read it.
#define TAKE_ARRAY_FROM_FILE(array,size,type,i_arg){                                                                                    \
                                if((sscanf(buffer,type,&(size))!=1) || check_input_received[i_arg]){                                    \
                                    FREE_MEMORY_ON_BAD_INPUT;                                                                           \
                                    return MALFORMED_INPUT_FILE;                                                                        \
                                }                                                                                                       \
                                data_buffer = (uint8_t*)malloc(size+5); /* One for the '\n' and one '\0' */                             \
                                                                                                                                        \
                                if((fgets(data_buffer,size+5,input_file) == NULL) || (data_buffer[size+3] != '\n')){                    \
                                    FREE_MEMORY_ON_BAD_INPUT;                                                                           \
                                    return MALFORMED_INPUT_FILE;                                                                        \
                                }                                                                                                       \
                                array = (uint8_t*)malloc(size);  /* This has to be deallocated at the end of the execution*/            \
                                memcpy(array,data_buffer+3,size);                                                                       \
                                check_input_received[i_arg] =1;                                                                         \
                                check_input_received[i_arg+1] =1;                                                                       \
                                free(data_buffer);}                                                                     

/// @var man
/// 	 Manual given via std out when no input is guven
const char* man = 
"*** Argon2 usage: ***\n\nInput from command line: [arguments in brackets are optional]\n  ./Argon2 --C \n  -P <password>\n  -S <salt>\n  -p <parallelization degree>\n  -m <memory usage>\n  -t <total passes>\n  -v <type of Argon2>\n  -l <tag size>\n  [-X <associated data>]\n  [-K <secret>]\n\nInput from file: [generate a template with ./Argon2 --T]\n  ./Argon2 --F <filename> -P <password> -S <salt>\n\n";
/// @var template  
///  	 Template for the file input mode Argon2 configuration file 
const char* template = 
"# This is a template for the Argon2 input file. Lines starting with # will be ignored\nX_size: <size of associated data>\nX: <associated data>\nK_size: <size of secret data>\nK: <secret data>\np: <degree of parallelization>\nm: <total memory usage in KiB>\nt: <total passes>\nv: <type of Argon2>\ntau: <tag size>";

/**
*  @fn int file_input_sanitization(int argc, char* argv[], Argon2_arguments* args, uint8_t* check_input_received)
*  Performs sanitization of an input from file.
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
            case 'P':
                TAKE_ARRAY_FROM_C_LINE(args->P,args->size_P,0);
                break;
            case 'S':
                TAKE_ARRAY_FROM_C_LINE(args->S,args->size_S,2);
                break;
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

        if(buffer[strlen(buffer)-1]!='\n'){
            return MALFORMED_INPUT_FILE;
            FREE_MEMORY_ON_BAD_INPUT;
        }

        switch(buffer[0]){
            case '#':
                // Do nothing, comment line 
                break;
            case 'X':
                TAKE_ARRAY_FROM_FILE(args->X,args->size_X,"X_size: %u\n",9);
                break;
            case 'K':
                TAKE_ARRAY_FROM_FILE(args->K,args->size_K,"K_size: %u\n",11);
                break;
            case 'p':
                TAKE_SCALAR_FROM_FILE(args->p,"p: %u\n",4);
                break;
            case 'm':
                TAKE_SCALAR_FROM_FILE(args->m,"m: %u\n",5);
                break;
            // The cases t and tau are handled togheter in an unique way, since they have the same starting letter
            case 't':{
                if((sscanf(buffer, "t: %u\n",&args->t) != 1)|| check_input_received[6]){
                    if((sscanf(buffer, "tau: %u",&args->tau) != 1)|| check_input_received[8]){
                        FREE_MEMORY_ON_BAD_INPUT;
                        return MALFORMED_INPUT_FILE; 
                    }
                    check_input_received[8] =1;
                        
                }else
                    check_input_received[6] =1;
            }break;
            case 'v':
                TAKE_SCALAR_FROM_FILE(args->y,"v: %u\n",7);
                break;
            default:{
                FREE_MEMORY_ON_BAD_INPUT;
                return MALFORMED_INPUT_FILE;
            }break;
        
        }                               
    
    }

    // Final check:
    // (°) If any mandatory argument is missing, free the memory eventually allocated for other arguments
    // (°) If any optional parameter is missing, initialize its size to zero

    for(int i = 0; i < 9; i++){

            if(!check_input_received[i]){
                FREE_MEMORY_ON_BAD_INPUT;
                return MISSING_PARAMETER;
            }

    }

    if(!check_input_received[11] && !check_input_received[12])
        args->size_K = 0;

    if(!check_input_received[9] && !check_input_received[10])
        args->size_X = 0;

    return SUCCESS;

}

/**
*  @fn int command_line_input_sanitization(int argc, char* argv[], Argon2_arguments* args, uint8_t* check_input_received)
*  Performs input sanitization when acquiring input from command line.
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
            case 'P':
                TAKE_ARRAY_FROM_C_LINE(args->P,args->size_P,0);
                break;
            case 'S':
                TAKE_ARRAY_FROM_C_LINE(args->S,args->size_S,2);
                break;
            case 'K':
                TAKE_ARRAY_FROM_C_LINE(args->K,args->size_K,11);
                break;
            case 'X':
                TAKE_ARRAY_FROM_C_LINE(args->X,args->size_X,9);
            break;
            case 'p':
                TAKE_SCALAR_FROM_C_LINE(args->p,4);
                break;
            case 'm':
                TAKE_SCALAR_FROM_C_LINE(args->m,5);
                break;
            case 't':
                TAKE_SCALAR_FROM_C_LINE(args->t,6);
                break;
            case 'v':
                TAKE_SCALAR_FROM_C_LINE(args->y,7);
                break;
            case 'l':
                TAKE_SCALAR_FROM_C_LINE(args->tau,8);
                break;
            default:
                return MALFORMED_INPUT;
                break;

        }
        i+=2;
    }

    // Final check:
    // (°) If there is any missing arguments returns an error
    // (°) Initialize size of optional arguments to zero if they are no given

    for(int i = 0; i < 9; i++){
        if(!check_input_received[i])
            return MISSING_PARAMETER;

    }
    if(!check_input_received[11] && !check_input_received[12])
        args->size_K = 0;

    if(!check_input_received[9] && !check_input_received[10])
        args->size_X = 0;

    return SUCCESS;

}

/**
 *	@fn int sanitize_input(int argc, char* argv[], Argon2_arguments* args)
 *  Checks the type of input provided (command line v.s. file) and calls the appropriate handler.
 *	@param argc  from the main
 *  @param argv	 from the main
 *  @param args  the argument for Argon2 to be inizialized
 *  @hidecallgraph
 */
int sanitize_input(int argc, char* argv[], Argon2_arguments* args){

        // Array used to record the received arguments: order defined in the file intestation
        uint8_t check_input_received[13];
        memset(check_input_received,0,13);

        // Check if any input is given
        if(argc == 1)
            return NO_INPUT_GIVEN;
        if((strlen(argv[1])!=3) || (argv[1][0]!='-') || (argv[1][1]!='-'))
            return MALFORMED_INPUT;

        // Read the input mode flag
        switch (argv[1][2]){
        case 'C':
            return command_line_input_sanitization(argc, argv, args, check_input_received);
            break; 
        case 'F':
            return file_input_sanitization(argc, argv, args, check_input_received);
            break; 
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

/**
 * 	@fn int main(int argc, char* argv[])
 *  Sanitizes input and uses it to initialize Argon2 arguments
 *  @hidecallgraph
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
                printf("Unable to write template, check if you have writing rights.\n");
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
	            if(args.size_K)
	                free(args.K);
	            if(args.size_X)
	                free(args.X);
			}

        }break;

    }
        
    return (sanitization!= 0);

}
