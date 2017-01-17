//Operation
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "Argon2_compression.h"
#include "Argon2_matrix.h"
#include "Argon2_body.h"

#if !defined CAT_N
#define CAT_N(array,pointer,n) {memcpy(array,pointer,n); array+=n;}
#endif
#if !defined ERROR
#define ERROR(msg) {puts((char*)msg); exit(1);}
#endif

void compute_H0(Argon2_arguments* args, uint8_t* H0){

	uint8_t* H0_input = (uint8_t*)malloc(10*4+args->size_P+args->size_S+args->size_K+args->size_X);
	uint8_t* H0_input_curr = H0_input;

	CAT_N(H0_input_curr,&(args->p),4);
	CAT_N(H0_input_curr,&(args->tau),4);
	CAT_N(H0_input_curr,&(args->m),4);
	CAT_N(H0_input_curr,&(args->t),4);
	CAT_N(H0_input_curr,&(args->v),4);
	CAT_N(H0_input_curr,&(args->y),4);
	CAT_N(H0_input_curr,&(args->size_P),4);
	CAT_N(H0_input_curr,args->P,args->size_P);
	CAT_N(H0_input_curr,&(args->size_S),4);
	CAT_N(H0_input_curr,args->S,args->size_S);
	CAT_N(H0_input_curr,&(args->size_K),4);
	CAT_N(H0_input_curr,args->K,args->size_K);
	CAT_N(H0_input_curr,&(args->size_X),4);
	CAT_N(H0_input_curr,args->X,args->size_X);

	blake2b((void*)H0, 64, (void*)H0_input,  H0_input_curr - H0_input, NULL, 0);

	free(H0_input);

}


//function computing a block  
//tau is the 32 bit tag length
//ZeroOne is to discriminate among B[][0] and B[][1]
//p is a parameter coming from Haven
void ComputeFirstBlock01(Argon2_matrix* B, uint8_t* H0, uint32_t tau, uint8_t c_byte)
{
	

	uint8_t* HprimeInput;
	Argon2_block block;

	memset(block.content,0,1024);

	HprimeInput = (uint8_t*) malloc(72); // 64 for H0 + 4 + 4
	memcpy(HprimeInput, H0, 64); //copy H0 into HprimeInput
	memset(HprimeInput+64,c_byte,4);

	for(uint32_t i=0; i< B->p; i++)
	{

		memcpy(HprimeInput+68, &i, 4);
		Hprime(HprimeInput, 72, 1024, block.content);

		if(Argon2_matrix_fill_block(i,0x01&&c_byte,B,&block))
			ERROR("A2B:: Unable to write block01");	

	}

	free(HprimeInput);

}


void ComputeFirstBlock(Argon2_matrix* B, uint8_t*H0, uint32_t tau, Argon2_indexing_arguments* args)
{
	ComputeFirstBlock01(B,H0,tau,0x00);
	ComputeFirstBlock01(B,H0,tau,0xFF);

	uint64_t iprime;
	uint64_t jprime;

	Argon2_block block;
	Argon2_block indexedBlock;
	Argon2_block Bij;

	//setting the arguments for indexing...
	//Argon2_indexing_arguments arguments;
	//arguments.r = 1; //first pass
	//arguments.l = 1; //we have p lanes, so we must increment l each time we increment i
	//arguments.s = 1; //we have 4 slice, we must increment s  at (1/4)*q,(2/4)*q,.. q
	//arguments.t =    //the total number of passes
	//arguments.i = 1; //it must be set again to 1 each time we start a new segment, a new segment starts exactly when slice counter is incremented

	for (args->l = 0; args->l < B->p; args->l++)
	{
		args->s = -1;
		for (args->c = 2; args->c < B->q; args->c++)
		{

			if(args->c%B->segment_length == 0 )
				{
					args->s++;
					args->i = 1;
				}

			iprime = Argon2_indexing(args, B);
			jprime = iprime & 0x00000000FFFFFFFF;
			iprime = iprime >> 32;


			//take the block needed
			if(Argon2_matrix_get_block(args->l,args->c-1, &block, B))
				ERROR("A2B:: Unable to get first block [l,c-1]");
			if(Argon2_matrix_get_block(iprime,jprime, &indexedBlock, B))
				ERROR("A2B:: Unable to get first block [iprime,jprime]");
			CompressionFunctionG((uint64_t*)(block.content), (uint64_t*)(indexedBlock.content), (uint64_t*)(Bij.content)); //compute G(B[i][j-1], B[i'][j'])
			if(Argon2_matrix_fill_block(args->l,args->c,B,&Bij)) //and set B[i][j] equal to this value
				ERROR("A2B:: Unable to write first block");
			
		}

	}

}

void ComputeBlock(Argon2_matrix* B, Argon2_indexing_arguments* args)
{

	uint64_t iprime;
	uint64_t jprime;

	Argon2_block block;
	Argon2_block indexedBlock;
	Argon2_block Bij;

	int myJ; //is q-1 if j=0 and j othewrise in the following loop

	//setting the arguments for indexing...
	//Argon2_indexing_arguments arguments;
	//arguments.r = 1; //first pass
	//arguments.l = 1; //we have p lanes, so we must increment l each time we increment i
	//arguments.s = 1; //we have 4 slice, we must increment s  at (1/4)*q,(2/4)*q,.. q
	//arguments.t =    //the total number of passes
	//arguments.i = 1; //it must be set again to 1 each time we start a new segment, a new segment starts exactly when slice counter is incremented

	for (args->l = 0; args->l < B->p; args->l++)
	{
		args->s = -1;
		for (args->c = 0; args->c < B->q; args->c++)
		{

			if(args->c%B->segment_length == 0 )
				{
					args->s++;
					args->i = 1;
				}
			if(args->c){ myJ = args->c;}
			else{myJ = B->q;}

			iprime = Argon2_indexing(args, B);
			jprime = iprime & 0x00000000FFFFFFFF;
			iprime = iprime >> 32;
			

			//take the block needed
			if(!(Argon2_matrix_get_block(args->l, myJ-1, &block, B) || Argon2_matrix_get_block(iprime,jprime, &indexedBlock, B)))
			{
				CompressionFunctionG((uint64_t*)(block.content), (uint64_t*)(indexedBlock.content), (uint64_t*)(Bij.content)); //compute G(B[i][j-1], B[i'][j'])

				int a = Argon2_matrix_get_block(args->l,myJ,&block,B); //take the block B[i][0] at step t

				XOR128((uint64_t*)(Bij.content), (uint64_t*)(block.content), (uint64_t*)(Bij.content),128); //XOR with B[i][0]

				if(Argon2_matrix_fill_block(args->l,args->c,B,&Bij)) //and set B[i][j] equal to this value
					ERROR("A2B:: Unable to write block\n");
			}
			else
				ERROR("A2B:: Unable to get blocks\n");
	

			//arguments.i++; //arguments.i must be incremented at every iteration -> managed in indexing
		}

	}
	
}
	
/*
* Function to get th final block, remember to initialize Bfinal.content to the vector of all zeros
*/
void BFinal(Argon2_matrix* B, Argon2_block* Bfinal)
{
	Argon2_block block;

	for (int i = 0; i < B->p; ++i)
	{
		if(Argon2_matrix_get_block(i, (B->q)-1, &block,B))
			ERROR("Unable to get final blocks");

		XOR128((uint64_t*)(Bfinal->content), (uint64_t*)(block.content), (uint64_t*)(Bfinal->content),128);
	}
}

void Argon2(Argon2_arguments* args, uint8_t* tag){

	Argon2_matrix B;

	if(Argon2_matrix_init(args->m, args->p, &B))
		ERROR("A2B:: Illegal pair of parameters (m,p)");

	// Initialize indexing arguments
	Argon2_indexing_arguments args_i;
        Argon2_indexing_arguments_init(&args_i, B.m, args->t, args->y);

	// Compute H0
	uint8_t H0[64];
	compute_H0(args,H0);

	// Start blocks computation
	ComputeFirstBlock(&B, H0, args->tau, &args_i);

	for(;args_i.r < args_i.t;args_i.r++)
		ComputeBlock(&B, &args_i);

	Argon2_block B_final;
	BFinal(&B, &B_final);
	
	Hprime(B_final.content, 1024, args->tau, tag);

	// free memory
	Argon2_matrix_free(&B);

}







