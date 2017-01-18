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
void ComputeFirstBlock01(Argon2_matrix* B, uint8_t* H0, uint32_t tau, uint32_t c){
	
	uint8_t* HprimeInput;
	Argon2_block block;

	memset(block.content,0,1024);

	HprimeInput = (uint8_t*) malloc(72); // 64 for H0 + 4 + 4
	memcpy(HprimeInput, H0, 64); //copy H0 into HprimeInput
	//memset(HprimeInput+64,c_byte,4);
	memcpy(HprimeInput+64, &c, 4);

	for(uint32_t i=0; i< B->p; i++)
	{

		memcpy(HprimeInput+68, &i, 4);
		Hprime(HprimeInput, 72, 1024, block.content);

		if(Argon2_matrix_fill_block(i,c,B,&block))
			ERROR("A2B:: Unable to write block01");	

	}

	free(HprimeInput);

}

void ComputeBlock(Argon2_matrix* B, Argon2_indexing_arguments* args){

	uint64_t iprime;
	uint64_t jprime;
	Argon2_block block;
	Argon2_block indexedBlock;
	Argon2_block Bij;

	for(args->s = 0; args->s < 4; args->s++){						// Cycle over the slices [sync points]

		for(args->l = 0; args->l < B->p; args->l++){					// Cycle over the segments

			if(args->s == 0 && args->r == 1)					// If first slice and first step we have
				args->c = 2;							// already computed first two blocks
			else
				args->c = args->s*B->segment_length;				// Set c to the beginning of the segment
			args->i = 1;								// Set the counter to 1 at the beginning of each
												// segment
			for(; args->c < (args->s+1)*B->segment_length; args->c++){		// Cycle over the elements of a segment

				iprime = Argon2_indexing(args, B);				// Compute block B[l][c]
				jprime = iprime & 0x00000000FFFFFFFF;
				iprime = iprime >> 32;

				if(Argon2_matrix_get_block(args->l,args->c-1 + 			// Get block B[l][c-1 mod B->q]
							   ((args->c == 0) ? B->q : 0), 
							   &block, B))	
					ERROR("A2B:: Unable to get block [l,c-1]");
				if(Argon2_matrix_get_block(iprime,jprime, &indexedBlock, B))	// Get block B[i'][j']
					ERROR("A2B:: Unable to get block [iprime,jprime]");
				CompressionFunctionG((uint64_t*)(block.content), 		// Compute G(B[l][c-1], B[i'][j'])
						     (uint64_t*)(indexedBlock.content), 
						     (uint64_t*)(Bij.content)); 
				if(Argon2_matrix_get_block(args->l,args->c, &block, B))		// Get block B[l][c]
					ERROR("A2B:: Unable to get block [l,c]");
				XOR_128((uint64_t*)Bij.content,					// Compute B[l][c] XOR G(B[l][c-1], B[i'][j'])
					(uint64_t*)block.content,
					(uint64_t*)Bij.content);			
				if(Argon2_matrix_fill_block(args->l,args->c,B,&Bij)) 		// Fill the correct block
					ERROR("A2B:: Unable to write block");

			}
		}
	}	
}
	
/*
* Function to get th final block, remember to initialize Bfinal.content to the vector of all zeros
*/
void BFinal(Argon2_matrix* B, Argon2_block* Bfinal){

	Argon2_block block;

	for (uint32_t i = 0; i < B->p; ++i)
	{
		printf("XOR block: [%u][%u]\n",i,B->q-1);
		if(Argon2_matrix_get_block(i, B->q-1, &block,B))
			ERROR("A2B:: Unable to get final blocks");

		uint64_t* tmp = (uint64_t*)block.content;
		printf("B[%d][7][0..15]: %016llX ", i,*tmp);
		printf("B[%d][7][16..31]: %016llX \n", i,*(tmp+1));

		XOR_128((uint64_t*)(Bfinal->content), (uint64_t*)(block.content), (uint64_t*)(Bfinal->content));

		tmp = (uint64_t*)Bfinal->content;
		printf("B_final[0..15]: %016llX ",*(tmp));
		printf("B_final[16..31]: %016llX \n\n",*(tmp+1));
		
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
	printf("H0:\n");
	for(int j = 0;j<8;j++){
		for(int i = 0;i<8;i++)
			printf("%02X ",H0[i+8*j]);
		printf("\n");
	}printf("\n");

	// Start blocks computation
	ComputeFirstBlock01(&B,H0,args->tau,0);

	uint64_t* tmp = (uint64_t*)B.matrix;
	Argon2_block tmp_block;
	tmp = (uint64_t*)tmp_block.content;
	
	for(int k = 0;k<B.p;k++){
		Argon2_matrix_get_block(k,0,&tmp_block,&B);
		for(int i = 0; i<4;i++){
			printf("B[%d][0][%d..%d]: %016llX  ", k, 16*i, 16*(i+1),*(tmp+i));
		}printf("\n");
	}printf("\n");

	ComputeFirstBlock01(&B,H0,args->tau,1);
	
	for(int k = 0;k<B.p;k++){
		Argon2_matrix_get_block(k,1,&tmp_block,&B);
		for(int i = 0; i<4;i++){
			printf("B[%d][1][%d..%d]: %016llX  ", k, 16*i, 16*(i+1),*(tmp+i));
		}printf("\n");
	}printf("\n");
	
	printf("args_i.t: %llu\n", args_i.t);

	for(args_i.r = 1; args_i.r <= args_i.t; args_i.r++){
		ComputeBlock(&B, &args_i);
		for(int k = 0;k<B.p;k++){
			Argon2_matrix_get_block(k,7,&tmp_block,&B);
			for(int i = 0; i<4;i++){
				printf("B_%llu[%d][7][%d..%d]: %016llX  ", args_i.r, k, 16*i, 16*(i+1),*(tmp+i));
			}printf("\n");
		}printf("\n");
	}

	// ------ ^ OK ^ -------

	Argon2_block B_final;
	memset(B_final.content,0,1024);
	BFinal(&B, &B_final);
	
	printf("args->tau: %u", args->tau);
	Hprime(B_final.content, 1024, args->tau, tag);

	// free memory
	Argon2_matrix_free(&B);

}







