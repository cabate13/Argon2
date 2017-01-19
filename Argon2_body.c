#include "Argon2_body.h"

#if !defined CAT_N
#define CAT_N(array,pointer,n) {memcpy(array,pointer,n); array+=n;}
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

	blake2b((void*)H0, 64, (void*)H0_input,  H0_input_curr - H0_input);

	free(H0_input);

}


//function computing a block  
//tau is the 32 bit tag length
//ZeroOne is to discriminate among B[][0] and B[][1]
//p is a parameter coming from Haven
void compute_first_block(Argon2_global_workspace* B, uint8_t* H0, uint32_t tau, uint32_t c){
	
	uint8_t* H_prime_input;
	Argon2_block block;

	memset(block.content,0,1024);

	H_prime_input = (uint8_t*) malloc(72); // 64 for H0 + 4 + 4
	memcpy(H_prime_input, H0, 64); //copy H0 into H_prime_input
	memcpy(H_prime_input+64, &c, 4);

	for(uint32_t i=0; i< B->p; i++)
	{

		memcpy(H_prime_input+68, &i, 4);
		H_prime(H_prime_input, 72, 1024, block.content);

		if(Argon2_matrix_fill_block(i,c,B,&block))
			ERROR("A2B:: Unable to write block01");	

	}

	free(H_prime_input);

}

void compute_segment(Argon2_global_workspace* B, Argon2_local_workspace* args){

	uint64_t i_prime;
	uint64_t j_prime;
	Argon2_block block;
	Argon2_block indexed_block;
	Argon2_block Bij;

	for(; args->c < (B->s+1)*B->segment_length; args->c++){			// Cycle over the elements of a segment

		i_prime = Argon2_indexing(B, args);				// Compute block B[l][c]
		j_prime = i_prime & 0x00000000FFFFFFFF;
		i_prime = i_prime >> 32;

		if(Argon2_matrix_get_block(args->l,args->c-1 + 			// Get block B[l][c-1 mod B->q]
					   ((args->c == 0) ? B->q : 0), 
					   &block, B))	
			ERROR("A2B:: Unable to get block [l,c-1]");

		if(Argon2_matrix_get_block(i_prime,j_prime, &indexed_block, B))	// Get block B[i'][j']
			ERROR("A2B:: Unable to get block [i',j']");

		A2_G((uint64_t*)(block.content), 				// Compute G(B[l][c-1], B[i'][j'])
		     (uint64_t*)(indexed_block.content), 
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

void perform_step(Argon2_global_workspace* B){


	for(B->s = 0; B->s < 4; B->s++){							// Cycle over the slices [sync points]

		#pragma omp parallel for
		for(uint32_t l = 0; l < B->p; l++){						// Cycle over the segments of a slice

			Argon2_local_workspace args;						// Initialize local workspace
			args.l = l;								// Set lane index
			if(B->s == 0 && B->r == 0)						// If first slice and first step we have
				args.c = 2;							// already computed first two blocks
			else 									// otherwise
				args.c = B->s*B->segment_length;				// Set c to the beginning of the segment
			args.i = 1;								// Argon2i: set counters for intexing:
			args.counter = 0;							// i = 1 and reset used pairs counter.

			compute_segment(B,&args);						// Compute the new value for the blocks 
												// int the segment
		}

	}

}
	
/*
* Function to get th final block, remember to initialize Bfinal.content to the vector of all zeros
*/
void finalize(Argon2_global_workspace* B, Argon2_block* Bfinal){

	Argon2_block block;

	for (uint32_t i = 0; i < B->p; ++i){

		if(Argon2_matrix_get_block(i, B->q-1, &block,B))
			ERROR("A2B:: Unable to get final blocks");

		XOR_128((uint64_t*)(Bfinal->content), (uint64_t*)(block.content), (uint64_t*)(Bfinal->content));

	}
}

void Argon2(Argon2_arguments* args, uint8_t* tag){

	Argon2_global_workspace B;

	if(Argon2_global_workspace_init(args->m, args->p, args->t, args->y, &B))
		ERROR("A2B:: Illegal pair of parameters (m,p)");

	// Compute H0
	uint8_t H0[64];
	compute_H0(args,H0);

	// Start blocks computation
	compute_first_block(&B,H0,args->tau,0);
	compute_first_block(&B,H0,args->tau,1);

	for(B.r = 0; B.r < B.t; B.r++)
		perform_step(&B);
	
	Argon2_block B_final;
	memset(B_final.content,0,1024);
	finalize(&B, &B_final);
	H_prime(B_final.content, 1024, args->tau, tag);

	//free memory
	Argon2_global_workspace_free(&B);
	

}







