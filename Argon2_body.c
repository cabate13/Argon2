// Argon2 v1.3 : PHC release
//
//      C implementation of the Argon2 memory hard function for password hashing and others applications
//
//      Credits to:  Alex Biryukov, Daniel Dinu and Dimitry Khovratovich
//

#include "Argon2_body.h"

/*
 * Concatenation of N bytes to the array. Also handles the update of the pointer to the tail of the array
 */
#if !defined CAT_N
#define CAT_N(array,pointer,n) {memcpy(array,pointer,n); array+=n;}
#endif

/*
 * Computes the seed for the initialization of the first two columns in the first step of Argon2
 */
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

	blake2b((void*)H0, H0_LENGTH, (void*)H0_input,  H0_input_curr - H0_input);

	free(H0_input);

}


/*
 * Initialization of the first two columns [c = 0,1] of the matrix, using the seed H0
 */
void compute_first_block(Argon2_global_workspace* B, uint8_t* H0, uint32_t tau, uint32_t c){
	
	uint8_t* H_prime_input;
	uint64_t* block;

	H_prime_input = (uint8_t*) malloc(H0_LENGTH+8); 
	memcpy(H_prime_input, H0, H0_LENGTH); //copy H0 into H_prime_input
	memcpy(H_prime_input+H0_LENGTH, &c, 4);

	for(uint32_t i=0; i< B->p; i++){

		if(Argon2_matrix_get_block(i,c,&block,B))
			ERROR("A2B:: Invalid index in first blocks computation");

		memcpy(H_prime_input+H0_LENGTH+4, &i, 4);
		H_prime(H_prime_input, H0_LENGTH+8, A2_MATRIX_BLOCK_LENGTH, (uint8_t*)block);

	}

	free(H_prime_input);

}

/*
 * Computes all the blocks in a segment
 */
void compute_segment(Argon2_global_workspace* B, Argon2_local_workspace* args){

	uint64_t i_prime;
	uint64_t j_prime;
	uint64_t* block;
	uint64_t* indexed_block;
	uint64_t support[A2_MATRIX_BLOCK_LENGTH];

	for(; args->c < (B->s+1)*B->segment_length; args->c++){			// Cycle over the elements of a segment

		i_prime = Argon2_indexing(B, args);				// Compute block B[l][c]:
		j_prime = i_prime & 0x00000000FFFFFFFF;				//   Find i',j'
		i_prime = i_prime >> 32;

		if(Argon2_matrix_get_block(args->l,args->c-1 + 			//   Get block B[l][c-1 mod B->q]
					   ((args->c == 0) ? B->q : 0), 
					   &block, B))	
			ERROR("A2B:: Unable to get block [l,c-1]");

		if(Argon2_matrix_get_block(i_prime,j_prime, &indexed_block, B))	//   Get block B[i'][j']
			ERROR("A2B:: Unable to get block [i',j']");
		
		A2_G(block, indexed_block, support, B->S, B->x);		// Compute G(B[l][c-1], B[i'][j'])		

		if(Argon2_matrix_get_block(args->l,args->c, &block, B))		// Get block B[l][c]
			ERROR("A2B:: Unable to get block [l,c]");

		XOR_128(support, block, block);	     			// Compute B[l][c] XOR G(B[l][c-1], B[i'][j'])

	}

}

/*
 * Initializes arguments and handles parallel computation in an Argon2 step.
 */
void perform_step(Argon2_global_workspace* B){

	if(B->x == A2DS)
	{
		uint64_t* block;
		Argon2_matrix_get_block(0,0,&block,B);
		S_Box_Inizialization(block,B->S);
	}

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
* Function to get the final block. Remark: B_final needs to be whitened
*/
void finalize(Argon2_global_workspace* B, uint64_t* B_final){

	uint64_t* block;

	for (uint32_t i = 0; i < B->p; ++i){

		if(Argon2_matrix_get_block(i, B->q-1, &block,B))
			ERROR("A2B:: Unable to get final blocks");

		XOR_128(B_final, block, B_final);

	}
}

void Argon2(Argon2_arguments* args, uint8_t* tag){



	Argon2_global_workspace B;
	if(Argon2_global_workspace_init(args->m, args->p, args->t, args->y, &B) == 1)
		ERROR("A2B:: Unable to initialize global workspace.");

	if(args->size_S<8 || args->p > 0xFFFFFF || args->tau<4 )
                ERROR("A2B:: Parameters out of bounds");
        if(args->m < args->p*8)
                ERROR("A2B:: Pair (m,p) not consistent, 8*p < m.")
        if(!((args->y == A2D) || (args->y == A2I) || (args->y == A2ID) || (args->y == A2DS))) 
                ERROR("A2B:: Illegal type for Argon2, Valid types:\nArgon2d:  0\nArgon2i:  1\nArgon2id: 2\nArgon2ds: 4\n");

	// Compute H0
	uint8_t H0[64];
	compute_H0(args,H0);

	// Start blocks computation
	compute_first_block(&B,H0,args->tau,0);
	compute_first_block(&B,H0,args->tau,1);

	#if defined FOLLOW_SPECS
	for(B.r = 1; B.r <= B.t; B.r++)
		perform_step(&B);
	#else
	for(B.r = 0; B.r < B.t; B.r++)
		perform_step(&B);
	#endif
	
	uint64_t B_final[A2_MATRIX_BLOCK_LENGTH/8];
	memset(B_final,0,A2_MATRIX_BLOCK_LENGTH);
	finalize(&B, B_final);
	H_prime((uint8_t*)B_final, A2_MATRIX_BLOCK_LENGTH, args->tau, tag);

	//free memory
	Argon2_global_workspace_free(&B);	

}







