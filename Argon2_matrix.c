/** 
* @file
* Manages memory used in Argon2, with particular care to block indexing and safe inizialization and destruction
*/
#include "Argon2_matrix.h"

/**
 * @fn int Argon2_global_workspace_init(uint32_t m, uint32_t p, uint32_t t, uint32_t x, Argon2_global_workspace* B)
 * Initializes the matrix and sets its parameters
 * @param m     KiB of memory to be used rounded down to the closest multiple of 4p
 * @param p     maximum degree of parallelism
 * @param t     total number of passes
 * @param x     type of Argon function
 * @param B     pointer to the memory matrix used for data storage in Argon2     
*/
int Argon2_global_workspace_init(uint32_t m, uint32_t p, uint32_t t, uint32_t x, Argon2_global_workspace* B){

        // Matrix initialization
        if(p == 0 || p > 0xFFFFFF || m < 8*p)
                return 1;

        B->p = p;
        B->m = (m/(4*p))*4*p;
        B->q = B->m/p;
        B->segment_length = B->q/4;
        B->matrix = (uint64_t*)malloc(B->m*1024);
        memset(B->matrix,0,B->m*A2_MATRIX_BLOCK_LENGTH);

        // Global parameters initialization
        B->t = t;
        B->x = x;
        B->r = 0;
        B->s = 0;

	// S-Box for Argon2ds
	if(x == A2DS)
		B->S = (uint64_t*) malloc(A2_MATRIX_BLOCK_LENGTH*sizeof(uint64_t));

        return 0;

}

/**
 * @fn int Argon2_matrix_get_block(uint32_t i, uint32_t j, uint64_t** dst, Argon2_global_workspace* src)
 * Gets the block in position (i,j) in the Argon2 matrix in global_workspace, storing it in dst
 */
int Argon2_matrix_get_block(uint32_t i, uint32_t j, uint64_t** dst, Argon2_global_workspace* src){

        if(i > (src->p - 1) || j > (src->q - 1))
                return 1;

        *dst = (src->matrix+A2_MATRIX_BLOCK_LENGTH/8*(j+src->q*i));
        return 0;

}

/**
 * @fn void Argon2_global_workspace_free(Argon2_global_workspace* B)
 * Deallocates the memory of the matrix and, if it is the case, also the memory used for the S-Box
 */
void Argon2_global_workspace_free(Argon2_global_workspace* B){

        free(B->matrix);
        B->matrix = NULL;
	
	if(B->x == A2DS)
		free(B->S);

}

/**
 * @fn uint64_t Argon2d_generate_values(Argon2_global_workspace* B, uint32_t i, uint32_t j)
 * Generates J1, J2 as specified in Argon2d data dependent indexing
 */
uint64_t Argon2d_generate_values(Argon2_global_workspace* B, uint32_t i, uint32_t j){

        uint64_t* block = 0;
        uint64_t J;
        j += B->q*(j==0); 
        if(Argon2_matrix_get_block(i,j-1,&block,B))
                ERROR("A2M:: Invalid indeces, reading random bytes from RAM");

        memcpy(&J,block,8);

        return J;

}

/**
 * @fn void Argon2i_generate_values(Argon2_global_workspace* B, Argon2_local_workspace* args)
 * Generates 128 pairs (J1,J2) t.b.u. in the data independent indexing function for Argon2i and Argon2id
 */
void Argon2i_generate_values(Argon2_global_workspace* B, Argon2_local_workspace* args){

        uint64_t zeros[A2I_PAIRS_NUMBER];
        uint64_t input[A2I_PAIRS_NUMBER];

        memset(zeros,0,A2I_PAIRS_NUMBER*sizeof(uint64_t));      // Build auxiliary input [0...0]
                                                                // Build input [r||l||s||m||t||x||i||0..0]
        input[0] = B->r;                                        // r: pass
        input[1] = args->l;                                     // l: lane
        input[2] = B->s;                                        // s: slice
        input[3] = B->m;                                        // m: total memory
        input[4] = B->t;                                        // t: total number f passes
        input[5] = B->x;                                        // x: Argon2 type number
        input[6] = args->i;                                     // i: counter of generate_values applications

        memset(input+7, 0, 121*sizeof(uint64_t));               // Remaining 968 positions are 0x00

        A2_G(zeros, input, args->pairs, B->S, B->x);            // Run G(0,G(0,Input));
        A2_G(zeros, args->pairs, args->pairs, B->S, B->x);

        args->i++;                                              // Increase counter of applications
        args->counter = 0;                                      // Restore counter of used blocks

}

/**
 * @fn uint64_t Argon2_indexing_mapping(Argon2_local_workspace* arg, Argon2_global_workspace* B, uint64_t J)
 * Maps the values J1, J2 into i',j', indeces of a referenciable block 
 */
uint64_t Argon2_indexing_mapping(Argon2_local_workspace* arg, Argon2_global_workspace* B, uint64_t J){

        uint64_t l;
        uint64_t referenceable_blocks;
        uint64_t first_referenceable_block;
        uint64_t index;
        uint32_t pair[2];

        pair[0] = (uint32_t)J;
        pair[1] = (uint32_t)(J >> 32); 

        l = pair[1] % B->p;

                                                                                // Compute R, set of referenceable blocks 
        if(B->r == 0){                                                          // First step

                if(B->s == 0){                                                  // First slice
                        referenceable_blocks = arg->c - 1;                      //   All computed blocks until now
                        l = arg->l;
                }
                else{                                                           // Successive Slices
                        if(l == arg->l)                                         //   Same lane
                                referenceable_blocks = B->s*B->segment_length   //     all blocks computed in lane but not overwritten
                                + (arg->c % B->segment_length) - 1;             //     excluded B[i][j-1]
                        else                                                    //   Different lanes
                                referenceable_blocks = B->s*B->segment_length   //     last s comuted segments
                                - ((arg->c % B->segment_length) == 0);          //     excluded the last element, if c is first of the
                                                                                //     slice
                }
                first_referenceable_block = 0;                                  // In any case, start from the beginning of the lane

        }else{                                                                  // Successive steps
                #ifdef FOLLOW_SPECS                                             // Remark: known issue, wrong implementation in phc winner code
                                                                                // Both the correct implementation and the wrong one provided
                        if(l == arg->l){                                        //   Same lane
                                referenceable_blocks = B->q-2;                  //     all blocks computed in lane but not overwritten yet 
                                first_referenceable_block = arg->c+1;           //     excluded B[i][j-1]  
                        }
                        else{                                                   //   Different lanes
                                referenceable_blocks = 3*B->segment_length -    //     last 3 computed segments
                                ((arg->c % B->segment_length) == 0);            //     excluded the last element, if c is first of the slice
                                first_referenceable_block = (B->s+1 % 4)*B->segment_length;
                        }

                #else

                        if(l == arg->l)                                         //   Same lane
                                referenceable_blocks = 3*B->segment_length +    //     all blocks computed in lane but not overwritten yet 
                                (arg->c % B->segment_length) - 1;               //     excluded B[i][j-1], starting from next segment     
                        else                                                    //     Different lanes
                                referenceable_blocks = 3*B->segment_length -    //     last 3 computed segments
                                ((arg->c % B->segment_length) == 0);            //     excluded the last element, if c is first of the slice

                        first_referenceable_block = (B->s+1 % 4)*B->segment_length; 
                         
                #endif
        }
                                                                                // Compute referenceable block
        index = pair[0];                                                        //   J
        index = (index*index) >> 32;                                            //   J^2 / 2^32 =: x
        index = (referenceable_blocks*index) >> 32;                             //   (|R|* x) / 2^32 =: y
        index = referenceable_blocks - 1 - index;                               //   (|R| - 1 - y) =: z
        index+= first_referenceable_block;                                      //   choose z-th block from the start of R
        index = index % B->q;                                                   //   |
        index^= ((uint64_t)l << 32);                                            //   Save index pair as ( lane || column ) 

        return index;

}

/*
 * @fn uint64_t Argon2_indexing(Argon2_global_workspace* B, Argon2_local_workspace* arg)
 * Handles the different indexing procedures, dependig on the type of Argon2
 */
uint64_t Argon2_indexing(Argon2_global_workspace* B, Argon2_local_workspace* arg){                      // If type is Argon2i or Argon2id and
                                                                                                        // we are in pas 0, slices 0,1, then
        if(B->x == A2I || ((B->x == A2ID) && (B->r == 0) && (B->s < 2))){                               // use data independent addressing
               
               #ifdef FOLLOW_SPECS

                if((arg->counter == A2I_PAIRS_NUMBER) || (arg->counter == 0))                           // generate values if necessary
                        Argon2i_generate_values(B,arg);
                        arg->counter++;
                return Argon2_indexing_mapping( arg, B, arg->pairs[(arg->counter-1)]);                  // map indeces

                #else

                if((arg->c % B->segment_length) % A2I_PAIRS_NUMBER == 0 || arg->counter == 0)           // generate values if necessary
                        Argon2i_generate_values(B,arg);
                
                arg->counter++;
                return Argon2_indexing_mapping( arg, B, arg->pairs[(arg->c % B->segment_length) % A2I_PAIRS_NUMBER]); 

                #endif 
        }                                                                                                                
        else                                                                                            // Otherwise just use data dependent
                return Argon2_indexing_mapping( arg, B, Argon2d_generate_values(B, arg->l, arg->c));    // p.r. and map indeces

}
