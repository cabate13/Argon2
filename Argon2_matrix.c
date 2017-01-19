#include "Argon2_matrix.h"

// Initializes the matrix and sets its parameters
int Argon2_global_workspace_init(uint32_t m, uint32_t p, uint32_t t, uint32_t x, Argon2_global_workspace* B){

        // Matrix initialization
        if(p == 0 || p > 0xFFFFFF || m < 8*p)
                return 1;

        B->p = p;
        B->m = (m/(4*p))*4*p;
        B->q = B->m/p;
        B->segment_length = B->q/4;
        B->matrix = (uint8_t*)malloc(B->m*1024);
        memset(B->matrix,0,B->m*1024);

        // Global parameters initialization
        B->t = t;
        B->x = x;
        B->r = 0;
        B->s = 0;

        return 0;

}

// Fills the block in position (i,j) in the Argon2 matrix B with the content of the source block
int Argon2_matrix_fill_block(uint32_t i, uint32_t j, Argon2_global_workspace* dst, Argon2_block* src){

        if(i > (dst->p - 1) || j > (dst->q - 1))
                return 1;

        memcpy((dst->matrix)+1024*(j+dst->q*i),src->content,1024);
        return 0;

}

// Gets the block in position (i,j) in the Argon2 matrix B, storing the content in the dst block
int Argon2_matrix_get_block(uint32_t i, uint32_t j, Argon2_block* dst, Argon2_global_workspace* src){

        if(i > (src->p - 1) || j > (src->q - 1))
                return 1;

        memcpy(dst->content,(src->matrix)+1024*(j+src->q*i),1024);
        return 0;

}

// GC
void Argon2_global_workspace_free(Argon2_global_workspace* B){

        free(B->matrix);
        B->matrix = NULL;

}

// Generates J1, J2 as specified in Argon2d: data dependent
uint64_t Argon2d_generate_values(Argon2_global_workspace* B, uint32_t i, uint32_t j){

        Argon2_block buffer;
        uint32_t J[2];
        j += B->q*(j==0);
        if(Argon2_matrix_get_block(i,j-1,&buffer,B))
                ERROR("A2M:: Invalid indeces, reading random bytes from RAM");
        memcpy(J,buffer.content,8);

        return *((uint64_t*)J);

}

// Generates 128 pairs (J1,J2) t.b.u. in the data independent indexing function:
// data independent
void Argon2i_generate_values(Argon2_global_workspace* gl_arg, Argon2_local_workspace* lo_arg){

        uint64_t zeros[128];
        uint64_t input[128];

        memset(zeros,0,128*sizeof(uint64_t));           // Build auxiliary input [0...0]
                                                        // Build input [r||l||s||m||t||x||i||0..0]
        input[0] = gl_arg->r;                           // r: pass
        input[1] = lo_arg->l;                           // l: lane
        input[2] = gl_arg->s;                           // s: slice
        input[3] = gl_arg->m;                           // m: total memory
        input[4] = gl_arg->t;                           // t: total number f passes
        input[5] = gl_arg->x;                           // x: Argon2 type number
        input[6] = lo_arg->i;                           // i: counter of generate_values applications

        memset(input+7, 0, 121*sizeof(uint64_t));       // Remaining 968 positions are 0x00

        A2_G(zeros, input, lo_arg->pairs);              // Run G(0,G(0,Input));
        A2_G(zeros, lo_arg->pairs, lo_arg->pairs);

        lo_arg->i++;                                    // Increase counter of applications
        lo_arg->counter = 0;                            // Restore counter of used blocks
}

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

                if(B->s == 0)                                                   // First slice
                        referenceable_blocks = arg->c - 1;                      //   All computed blocks until now

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

                if(l == arg->l)                                                 //   Same lane
                        referenceable_blocks = 3*B->segment_length +            //     all blocks computed in lane but not overwritten yet 
                        (arg->c % B->segment_length) - 1;                       //     excluded B[i][j-1]     
                else                                                            //   Different lanes
                        referenceable_blocks = 3*B->segment_length -            //     last 3 computed segments
                        ((arg->c % B->segment_length) == 0);                    //     excluded the last element, if c is first of the slice

                first_referenceable_block = (B->s+1 % 4)*B->segment_length;     // In any case, start counting from the beginning of the 
                                                                                // next segment
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

uint64_t Argon2_indexing(Argon2_global_workspace* B, Argon2_local_workspace* arg){                      // If type is Argon2i or Argon2id and
                                                                                                        // we are in pas 0, slices 0,1, then
        if(B->x == 1 || ((B->x == 2) && (B->r == 0) && (B->s < 2))){                                    // use data independent addressing
                if(arg->counter == 128 || arg->counter == 0)                                            // generate values if necessary
                        Argon2i_generate_values(B,arg);
                arg->counter++;
                return Argon2_indexing_mapping( arg, B, arg->pairs[arg->counter-1]);                    // map indeces
        }
        else                                                                                            // Otherwise just use data dependent
                return Argon2_indexing_mapping( arg, B, Argon2d_generate_values(B, arg->l, arg->c));    // p.r. and map indeces

}


