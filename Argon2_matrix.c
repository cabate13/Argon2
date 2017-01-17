#include "Argon2_matrix.h"
#include "Argon2_compression.h"

// Initializes the arguments for indexing
void Argon2_indexing_arguments_init(Argon2_indexing_arguments* args, uint32_t m, uint32_t t, uint32_t x){
        
        args->m = m;
        args->t = t;
        args->x = x;

        args->r = 0;
        args->l = 0;
        args->c = 0;
        args->s = 0;
        args->t = 0;
        args->i = 0;
        args->counter = 0;

}

// Initializes the matrix and sets its parameters
int Argon2_matrix_init(uint32_t m_raw, uint32_t p, Argon2_matrix* B){

        if(p == 0 || p > 0xFFFFFF || m_raw < 8*p)
                return 1;

        B->p = p;
        B->m = (m_raw/(4*p))*4*p;
        B->q = B->m/p;
        B->segment_length = B->q/4;
        B->matrix = (uint8_t*)malloc(B->m*1024);
        memset(B->matrix,0,B->m*1024);

        return 0;

}

// Fills the block in position (i,j) in the Argon2 matrix B with the content of the source block
int Argon2_matrix_fill_block(uint32_t i, uint32_t j, Argon2_matrix* dst, Argon2_block* src){

        if(i > (dst->p - 1) || j > (dst->q - 1))
                return 1;

        memcpy((dst->matrix)+1024*(j+dst->q*i),src->content,1024);
        return 0;

}

// Gets the block in position (i,j) in the Argon2 matrix B, storing the content in the dst block
int Argon2_matrix_get_block(uint32_t i, uint32_t j, Argon2_block* dst, Argon2_matrix* src){

        if(i > (src->p - 1) || j > (src->q - 1))
                return 1;

        memcpy(dst->content,(src->matrix)+1024*(j+src->q*i),1024);
        return 0;

}

// GC
void Argon2_matrix_free(Argon2_matrix* B){

        B->m = 0;
        B->p = 0;
        B->q = 0;
        free(B->matrix);
        B->matrix = NULL;

}

// Generates J1, J2 as specified in Argon2d: data dependent
uint64_t Argon2d_generate_values(Argon2_matrix* B, uint32_t i, uint32_t j){

        Argon2_block buffer;
        uint32_t J[2];
        j += B->q*(j==0);
        if(Argon2_matrix_get_block(i,j-1,&buffer,B))
                printf("A2M:: Warning: invalid indeces, reading random bytes from RAM\n");
        memcpy(J,buffer.content,8);

        return *((uint64_t*)J);

}

// Generates 128 pairs (J1,J2) t.b.u. in the data independent indexing function:
// data independent
void Argon2i_generate_values(Argon2_indexing_arguments* arg){

        uint64_t zeros[128];
        uint64_t input[128];

        memset(zeros,0,128*sizeof(uint64_t));

        input[0] = arg->r;
        input[1] = arg->l;
        input[2] = arg->s;
        input[3] = arg->m;
        input[4] = arg->t;
        input[5] = arg->x;
        input[6] = arg->i;
        input[7] = 0;

        memset(input+8, 0, 120*sizeof(uint64_t));

        CompressionFunctionG(zeros, input, arg->pairs);
        CompressionFunctionG(zeros, arg->pairs, arg->pairs);

        arg->i++;
        arg->counter = 0;
}

uint64_t Argon2_indexing_mapping(Argon2_indexing_arguments* arg, Argon2_matrix* B, uint64_t J){

        uint64_t l;
        uint64_t referenceable_blocks;
        uint64_t first_referenceable_block;
        uint64_t index;
        uint32_t pair[2];

        pair[0] = (uint32_t)J;
        pair[1] = (uint32_t)(J >> 32);

        // Compute total referenceable blocks
        if(arg->r == 0 && arg->s == 0)
                l = arg->l;
        else
                l = pair[1] % B->p;

        if(l == arg->l){
                // Computed blocks in that lane except c-1: |0 .. c-2|
                referenceable_blocks = arg->c-1;
                first_referenceable_block = 0;
        }
        else{
                // Last three finished segments [i.e. the other three] | start of next segment ... |
                // This is three segments long and starts in the next segment. If it is the case exclude
                // last block.
                referenceable_blocks = 3*B->segment_length - ((arg->c % B->segment_length) == 0);
                first_referenceable_block = (arg->c/B->segment_length + 1) * B->segment_length;
        }

        // Compute referenceable block
        index = pair[0];
        index = (index*index) >> 32;
        index = (referenceable_blocks*index) >> 32;
        index = referenceable_blocks - 1 - index;
        index+= first_referenceable_block;
        index = index % B->q;
        index^= ((uint64_t)l << 32);

        return index;

}

uint64_t Argon2_indexing(Argon2_indexing_arguments* arg, Argon2_matrix* B){

        if(arg->x){
                if(arg->counter == 128 || arg->counter == 0)
                        Argon2i_generate_values(arg);
                arg->counter++;
                return Argon2_indexing_mapping( arg, B, arg->pairs[arg->counter-1]);
        }
        else
                return Argon2_indexing_mapping( arg, B, Argon2d_generate_values(B, arg->l, arg->c));

}


