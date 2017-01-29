/**
* @file
* Interface for memory management and context separation for parallel computation
*/

#if !defined A2_MATRIX


#define A2_MATRIX
/**
* @def 
* size of data blocks in Argon2 matrix
*/
#define A2_MATRIX_BLOCK_LENGTH 1024
#define A2I_PAIRS_NUMBER 128

#include "Argon2_compression.h"

/**
 * @struct
 * Global workspace, fixed for all the parallel threads. Contains all the shared data between independent segment computations
 */
typedef struct{

        uint64_t* matrix;
        //! degree of parallelism
        uint32_t p;
        //! number of columns in the matrix
        uint32_t q;
        //! pass number
        uint64_t r;
        //! Total memory blocks
        uint64_t m;
        //! Slice number
        uint64_t s;
        //! total passes number
        uint64_t t;
        //! type number
        uint64_t x;

        uint32_t segment_length;
	//! S-Box for Argon2ds
	uint64_t* S;

}Argon2_global_workspace;

/**
 * @struct
 * Local workspace, one for each independent thread. Contains specific data for each parallel segment computation
 */
typedef struct{

        //! lane number
        uint64_t l;
        //! column number
        uint64_t c;
        //! counter [reset for every segment]
        uint64_t i;
        //! place to save the 128 pairs in argon2i
        uint64_t pairs[A2I_PAIRS_NUMBER];
        //! used pairs counter
        uint64_t counter;

}Argon2_local_workspace;

/**
 * @fn int Argon2_global_workspace_init(uint32_t m, uint32_t p, uint32_t t, uint32_t x, Argon2_global_workspace* B)
 * Initializes the global workspace, allocating space for the matrix and setting parameters according to Argon2 input
 */
int Argon2_global_workspace_init(uint32_t m, uint32_t p, uint32_t t, uint32_t x, Argon2_global_workspace* B);

/**
 * @fn int Argon2_matrix_get_block(uint32_t i, uint32_t j, uint64_t** dst, Argon2_global_workspace* src)
 * Gets the block in position (i,j) in the Argon2 matrix B, storing a pointer to it in dst
 */
int Argon2_matrix_get_block(uint32_t i, uint32_t j, uint64_t** dst, Argon2_global_workspace* src);

/**
 * @fn uint64_t Argon2_indexing(Argon2_global_workspace* B, Argon2_local_workspace* arg)
 * Indexing function, computes (i',j'), given the current position
 */
uint64_t Argon2_indexing(Argon2_global_workspace* B, Argon2_local_workspace* arg);

/**
 * @fn void Argon2_global_workspace_free(Argon2_global_workspace* B)
 * Safely deallocates memory used in the global workspace
 */
void Argon2_global_workspace_free(Argon2_global_workspace* B);

#endif
