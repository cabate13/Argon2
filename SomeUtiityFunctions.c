//Some Utility functions

/*
* Utility function. Takes in input a matrix and an array and copy the content of the matrix into the array, 
* row (col) is the number of rows (columns) of the matrix.
*/
void matrixToArray(uint128_t** M, uint128_t* a, int row, int col);

/*
* Utility function. Takes in input a matrix and an array and copy the content of the array into the matrix, 
* row (col) is the number of rows (columns) of the matrix
*/
void arrayToMatrix(uint128_t* a, uint128_t** M, int row, int col);

/*
* Utility function. It perform the malloc of a matrix with elements of type uint128_t
*/
uint128_t** matrixMalloc(uint128_t** M, int row, int col);

/*
*Utility function. It free the memory occupied by a matrix
*/
void matrixFree(uint128_t** M, int row);

/*
* Utility function. It computes the transpose of a given matrix
*/
uint128_t** transpose(uint128_t** M, int row, int col);


void matrixToArray(uint128_t** M, uint128_t* a, int row, int col)
{
        for (int i = 0; i < row; ++i)
        {
                for (int j = 0; j < col; j++)
                {
                        a[j + col*i] = M[i][j];
                }

        }
}

void arrayToMatrix(uint128_t* a, uint128_t** M, int row, int col)
{
        for (int i = 0; i < row; i++)
        {
                for (int j = 0; i < col; j++)
                {
                       M[i][j] = a[j + col*i];
                }
        }
}

uint128_t** matrixMalloc(uint128_t** M, int row, int col)
{
        M = (uint128_t**) malloc(16*row);

        for (int i = 0; i < row; ++i)
        {
                M[i] = (uint128_t*) malloc(16*col);
        }

        return M;
}

void matrixFree(uint128_t** M, int row)
{
        for (int i = 0; i < row; i++)
        {
                free(M[i]);
        }

        free(M);
}

uint128_t** transpose(uint128_t** M, int row, int col)
{
	uint128_t** T;
	T = matrixMalloc(T,col,row);

        for (int i = 0; i < row; i++)
        {
                for (int j = 0; j < col; j++)
                {
                        T[i][j] = M[j][i];
                }
        }
        
    return T;
}