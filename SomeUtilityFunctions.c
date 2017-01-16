//Some Utility functions

#include <stdio.h>
#include <stdlib.h>
#include "blake2b.h"
#include "SomeUtilityFunctions.h"

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
                for (int j = 0; j < col; j++)
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