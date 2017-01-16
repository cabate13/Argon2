//Operation
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "CompressionFunction.h"
#include "blake2b.h"
#include "Argon2_matrix.h"

//function computing a block  
//tau is the 32 bit tag length
//ZeroOne is to discriminate amonge B[][0] and B[][1]
//p is a parameter coming from Haven
void ComputeFirstBlock01(Argon2_matrix* B, uint8_t* H0, uint8_t tau, int ZeroOne, Argon2_indexing_arguments arguments);

void ComputeFirstBlock(Argon2_matrix* B, uint8_t*H0, uint8_t tau, Argon2_indexing_arguments arguments);

void ComputeThBlock(Argon2_matrix* B, Argon2_indexing_arguments arguments);

/*
* Function to get th final block, remember to initialize Bfinal.content to the vector of all zeros
*/
void BFinal(Argon2_matrix* B, Argon2_block* Bfinal);


void ComputeFirstBlock01(Argon2_matrix* B, uint8_t* H0, uint8_t tau, int ZeroOne, Argon2_indexing_arguments arguments)
{
	uint8_t Zero[4] = [0,0,0,0];
	uint8_t One[4] = [64,64,64,64];

	uint8_t* HprimeInput;
	HprimeInput = (uint8_t*) malloc(sizeof(uint8_t)*72); // 64 for H0 + 4 + 4

	memcpy(HprimeInput, H0, 64); //copy H0 into HprimeInput

	for(int i=0; i< B.p; i++)
	{
		
		if(ZeroOne)
		{
			memcpy(HprimeInput+64, One, 4)
		}

		else 
		{
			memcpy(HprimeInput+64, Zero, 4);
		}

		uint8_t arrayI[4] = {i,i,i,i};

		memcpy(HprimeInput+68, arrayI, 4);

		Argon2_block block;

		//apply Hprime and print if something went wrong
		if(!Argon2_matrix_get_block(i, ZeroOne, block, B))
		{
			Hprime(HprimeInput, 72, tau, block.content);
		}
		else
		{
			printf("ERROR\n");
		}

		if(Argon2_matrix_fillblock(i,ZeroOne,B,block))
		{
			printf("ERROR\n");
		}

	}

}


void ComputeFirstBlock(Argon2_matrix* B, uint8_t*H0, uint8_t tau, Argon2_indexing_arguments arguments)
{
	ComputeFirstBlock01(B,H0,tau,0);
	ComputeFirstBlock01(B,H0,tau,1);

	uint64_t iprime;
	uint64_t jprime;

	Argon2_block* block = (Argon2_block*) malloc(sizeof(Argon2_block));
	Argon2_block* indexedBlock = (Argon2_block*) malloc(sizeof(Argon2_block));
	Argon2_block* Bij = (Argon2_block*) malloc(sizeof(Argon2_block));

	//setting the arguments for indexing...
	//Argon2_indexing_arguments arguments;
	//arguments.r = 1; //first pass
	//arguments.l = 1; //we have p lanes, so we must increment l each time we increment i
	//arguments.s = 1; //we have 4 slice, we must increment s  at (1/4)*q,(2/4)*q,.. q
	//arguments.t =    //the total number of passes
	//arguments.i = 1; //it must be set again to 1 each time we start a new segment, a new segment starts exactly when slice counter is incremented

	for (int i = 0; i < B.p; ++i)
	{
		for (int j = 2; j < B.q; ++j)
		{
			iprime = Argon2_indexing(arguments, B);
			iprime = iprime >> 32;
			jprime = iprime ^ 0x00000000FFFFFFFF;

			//take the block needed
			if(!(Argon2_matrix_get_block(i,j-1, B, block) || Argon2_matrix_get_block(iprime,jprime, B,indexedBlock)))
			{
				G((uint64_t*)block, (uint64_t*)indexedBlock, (uint64_t*)(Bij.content)); //compute G(B[i][j-1], B[i'][j'])
				if(! Argon2_matrix_fillblock(i,j,B,Bij)); //and set B[i][j] equal to this value
				else
					printf("ERROR\n");
			}
			else
				{printf("ERROR\n");}

			if((j == q/4 || j == q/2 || j == (3/4)*q))
				{
					arguments.s++;
					arguments.i = 1;
				}	

			arguments.i++; //arguments.i must be incremented at every iteration
		}

		arguments.l++;

	}

	//free memory
	free(block);
	free(indexedBlock);
	free(Bij);
}

void ComputeThBlock(Argon2_matrix* B, Argon2_indexing_arguments arguments)
{

	uint64_t iprime;
	uint64_t jprime;

	Argon2_block* block = (Argon2_block*) malloc(sizeof(Argon2_block));
	Argon2_block* indexedBlock = (Argon2_block*) malloc(sizeof(Argon2_block));
	Argon2_block* Bij = (Argon2_block*) malloc(sizeof(Argon2_block));

	int myJ; //is q-1 if j=0 and j othewrise in the following loop

	//setting the arguments for indexing...
	//Argon2_indexing_arguments arguments;
	//arguments.r = 1; //first pass
	//arguments.l = 1; //we have p lanes, so we must increment l each time we increment i
	//arguments.s = 1; //we have 4 slice, we must increment s  at (1/4)*q,(2/4)*q,.. q
	//arguments.t =    //the total number of passes
	//arguments.i = 1; //it must be set again to 1 each time we start a new segment, a new segment starts exactly when slice counter is incremented

	for (int i = 0; i < B.p; ++i)
	{
		for (int j = 0; j < B.q; ++j)
		{

			if(j){ myJ = j;}
			else{myJ = B.q;}

			iprime = Argon2_indexing(arguments, B);
			iprime = iprime >> 32;
			jprime = iprime ^ 0x00000000FFFFFFFF;

			//take the block needed
			if(!(Argon2_matrix_get_block(i, myJ-1, B, block) || Argon2_matrix_get_block(iprime,jprime, B,indexedBlock)))
			{
				G((uint64_t*)block, (uint64_t*)indexedBlock, (uint64_t*)(Bij.content)); //compute G(B[i][j-1], B[i'][j'])

				int a = Argon2_matrix_get_block(i,myJ,B,block); //take the block B[i][0] at step t

				XOR128((uint64_t*)(Bij.content), (uint64_t*)block.content, (uint64_t*)(Bij.content)); //XOR with B[i][0]

				if(! Argon2_matrix_fillblock(i,j,B,Bij)); //and set B[i][j] equal to this value
				else
					printf("ERROR\n");
			}
			else
				{printf("ERROR\n");}

			if((j == q/4 || j == q/2 || j == (3/4)*q))
				{
					arguments.s++;
					arguments.i = 1;
				}	

			arguments.i++; //arguments.i must be incremented at every iteration
		}

		arguments.l++;

	}

	//free memory
	free(block);
	free(indexedBlock);
	free(Bij);
	
}
	
void BFinal(Argon2_matrix* B, Argon2_block* Bfinal)
{
	Argon2_block block;

	for (int i = 0; i < B.p; ++i)
	{
		if(Argon2_matrix_get_block(i, (B.q)-1, block,B))
			printf("ERROR\n");

		XOR128((uint64_t*)Bfinal.content, (uint64_t*)block.content, (uint64_t*) Bfinal.content,128);
	}
}