//CoreG

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

/*
* Utility function, it takes the left part of an integer represented by 64 bits
*/
uint32_t getLeft(uint64_t x);

/*
* Function G, see pages 18 - 19
*/
void CoreG(uint64_t* a, uint64_t* b, uint64_t* c, uint64_t* d);

/*
* Blake2b but it does not look like a permutation...
*/
void Blake2b(uint64_t* S);


// a Test
int main(void)
{

	
	uint64_t a = 123456 ;

	uint64_t S[16];

	for (int i = 0; i < 16; ++i)
	{
		S[i] = a*(i+1);
	}

	for (int i = 0; i < 16; ++i)
	{
		printf("%lu\n", S[i]);
	}

	printf("FINE\n");

 	Blake2b((uint64_t*)&S);

 	
 	for (int i = 0; i < 16; ++i)
	{
		printf("%lu\n", S[i]);
	}

	
	return 0;	

}


uint32_t getLeft(uint64_t x)
{
	
	uint32_t xl;
	memcpy(&xl, &x +sizeof(xl), sizeof(xl));
	return xl;
}

void CoreG(uint64_t* a, uint64_t* b, uint64_t* c, uint64_t* d)
{
	uint32_t al = getLeft(*a);
	uint32_t bl = getLeft(*b);
	uint32_t cl = getLeft(*c);
	uint32_t dl = getLeft(*d);

	*a = *a + *b + 2*al*bl;
	*d = (*d ^ *a) >> 32;
	*c = *c + *d + 2*cl*dl;
	*b = (*b ^ *c) >> 24;
	*a = *a + *b + 2*al*bl;
	*d = (*d ^ *a) >> 16;
	*c = *c + *d + 2*cl*dl;
	*b = (*b ^ *c) >> 63;
}


void Blake2b(uint64_t* S)
{
	CoreG((uint64_t*)S, (uint64_t*)S+4, (uint64_t*)S+8, (uint64_t*)S+12);
	CoreG((uint64_t*)S+1, (uint64_t*)S+5,(uint64_t*)S+9,(uint64_t*)S+13);
	CoreG((uint64_t*)S+2, (uint64_t*)S+6, (uint64_t*)S+10, (uint64_t*)S+14);
	CoreG((uint64_t*)S+3, (uint64_t*)S+7, (uint64_t*)S+11, (uint64_t*)S+15);
	CoreG((uint64_t*)S+0, (uint64_t*)S+5, (uint64_t*)S+10, (uint64_t*)S+15);
	CoreG((uint64_t*)S+1, (uint64_t*)S+6, (uint64_t*)S+11, (uint64_t*)S+12);
	CoreG((uint64_t*)S+2, (uint64_t*)S+7, (uint64_t*)S+8, (uint64_t*)S+13);
	CoreG((uint64_t*)S+3, (uint64_t*)S+4, (uint64_t*)S+9, (uint64_t*)S+14);
}

