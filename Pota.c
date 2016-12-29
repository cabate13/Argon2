//Blake2b

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

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

	
	uint64_t a = 1024*1024 ;

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


void CoreG(uint64_t* a, uint64_t* b, uint64_t* c, uint64_t* d)
{
	uint32_t al = (*a>>32) & 0xffffffff;
	uint32_t bl = (*b>>32) & 0xffffffff;
	uint32_t cl = (*c>>32) & 0xffffffff;
	uint32_t dl = (*d>>32) & 0xffffffff;

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
	CoreG((uint64_t*)S, (uint64_t*)(S+4), (uint64_t*)(S+8), (uint64_t*)(S+12));
	CoreG((uint64_t*)(S+1), (uint64_t*)(S+5),(uint64_t*)(S+9),(uint64_t*)(S+13));
	CoreG((uint64_t*)(S+2), (uint64_t*)(S+6), (uint64_t*)(S+10), (uint64_t*)(S+14));
	CoreG((uint64_t*)(S+3), (uint64_t*)(S+7), (uint64_t*)(S+11), (uint64_t*)(S+15));
	CoreG((uint64_t*)S, (uint64_t*)(S+5), (uint64_t*)(S+10), (uint64_t*)(S+15));
	CoreG((uint64_t*)(S+1), (uint64_t*)(S+6), (uint64_t*)(S+11), (uint64_t*)(S+12));
	CoreG((uint64_t*)(S+2), (uint64_t*)(S+7), (uint64_t*)(S+8), (uint64_t*)(S+13));
	CoreG((uint64_t*)(S+3), (uint64_t*)(S+4), (uint64_t*)(S+9), (uint64_t*)(S+14));
}

