debug = 0
genkat = 0
follow-specifications = 0
CFLAGS += -fopenmp
CC = gcc
UNAME_S := $(shell uname -s)

# Handle debug version
ifeq ($(debug), 1)
	CFLAGS += -ggdb
endif
# Handle OS compilation [use gcc-6 from homebrew]
ifeq ($(UNAME_S),Darwin)
	CC=gcc-6 
endif
# Handle genkat tests
ifneq ($(genkat),0)
	CFLAGS += -DTEST
endif
# Handle specification v.s. phc-implementation discrepancies
ifneq ($(follow-specifications),0)
	CFLAGS += -DFOLLOW_SPECS
endif

Argon2: Blake2b.o Argon2_compression.o Argon2_matrix.o Argon2_body.o
	$(CC) $@.c $? -o $@ $(CFLAGS) 

Blake2b:
	$(CC) -o $@.o -c $@.c $(CFLAGS)

Argon2_compression: 
	$(CC) -o $@.o .c $@.c $(CFLAGS)

Argon2_matrix: 
	$(CC) -o $@.o -c $@.c $(CFLAGS)

Argon2_body: 
	$(CC) -o $@.o -c $@.c $(CFLAGS)

.PHONY : clean purge
clean:
	-rm *.o
	-rm -rf *.dSYM
purge: clean
	-rm Argon2

