debug = 0
follow-specifications = 0
CFLAGS += -fopenmp 
BAD_MEMORY_FLAGS = -g -std=c99
CC = gcc
UNAME_S := $(shell uname -s)
SRC = Blake2b.o Argon2_compression.o Argon2_matrix.o Argon2_body.o
DST = Argon2



# Handle debug version
ifeq ($(debug), 1)
	CFLAGS += -ggdb
endif
# Handle OS compilation [use gcc-6 from homebrew]
ifeq ($(UNAME_S),Darwin)
	CC=gcc-6 
endif
# Handle specification v.s. phc-implementation discrepancies
ifneq ($(follow-specifications),0)
	CFLAGS += -DFOLLOW_SPECS
endif

$(DST): $(SRC)
	$(CC) $@.c $? -o $@ $(CFLAGS) 

Blake2b:
	$(CC) -o $@.o -c $@.c $(CFLAGS)

Argon2_compression: 
	$(CC) -o $@.o .c $@.c $(CFLAGS)

Argon2_matrix: 
	$(CC) -o $@.o -c $@.c $(CFLAGS)

Argon2_body: 
	$(CC) -o $@.o -c $@.c $(CFLAGS)

TEST : $(SRC)
	$(CC) $@.c $? -o $@ $(CFLAGS)

bad_memory : $(SRC)
	$(CC) $(DST).c $? -o $(DST) $(CFLAGS) $(BAD_MEMORY_FLAGS) 

TEST_bad_memory : $(SRC)
	$(CC) $(BAD_MEMORY_FLAGS) TEST.c $? -o TEST $(CFLAGS) 


.PHONY : clean purge
clean:
	-rm *.o
	-rm -rf *.dSYM
	-rm TEST
purge: clean
	-rm Argon2

