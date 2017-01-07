# Compile libraries

gcc -o blake2b.o -c blake2b.c 
gcc -o Argon2_compression.o -c Argon2_compression.c 
gcc -o Argon2_matrix.o -c Argon2_matrix.c 
gcc -o SomeUtilityFunctions.o -c SomeUtilityFunctions.c 

# Compile executables and link libraries

gcc blake2btest.c blake2b.o -o blake2btest 
gcc Argon2_compression_test.c blake2b.o Argon2_compression.o SomeUtilityFunctions.o -o Argon2_compression_test
#gcc Argon2_matrix_testing.c blake2b.o Argon2_compression.o Argon2_matrix.o -o Argon2_matrix_test

# Clean leftovers

rm *.o >> /dev/null
