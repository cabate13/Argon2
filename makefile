# Compile libraries

gcc-6 -o blake2b.o -c blake2b.c 
gcc-6 -o Argon2_compression.o -c Argon2_compression.c 
gcc-6 -o Argon2_matrix.o -c Argon2_matrix.c 
gcc-6 -o Argon2_body.o -c Argon2_body.c -fopenmp
# Compile executables and link libraries

gcc-6 blake2btest.c blake2b.o -o blake2btest 
gcc-6 Argon2_compression_test.c blake2b.o Argon2_compression.o -o Argon2_compression_test
gcc-6 Argon2_matrix_test.c blake2b.o Argon2_compression.o Argon2_matrix.o -o Argon2_matrix_test
gcc-6 Argon2.c blake2b.o Argon2_compression.o Argon2_matrix.o Argon2_body.o -o Argon2 -fopenmp

# Clean leftovers

rm *.o >> /dev/null
