# Argon2
Argon2_AdvancedProgramming16/17

Per compilare:

$ make

make options:

(°) debug = 1 -> compile with flag -ggdb, creating the table of symbols
(°) genkat = 1 -> compile with -DTEST, compiling a test main that creates the genkat test vectors as in the phc winner implementation
(°) follow-specifications = 1 -> compile with -DFOLLOW_SPECIFICATION, strictly following the Argon2 specification

exa.: $ make debug=1 genkat=1 -> Provides the table of symbols and compiles a test main. 

Per cancellare i file oggetto e altri file di debug

$ make clean

Per eliminare Argon2

$ make purge