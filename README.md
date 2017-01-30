# Argon2
Argon2_AdvancedProgramming16/17

Per compilare:

$ make

make options:

(°) debug = 1 -> compile with flag -ggdb, creating the table of symbols
(°) follow-specifications = 1 -> compile with -DFOLLOW_SPECIFICATION, strictly following the Argon2 specification

exa.: $ make debug=1  

Regole del makefile:

Per creare un main di test, che compari l'hash generato con la versione ufficiale della phc release:

$ make test

Per creare una versione di argon2 o del test per argon2 su cui fare un'analisi della memoria usata:

$ make bad_memory

o

$ make test_bad_memory

Per creare un benchmark che valuti le prestazioni di Argon2 su diversi parametri:

$ make bench

Per cancellare i file oggetto e altri file evenutalmente creati:

$ make clean

Per eliminare completamente Argon2:

$ make purge
