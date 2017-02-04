# Argon2
Argon2_AdvancedProgramming16/17

A complete overview of this implementation can be found in html/index.html, alongside with a complete guide for building the main executable and few others utility executables.

Compilation:

$ make

make options:

(°) debug = 1 -> compile with flag -ggdb, creating the table of symbols
(°) follow-specifications = 1 -> compile with -DFOLLOW_SPECIFICATION, strictly following the Argon2 specification  

Makefile rules:

$ make test

Creates a test executable, in order to compare this implementation with the official one

$ make clean
$ make purge

The former cleans object files and test executables, the latter completely removes previous builds.
