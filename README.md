## Quick start
Pass a path to an executable file, either a Windows .exe (a PE file)
or a Linux executable (an ELF file). The executable must be compiler
for either x86 or amd64 platform. You need debug symbols either
in the file or in an associated .pdb.

    $ symtree a.out

The tool will print the list of all symbols with non-zero size in the executable.
For each symbol it prints the list of symbols on which the former depends.
It also prints the size of the symbol and the total size of itself and its dependencies.

For instance, in the following example, the function `main` calls function `foo`.

    4007b0 main 61 470
        40077d 51 409 _Z3fooi
    40077d _Z3fooi 51 409
        400804 50 358 _ZN1BC2Ei
    ...

Here, the function `main` is 61 bytes long, `foo` is 51 bytes long.
However `foo` depends on even more functions (in this case,
a constructor `B::B`). Put together, all dependencies of `main`
take 409 bytes and with 61 bytes from `main` it needs 470 bytes
in total.

## Known limitations
 * Only x86 and amd64 binaries are supported.
 * The sources currently only build on Windows (but Linux binaries
   can still be processed, only not on Linux).
 * For Windows binaries, data symbols are not visible. Therefore,
   class constructors will not see their virtual tables
   and virtual functions will not be included in the contructors'
   sizes.
 * Exception handling code is generally not visible for any platform.
 * Some functions have zero size (typically those written in assembler
   or those compiled long long ago), those will not be visible.
