@echo off

call getcomp.bat rosbe

set opts=-std=c99 -mconsole -Os -s -Wall -Wextra -DNONMMAP_FALLBACK
set link=
set compiles=src\main.c src\mman.c
set outname=.\bin\decryptry

del %outname%.exe
gcc -o %outname%.exe %compiles% %opts% %link% 2> %outname%_err.log
IF %ERRORLEVEL% NEQ 0 (
    echo oops %outname%!
    pause
)