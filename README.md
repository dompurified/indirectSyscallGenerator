# IndirectSyscallGenerator
### How to use (for pasters)
1. stop being a paster
### How to use (for pwn1337h4xorz)
1. add \ to last line of ___initializeAllSyscalls macro (syscalls.h)
1. add `i(X, Y, Z)` where your ntdll function's prototype is this: NTSTATUS(NTAPI* ntX)(Y, Z);
1. run `node syscallExtracter.js`
1. paste your macro into the script
1. paste output into syscalls.asm

note: you have to change lazyimporter and xorstr locations (they are optional and you can just remove the #include's)
⭐ please star bro, i'd appreciate it a lot
> this project didn't take a lot to make, but i really don't want pasters ruining it. if you don't know what indirect syscalls are or how to use them, i'd recommend you to actually implement them manually