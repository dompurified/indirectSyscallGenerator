# IndirectSyscallGenerator
### How to use
1. add \ to last line of INIT_SYSCALLS macro (syscalls.h)
1. add `i(X, Y, Z)` where your ntdll function's prototype is this: NTSTATUS(NTAPI* NtX)(Y, Z);
1. run `node syscallExtracter.js`
1. paste your macro into the script
1. paste output into syscalls.asm

note 1: if you want to change the function return type and/or calling convention, use j(ret, __calling_convention, function) instead of i(function)<br>
note to note 1: the j macro isn't supported yet in the js script<br>
note 2: you have to change lazyimporter and xorstr locations (they are optional and you can just remove the #include's)<br>
note 3: you have to call init_syscalls() at the start of your program, or else you'll get STATUS_ACCESS_VIOLATION for jumping to the syscall stub, which isn't initialized, thus nullptr
