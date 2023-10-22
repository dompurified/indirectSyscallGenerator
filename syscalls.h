// note: some function names (like NtCreateProcess) are going to be defined as i(CreateProcess, ...)
// however, since CreateProcess in windows.h is defined as CreateProcess[A/W], it actually turns to NtCreateProcess[A/W]
// thus, i recommend checking your windows.h macro definitions, and if your definitions collides with a windows.h macro, 
// #undef CreateProcess
// #define INIT_SYSCALLS()\ 
// i(CreateProcess, ...)
// #ifndef _UNICODE
// #define CreateProcess CreateProcessA
// #else
// #define CreateProcess CreateProcessW
// #endif

#define INIT_SYS