#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <cstdint>

// note: windows.h has macro defs for some functions, e.g. CreateProcess
// i recommend #undef'ing them before using i in your INIT_SYSCALLS macro

#define INIT_SYSCALLS()\
i(OpenProcess, HANDLE* pOutHandle, ACCESS_MASK desiredAccess, OBJECT_ATTRIBUTES* pObjectAttributes, CLIENT_ID* pClientId)

// ^^^^^^^^^^^^^^^^^^^^^^^^^^
// your ntdll & syscall definitions

#define STRING_OBFUSCATE(string) string
// ^^^^^^^^^^^^^^^^^^^^^^^^^^
// your string obfuscation function


// indirectSyscallGenerator code (don't change unless you know what you're doing)
// ˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅

/*
* @brief initializes indirect syscalls (github.com/dompurified/indirectSyscallGenerator)
*/
bool initSyscalls();


#undef i
#undef j
