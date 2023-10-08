#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>

// note: some function names (like NtCreateProcess) are going to be defined as i(CreateProcess, ...)
// however, since CreateProcess in windows.h is defined as CreateProcess[A/W], it actually turns to NtCreateProcess[A/W]
// thus, i recommend checking your windows.h macro definitions, and if your definitions collides with a windows.h macro, 
// #undef CreateProcess
// #define ___initializeAllSyscalls()\ 
// i(CreateProcess, ...)
// #ifndef _UNICODE
// #define CreateProcess CreateProcessA
// #else
// #define CreateProcess CreateProcessW
// #endif

#define ___initializeAllSyscalls()\
i(OpenProcess, PHANDLE, ACCESS_MASK, OBJECT_ATTRIBUTES*, CLIENT_ID*)\
i(WriteVirtualMemory, HANDLE, void*, void*, size_t, size_t*)\
i(ReadVirtualMemory, HANDLE, void*, void*, size_t, size_t*)\
i(Close, HANDLE)\

// ^^^^^^^^^^^^^^^^^^^^^^^^^^
// your function definitions

// xorstr and lazy_importer imports
// ˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅
#if defined(__cplusplus)
#include "../sdk/xorstr.hpp" // change path
#include "../sdk/lazy_importer.hpp"
#endif

// indirectSyscallGenerator code (don't change unless you know what you're doing)
// ˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅

#define STATUS_SUCCESS 0

EXTERN_C_START
#define i(f,...)DWORD sysnum_Nt##f;void* stub_Nt##f;
#define j(r,c,f,...)i(f)
___initializeAllSyscalls() // sysnums && stubs
#undef i
#define j(ret, convention, func, ...) ret convention sys##func(##__VA_ARGS__);
#define i(...) j(long /* NTSTATUS */, NTAPI /* __stdcall*/, ##__VA_ARGS__)
___initializeAllSyscalls() // functions definitions
#undef i
EXTERN_C_END

// syscall info
#if defined(__cplusplus)
#include "../sdk/xorstr.hpp" // change path
#include "../sdk/lazy_importer.hpp"
#endif
typedef struct SyscallInfo {
    DWORD sysnum;
    void* stub;
} SyscallInfo;
SyscallInfo getSyscallInfo(uint8_t* function) { // note: this isnt perfect and might lead to false positives, doesnt really matter most of the time in ntdll cuz the functions are so small
    uint32_t sysnum{};
    uint8_t* stub{};
    for (uint8_t i = 0; i < 100; ++i, ++function) {
        if (*function == 0xB8) sysnum = *(DWORD*)(function + 1);
        if (*function == 0x0F && function[1] == 0x05) stub = function;
        if (stub && sysnum) break;
    }

    return SyscallInfo{
        sysnum,
        stub,
    };
}


#ifdef _
#define xorstring_or_string(string) _(string)
#elseif defined(xorstr_)
#define xorstring_or_string(string) xorstr_(string)
#else
#define xorstring_or_string(string) string
#endif
#ifdef LI_FN
#define li_fn_or_fn(func) LI_FN(func)
#else
#define li_fn_or_fn(func) f
#endif
// before, this macro was a complete mess. i don't exactly know why i chose to do it like it, but i decided to change it
#define i(func,...) {\
    auto ntdllFunc = (uint8_t*)li_fn_or_fn(GetProcAddress)(ntdll, xorstring_or_string("Nt" #func));\
    if (!ntdllFunc) return 0;\
    auto info = getSyscallInfo(ntdllFunc);
    if (!info.stub || !info.sysnum) return 0;\
    sysnum_Nt##func = info.sysnum; stub_Nt##func = info.stub;\ // sysnum_NtOpenProcess = info.sysnum;
}
#define j(ret,convention,func,...) i(func)
bool initializeSyscalls() {
    auto ntdll = li_fn_or_fn(GetModuleHandle)(xorstring_or_string(_T("ntdll.dll"))); if (!ntdll) return 0;
    ___initializeAllSyscalls()
    return 1;
}


#undef xorstring_or_string
#undef li_fn_or_fn
#undef i
#undef j

