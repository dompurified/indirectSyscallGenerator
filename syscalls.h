#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <winternl.h>

#define ___initializeAllSyscalls()\
i(OpenProcess, PHANDLE, ACCESS_MASK, OBJECT_ATTRIBUTES*, CLIENT_ID*)\
i(WriteVirtualMemory, HANDLE, void*, void*, size_t, size_t*)\
i(ReadVirtualMemory, HANDLE, void*, void*, size_t, size_t*)\
i(Close, HANDLE)\

#define STATUS_SUCCESS 0

EXTERN_C_START
#define i(f,...)DWORD sysnum_Nt##f;void* stub_Nt##f;
#define j(f,...)i(f)
___initializeAllSyscalls() // sysnums && stubs
#undef i
#define j(r,c,f,...)r c sys##f(##__VA_ARGS__);
#define i(...)j(long,NTAPI,##__VA_ARGS__)
___initializeAllSyscalls() // functions definitions
#undef i
EXTERN_C_END

// syscall info
#if defined(__cplusplus)
#include "../sdk/xorstr.hpp" // change path
#include "../sdk/lazy_importer.hpp"
#endif
typedef struct SyscallInfo {
    DWORD n;
    void* s;
} SyscallInfo;
SyscallInfo sys_gsi(uint8_t* function) { // note: this isnt perfect and might lead to false positives, doesnt really matter most of the time in ntdll cuz the functions are so small
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
#define s(z)_(z)
#else
#define s(z)z
#endif
#ifdef LI_FN
#define l(f)LI_FN(f)
#else
#define l(f)f
#endif
#define i(f,...){auto p=(uint8_t*)l(GetProcAddress)(ntdll,s("Nt"#f));if(!p)return false;auto i=sys_gsi(p);if(!i.s||!i.n)return false;sysnum_Nt##f=i.n;stub_Nt##f=i.s;}
bool initializeSyscalls() {
    auto ntdll = l(GetModuleHandleW)(s(L"ntdll.dll")); if (!ntdll)return false;
        ___initializeAllSyscalls()
    return true;
}


#undef s
#undef l
#undef i

