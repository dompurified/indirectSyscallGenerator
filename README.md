# indirect syscall generator
### ⚠ warn
this project is in a half-broken state. you can take inspiration from it, but i wouldn't recommend using it. <br/>
<br/>
`main.cpp`
```cpp
int main() {
    if (!initSyscalls()) {
        std::println("[!] failed to initialize syscalls");
        return EXIT_FAILURE;
    }

    const DWORD pid{ 1337 };

    HANDLE processHandle;
    OBJECT_ATTRIBUTES objectAttributes{};
    CLIENT_ID clientId{
        .UniqueProcess = (HANDLE)(std::uintptr_t)pid,
    };
    if (const NTSTATUS status{ sysOpenProcess(&processHandle, PROCESS_ALL_ACCESS, &objectAttributes, &clientId) }; status != STATUS_SUCCESS) {
        std::println("[!] failed to open process [{}]", (unsigned)status);
        return EXIT_FAILURE;
    }

    std::println("[+] open handle to process! [0x{:X}]", (std::uintptr_t)processHandle);
    return EXIT_SUCCESS;
}
```
`syscalls.h`
```cpp
#define INIT_SYSCALLS()\
i(OpenProcess, HANDLE* pOutHandle, ACCESS_MASK desiredAccess, OBJECT_ATTRIBUTES* pObjectAttributes, CLIENT_ID* pClientId)\
i(AnotherSyscall, A a, B b) /* NTSTATUS NTAPI NtAnotherSyscall(A a, B b); */

// ^^^^^^^^^^^^^^^^^^^^^^^^^^
// your ntdll & syscall definitions

#define STRING_OBFUSCATE(string) string
// ^^^^^^^^^^^^^^^^^^^^^^^^^^
// your string obfuscation function


// indirectSyscallGenerator code (don't change unless you know what you're doing)
// ˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅˅
// ...
```
**note** 1: if you want to change the function return type and/or calling convention, use j(ret, __calling_convention, function) instead of i(function)<br>
**note** 2: the j macro isn't supported yet in the js script<br>
