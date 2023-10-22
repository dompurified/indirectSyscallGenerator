#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdint.h>

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

#define INIT_SYSCALLS()\
i(OpenProcess, HANDLE*, ACCESS_MASK, OBJECT_ATTRIBUTES*, CLIENT_ID*)

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
// global vars with syscall nums && syscall stubs
#define i(func,...) DWORD sysnum_Nt##func;\
					void* stub_Nt##func; 	// DWORD sysnum_NtOpenProcess; 	// 0x123
										 	// void* stub_NtOpenProcess; 	// ntdll!NtOpenProcess + 0x123

#define j(ret, convention, func, ...) i(func)

INIT_SYSCALLS()

#undef i
#undef j

// function defs

#define j(ret, convention, func, ...) ret convention sys##func(##__VA_ARGS__); // NTSTATUS NTAPI sysOpenProcess(HANDLE*, ACCESS_MASK, OBJECT_ATTRIBUTES*, CLIENT_ID*)
#define i(func, ...) j(long /* NTSTATUS */, NTAPI /* __stdcall*/, func, ##__VA_ARGS__)

INIT_SYSCALLS()

#undef i
#undef j
EXTERN_C_END

// make using xorstr/lazyimporter optional
#ifdef _
#define xorstring_or_string(string) _(string)
#elif defined(xorstr_)
#define xorstring_or_string(string) xorstr_(string)
#else
#define xorstring_or_string(string) string
#endif
#ifdef LI_FN
#define li_fn_or_fn(func) LI_FN(func)
#else
#define li_fn_or_fn(func) func
#endif

// get module base && function base from peb
#if defined(__cplusplus)
extern "C" TEB* get_teb_x64();
extern "C" TEB* get_teb_x86();
#if defined(_WIN64)
#define get_teb get_teb_x64
#else
#define get_teb get_teb_x86
#endif
#include <vector>
#include <string_view>
#include <optional>

std::wstring_view get_file_name(const std::wstring_view& path) {
	return path.substr(path.find_last_of(L'\\') + 1);
}

std::vector<const LDR_DATA_TABLE_ENTRY*> get_loader_table_entries(const PEB* const p_peb) {
	std::vector<const LDR_DATA_TABLE_ENTRY*> entries;

	for (const LIST_ENTRY* p_current_entry{ &p_peb->Ldr->InMemoryOrderModuleList };;) {
		p_current_entry = p_current_entry->Flink;
		if (p_current_entry == &p_peb->Ldr->InMemoryOrderModuleList)
			break;

		const LDR_DATA_TABLE_ENTRY* const p_module_entry{ CONTAINING_RECORD(p_current_entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks) };
		entries.push_back(p_module_entry);
	}

	return entries;
}

class c_function {
public:
	const char* const name;
	const std::uint8_t* const address;
};
std::optional<std::vector<c_function>> get_eat_functions(const std::uint8_t* const module) {
	const auto p_dos_headers{ reinterpret_cast<const IMAGE_DOS_HEADER*>(module) };
	if (p_dos_headers->e_magic != IMAGE_DOS_SIGNATURE)
		return std::nullopt;
	const auto p_nt_headers{ reinterpret_cast<const IMAGE_NT_HEADERS*>(module + p_dos_headers->e_lfanew) };
	if (p_nt_headers->Signature != IMAGE_NT_SIGNATURE)
		return std::nullopt;


	const auto p_eat{ reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(module + p_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) };
	const auto address_of_names{ reinterpret_cast<const std::uint32_t*>(module + p_eat->AddressOfNames) };
	const auto address_of_functions{ reinterpret_cast<const std::uint32_t*>(module + p_eat->AddressOfFunctions) };
	const auto address_of_ordinals{ reinterpret_cast<const std::uint16_t*>(module + p_eat->AddressOfNameOrdinals) };

	std::vector<c_function> functions;
	for (std::uint32_t i{}; i < p_eat->NumberOfNames; ++i) {
		const auto name{ reinterpret_cast<const char*>(module + address_of_names[i]) };
		const std::uint16_t ordinal{ address_of_ordinals[i] };
		const std::uint8_t* const p_function{ reinterpret_cast<const uint8_t*>(module + address_of_functions[ordinal]) };

		functions.push_back({
			.name = name,
			.address = p_function,
			});
	}

	return functions;
}
const std::uint8_t* get_function_by_name(const std::uint8_t* const module, const std::string_view name) {
	const std::optional<std::vector<c_function>> functions{ get_eat_functions(module) };
	if (!functions)
		return nullptr;
	for (const c_function& function : *functions) {
		if (name.compare(function.name) == 0)
			return function.address;
	}

	return nullptr;
}

std::uint8_t* get_module_base(const PEB* const p_peb, const std::wstring_view& module_name) {
	for (const LDR_DATA_TABLE_ENTRY* p_entry : get_loader_table_entries(p_peb)) {
		const std::wstring file_name{ get_file_name(p_entry->FullDllName.Buffer) };
		if (module_name.compare(file_name) == 0) {
			return reinterpret_cast<std::uint8_t*>(p_entry->DllBase);
		}
	}

	return nullptr;
}
#define GET_MODULE_BASE(name) get_module_base(get_teb()->ProcessEnvironmentBlock, name)
#define GET_FUNC_ADDR(module, name) get_function_by_name(module, name)
#else
#define GET_MODULE_BASE(name) (uint8_t*)li_fn_or_fn(GetModuleHandleW)(name)
#define GET_FUNC_ADDR(module, name) (uint8_t*)li_fn_or_fn(GetProcAddress)((HMODULE)module, name)
#endif

// syscall info
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

// before, this macro was a complete mess. i don't exactly know why i chose to do it like it, but i decided to change it
#define i(func,...) {\ // 									  "NtOpenProcess"
    auto ntdllFunc = GET_FUNC_ADDR(ntdll, xorstring_or_string("Nt" #func)); \ // ntdll!NtOpenProcess
    if (!ntdllFunc) return 0; \ // false
    auto syscall_info = getSyscallInfo(ntdllFunc); \
	if (!syscall_info.stub || !syscall_info.sysnum) \
		return 0; \ // false
    sysnum_Nt##func = info.sysnum;\ // sysnum_NtOpenProcess = 0x123;
	stub_Nt##func = info.stub;\		// stub_NtOpenProcess = ntdll!NtOpenProcess + 0x123;
}
#define j(ret, convention, func,...) i(func)

bool init_syscalls() {
    auto ntdll = GET_MODULE_BASE(xorstring_or_string(L"ntdll.dll")); \
	if (!ntdll) \
		return 0; \ // false
	INIT_SYSCALLS() \
    return 1; \ // true
}


#undef xorstring_or_string
#undef li_fn_or_fn
#undef i
#undef j
