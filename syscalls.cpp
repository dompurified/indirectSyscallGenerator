#include <cstdint>
#include <string_view>
#include "syscalls.h"

extern "C" {
	// global vars with syscall nums && syscall stubs

#define i(func,...) DWORD sysnum_Nt##func;\
					const std::uint8_t* stub_Nt##func;
#define j(ret, convention, func, ...) i(func)

	INIT_SYSCALLS()

#undef i
#undef j

	// function defs

													//	long 	__stdcall 	sysOpenProcess(...)
#define 				j(ret, 	convention, func, ...)	ret		convention 	sys##func(##__VA_ARGS__);
#define i(func, ...) 	j(long, __stdcall, 	func, ##__VA_ARGS__)

	INIT_SYSCALLS()

#undef i
#undef j
}

// get module base & function base from peb
const std::uint8_t* getExportAddress(const std::uint8_t* const module, const std::string_view exportName) {
	// check header signatures
	const auto pDosHeaders{ reinterpret_cast<const IMAGE_DOS_HEADER*>(module) };
	if (pDosHeaders->e_magic != IMAGE_DOS_SIGNATURE) {
		return nullptr;
	}
	const auto pNtHeaders{ reinterpret_cast<const IMAGE_NT_HEADERS*>(module + pDosHeaders->e_lfanew) };
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return nullptr;
	}


	// get eat address
	const auto pEat{ reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(module + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) };

	// get function name, ordinal, addresses pointers
	const auto pNames{		reinterpret_cast<const std::uint32_t*>(module + pEat->AddressOfNames) };
	const auto pFunctions{	reinterpret_cast<const std::uint32_t*>(module + pEat->AddressOfFunctions) };
	const auto pOrdinals{	reinterpret_cast<const std::uint16_t*>(module + pEat->AddressOfNameOrdinals) };

	for (std::uint32_t i{}; i < pEat->NumberOfNames; ++i) {
		const auto name{						reinterpret_cast<const char*>(module + pNames[i]) };
		const std::uint16_t ordinal{			pOrdinals[i] };
		const std::uint8_t* const pFunction{	reinterpret_cast<const uint8_t*>(module + pFunctions[ordinal]) };

		if (exportName.compare(name) == 0) {
			return pFunction;
		}
	}

	return nullptr;
}

std::uint8_t* getModuleBase(const PEB* const pPeb, const std::wstring_view& moduleName) {
	const LIST_ENTRY* const initialEntry{ &pPeb->Ldr->InMemoryOrderModuleList }; // store initial entry for list endmark
	for (const LIST_ENTRY* pEntry{ initialEntry };;) {
		pEntry = pEntry->Flink; // get next entry
		if (pEntry == initialEntry) {
			break;
		}

		const LDR_DATA_TABLE_ENTRY* const pModule{ CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks) };
		if (moduleName.compare(pModule->FullDllName.Buffer) == 0) { // compare module names
			return reinterpret_cast<std::uint8_t*>(pModule->DllBase);
		}
	}

	return nullptr;
}

// initialize
#define i(func,...) {\
	std::uint8_t startSignature[] = { 0x4C, 0x8B, 0xD1, 0xB8 };\
	std::uint8_t syscallRetSignature[] = { 0x0F, 0x05, 0xC3 };\
\
	/* get eat address */\
	const std::uint8_t* const ntdllFunction{ getExportAddress(ntdll, STRING_OBFUSCATE("Nt" #func)) };\
	if (!ntdllFunction) {\
		/* return from initSyscalls */\
		return false;\
	}\
\
	/* edr hook detection */\
	if (memcmp(ntdllFunction, startSignature, sizeof(startSignature)) != 0){\
		/* return from initSyscalls */\
		return false;\
	}\
	if (memcmp(ntdllFunction + 0x12, syscallRetSignature, sizeof(syscallRetSignature)) != 0){\
		/* return from initSyscalls */\
		return false;\
	}\
\
	/* set globals */\
	sysnum_Nt##func =	*reinterpret_cast<const DWORD*>(ntdllFunction + 0x4); \
	stub_Nt##func =		ntdllFunction + 0x12; \
}
#define j(ret, convention, func,...) i(func)

TEB* getTeb() { return reinterpret_cast<TEB*>(__readgsqword(0x30)); };

bool initSyscalls() {
	const std::uint8_t* const ntdll{ getModuleBase(getTeb()->ProcessEnvironmentBlock, STRING_OBFUSCATE(L"C:\\Windows\\SYSTEM32\\ntdll.dll")) };
	if (!ntdll) {
		return false;
	}

	INIT_SYSCALLS();

	return true;
}