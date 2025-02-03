#pragma once

#include <Windows.h>
#include <winternl.h>

#include <stdio.h>

#define		EXPORTED_FUNC_NAME		"ReflectiveFunction"

#define ALLOC(SIZE)				LocalAlloc(LPTR, (SIZE_T)SIZE)
#define FREE(BUFF)				LocalFree((LPVOID)BUFF)
#define REALLOC(BUFF, SIZE)		LocalReAlloc(BUFF, SIZE,  LMEM_MOVEABLE | LMEM_ZEROINIT)

BOOL ReadReflectiveDll(IN LPWSTR szFileName, OUT PBYTE* ppFileBuffer, OUT PDWORD pdwFileSize);
DWORD RVA2Offset(IN DWORD dwRVA, IN PBYTE pBaseAddress);
DWORD GetReflectiveFunctionOffset(IN ULONG_PTR uRflDllBuffer);
BOOL GetRemoteProcessHandle(IN LPWSTR szProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess);
BOOL InjectAndRunRflDll(IN HANDLE hProcess, IN DWORD dwRflFuncOffset, IN PBYTE pRflDllBuffer, IN DWORD dwRflDllSize);