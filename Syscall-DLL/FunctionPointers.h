#pragma once

#include <Windows.h>

// https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya
//
typedef HMODULE(WINAPI* fnLoadLibraryA)(IN LPCSTR lpLibFileName);



// https://learn.microsoft.com/en-us/windows/win32/api/threadpoolapiset/nf-threadpoolapiset-createthreadpooltimer
//
typedef PTP_TIMER(WINAPI* fnCreateThreadpoolTimer)(IN PTP_TIMER_CALLBACK pfnti, IN OUT OPTIONAL PVOID pv, IN OPTIONAL PTP_CALLBACK_ENVIRON pcbe);



// https://learn.microsoft.com/en-us/windows/win32/api/threadpoolapiset/nf-threadpoolapiset-setthreadpooltimer
//
typedef void (WINAPI* fnSetThreadpoolTimer)(IN OUT PTP_TIMER pti, IN OPTIONAL PFILETIME pftDueTime, IN DWORD msPeriod, IN DWORD msWindowLength);


typedef NTSTATUS(WINAPI* fnNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

// https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
//
typedef DWORD(WINAPI* fnWaitForSingleObject)(IN HANDLE hHandle, IN DWORD dwMilliseconds);



// https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler
//
typedef PVOID(WINAPI* fnAddVectoredExceptionHandler)(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler);



// https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-removevectoredexceptionhandler
//
typedef ULONG(WINAPI* fnRemoveVectoredExceptionHandler)(PVOID Handle);


typedef HMODULE(WINAPI* fnLoadLibraryA)(LPCSTR lpLibFileName);

typedef LPVOID(WINAPI* fnVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

typedef BOOL(WINAPI* fnVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

typedef BOOLEAN(WINAPI* fnRtlAddFunctionTable)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);

typedef NTSTATUS(NTAPI* fnNtFlushInstructionCache)(HANDLE hProcess, PVOID BaseAddress, ULONG NumberOfBytesToFlush);

typedef BOOL(WINAPI* fnDllMain)(HINSTANCE, DWORD, LPVOID);