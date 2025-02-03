// dllmain.cpp : Defines the entry point for the DLL application.

#include "Reflective.h"
#include "Debug.h"
#ifdef DEBUG

extern __declspec(dllexport) VOID MsgboxFunc() {
    MessageBoxA(NULL, "Hello RDI func work well!", "Leviathan", MB_OK | MB_ICONINFORMATION);
}

#endif

#define PIPE_NAME "\\\\.\\pipe\\MyReflectivePipe"

DWORD WINAPI PipeClientThread(LPVOID lpParam)
{
    HANDLE hPipe;
    char buffer[512];
    DWORD bytesRead, bytesWritten;

    while (TRUE)
    {
        hPipe = CreateFileA(
            PIPE_NAME,              
            GENERIC_READ | GENERIC_WRITE, 
            0, NULL,                
            OPEN_EXISTING,          
            0, NULL
        );

        if (hPipe != INVALID_HANDLE_VALUE)
            break;

        Sleep(1000);
    }

    PRINT("[+] Connected to injector pipe!\n");

   
    DWORD dataSize = 0;
    PVOID buffer2 = NULL;

    if (!ReadFile(hPipe, &dataSize, sizeof(DWORD), &bytesRead, NULL)) {
            PRINT("[-] ReadFile for dataSize failed: %d\n", GetLastError());
    }
    else {
            PRINT("[+] datasize: %d (bytesRead: %d)\n", dataSize, bytesRead);
            Sleep(500);
     }


    // **Reading PVOID**
    
        if (ReadFile(hPipe, &buffer2, sizeof(PVOID), &bytesRead, NULL)) {
            PRINT("[+] pAddr: 0x%p (bytesRead: %d)\n", buffer2, bytesRead);
        }
        else {
            PRINT("[+] datasize: 0x%p (bytesRead: %d)\n", buffer2, bytesRead);
            Sleep(500);
        }
    CloseHandle(hPipe);


    PRINT("Wait 15s to free area!\n");
    Sleep(15000);
    
    PRINT("FREE RDI_INJECTION AREA:\n");
    if (!VirtualFree(buffer2, 0, MEM_RELEASE)) {
        PRINT("[-] VirtualFree failed! Error: %d\n", GetLastError());
    }
    else {
        PRINT("[+] Successfully freed memory at: 0x%p\n", buffer2);
    }
    return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: {
#ifdef DEBUG
        
        CreateDebugConsole();
        CreateThread(NULL, 0, PipeClientThread, NULL, 0, NULL);
        MsgboxFunc();
#endif // DEBUG
        break;

    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
