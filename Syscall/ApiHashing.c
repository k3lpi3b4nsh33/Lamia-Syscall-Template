#include <Windows.h>

#include "Structs.h"
#include "Common.h"
#include "FunctionPointers.h"

// Function to get the address of a function by its hash
FARPROC GetProcAddressH(IN HMODULE hModule, IN UINT32 uApiHash)
{
	PBYTE	pBase                      = (PBYTE)hModule;
	PIMAGE_NT_HEADERS pImgNtHdrs       = NULL;
	PIMAGE_EXPORT_DIRECTORY pImgExpdir = NULL;
	PDWORD	pdwFunctionNameArray       = NULL;
	PDWORD	pdwFunctionAddressArray    = NULL;
	PWORD	pwFunctionOrdinalArray      = NULL;
	DWORD	dwImgExportDirSize         = 0x00;

	// Check for invalid module or hash
	if (!hModule || !uApiHash)
	{
#ifdef DEBUG
		printf("GetProcessAddressH Failed!!");
#endif
		return NULL;
	}

	// Get the NT headers of the module
	pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + ((PIMAGE_DOS_HEADER)pBase)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
		return NULL;
	}

	// Get the export directory and related arrays
	pImgExpdir              = (PIMAGE_EXPORT_DIRECTORY)(pBase + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	dwImgExportDirSize      = pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	pdwFunctionNameArray    = (PDWORD)(pBase + pImgExpdir->AddressOfNames);
	pdwFunctionAddressArray = (PDWORD)(pBase + pImgExpdir->AddressOfFunctions);
	pwFunctionOrdinalArray   = (PWORD)(pBase + pImgExpdir->AddressOfNameOrdinals);

	// Iterate over all exported functions
	for (DWORD i = 0; i < pImgExpdir->NumberOfFunctions; i++) {

		CHAR* pFunctionName = (CHAR*)(pBase + pdwFunctionNameArray[i]);
		PVOID	pFunctionAddress = (PVOID)(pBase + pdwFunctionAddressArray[pwFunctionOrdinalArray[i]]);

		// Check if the hash matches
		if (CHASH(pFunctionName) == uApiHash) {

			// Handle forwarded functions
			if ((((ULONG_PTR)pFunctionAddress) >= ((ULONG_PTR)pImgExpdir)) &&
				(((ULONG_PTR)pFunctionAddress) < ((ULONG_PTR)pImgExpdir) + dwImgExportDirSize)
				) {

				CHAR	cForwarderName[MAX_PATH] = { 0 };
				DWORD	dwDotOffset = 0x00;
				PCHAR	pcFunctionMod = NULL;
				PCHAR	pcFunctionName = NULL;

				// Copy the forwarder name
				Memcpy(cForwarderName, pFunctionAddress, strlen((PCHAR)pFunctionAddress));

				// Find the dot in the forwarder name
				for (int i = 0; i < strlen((PCHAR)cForwarderName); i++) {

					if (((PCHAR)cForwarderName)[i] == '.') {
						dwDotOffset = i;
						cForwarderName[i] = '\0';
						break;
					}
				}

				pcFunctionMod = cForwarderName;
				pcFunctionName = cForwarderName + dwDotOffset + 1;

				// Load the library and get the function address
				fnLoadLibraryA pLoadLibraryA = (fnLoadLibraryA)GetProcAddressH(GetModuleHandleH(kernel32dll_CH), LoadLibraryA_CH);
				if (pLoadLibraryA)
					return GetProcAddressH(pLoadLibraryA(pcFunctionMod), CHASH(pcFunctionName));
			}
			return (FARPROC)pFunctionAddress;
		}

	}

	return NULL;
}

// Function to get the module handle by its hash
HMODULE GetModuleHandleH(IN UINT32 uModuleHash) {

	PPEB					pPeb = NULL;
	PPEB_LDR_DATA			pLdr = NULL;
	PLDR_DATA_TABLE_ENTRY	pDte = NULL;

	// Get the PEB (Process Environment Block)
	pPeb = (PPEB)__readgsqword(0x60);
	pLdr = (PPEB_LDR_DATA)(pPeb->LoaderData);
	pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

	// Return the handle of the local .exe image if no hash is provided
	if (!uModuleHash)
		return (HMODULE)(pDte->InInitializationOrderLinks.Flink);

	// Iterate over the loaded modules
	while (pDte) {

		if (pDte->FullDllName.Buffer && pDte->FullDllName.Length < MAX_PATH) {

			CHAR	cLDllName[MAX_PATH] = { 0 };
			DWORD	x = 0x00;

			// Convert the DLL name to lowercase
			while (pDte->FullDllName.Buffer[x]) {

				CHAR	wC = pDte->FullDllName.Buffer[x];

				// Convert to lowercase
				if (wC >= 'A' && wC <= 'Z')
					cLDllName[x] = wC - 'A' + 'a';
				// Copy other characters (numbers, special characters ...)
				else
					cLDllName[x] = wC;

				x++;
			}

			cLDllName[x] = '\0';

			// Check if the hash matches
			if (CHASH(pDte->FullDllName.Buffer) == uModuleHash || CHASH(cLDllName) == uModuleHash)
				return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
		}

		// Move to the next node in the linked list
		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
	}

	return NULL;
}