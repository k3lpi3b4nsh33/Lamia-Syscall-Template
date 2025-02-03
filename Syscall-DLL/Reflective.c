#include "Reflective.h"
#include <stdio.h>



BOOL FixImportAddressTable(IN PIMAGE_DATA_DIRECTORY pEntryImportDataDir, IN PBYTE pPeBaseAddress) {

	// Pointer to an import descriptor for a DLL
	PIMAGE_IMPORT_DESCRIPTOR	pImgDescriptor = NULL;
	// Iterate over the import descriptors
	for (SIZE_T i = 0; i < pEntryImportDataDir->Size; i += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
		// Get the current import descriptor
		pImgDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(pEntryImportDataDir->VirtualAddress + pPeBaseAddress + i);
		// If both thunks are NULL, we've reached the end of the import descriptors list
		if (pImgDescriptor->OriginalFirstThunk == NULL && pImgDescriptor->FirstThunk == NULL)
			break;

		// Retrieve LoadLibraryA's function pointer via API hashing
		fnLoadLibraryA	pLoadLibraryA = (fnLoadLibraryA)GetProcAddressH(GetModuleHandleH(kernel32dll_CH), LoadLibraryA_CH);
		// Retrieve information from the current import descriptor
		LPSTR			cDllName = (LPSTR)((ULONGLONG)pPeBaseAddress + pImgDescriptor->Name);
		ULONG_PTR		uOriginalFirstThunkRVA = pImgDescriptor->OriginalFirstThunk;
		ULONG_PTR		uFirstThunkRVA = pImgDescriptor->FirstThunk;
		SIZE_T			ImgThunkSize = 0x00;
		HMODULE			hModule = NULL;

		// If OriginalFirstThunk is NULL, fallback to FirstThunk
		/*
		if (uOriginalFirstThunkRVA == NULL)
			uOriginalFirstThunkRVA = uFirstThunkRVA;
		*/

		if (!pLoadLibraryA)
			return FALSE;

		// Try to load the DLL referenced by the current import descriptor
		if (!(hModule = pLoadLibraryA(cDllName)))
			return FALSE;

		// Iterate over the imported functions for the current DLL
		while (TRUE) {
			// Get pointers to the first thunk and original first thunk data
			PIMAGE_THUNK_DATA			pOriginalFirstThunk = (PIMAGE_THUNK_DATA)(pPeBaseAddress + uOriginalFirstThunkRVA + ImgThunkSize);
			PIMAGE_THUNK_DATA			pFirstThunk = (PIMAGE_THUNK_DATA)(pPeBaseAddress + uFirstThunkRVA + ImgThunkSize);
			PIMAGE_IMPORT_BY_NAME		pImgImportByName = NULL;
			ULONG_PTR					pFuncAddress = NULL;

			// At this point both 'pOriginalFirstThunk' & 'pFirstThunk' will have the same values
			// However, to populate the IAT (pFirstThunk), one should use the INT (pOriginalFirstThunk) to retrieve the 
			// functions addresses and patch the IAT (pFirstThunk->u1.Function) with the calculated address.
			if (pOriginalFirstThunk->u1.Function == NULL && pFirstThunk->u1.Function == NULL) {
				break;
			}

			// If the ordinal flag is set, import the function by its ordinal number
			if (IMAGE_SNAP_BY_ORDINAL(pOriginalFirstThunk->u1.Ordinal)) {
				// Since our GetProcAddressH function doesn't support ordinals as input, one can fetch the function address via the following code:

				// Retrieve required headers of the loaded DLL module
				PIMAGE_NT_HEADERS		_pImgNtHdrs = NULL;
				PIMAGE_EXPORT_DIRECTORY	_pImgExportDir = NULL;
				PDWORD					_pdwFunctionAddressArray = NULL;

				_pImgNtHdrs = ((ULONG_PTR)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew);
				if (_pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
					return FALSE;
				_pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(((ULONG_PTR)hModule) + _pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
				_pdwFunctionAddressArray = (PDWORD)((ULONG_PTR)hModule + _pImgExportDir->AddressOfFunctions);
				// Use the ordinal to retrieve the function address
				pFuncAddress = ((ULONG_PTR)hModule + _pdwFunctionAddressArray[pOriginalFirstThunk->u1.Ordinal]);

				if (!pFuncAddress) {
					return FALSE;
				}
			}
			// Import function by name
			else {
				pImgImportByName = (PIMAGE_IMPORT_BY_NAME)((SIZE_T)pPeBaseAddress + pOriginalFirstThunk->u1.AddressOfData);
				if (!(pFuncAddress = (ULONG_PTR)GetProcAddressH(hModule, CHASH(pImgImportByName->Name)))) {
					return FALSE;
				}
			}

			// Install the function address in the IAT
			pFirstThunk->u1.Function = (ULONGLONG)pFuncAddress;

			// Move to the next function in the IAT/INT array
			ImgThunkSize += sizeof(IMAGE_THUNK_DATA);

		}
	}

	return TRUE;
}
BOOL FixMemPermissions(IN ULONG_PTR pPeBaseAddress, IN PIMAGE_NT_HEADERS pImgNtHdrs, IN PIMAGE_SECTION_HEADER pImgSecHdr) {

	fnVirtualProtect	pVirtualProtect = NULL;

	if (!(pVirtualProtect = (fnVirtualProtect)GetProcAddressH(GetModuleHandleH(kernel32dll_CH), VirtualProtect_CH)))
		return FALSE;

	// Loop through each section of the PE image.
	for (DWORD i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {

		// Variables to store the new and old memory protections.
		DWORD	dwProtection = 0x00,
			dwOldProtection = 0x00;

		// Skip the section if it has no data or no associated virtual address.
		if (!pImgSecHdr[i].SizeOfRawData || !pImgSecHdr[i].VirtualAddress)
			continue;

		// Determine memory protection based on section characteristics.
		// These characteristics dictate whether the section is readable, writable, executable, etc.
		if (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE)
			dwProtection = PAGE_WRITECOPY;

		if (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ)
			dwProtection = PAGE_READONLY;

		if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwProtection = PAGE_READWRITE;

		if (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
			dwProtection = PAGE_EXECUTE;

		if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE))
			dwProtection = PAGE_EXECUTE_WRITECOPY;

		if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwProtection = PAGE_EXECUTE_READ;

		if ((pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ))
			dwProtection = PAGE_EXECUTE_READWRITE;

		// Apply the determined memory protection to the section.
		if (!pVirtualProtect((PVOID)(pPeBaseAddress + pImgSecHdr[i].VirtualAddress), pImgSecHdr[i].SizeOfRawData, dwProtection, &dwOldProtection)) {
			return FALSE;
		}
	}

	return TRUE;
}
BOOL FixReloc(IN PIMAGE_DATA_DIRECTORY pEntryBaseRelocDataDir, IN ULONG_PTR pPeBaseAddress, IN ULONG_PTR pPreferableAddress) {

	// Pointer to the beginning of the base relocation block.
	PIMAGE_BASE_RELOCATION pImgBaseRelocation = (pPeBaseAddress + pEntryBaseRelocDataDir->VirtualAddress);

	// The difference between the current PE image base address and its preferable base address.
	ULONG_PTR uDeltaOffset = pPeBaseAddress - pPreferableAddress;

	// Pointer to individual base relocation entries.
	PBASE_RELOCATION_ENTRY pBaseRelocEntry = NULL;

	// Iterate through all the base relocation blocks.
	while (pImgBaseRelocation->VirtualAddress) {

		// Pointer to the first relocation entry in the current block.
		pBaseRelocEntry = (PBASE_RELOCATION_ENTRY)(pImgBaseRelocation + 1);

		// Iterate through all the relocation entries in the current block.
		while ((PBYTE)pBaseRelocEntry != (PBYTE)pImgBaseRelocation + pImgBaseRelocation->SizeOfBlock) {
			// Process the relocation entry based on its type.
			switch (pBaseRelocEntry->Type) {
			case IMAGE_REL_BASED_DIR64:
				// Adjust a 64-bit field by the delta offset.
				*((ULONG_PTR*)(pPeBaseAddress + pImgBaseRelocation->VirtualAddress + pBaseRelocEntry->Offset)) += uDeltaOffset;
				break;
			case IMAGE_REL_BASED_HIGHLOW:
				// Adjust a 32-bit field by the delta offset.
				*((DWORD*)(pPeBaseAddress + pImgBaseRelocation->VirtualAddress + pBaseRelocEntry->Offset)) += (DWORD)uDeltaOffset;
				break;
			case IMAGE_REL_BASED_HIGH:
				// Adjust the high 16 bits of a 32-bit field.
				*((WORD*)(pPeBaseAddress + pImgBaseRelocation->VirtualAddress + pBaseRelocEntry->Offset)) += HIWORD(uDeltaOffset);
				break;
			case IMAGE_REL_BASED_LOW:
				// Adjust the low 16 bits of a 32-bit field.
				*((WORD*)(pPeBaseAddress + pImgBaseRelocation->VirtualAddress + pBaseRelocEntry->Offset)) += LOWORD(uDeltaOffset);
				break;
			case IMAGE_REL_BASED_ABSOLUTE:
				// No relocation is required.
				break;
			default:
				// Unknown relocation types.
				return FALSE;
			}
			// Move to the next relocation entry.
			pBaseRelocEntry++;
		}

		// Move to the next relocation block.
		pImgBaseRelocation = (PIMAGE_BASE_RELOCATION)pBaseRelocEntry;
	}

	return TRUE;
}


extern __declspec(dllexport) BOOL ReflectiveFunction() {

	ULONG_PTR				uTmpAddress = NULL;	 // Tmp variable used to brute force the reflective DLL base address
	ULONG_PTR				uReflectiveDllModule = NULL;
	PIMAGE_DOS_HEADER		pImgDosHdr = NULL;
	PIMAGE_NT_HEADERS		pImgNtHdrs = NULL;
	PBYTE					pPeBaseAddress = NULL;
	fnDllMain				pDllMain = NULL;
	PE_HDRS					PeHdrs = { 0x00 };

	fnVirtualAlloc				pVirtualAlloc = NULL;
	fnRtlAddFunctionTable		pRtlAddFunctionTable = NULL;
	fnNtFlushInstructionCache	pNtFlushInstructionCache = NULL;

	// Use API hashing to retrieve the WinAPIs function pointers
	if (!(pVirtualAlloc = (fnVirtualAlloc)GetProcAddressH(GetModuleHandleH(kernel32dll_CH), VirtualAlloc_CH)))
		return FALSE;
	if (!(pRtlAddFunctionTable = (fnRtlAddFunctionTable)GetProcAddressH(GetModuleHandleH(kernel32dll_CH), RtlAddFunctionTable_CH)))
		return FALSE;
	if (!(pNtFlushInstructionCache = (fnNtFlushInstructionCache)GetProcAddressH(GetModuleHandleH(ntdlldll_CH), NtFlushInstructionCache_CH)))
		return FALSE;

	// Brute forcing ReflectiveDllLdr.dll's base address, starting at ReflectiveFunction's address
	uTmpAddress = (ULONG_PTR)ReflectiveFunction;

	do
	{
		pImgDosHdr = (PIMAGE_DOS_HEADER)uTmpAddress;

		// Check if the current uTmpAddress is a DOS header
		if (pImgDosHdr->e_magic == IMAGE_DOS_SIGNATURE)
		{
			// To terminate false positives - we do another check by retrieving the NT header and checking its signature as well
			pImgNtHdrs = (PIMAGE_NT_HEADERS)(uTmpAddress + pImgDosHdr->e_lfanew);

			if (pImgNtHdrs->Signature == IMAGE_NT_SIGNATURE) {
				// If valid, the current uTmpAddress is ReflectiveDllLdr.dll's base address 
				uReflectiveDllModule = uTmpAddress;
				break;
			}
		}
		// Keep decrementing to reach the DLL's base address
		uTmpAddress--;

	} while (TRUE);


	if (!uReflectiveDllModule)
		return FALSE;


	// Initializing the 'PeHdrs' structure
	PeHdrs.pImgNtHdrs = pImgNtHdrs;
	PeHdrs.pImgSecHdr = IMAGE_FIRST_SECTION(PeHdrs.pImgNtHdrs);
	PeHdrs.pEntryImportDataDir = &PeHdrs.pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PeHdrs.pEntryBaseRelocDataDir = &PeHdrs.pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	PeHdrs.pEntryTLSDataDir = &PeHdrs.pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	PeHdrs.pEntryExceptionDataDir = &PeHdrs.pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	PeHdrs.pEntryExportDataDir = &PeHdrs.pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	// Allocating memory for the PE
	if ((pPeBaseAddress = pVirtualAlloc(NULL, PeHdrs.pImgNtHdrs->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) == NULL) {
		return FALSE;
	}

	// Copying PE sections
	for (int i = 0; i < PeHdrs.pImgNtHdrs->FileHeader.NumberOfSections; i++) {
		Memcpy(
			(PVOID)(pPeBaseAddress + PeHdrs.pImgSecHdr[i].VirtualAddress),
			(PVOID)(uReflectiveDllModule + PeHdrs.pImgSecHdr[i].PointerToRawData),
			PeHdrs.pImgSecHdr[i].SizeOfRawData
		);
	}

	// Calculating ReflectiveDllLdr.dll's entry point address 
	pDllMain = (fnDllMain)(pPeBaseAddress + PeHdrs.pImgNtHdrs->OptionalHeader.AddressOfEntryPoint);

	// Fixing the IAT 
	if (!FixImportAddressTable(PeHdrs.pEntryImportDataDir, pPeBaseAddress))
		return FALSE;

	// Applying relocations
	if (!FixReloc(PeHdrs.pEntryBaseRelocDataDir, pPeBaseAddress, PeHdrs.pImgNtHdrs->OptionalHeader.ImageBase))
		return FALSE;

	// Setting up suitable memory permissions
	if (!FixMemPermissions(pPeBaseAddress, PeHdrs.pImgNtHdrs, PeHdrs.pImgSecHdr))
		return FALSE;

	// Set exception handlers of the injected PE (if exists)
	if (PeHdrs.pEntryExceptionDataDir->Size) {
		// Retrieve the function table entry
		PIMAGE_RUNTIME_FUNCTION_ENTRY pImgRuntimeFuncEntry = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(pPeBaseAddress + PeHdrs.pEntryExceptionDataDir->VirtualAddress);
		// Register the function table
		if (!pRtlAddFunctionTable(pImgRuntimeFuncEntry, (PeHdrs.pEntryExceptionDataDir->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)) - 1, pPeBaseAddress)) {
		}
	}

	// Execute TLS callbacks (if exists)
	if (PeHdrs.pEntryTLSDataDir->Size) {
		// Retrieve the address of the TLS Directory.
		PIMAGE_TLS_DIRECTORY	pImgTlsDirectory = (PIMAGE_TLS_DIRECTORY)(pPeBaseAddress + PeHdrs.pEntryTLSDataDir->VirtualAddress);
		// Get the address of the TLS Callbacks from the TLS Directory.
		PIMAGE_TLS_CALLBACK* pImgTlsCallback = (PIMAGE_TLS_CALLBACK*)(pImgTlsDirectory->AddressOfCallBacks);
		CONTEXT					pCtx = { 0x00 };
		// Iterate through and invoke each TLS Callback until a NULL callback is encountered.
		for (; *pImgTlsCallback; pImgTlsCallback++)
			(*pImgTlsCallback)((LPVOID)pPeBaseAddress, DLL_PROCESS_ATTACH, &pCtx);
	}

	// Flushing the instruction cache
	pNtFlushInstructionCache((HANDLE)-1, NULL, 0x00);

	// Execute ReflectiveDllLdr.dll's EP
	return pDllMain((HMODULE)pPeBaseAddress, DLL_PROCESS_ATTACH, NULL);
}
