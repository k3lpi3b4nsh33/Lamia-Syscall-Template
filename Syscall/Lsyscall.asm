.data
	LamiaSystemcall			DWORD	0h	
	qSyscallInsAdress	    QWORD	0h	


.code

	SetSSn proc
                                                 ; Initialization phase: clear registers and set initial values
        xor eax, eax                             ; eax = 0
        xor r9, r9                               ; r9 = 0
        xor r10, r10                             ; r10 = 0
        mov LamiaSystemcall, eax                 ; Initialize LamiaSystemcall = 0
        mov qSyscallInsAdress, rax               ; Initialize qSyscallInsAdress = 0

                                                 ; Introduce pseudo-logic: save and restore ecx
        mov r10d, ecx                            ; Save ecx to r10d
        xor ecx, ecx                             ; Clear ecx
        lea ecx, [r10]                           ; Restore ecx using LEA to add obfuscation

                                                 ; Fake branch: create a pseudo-logic path
        cmp ecx, 0                               ; Check if ecx is 0
        jne LamiaPart1                           ; If not zero, jump to fake logic
        jmp ContinueLoop                         ; Otherwise, enter main logic

    LamiaPart1:
                                                 ; Irrelevant complex logic block to confuse reverse engineers
        inc r8                                   ; Fake system call address
        xor r9, r8                               ; Add obfuscation operation
        test r9, r8                              ; Fake condition test, has no effect
        nop                                      ; Retain execution flow

    ContinueLoop:
                                                 ; Main loop logic: simulate SSN traversal
        LoopSSN:
            cmp eax, ecx                         ; Compare eax and ecx
            je EndLoop                           ; If equal, exit the loop
            inc eax                              ; Increment eax
            jnz LoopSSN                          ; Obfuscation branch
            jmp LoopSSN                          ; Return to the start of the loop
    EndLoop:

                                                 ; Result processing phase
    xor r9, r9                                   ; Clear r9
    mov LamiaSystemcall, eax                     ; Save final SSN to LamiaSystemcall
    mov r8, rdx                                  ; Get system call instruction address into r8
    mov qSyscallInsAdress, r8                    ; Save address to qSyscallInsAdress

                                                 ; Introduce stack operations to add complexity
    push rax                                     ; Push rax onto the stack
    pop rax                                      ; Restore rax from the stack
    xor rax, rax                                 ; Add extra clearing operation


    ret                                          ; Return
    
    SetSSn endp


                                                 ; SetSSn should look like this :
	                                             ; SetSSn PROC
	                                             ;	mov LamiaSystemcall, 0h
	                                             ;	mov qSyscallInsAdress, 0h
	                                             ;	mov LamiaSystemcall, ecx
	                                             ;	mov qSyscallInsAdress, rdx
	                                             ;	ret
	                                             ;SetSSn ENDP


    RunSyscall proc
                                                 ; Initialization phase: prepare registers
            xor r10, r10                         ; r10 = 0
            mov rax, rcx                         ; rax = rcx
            mov r10, rax                         ; r10 = rax = rcx
            xor eax, eax                         ; eax = 0

                                                 ; Main loop to match system call
        LoopSyscall:
            cmp eax, LamiaSystemcall             ; Compare with LamiaSystemcall
            je Run                               ; If match, jump to Run
            inc eax                              ; Increment eax
            jmp LoopSyscall                      ; Repeat loop

                                                 ; Irrelevant dead code to confuse reverse engineers
            xor eax, eax                         ; Dead code, will not run
            xor rcx, rcx                         ; Dead code, will not run
            shl r10, 2                           ; Dead code, will not run
            shl r8, 2                            ; Dead code, will not run

                                                 ; Execution phase: jump to system call address
        Run:
            jmp qword ptr [qSyscallInsAdress]    ; Jump to the system call address

                                                 ; Cleanup phase
            xor r10, r10                         ; r10 = 0
            mov qSyscallInsAdress, r10           ; Clear qSyscallInsAdress
            ret                                  ; Return
    RunSyscall endp


                                                 ; RunSyscall should look like this :
	                                             ;RunSyscall PROC
	                                             ;	mov r10, rcx
	                                             ;	mov eax, LamiaSystemcall
	                                             ;	jmp qword ptr [qSyscallInsAdress]
	                                             ;	ret
	                                             ;RunSyscall ENDP


end