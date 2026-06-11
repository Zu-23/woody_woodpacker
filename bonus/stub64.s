BITS 64
global _start

_start:
    push rax
    push rdi
    push rsi
    push rdx
    push rcx
    push r11
    pushfq 

    ; ----------------------------------------------------
    ; ANTI-VM: CPUID Hypervisor Check
    ; ----------------------------------------------------
    mov eax, 1              ; Request CPU feature flags
    cpuid                   ; Execute the hardware instruction
    
    bt ecx, 31              ; Bit Test: Check the 31st bit of ECX
    jc vm_detected         ; If the bit is 1 (Carry Flag set), we are in a VM!

    ; ----------------------------------------------------
    ; ANTI-DEBUGGING: ptrace(PTRACE_TRACEME, 0, 0, 0)
    ; ----------------------------------------------------
    mov rax, 101            ; syscall number for sys_ptrace
    xor rdi, rdi            ; arg 1: PTRACE_TRACEME (0)
    xor rsi, rsi            ; arg 2: NULL
    xor rdx, rdx            ; arg 3: NULL
    xor r10, r10            ; arg 4: NULL
    syscall

    test rax, rax           ; Check the return value
    jl debugger_detected   ; If less than 0 (error), jump to exit

    mov rax, 0xDDDDDDDDDDDDDDD1
    lea rdi, [rel _start]
    mov r10, 0xAAAAAAAAAAAAAAA1
    sub rdi, r10
    mov rcx, 0xBBBBBBBBBBBBBBB1
    call decrypt_chunk 

    mov rax, 0xDDDDDDDDDDDDDDD1
    lea rdi, [rel _start]
    mov r10 , 0xAAAAAAAAAAAAAAA2
    sub rdi, r10
    mov rcx, 0xBBBBBBBBBBBBBBB2  
    call decrypt_chunk

    mov rax, 0xDDDDDDDDDDDDDDD1
    lea rdi, [rel _start]
    mov r10 , 0xAAAAAAAAAAAAAAA3
    sub rdi, r10
    mov rcx, 0xBBBBBBBBBBBBBBB3  
    call decrypt_chunk

    mov rax, 9                   ; sys_mmap
    xor rdi, rdi                 ; addr = NULL
    mov rsi, 0xBBBBBBBBBBBBBBB1  ; size
    mov rdx, 3                   ; PROT_READ | PROT_WRITE
    mov r10, 0x22                ; MAP_PRIVATE | MAP_ANONYMOUS
    mov r8, -1
    xor r9, r9
    syscall

    ; ; result in rax
    mov r12, rax            ; save buffer pointer
    mov r15, rax        ; <-- save mmap BASE here, never touch r15 again
    
    lea rdi, [rel _start]
    mov r10, 0xAAAAAAAAAAAAAAA1
    sub rdi, r10
    mov rcx, 0xEEEEEEEEEEEEEEE1
    call decompress

    lea rdi, [rel _start]
    mov r10, 0xAAAAAAAAAAAAAAA1 ; .text address
    sub rdi, r10
    mov rcx, 0xBBBBBBBBBBBBBBB1 ; .text size

    mov rsi, r15        ; <-- use the saved base, not the broken sub
    rep movsb

    call msg

    popfq
    pop r11
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    pop rax

    lea rax, [rel _start]
    mov r10, 0xCCCCCCCCCCCCCCCC
    sub rax, r10
    push rax
    ret

debugger_detected:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel debugger]
    mov rdx, 23
    syscall
    ; Intentionally kill the process to protect the payload
    mov rax, 60             ; syscall number for sys_exit
    mov rdi, 1            ; Return an angry exit code
    syscall

vm_detected:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel virtualmc]
    mov rdx, 19
    syscall
    ; Intentionally kill the process
    mov rax, 60             ; syscall: sys_exit
    mov rdi, 2            ; Angry exit code
    syscall

msg:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel woody]
    mov rdx, 14
    syscall
    ret

decompress:
    test rcx, rcx
    jz .done
    mov r14, rdi
    add r14, rcx

.loop:
    cmp rdi, r14
    jge .done

    mov bl, [rdi]
    inc rdi
    mov dl, 8
    
.loop2:
    test bl, 1
    jnz .literal

    movzx r8d, byte [rdi]
    shl r8d, 8
    movzx r9d, byte [rdi+1]
    or r8d, r9d
    add rdi, 2

    mov r9d, r8d
    shr r9d, 4              ; offset = high 12 bits
    mov r10d, r8d
    and r10d, 0xF           ; length - 3 = low 4 bits
    add r10d, 3
    mov r11d, r10d
    mov r13, r12
    sub r13, r9
    
.copy:
    mov al, [r13]
    inc r13
    mov [r12], al
    inc r12
    dec r11d
    jnz .copy
    jmp .next
    
.literal:
    mov al, [rdi]
    inc rdi
    mov [r12], al
    inc r12
    
.next:
    shr bl, 1
    dec dl
    jnz .loop2
    jmp .loop
.done:
    ret


; decrypt_chunk:
;     test rcx, rcx
;     jz .done
; .loop:
;     xor byte [rdi], al
;     ror rax, 8

;     inc rdi
;     dec rcx
;     jnz .loop
; .done:
;     ret


; -------------------------------------------------------------------------
; MACRO: Intel AES-128 Key Expansion
; Must be included in your stub64.s file so the CPU can expand the key
; -------------------------------------------------------------------------
%macro KEY_EXPAND 3
    movdqa xmm15, %1
    aeskeygenassist xmm14, %1, %3
    pshufd xmm14, xmm14, 0xff
    movdqa xmm13, xmm15
    pslldq xmm13, 4
    pxor xmm15, xmm13
    pslldq xmm13, 4
    pxor xmm15, xmm13
    pslldq xmm13, 4
    pxor xmm15, xmm13
    pxor xmm15, xmm14
    movdqa %2, xmm15
%endmacro

decrypt_chunk:
    ; Inputs from your stub:
    ; rdi = buffer (Memory address to decrypt)
    ; rcx = size (Number of bytes to decrypt)
    ; rax = key (64-bit key passed from your patcher)

    test rcx, rcx
    jz .done                ; If size is 0, exit immediately

    ; 1. Load the 64-bit key from RAX into a 128-bit register
    movq xmm0, rax          ; xmm0 = Round Key 0

    ; 2. Expand the key into 10 round keys (xmm1 to xmm10)
    KEY_EXPAND xmm0, xmm1, 0x01
    KEY_EXPAND xmm1, xmm2, 0x02
    KEY_EXPAND xmm2, xmm3, 0x04
    KEY_EXPAND xmm3, xmm4, 0x08
    KEY_EXPAND xmm4, xmm5, 0x10
    KEY_EXPAND xmm5, xmm6, 0x20
    KEY_EXPAND xmm6, xmm7, 0x40
    KEY_EXPAND xmm7, xmm8, 0x80
    KEY_EXPAND xmm8, xmm9, 0x1B
    KEY_EXPAND xmm9, xmm10, 0x36

    ; 3. Initialize the Block Counter
    pxor xmm11, xmm11       ; xmm11 = Block Counter (Starts at 0)
    mov r8, 1
    movq xmm12, r8          ; xmm12 = 1 (Increment value for the counter)

.loop:
    cmp rcx, 0
    jle .done               ; Exit if size <= 0

    ; 4. Encrypt the Counter (xmm11) to generate the Keystream
    movdqa xmm13, xmm11     ; Copy counter into xmm13
    pxor xmm13, xmm0        ; Initial AddRoundKey
    aesenc xmm13, xmm1      ; Round 1
    aesenc xmm13, xmm2      ; Round 2
    aesenc xmm13, xmm3      ; Round 3
    aesenc xmm13, xmm4      ; Round 4
    aesenc xmm13, xmm5      ; Round 5
    aesenc xmm13, xmm6      ; Round 6
    aesenc xmm13, xmm7      ; Round 7
    aesenc xmm13, xmm8      ; Round 8
    aesenc xmm13, xmm9      ; Round 9
    aesenclast xmm13, xmm10 ; Round 10 - xmm13 now holds the Keystream!

    ; Increment the counter for the next 16-byte block
    paddq xmm11, xmm12

    ; Check if we have a full 16-byte block left to decrypt
    cmp rcx, 16
    jl .partial_block

    ; 5. Decrypt full 16-byte block
    movdqu xmm14, [rdi]     ; Load 16 bytes of encrypted payload
    pxor xmm14, xmm13       ; XOR with Keystream to decrypt
    movdqu [rdi], xmm14     ; Write decrypted data back to memory

    add rdi, 16             ; Move pointer forward 16 bytes
    sub rcx, 16             ; Decrease remaining size by 16 bytes
    jmp .loop

.partial_block:
    ; 6. Decrypt leftover bytes (if size is not a multiple of 16)
    sub rsp, 16
    movdqu [rsp], xmm13     ; Spill the 16-byte Keystream to the stack
    xor r8, r8              ; r8 = byte index counter

.byte_loop:
    cmp r8, rcx
    jge .cleanup
    mov r9b, [rsp + r8]     ; Read 1 byte of the Keystream
    xor [rdi + r8], r9b     ; XOR it with 1 byte of the encrypted payload
    inc r8
    jmp .byte_loop

.cleanup:
    add rsp, 16             ; Restore the stack pointer

.done:
    ret
    
woody: db "....WOODY....", 10
debugger: db "Debugger was detected!", 10
virtualmc: db "Running inside VM!", 10