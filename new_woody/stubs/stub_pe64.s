BITS 64
global _start

section .text
_start:
    ; --- 1. Save Windows x64 CPU Context ---
    pushfq
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    ; --- 2. Setup Decryption ---
    lea rdi, [rel _start]
    
    sub rdi, 0x11111111             ; p_dist
    mov rcx, 0x22222222             ; p_size
    mov rax, 0x3333333333333333  ; p_key

decrypt_loop:
    test rcx, rcx
    jz done
    
    xor byte [rdi], al
    ror rax, 8

    inc rdi
    dec rcx
    jmp decrypt_loop

done:
    ; --- 3. Restore CPU Context ---
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    popfq

    ; --- 4. Jump to Host ---
    db 0xE9
    dd 0xAAAAAAAA                   ; p_jmp

    ; --- 5. Boundary Padding ---
    ; Pushes the placeholder away from EOF so the C loop finds it
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop