BITS 64
global _start

section .text
_start:
    ; --- 1. Save CPU Context ---
    ; We must leave the registers exactly as we found them so the host program doesn't crash.
    pushfq
    push rax
    push rbx
    push rcx
    push rdx
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

    lea rdi, [rel _start]
    
    sub rdi, 0x11111111             ; p_dist: Distance backwards to the encrypted text segment
    mov rcx, 0x22222222             ; p_size: Number of bytes to decrypt
    mov rax, 0x3333333333333333     ; p_key:  Your 64-bit generated key

decrypt_loop:
    test rcx, rcx                   ; Check if counter is 0
    jz print_msg                    ; If 0, decryption is done
    
    xor byte [rdi], al              ; Decrypt one byte using the lowest 8 bits of RAX
    ror rax, 8                      ; Rotate the key to keep it synced with your C encryptor

    inc rdi
    dec rcx
    jmp decrypt_loop

print_msg:
    mov rax, 1                      
    mov rdi, 1                      
    lea rsi, [rel woody_msg]        ; Position-independent pointer to the string
    mov rdx, 14                     ; Length (13 chars + 1 newline = 14)
    syscall

 
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
    pop rdx
    pop rcx
    pop rbx
    pop rax
    popfq


    db 0xE9
    dd 0xAAAAAAAA                   ; p_jmp: Relative offset to the host's real entry point

woody_msg:
    db "....WOODY....", 10