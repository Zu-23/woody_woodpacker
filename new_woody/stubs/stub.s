BITS 64
global _start

section .text
_start:
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
    test rcx, rcx                   
    jz print_msg                    
    
    xor byte [rdi], al              
    
    ror rax, 8                    

    inc rdi
    dec rcx
    jmp decrypt_loop

print_msg:
    mov rax, 1                      
    mov rdi, 1                      
    lea rsi, [rel woody_msg]        
    mov rdx, 14                     
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