BITS 64
global _start

section .text
_start:

    pushfq
    push rax
    push rdi
    push rsi
    push rdx
    push rcx
    push rbx
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    mov rax, 1                  ; syscall number for sys_write
    mov rdi, 1                  ; file descriptor 1 is STDOUT
    lea rsi, [rel msg]          ; RIP-relative address to our string
    mov rdx, 14                 ; length of the string (13 chars + 1 newline)
    syscall


    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rbx
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    pop rax
    popfq
    db 0xE9
    dd 0xAAAAAAAA


msg:
    db "....WOODY....", 10 