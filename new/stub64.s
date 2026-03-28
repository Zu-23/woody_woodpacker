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

    mov rax, 1
    mov rdi, 1
    lea rsi, [rel woody]
    mov rdx, 14
    syscall

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

decrypt_chunk:
    test rcx, rcx
    jz .done
.loop:
    xor byte [rdi], al
    ror rax, 8

    inc rdi
    dec rcx
    jnz .loop
.done:
    ret

woody: db "....WOODY....", 10