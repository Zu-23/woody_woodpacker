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

    mov eax, 0xDDDDDDD1 
    mov rdi, 0xAAAAAAAAAAAAAAA1  
    mov rcx, 0xBBBBBBBBBBBBBBB1  
    call decrypt_chunk

    mov rdi, 0xAAAAAAAAAAAAAAA2  
    mov rcx, 0xBBBBBBBBBBBBBBB2  
    call decrypt_chunk

    mov rdi, 0xAAAAAAAAAAAAAAA3  
    mov rcx, 0xBBBBBBBBBBBBBBB3  
    call decrypt_chunk

    mov rax, 1                  ; sys_write
    mov rdi, 1                  ; stdout
    lea rsi, [rel woody]        ; load string
    mov rdx, 14                 ; length
    syscall     

    popfq
    pop r11
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    pop rax

    mov rax, 0xCCCCCCCCCCCCCCC2 
    push rax
    ret

; --- SUBROUTINE (Stays at the bottom) ---
decrypt_chunk:
    test rcx, rcx
    jz .done
.loop:
    xor byte [rdi], al
    ror eax, 8
    inc rdi
    dec rcx
    jnz .loop
.done:
    ret

; --- DATA ---
woody: db "....WOODY....", 10