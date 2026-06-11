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