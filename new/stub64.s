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

    ; call decompress_section

    mov rax, 9                   ; sys_mmap
    xor rdi, rdi                 ; addr = NULL
    mov rsi, 0xDDDDDDDDDDDDDDD1  ; size
    mov rdx, 3                   ; PROT_READ | PROT_WRITE
    mov r10, 0x22                ; MAP_PRIVATE | MAP_ANONYMOUS
    mov r8, -1
    xor r9, r9
    syscall

    ; result in rax
    mov r12, rax            ; save buffer pointer
    
    lea rdi, [rel _start]
    mov r10, 0xAAAAAAAAAAAAAAA1
    sub rdi, r10
    mov rcx, 0xBBBBBBBBBBBBBBB1

    call decompress

    lea rdi, [rel _start]
    mov r10, 0xAAAAAAAAAAAAAAA1 ; .text address
    sub rdi, r10
    mov rcx, 0xBBBBBBBBBBBBBBB1 ; .text size

    sub r12, rcx
    mov rsi, r12
    rep movsb

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

decompress:
.loop:
    mov bl, [rdi]        ; flags
    inc rdi
    mov cl, 8            ; 8 items
.loop2:
    test bl, 1
    jnz .literal
    movzx r8d, word [rdi] ; TOKEN
    add rdi, 2
    mov r9d, r8d
    shr r9d, 4            ; offset
    mov r10d, r8d
    and r10d, 0xF
    add r10d, 3           ; length
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
    shr bl, 1            ; next bit
    dec cl
    jnz .loop2
    jmp .loop


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