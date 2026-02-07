bits 64

start_anchor:
    pushfq
    push rax
    push rdi
    push rsi
    push rdx
    lea rdi, [rel start_anchor] 
    sub rdi, 0x11111111             
    xor byte [rdi], 0xAA        
    mov rax, 1                  
    mov rdi, 1                  
    lea rsi, [rel msg]          
    mov rdx, 3                  
    syscall

    pop rdx
    pop rsi
    pop rdi
    pop rax
    popfq

    db 0xe9
    dd 0xAAAAAAAA

msg: db "HI", 0x0a