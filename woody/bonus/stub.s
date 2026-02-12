BITS 64
global _start

_start:
    pushfq
    push rax            
    push rbx
    push rcx
    push rdx
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
    push rbp

    lea rdi, [rel _start]   
    sub rdi, 0x11111111         
    mov rcx, 0x22222222         

    mov rax, 0x1122334455667788 

decrypt_loop:
    test rcx, rcx               
    jz payload_start
    
    xor byte [rdi], al          
    ror rax, 8                  

    inc rdi                     
    dec rcx                     
    jmp decrypt_loop            

payload_start:
    mov rax, 1                  
    mov rdi, 1                  
    lea rsi, [rel msg]          
    mov rdx, 15                 
    syscall

    pop rbp
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
    pop rdx
    pop rcx
    pop rbx
    pop rax             
    popfq

    db 0xe9
    dd 0xAAAAAAAA       

msg: db "....WOODY....", 10