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

    ; Load the 32-bit Master Key into EAX
    mov eax, 0xDDDDDDDD 

    ; 2. DECRYPT .TEXT
    mov rdi, 0xAAAAAAAAAAAAAAA1  ; Placeholder for .text Address
    mov rcx, 0xBBBBBBBBBBBBBBB1  ; Placeholder for .text Size
    call decrypt_chunk

    ; 3. DECRYPT .RODATA
    mov rdi, 0xAAAAAAAAAAAAAAA2  ; Placeholder for .rodata Address
    mov rcx, 0xBBBBBBBBBBBBBBB2  ; Placeholder for .rodata Size
    call decrypt_chunk

    ; 4. DECRYPT .DATA
    mov rdi, 0xAAAAAAAAAAAAAAA3  ; Placeholder for .data Address
    mov rcx, 0xBBBBBBBBBBBBBBB3  ; Placeholder for .data Size
    call decrypt_chunk

    ; 3. Restore CPU state
    popfq
    pop r11
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    pop rax

    mov rax, 0xCCCCCCCCCCCCCCCC ; Placeholder for Original Entry Point
    push rax
    ret

decrypt_chunk:
    test rcx, rcx
    jz .done

.loop:
    xor byte [rdi], al          ; Decrypt one byte
    ror eax, 8                  ; Rotate key

    inc rdi                     ; Move to next byte (Using 64-bit RDI!)
    dec rcx                     ; Decrease counter (Using 64-bit RCX!)
    jnz .loop                   ; If RCX is not zero, loop again
    ret

print_msg:
        mov rax, 1                  ; syscall number for sys_write
        mov rdi, 1                  ; file descriptor 1 (stdout)
        
        lea rsi, [rel woody]    
        
        mov rdx, 14                 ; length of the string
        syscall     

.done:
    ret

woody: db "....WOODY....", 10