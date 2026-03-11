BITS 32
global _start

section .text
_start:
    ; --- 1. Save CPU Context ---
    pushad                          ; Saves EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI
    pushfd                          ; Saves EFLAGS

    ; --- 2. The PIC Trick (Find our runtime memory address) ---
    call get_eip
get_eip:
    pop ebp                         ; EBP now holds the exact runtime address of 'get_eip'

    ; --- 3. Setup Decryption ---
    ; We use EBP as our base pointer to calculate all relative addresses
    lea edi, [ebp - (get_eip - _start)] ; EDI now points to the absolute address of _start
    
    sub edi, 0x11111111             ; p_dist: Distance backwards to the encrypted text
    mov ecx, 0x22222222             ; p_size: Number of bytes to decrypt
    mov eax, 0x33333333             ; p_key:  32-bit rotating key

decrypt_loop:
    test ecx, ecx                   ; Check if counter is 0
    jz print_msg                    ; If 0, decryption is done
    
    xor byte [edi], al              ; Decrypt one byte using the lowest 8 bits of EAX
    ror eax, 8                      ; Rotate 32-bit key

    inc edi
    dec ecx
    jmp decrypt_loop

print_msg:
    ; --- 4. 32-bit Syscall ---
    mov eax, 4                      ; syscall: sys_write (4 in 32-bit)
    mov ebx, 1                      ; fd: stdout
    lea ecx, [ebp + (woody_msg - get_eip)] ; PIC pointer to the string!
    mov edx, 14                     ; length
    int 0x80                        ; Invoke 32-bit kernel syscall

    ; --- 5. Restore CPU Context ---
    popfd
    popad

    ; --- 6. Jump to Original Entry Point ---
    db 0xE9
    dd 0xAAAAAAAA                   ; p_jmp: Relative offset to host's real entry point

woody_msg:
    db "....WOODY....", 10