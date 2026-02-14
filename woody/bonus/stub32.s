BITS 32
global _start

_start:
    ; --- 1. Save all registers ---
    ; In 32-bit, we don't have r8-r15. 
    ; 'pushad' pushes EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI all at once.
    pushfd
    pushad

    ; --- 2. Get Current Instruction Pointer (The 32-bit Trick) ---
    ; We need to find where we are in memory to calculate offsets.
    call get_pc
get_pc:
    pop ebx                 ; EBX now holds the absolute address of 'get_pc'

    ; --- 3. Calculate Start of Text Segment ---
    ; We want EDI to point to '_start'.
    ; Math: EDI = Runtime_Address_of_get_pc - (Distance_between_get_pc_and_start)
    lea edi, [ebx - (get_pc - _start)] 
    
    sub edi, 0x11111111     ; PLACEHOLDER: p_dist (Distance to target code)
    
    mov ecx, 0x22222222     ; PLACEHOLDER: p_size (Size of encrypted part)
    mov eax, 0x33333333     ; PLACEHOLDER: p_key  (32-bit Key)

decrypt_loop:
    test ecx, ecx
    jz print_msg
    
    xor byte [edi], al      ; XOR using the low byte of EAX
    ror eax, 8              ; Rotate the 32-bit key

    inc edi
    dec ecx
    jmp decrypt_loop

print_msg:
    ; --- 4. Print "....WOODY...." (int 0x80) ---
    ; 32-bit Linux Syscall: EAX=4 (write), EBX=FD, ECX=Buffer, EDX=Length
    
    mov eax, 4              ; sys_write
    
    ; Calculate address of 'msg' relative to our anchor 'ebx'
    lea ecx, [ebx + (msg - get_pc)] 
    
    mov ebx, 1              ; File Descriptor 1 (STDOUT)
    mov edx, 14             ; Length: "....WOODY...." (13) + \n (1) = 14
    int 0x80                ; Interrupt to call kernel

    ; --- 5. Restore Registers ---
    popad                   ; Restores EAX...EDI
    popfd                   ; Restores Flags

    ; --- 6. Jump back to Original Entry Point ---
    db 0xe9
    dd 0xAAAAAAAA           ; PLACEHOLDER: p_jmp (Relative Jump Offset)

msg: db "....WOODY....", 10