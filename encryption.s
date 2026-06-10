; global encrypt_section

; section .text
; encrypt_section:
;     add rdi, rsi
;     xor rax, rax
; .loop:
;     cmp rax, rdx
;     jge .done
;     mov r8b, cl
;     xor [rdi + rax], r8b
;     ror rcx, 8
;     inc rax
;     jmp .loop
; .done:
;     ret
global encrypt_section

section .text

; -------------------------------------------------------------------------
; MACRO: Intel AES-128 Key Expansion
; This macro takes the original key and magically computes the next round key
; %1 = Current Key, %2 = Destination for New Key, %3 = RCON (Round Constant)
; -------------------------------------------------------------------------
%macro KEY_EXPAND 3
    movdqa xmm15, %1
    aeskeygenassist xmm14, %1, %3
    pshufd xmm14, xmm14, 0xff
    movdqa xmm13, xmm15
    pslldq xmm13, 4
    pxor xmm15, xmm13
    pslldq xmm13, 4
    pxor xmm15, xmm13
    pslldq xmm13, 4
    pxor xmm15, xmm13
    pxor xmm15, xmm14
    movdqa %2, xmm15
%endmacro

encrypt_section:
    ; C signature: void encrypt_section(char *buffer, uint64_t offset, uint64_t size, uint64_t key)
    ; Registers: rdi = buffer, rsi = offset, rdx = size, rcx = key
    
    add rdi, rsi            ; rdi now points to the exact start of the section

    ; 1. Load the 64-bit key from C into a 128-bit register (upper 64 bits become 0)
    movq xmm0, rcx          ; xmm0 = Round Key 0

    ; 2. Expand the key into 10 more round keys (stored in xmm1 to xmm10)
    KEY_EXPAND xmm0, xmm1, 0x01
    KEY_EXPAND xmm1, xmm2, 0x02
    KEY_EXPAND xmm2, xmm3, 0x04
    KEY_EXPAND xmm3, xmm4, 0x08
    KEY_EXPAND xmm4, xmm5, 0x10
    KEY_EXPAND xmm5, xmm6, 0x20
    KEY_EXPAND xmm6, xmm7, 0x40
    KEY_EXPAND xmm7, xmm8, 0x80
    KEY_EXPAND xmm8, xmm9, 0x1B
    KEY_EXPAND xmm9, xmm10, 0x36

    ; 3. Initialize the CTR (Counter)
    pxor xmm11, xmm11       ; xmm11 = Block Counter (Starts at 0)
    mov rax, 1
    movq xmm12, rax         ; xmm12 = 1 (Used to increment the counter later)

.loop:
    cmp rdx, 0
    jle .done               ; If size <= 0, we are finished

    ; 4. Encrypt the Counter (xmm11) using the AES Hardware Pipeline
    movdqa xmm13, xmm11     ; Copy the counter into xmm13
    pxor xmm13, xmm0        ; Initial AddRoundKey
    aesenc xmm13, xmm1      ; Round 1
    aesenc xmm13, xmm2      ; Round 2
    aesenc xmm13, xmm3      ; Round 3
    aesenc xmm13, xmm4      ; Round 4
    aesenc xmm13, xmm5      ; Round 5
    aesenc xmm13, xmm6      ; Round 6
    aesenc xmm13, xmm7      ; Round 7
    aesenc xmm13, xmm8      ; Round 8
    aesenc xmm13, xmm9      ; Round 9
    aesenclast xmm13, xmm10 ; Round 10 (Final) - xmm13 is now our Keystream Block!

    ; Increment the block counter for the next loop
    paddq xmm11, xmm12

    ; Check if we have less than 16 bytes left to encrypt
    cmp rdx, 16
    jl .partial_block

    ; 5. XOR the 16-byte Keystream directly against the Plaintext
    movdqu xmm14, [rdi]     ; Load 16 bytes of data
    pxor xmm14, xmm13       ; XOR data with Keystream
    movdqu [rdi], xmm14     ; Write the encrypted 16 bytes back to memory

    add rdi, 16             ; Move pointer forward by 16 bytes
    sub rdx, 16             ; Reduce remaining size by 16 bytes
    jmp .loop

.partial_block:
    ; 6. Handle Leftover Bytes (if size is not a multiple of 16)
    sub rsp, 16
    movdqu [rsp], xmm13     ; Spill the 16-byte Keystream to the stack temporarily
    xor rcx, rcx            ; rcx = byte index counter

.byte_loop:
    cmp rcx, rdx
    jge .cleanup
    mov al, [rsp + rcx]     ; Read 1 byte of the Keystream
    xor [rdi + rcx], al     ; XOR it with 1 byte of the actual data
    inc rcx
    jmp .byte_loop

.cleanup:
    add rsp, 16             ; Restore the stack pointer

.done:
    ret