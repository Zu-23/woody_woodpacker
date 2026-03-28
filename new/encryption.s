global encrypt_section

section .text
encrypt_section:
    add rdi, rsi
    xor rax, rax
.loop:
    cmp rax, rdx
    jge .done
    mov r8b, cl
    xor [rdi + rax], r8b
    ror rcx, 8
    inc rax
    jmp .loop
.done:
    ret