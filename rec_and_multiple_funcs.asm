.section .data
msg: .ascii "hello intel x64\n"
msg_len: .quad msg_len - msg

msg2: .ascii "goodbye intel x64\n"
msg_len2: .quad msg_len2 - msg2


.text
.global _start

foo:
    cmp $0,%r8
    je end
    mov $0x1, %rax
    mov $0x1, %rdi
    mov $msg, %rsi
    mov (msg_len), %rdx

    syscall
    dec %r8
    call foo
end:    
    retq


fee:
    mov $0x1, %rax
    mov $0x1, %rdi
    mov $msg2, %rsi
    mov (msg_len2), %rdx
    syscall
    ret

_start:
    mov $4, %r8
    callq foo
    mov $4, %r8
    callq foo
    mov $4, %r8
    callq foo
    xor %rax, %rax
    mov $4, %r8
    callq foo

    callq fee
    mov $0x3c, %rax
    mov $0x0, %rdi
    syscall

