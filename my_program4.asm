.section .data
msg: .ascii "print me to file and maybe also to screen\n"
msg_len: .quad msg_len - msg
msg2: .ascii "only print to screen\n"
msg_len2: .quad msg_len2 - msg2
msg3: .ascii "print once\n"
msg_len3: .quad msg_len3 - msg3

.text
.global _start
_start:
    movq $1, %rax
    movq $1, %rdi
    movq $msg3, %rsi
    movq (msg_len3), %rdx
    syscall

	call foo

	movq $1, %rax
    syscall

    call foo

    movq $1, %rax
    syscall

    movq $60, %rax
    movq $0, %rdi
    syscall

foo:
    movq $1, %rax
    syscall
	ret

