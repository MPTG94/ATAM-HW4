.section .data
msg: .ascii "print me to file and maybe also to screen\n"
msg_len: .quad msg_len - msg
msg2: .ascii "only print to screen\n"
msg_len2: .quad msg_len2 - msg2

.text
.global _start
_start:
    movq $1, %rax
    movq $1, %rdi
    movq $msg2, %rsi
    movq (msg_len2), %rdx
    syscall

	call foo

	xor %rax, %rax
	addq %rax, %rax
	movq $1, %rax
    movq $1, %rdi
    movq $msg2, %rsi
    movq (msg_len2), %rdx
    syscall

    movq $60, %rax
    movq $0, %rdi
    syscall

foo:
	movq $1, %rax
    movq $1, %rdi
    movq $msg, %rsi
    movq (msg_len), %rdx
    syscall
	ret

