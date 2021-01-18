.section .data
msg: .ascii "hello intel x64 - check\n"
msg_len: .quad msg_len - msg

.text
.global _start
_start:
	call foo
	movq $60, %rax
	movq $0, %rdi
	syscall
	xor %rax, %rax
	addq %rax, %rax

foo:
	movq $1, %rax
    	movq $1, %rdi
    	movq $msg, %rsi
    	movq (msg_len), %rdx
    	syscall
	ret

