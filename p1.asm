.section .data
msg: .ascii "hello test1\n"
msg_len: .quad msg_len - msg
msg2: .ascii "hello test2\n"
msg_len2: .quad msg_len2 - msg2
msg3: .ascii "hello test3\n"
msg_len3: .quad msg_len3 - msg3


.text
.global _start
_start:
    # write your code here
	xor %rax,%rax
	mov $10,%r10
loop1:	movq $msg, %rsi
	movq (msg_len), %rdx
	call print
	dec %r10
	cmp $0,%r10
	jne loop1
	mov $10,%r10
loop2:	movq $msg2, %rsi
	movq (msg_len2), %rdx
	call print
	dec %r10
	cmp $0,%r10
	jne loop2
	mov $10,%r10
loop3:	movq $msg3, %rsi
	movq (msg_len3), %rdx
	call print
	dec %r10
	cmp $0,%r10
	jne loop3
	movq $60,%rax
	syscall

print:
	movq $1, %rax
	movq $1, %rdi

	syscall
	ret
