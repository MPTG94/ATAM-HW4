.section .data
msg: .ascii "hello intel x64\n"
msg_len: .quad msg_len - msg

.text
.global _start
_start:
	# write "hello intel x64" to screen
    movq $1, %rax
    movq $1, %rdi
    movq $msg, %rsi
    movq (msg_len), %rdx
    syscall
	
    # exit
    movq $60, %rax
    movq $0, %rdi
    syscall


