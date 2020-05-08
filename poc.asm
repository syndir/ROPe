	global	poc
	section	.text
poc:
	mov rax, 0

poc1:	
	pop rdx
	ret

poc2:	
	pop r10
	ret

poc3:	
	pop r8
	ret

poc4:	
	pop r9
	ret

poc5:	
	pop rax
	ret

poc6:	
	xor eax, eax
	ret

poc7:	
	pop rdi
	ret

poc8:	
	pop rbx
	ret

poc9:	
	pop rsi
	ret

poc10:
	xchg rax, r12
	ret

poc11:
	mov [rsp + 0x8], r12
	ret

poc12:
	push r12
	ret

poc13:
	pop rdx
	push rbx
	pop r8
	ret

poc14:
	push rsp
	mov rax, 4
	xor eax, eax
	pop r9
	ret
	
poc15:
	add eax, 100
	inc ecx
	inc ecx
	mov rsp, rbp
	pop rcx
	ret
