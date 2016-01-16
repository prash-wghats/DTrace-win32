 ;
 ; CDDL HEADER START
 ;
 ; The contents of this file are subject to the terms of the
 ; Common Development and Distribution License, Version 1.0 only
 ; (the "License").  You may not use this file except in compliance
 ; with the License.
 ;
 ; You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 ; or http://www.opensolaris.org/os/licensing.
 ; See the License for the specific language governing permissions
 ; and limitations under the License.
 ;
 ; When distributing Covered Code, include this CDDL HEADER in each
 ; file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 ; If applicable, add the following below this CDDL HEADER, with the
 ; fields enclosed by brackets "[]" replaced with your own identifying
 ; information: Portions Copyright [yyyy] [name of copyright owner]
 ;
 ; CDDL HEADER END
 ;

extern fbt_proc:PROC
extern IllInstISRAddress:qword

.code
PUBLIC interrupt_fbt6
interrupt_fbt6 PROC FRAME
	.pushframe
	 sub rsp, 8h
	.allocstack 8h
	push rbp
	.pushreg rbp
	sub rsp, 0A8h
	.allocstack 0A8h
	lea rbp, [rsp+030h]
	.setframe rbp, 030h
	.endprolog
	 test byte ptr [rsp+0C0h], 03h
	 jnz kernel 
	mov qword ptr [rbp], rcx
	mov qword ptr [rbp+8], rdx
	mov qword ptr [rbp+16], r8
	mov qword ptr [rbp+24], r9
	mov qword ptr [rbp+32], r10
	mov qword ptr [rbp+40], r11
	mov qword ptr [rbp+48], r12
	mov qword ptr [rbp+56], r13
	mov qword ptr [rbp+64], r14
	mov qword ptr [rbp+72], r15
	;mov word ptr [rbp+80], es
	;mov word ptr [rbp+82], ds
	;mov word ptr [rbp+84], gs
	;mov word ptr [rbp+86], fs
	mov qword ptr [rbp+88], rbx
	mov qword ptr [rbp+96], rax
	mov qword ptr [rbp+104], rsi
	mov qword ptr [rbp+112], rdi
	
	mov rcx, rbp
	call fbt_proc
	mov [rsp + 028h], rax
	
	mov rdi, qword ptr [rbp+112]
	mov rsi, qword ptr [rbp+104] 
	mov rax, qword ptr [rbp+96]
	mov rbx, qword ptr [rbp+88]
	;mov fs, word ptr [rbp+86]
	;mov gs, word ptr [rbp+84]
	;mov ds, word ptr [rbp+82]
	;mov es, word ptr [rbp+80]
	mov r15, qword ptr [rbp+72]
	mov r14, qword ptr [rbp+64]
	mov r13, qword ptr [rbp+56]
	mov r12, qword ptr [rbp+48]
	mov r11, qword ptr [rbp+40]
	mov r10, qword ptr [rbp+32]
	mov r9, qword ptr [rbp+24]
	mov r8, qword ptr [rbp+16]
	mov rdx, qword ptr [rbp+8]
	mov rcx, qword ptr [rbp]
	test byte ptr [rsp + 028h], 1
	jz kernel
	lea rsp, [rbp-030h]
	add rsp, 0A8h
	pop rbp
	add rsp, 8h
	iretq
kernel:
	lea rsp, [rbp-030h]
	add rsp, 0A8h
	pop rbp
	add rsp, 8h
	JMP QWORD PTR IllInstISRAddress
interrupt_fbt6 ENDP

END	