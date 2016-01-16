 ;
 ; Redistribution and use in source and binary forms, with or without
 ; modification, are permitted provided that the following conditions
 ; are met:
 ; 1. Redistributions of source code must retain the above copyright
 ;    notice, this list of conditions and the following disclaimer.
 ; 2. Redistributions in binary form must reproduce the above copyright
 ;    notice, this list of conditions and the following disclaimer in the
 ;    documentation and/or other materials provided with the distribution.
 ; 
 ; THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 ; ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 ; IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ; ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 ; FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 ; DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 ; OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 ; HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 ; LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 ; OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 ; SUCH DAMAGE.
 ;

extern FasttrapHookISR:qword
extern FasttrapRetHookISR:qword
extern fasttrap_pid_probe:PROC
extern fasttrap_return_probe:PROC
extern dtrace_user_probe:PROC

T_DTRACE_RET equ 7fh
T_DTRACE_FASTTRAP equ 03h

.code
PUBLIC interrupt_fasttrap
interrupt_fasttrap PROC
	push rbp
	sub rsp, 0b0h
	lea rbp, [rsp+30h]
	mov qword ptr [rbp], r15
	mov qword ptr [rbp+8], r14
	mov qword ptr [rbp+16], r13
	mov qword ptr [rbp+24], r12
	mov qword ptr [rbp+32], r11
	mov qword ptr [rbp+40], r10
	mov qword ptr [rbp+48], r9
	mov qword ptr [rbp+56], r8
	mov qword ptr [rbp+64], rdi
	mov qword ptr [rbp+72], rsi
	mov qword ptr [rbp+80], rax
	mov qword ptr [rbp+88], rbx
	mov qword ptr [rbp+96], rdx
	mov qword ptr [rbp+104], rcx
	mov dword ptr [rbp+112], T_DTRACE_FASTTRAP
	;mov word ptr [rbp+116], fs
	;mov word ptr [rbp+118], gs
	mov dword ptr [rbp+120], 0 ;err
	;mov word ptr [rbp+124], es
	;mov word ptr [rbp+126], ds

	mov rax, [rbp+90h]
	and rax, 03h
	cmp rax, 03h
	jne kern
	swapgs
	mov rcx, rbp
	call dtrace_user_probe
	cmp rax, 0
	jne kern0
	mov rcx, qword ptr [rbp+104]
	mov rdx, qword ptr [rbp+96] 
	mov rbx, qword ptr [rbp+88]
	mov rax, qword ptr [rbp+80]
	mov rsi, qword ptr [rbp+72]
	mov rdi, qword ptr [rbp+64]
	mov r8, qword ptr [rbp+56]
	mov r9, qword ptr [rbp+48]
	mov r10, qword ptr [rbp+40]
	mov r11, qword ptr [rbp+32]
	mov r12, qword ptr [rbp+24]
	mov r13, qword ptr [rbp+16]
	mov r14, qword ptr [rbp+8]
	mov r15, qword ptr [rbp]
	
	;lea rsp, [rbp-30h]
	add rsp, 0b0h
	pop rbp
	swapgs
	iretq

kern0:
	swapgs
kern:
	mov rcx, qword ptr [rbp+104]
	mov rdx, qword ptr [rbp+96] 
	mov rbx, qword ptr [rbp+88]
	mov rax, qword ptr [rbp+80]
	mov rsi, qword ptr [rbp+72]
	mov rdi, qword ptr [rbp+64]
	mov r8, qword ptr [rbp+56]
	mov r9, qword ptr [rbp+48]
	mov r10, qword ptr [rbp+40]
	mov r11, qword ptr [rbp+32]
	mov r12, qword ptr [rbp+24]
	mov r13, qword ptr [rbp+16]
	mov r14, qword ptr [rbp+8]
	mov r15, qword ptr [rbp]
	;lea rsp, [rbp-30h]
	add rsp, 0b0h
	pop rbp
	JMP QWORD PTR FasttrapHookISR
interrupt_fasttrap ENDP

PUBLIC interrupt_fasttrapRET
interrupt_fasttrapRET PROC
	push rbp
	sub rsp, 0b0h
	lea rbp, [rsp+30h]
	mov qword ptr [rbp], r15
	mov qword ptr [rbp+8], r14
	mov qword ptr [rbp+16], r13
	mov qword ptr [rbp+24], r12
	mov qword ptr [rbp+32], r11
	mov qword ptr [rbp+40], r10
	mov qword ptr [rbp+48], r9
	mov qword ptr [rbp+56], r8
	mov qword ptr [rbp+64], rdi
	mov qword ptr [rbp+72], rsi
	mov qword ptr [rbp+80], rax
	mov qword ptr [rbp+88], rbx
	mov qword ptr [rbp+96], rdx
	mov qword ptr [rbp+104], rcx
	mov dword ptr [rbp+112], T_DTRACE_RET
	;mov word ptr [rbp+116], fs
	;mov word ptr [rbp+118], gs
	mov dword ptr [rbp+120], 0 ;err
	;mov word ptr [rbp+124], es
	;mov word ptr [rbp+126], ds

	mov rax, [rbp+90h]
	and rax, 03h
	cmp rax, 03h
	jne kern1
	swapgs
	mov rcx, rbp
	call dtrace_user_probe
	cmp rax, 0
	jne kern1
	mov rcx, qword ptr [rbp+104]
	mov rdx, qword ptr [rbp+96] 
	mov rbx, qword ptr [rbp+88]
	mov rax, qword ptr [rbp+80]
	mov rsi, qword ptr [rbp+72]
	mov rdi, qword ptr [rbp+64]
	mov r8, qword ptr [rbp+56]
	mov r9, qword ptr [rbp+48]
	mov r10, qword ptr [rbp+40]
	mov r11, qword ptr [rbp+32]
	mov r12, qword ptr [rbp+24]
	mov r13, qword ptr [rbp+16]
	mov r14, qword ptr [rbp+8]
	mov r15, qword ptr [rbp]
	
	;lea rsp, [rbp-30h]
	add rsp, 0b0h
	pop rbp
	swapgs
	iretq

kern1:
	mov rcx, qword ptr [rbp+104]
	mov rdx, qword ptr [rbp+96] 
	mov rbx, qword ptr [rbp+88]
	mov rax, qword ptr [rbp+80]
	mov rsi, qword ptr [rbp+72]
	mov rdi, qword ptr [rbp+64]
	mov r8, qword ptr [rbp+56]
	mov r9, qword ptr [rbp+48]
	mov r10, qword ptr [rbp+40]
	mov r11, qword ptr [rbp+32]
	mov r12, qword ptr [rbp+24]
	mov r13, qword ptr [rbp+16]
	mov r14, qword ptr [rbp+8]
	mov r15, qword ptr [rbp]
	;lea rsp, [rbp-30h]
	add rsp, 0b0h
	pop rbp
	;swapgs
	JMP QWORD PTR FasttrapRetHookISR
interrupt_fasttrapRET ENDP

END