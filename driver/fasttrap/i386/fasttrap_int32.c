/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
#include "fasttrap_win32.h"

/* FASTTRAP interrupt routine for vector 0x03 (breakpoint instruction ) */

__declspec( naked ) void interrupt_fasttrap( void )
{
	__asm {
		push 0
		push T_DTRACE_FASTTRAP
		PUSHAD
		push ds
		push es
		push fs
		push gs		
		mov     ebx,0x30
		mov     eax,0x23
		mov     fs,bx
		mov     ds,ax
		mov     es,ax
		mov ebx, [esp+60]	
		and ebx, 0x03	/* check for user trap */
		cmp ebx, 0x03
		jne kernel
		mov ebx, esp
		push ebx
		call dtrace_user_probe
		cmp eax, 0
		jne kernel
		pop gs	
		pop fs
		pop es
		pop ds
		POPAD
		add esp, 8
		iretd
kernel:
		pop gs		
		pop fs
		pop es
		pop ds
		POPAD
		add esp, 8
		JMP DWORD PTR FasttrapHookISR
	}
}

__declspec( naked ) void interrupt_fasttrapRET( void )
{
	__asm {
		PUSH 0
		push T_DTRACE_RET
		PUSHAD
		push ds
		push es
		push fs
		push gs		
		mov     ebx,0x30
		mov     eax,0x23
		mov     fs,bx
		mov     ds,ax
		mov     es,ax
		mov ebx, [esp+60]	
		and ebx, 0x03	/* check for user trap */
		cmp ebx, 0x03
		jne kernret
		mov ebx, esp
		push ebx
		call dtrace_user_probe
		cmp eax, 0
		jne kernret
		pop gs
		pop fs
		pop es
		pop ds
		POPAD
		add esp, 8
		iretd
kernret:
		pop gs
		pop fs
		pop es
		pop ds
		POPAD
		add esp, 8
		JMP DWORD PTR FasttrapRetHookISR
	}
}