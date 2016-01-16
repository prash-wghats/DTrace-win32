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
 ; $FreeBSD: release/10.0.0/sys/cddl/dev/dtrace/i386/dtrace_asm.S 227430 2011-11-10 22:03:35Z rstone $

 ; Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 ; Use is subject to license terms.



;/* FBT interrupt routine for vector 0x06 (illegal instruction ) */

.586
.MODEL FLAT, stdcall 

DTRACE_INVOP_PUSHL_EBP		equ 1
DTRACE_INVOP_POPL_EBP		equ 2
DTRACE_INVOP_LEAVE		equ 3
DTRACE_INVOP_NOP		equ 4
DTRACE_INVOP_RET		equ 5
DTRACE_INVOP_MOV_EDI_EDI0_V0	equ 6
DTRACE_INVOP_SUB_RSP_8		equ 7
DTRACE_INVOP_SUB_RSP_32		equ 8
 
extern fbt_proc@4:PROC
extern IllInstISRAddress:dword

.data
.CODE

interrupt_fbt6 proc
		PUSHAD
		mov ebx, [esp+36]	;/* load calling CS */
		and ebx, 03h		;/* check for user trap */
		cmp ebx, 03h
		je user

		push esp
		call fbt_proc@4
		cmp eax, DTRACE_INVOP_MOV_EDI_EDI0_V0
		je invop_movediedi
		cmp eax, DTRACE_INVOP_PUSHL_EBP
		je invop_push
		cmp eax, DTRACE_INVOP_POPL_EBP
		je invop_pop
		cmp eax, DTRACE_INVOP_LEAVE
		je invop_leave
		cmp eax, DTRACE_INVOP_NOP
		je invop_nop
user:
		POPAD
		JMP DWORD PTR IllInstISRAddress
invop_push:
	;/*
	 ;* We must emulate a "pushl %ebp".  To do this, we pull the stack
	; * down 4 bytes, and then store the base pointer.
	 ;*/
		popad				
		sub esp, 4          		;/* make room for %ebp */                     	
		push eax                        ;/* push temp */                   
		mov eax, [esp+8]              	;/* load calling EIP */            
		inc eax                        ;	/* increment over LOCK prefix */  
		mov [esp+4], eax               	;/* store calling EIP */           
		mov eax, [esp+12]             	;/* load calling CS */             
		mov [esp+8], eax               	;/* store calling CS */            
		mov eax, [esp+16]              	;/* load calling EFLAGS */         
		mov [esp+12], eax              	;/* store calling EFLAGS */        
		mov [esp+16], ebp              	;/* push %ebp */                   
		pop eax	                        ;/* pop off temp */                
		iretd                           ;/* Return from interrupt. */      
invop_movediedi:
	;/*
	; * We must emulate a "mov edi, edi".  To do this, increment eip to the next instruction.
	; */
		popad
		push eax			;/* push temp */ 
		mov eax, [esp+4]		;/* load calling EIP */ 
		inc eax				;/* increment to next instruction */
		inc eax
		mov [esp+4], eax		;/* store EIP */
		pop eax				;/* pop off temp */ 
		iretd				;/* Return from interrupt. */   
invop_pop:
	;/*
	; * We must emulate a "popl %ebp".  To do this, we do the opposite of
	; * the above:  we remove the %ebp from the stack, and squeeze up the
	; * saved state from the trap.
	 ;*/
		popad				
		push eax            		;/* push temp */                              
		mov ebp, [esp+16]               ;/* pop %ebp */                   
		mov eax, [esp+12]              ; /* load calling EFLAGS */        
		mov [esp+16], eax               ;/* store calling EFLAGS */       
		mov eax, [esp+8]                ;/* load calling CS */            
		mov [esp+12], eax              ; /* store calling CS */           
		mov eax, [esp+4]               ; /* load calling EIP */           
		inc eax                        ; /* increment over LOCK prefix */ 
		mov [esp+8], eax                ;/* store calling EIP */          
		pop eax                         ;/* pop off temp */               
		add esp, 4                     ; /* adjust stack pointer */       
		iretd                          ; /* Return from interrupt. */     
invop_leave:
	;/*
	; * We must emulate a "leave", which is the same as a "movl %ebp, %esp"
	; * followed by a "popl %ebp".  This looks similar to the above, but
	; * requires two temporaries:  one for the new base pointer, and one
	; * for the staging register.
	; */
		popad
		push eax      		;/* push temp */
		push ebx              	;/* push temp */
		mov ebx, ebp         	;/* set temp to old %ebp */
		mov ebp, [ebx]        	;/* pop %ebp */
		mov eax, [esp+16]     	;/* load calling EFLAGS */
		mov [ebx], eax	       ; /* store calling EFLAGS */
		mov eax, [esp+12]     	;/* load calling CS */
		mov [ebx-4], eax      	;/* store calling CS */
		mov eax, [esp+8]     	;/* load calling EIP */
		inc eax           	;/* increment over LOCK prefix */
		mov [ebx-8], eax    	;/* store calling EIP */
		sub ebx, 8             ;/* adjust for three pushes, one pop */
		mov [esp+8], ebx     	;/* temporarily store new %esp */
		pop ebx               	;/* pop off temp */
		pop eax              	;/* pop off temp */
		mov esp, [esp]      	;/* set stack pointer */
		iretd                  ;/* return from interrupt */
invop_nop:
	;/*
	; * We must emulate a "nop".  This is obviously not hard:  we need only
	; * advance the %eip by one.
	; */
		popad
		inc byte ptr [esp]
		iretd
			
interrupt_fbt6 endp

END