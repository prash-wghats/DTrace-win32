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
 
#ifndef _FASTTRAP_WIN32_H
#define _FASTTRAP_WIN32_H

#include <ntifs.h>
#include <sys/dtrace_misc.h>
#include <ntstrsafe.h>
#include <ntintsafe.h>
#include <stdio.h>
#include <errno.h>
#include <stddef.h>
#include <sys/dtrace.h>
#include <sys/dtrace_win32.h>
#include "regset.h"

extern void dtrace_hook_int(UCHAR ivec, void (*InterruptHandler)( void ), uintptr_t *paddr);

#ifdef _AMD64_
extern UINT64 FasttrapHookISR;
extern UINT64 FasttrapRetHookISR;
#else
extern UINT32 FasttrapHookISR;
extern UINT32 FasttrapRetHookISR;
#endif


#define T_DTRACE_RET 0x7f
#define T_DTRACE_FASTTRAP 0x03
#define T_BPTFLT 0x3
#define T_DTRACE_PROBE 0xfe

typedef PVOID timeout_id_t;

int32_t fuword32(const void *base);
int64_t fuword64(const void *base);
int suword32(void *base, int32_t word);
int suword64(void *base, int64_t word);
int fasttrap_copyout(void * kaddr, void * uaddr, int len);

int uread(proc_t *p, void *kaddr, size_t len, uintptr_t uaddr);
int uwrite(proc_t *p, void *kaddr, size_t len, uintptr_t uaddr);
timeout_id_t timeout(void (*func)(void *), void* unused, hrtime_t nano);
void untimeout(timeout_id_t id);

void fasttrap_winsig(pid_t pid, uintptr_t addr);

int dtrace_user_probe(struct reg *rp);
int dtrace_attached(void);
void interrupt_fasttrap( void );
void interrupt_fasttrapRET( void ) ;

VOID CreateProcFunc(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create);

#endif