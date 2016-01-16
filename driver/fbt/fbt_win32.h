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
 
#ifndef	_FBT_WIN32_H
#define	_FBT_WIN32_H

#include <ntifs.h>
#include <sys/dtrace_misc.h>
#include <ntstrsafe.h>
#include <ntintsafe.h>
#include <stdio.h>
#include <errno.h>
#include <stddef.h>
#include <Aux_klib.h>
#include <Ntimage.h>
#include <sys/dtrace.h>
#include <sys/dtrace_win32.h>

#define PtrFromRva( base, rva ) ( ( ( PUCHAR ) base ) + rva )

__declspec(dllimport) cpu_data_t *CPU;
__declspec(dllimport) cpu_core_t *cpu_core;
__declspec(dllimport) int KTRAP_FRAME_Offset_KTHREAD;


typedef struct linker_sym {
	uintptr_t value;
	int size;
	char *name;
	int index;
} linker_symval_t;

void heapsort(linker_symval_t *heap, int no);
void fbt_create_probe_mod(modctl_t *lf, char *modname);
char *cleanddpath(char *str);


#define MAXPATHLEN	120

void *fbt_malloc(int sz);
void fbt_free(void *blk);
void fbt_trace_frame(thread_t *td, uintptr_t *stack);
void fbt_provide_module(void *arg, modctl_t *lf);
int fbt_provide_module_function(modctl_t *lf, int symindx,linker_symval_t *symval, void *opaque);
int fbt_mdl_copy(PVOID dest, PVOID src, ULONG size);
int fbt_load(void *dummy);
int fbt_unload(void);
void fbt_open(void);
void fbt_close(void);

int fbt_win32_noprobe_list(const char *name);

#endif