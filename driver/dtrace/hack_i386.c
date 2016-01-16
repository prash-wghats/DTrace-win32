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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE. 
 */
 
#include <ntifs.h>
#include <sys/dtrace_misc.h>
#include <sys/dtrace_win32.h>
#include <sys/dtrace_impl.h>
#include <ntstrsafe.h>
#include <ntintsafe.h>
#include <errno.h>
#include <stddef.h>
#include "dtrace_private.h"


/* Dpc Stack Information for the current cpu */
PVOID readKPCR(void)
{
	PVOID KPcr;
    _asm
    {
        mov eax, fs:[0x1C]  // Self
        mov [KPcr], eax
    }
    return KPcr;
}

/*
 * Get Address of NtReadVirtualMemory, NtWriteVirtualMemory and NtProtectVirtualMemory.
 * Used in fasttrap provider.
 */
 
 /* The structure representing the System Service Table. */
typedef struct SystemServiceTable {
	UINT32* 	ServiceTable;
	UINT32* 	CounterTable;
	UINT32		ServiceLimit;
	UINT32*     ArgumentTable;
} SST;

/* Declaration of KeServiceDescriptorTable, which is exported by ntoskrnl.exe. */
__declspec(dllimport) SST KeServiceDescriptorTable;

NtReadVirtualMemory_t NtReadVirtualMemory;
NtWriteVirtualMemory_t NtWriteVirtualMemory;
NtProtectVirtualMemory_t NtProtectVirtualMemory;

static int KPRCB_Offset_Dpc_Stack;		// Dpc Stack Address Offset in KPRCB structure (32 bit only)
static int KTRAP_FRAME_Offset_KTHREAD;		
int Profile_Stack_Skip_Frames;			// Number of stack frames to skip (for amd64 DPC stacktrace)
static int NtReadVirtMemIndex;
static int NtWriteVirtMemIndex;
static int NtProtVirtMemIndex;
	

static void VirtFuncFromSSDT()
{
	PLONG ssdt;
	/* identify the address of SSDT table */
	ssdt = KeServiceDescriptorTable.ServiceTable;
	NtReadVirtualMemory = (NtReadVirtualMemory_t) ssdt[NtReadVirtMemIndex];
	NtWriteVirtualMemory = (NtReadVirtualMemory_t) ssdt[NtWriteVirtMemIndex];
	NtProtectVirtualMemory = (NtProtectVirtualMemory_t) ssdt[NtProtVirtMemIndex];
}

int DtraceWinOSHackData()
{
	RTL_OSVERSIONINFOEXW os;
	ULONG maj, min;
	USHORT sp;
	int status = 0;

	RtlZeroMemory(&os, sizeof(RTL_OSVERSIONINFOEXW));
	os.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);

	if (RtlGetVersion((PRTL_OSVERSIONINFOW) &os) == STATUS_SUCCESS)
		dprintf("dtrace.sys: OS Details => Major %d: Minor %d: SP Major %d: SP Minor %d\n", 
		    os.dwMajorVersion, os.dwMinorVersion, os.wServicePackMajor, os.wServicePackMinor);
	else {
		dprintf("dtrace.sys: failed to get OS Details\n");
		return 0;
	}
	maj = os.dwMajorVersion;
	min = os.dwMinorVersion;
	sp = os.wServicePackMajor;

	if (maj == 5 && min == 1) {	/* WinXP */
		switch(sp) {
		case 0:
		case 1:
		case 2:
		case 3:
			KPRCB_Offset_Dpc_Stack = 0x868;
			KTRAP_FRAME_Offset_KTHREAD = 0x134;
			NtReadVirtMemIndex = 0xBA;
			NtWriteVirtMemIndex = 0x115;
			NtProtVirtMemIndex = 0x89;
			status = 1;
			break;
		default:
			status = 0;
		}
	} else if (maj == 5 && min == 2) { /* Windows Server 2003 */
		switch(sp) {
		case 0:
		case 1:
		case 2:
		default:
			status = 0;
		}
	} else if (maj == 6 && min == 0) { /* Windows Vista, Windows Server 2008 */
		switch(sp) {
		case 0:
		case 1:
		case 2:
			KPRCB_Offset_Dpc_Stack = 0x1988;	
			KTRAP_FRAME_Offset_KTHREAD = 0x120;
			NtReadVirtMemIndex = 0x16a;
			NtWriteVirtMemIndex = 0x105;
			NtProtVirtMemIndex = 0xd2;
			status = 1;
			break;
		default:
			status = 0;
		}
	} else if (maj == 6 && min == 1) { /* Windows 7, Windows Server 2008 R2 */
		switch(sp) {
		case 0:
		case 1:
			KPRCB_Offset_Dpc_Stack = 0x1908;	/* 0 */
			KTRAP_FRAME_Offset_KTHREAD = 0x128;
			NtReadVirtMemIndex = 277;
			NtWriteVirtMemIndex = 399;
			NtProtVirtMemIndex = 215;
			status = 1;
			break;
		default:
			status = 0;
		}
	} else if (maj == 6 && min == 2) { /* Windows 8, Windows Server 2012 */
		switch(sp) {
		case 0:
		case 1:
			KPRCB_Offset_Dpc_Stack = 0x2208;	
			KTRAP_FRAME_Offset_KTHREAD = 0x6c;
			NtReadVirtMemIndex = 131;
			NtWriteVirtMemIndex = 2;
			NtProtVirtMemIndex = 195;
			status = 1;
			break;
		default:
			status = 0;
		}
	} else if (maj == 6 && min == 3) { /* Windows 8.1 */
		switch(sp) {
		case 0:
		//case 1:
			KPRCB_Offset_Dpc_Stack = 0x2210;	
			KTRAP_FRAME_Offset_KTHREAD = 0x6c;
			NtReadVirtMemIndex = 134;
			NtWriteVirtMemIndex = 3;
			NtProtVirtMemIndex = 198;
			status = 1;
			break;
		default:
			status = 0;
		}
	} else if (maj == 10 && min == 0) { /* Windows 10 */
		switch(sp) {
		case 0:
			KPRCB_Offset_Dpc_Stack = 0x2210;	
			KTRAP_FRAME_Offset_KTHREAD = 0x6c;
			NtReadVirtMemIndex = 136;
			NtWriteVirtMemIndex = 4;
			NtProtVirtMemIndex = 200;
			status = 1;
			break;
		default:
			status = 0;
		}
	} else {
		status = 0;
	}
	
	if (status) 
		VirtFuncFromSSDT();
		
	return status;
}


#define KTRAP_FRAME_I386_OFFSET_EIP	0x68
#define KTRAP_FRAME_I386_OFFSET_ESP	0x74
#define KTRAP_FRAME_I386_OFFSET_EBP	0x60

void DtraceWinOSDpcStack(thread_t *td)
{
	int dpc_frames = 1;
	CONTEXT  Context;
	PVOID Kprcb, Kpcr, DpcStack, ebp, Trapframe;
	struct frame *f;
	uintptr_t pc;
	KPCR *pcr;
	cpu_data_t *cpu = &CPU[KeGetCurrentProcessorNumber()];
	
	if (KPRCB_Offset_Dpc_Stack == 0) {
		dprintf("dtrace.sys: DPC stack base not found\n");
		return;
	}
	
	Context.ContextFlags = CONTEXT_CONTROL;
	RtlCaptureContext(&Context);
	
	/*  If the kernel is interrupted when running idle, the kernel stack is used for dpc processing.*/
	if (Context.Esp >= td->kbase || Context.Esp < td->klimit) {
		/*
		  DPC stack layout in 32 bit, during dpc processing.
		  
					DPC stack
					  |	|
					  |Kaddr|
		  KPCR->KPRCB->DpcStack-> |	|
		  
					kernel stack
				    Kaddr |ffff|
				    	  |ebp |
		*/
		Kpcr = readKPCR();
		Kprcb = ((KPCR *)Kpcr)->Prcb;
		DpcStack = *((PVOID *) ((UINT_PTR) Kprcb + KPRCB_Offset_Dpc_Stack));
		ebp = *((PVOID *) ((PVOID *)DpcStack-1));
		ebp = ((PVOID *) ebp + 1);
		
		f = (struct frame *) ebp;
		
		while (dpc_frames && f != NULL) {
			if ((uintptr_t)f >= td->kbase || (uintptr_t) f < td->klimit) 
				break;
			f = f->f_frame;
			dpc_frames--;
		}
		if (!dpc_frames && f != NULL) {
			if (INKERNEL((uintptr_t) f->f_frame)) {
				td->ebp = (uintptr_t) f->f_frame;
				cpu->cpu_profile_pc = f->f_retaddr;
				cpu->cpu_profile_upc = 0;
				Trapframe = *((PVOID *) ((UINT_PTR) td->td + KTRAP_FRAME_Offset_KTHREAD)); 
				if (Trapframe != NULL && Trapframe < (PVOID) td->kbase && Trapframe > (PVOID) td->klimit) {
					td->tf->r_ebp = (ULONG) *((PVOID *) ((UINT_PTR) Trapframe + KTRAP_FRAME_I386_OFFSET_EBP));
					td->tf->r_eip = (ULONG)  *((PVOID *) ((UINT_PTR) Trapframe + KTRAP_FRAME_I386_OFFSET_EIP));
					td->tf->r_esp = (ULONG) *((PVOID *) ((UINT_PTR) Trapframe + KTRAP_FRAME_I386_OFFSET_ESP));
				}
			} else {
				cpu->cpu_profile_upc = f->f_retaddr;
				cpu->cpu_profile_pc = 0;
				td->tf->r_eip = f->f_retaddr;
				td->tf->r_ebp = (uintptr_t) f->f_frame;
			}
		}
	}
}

ZwQueryInformationProcess_t ZwQueryInformationProcess;
void DtraceWinOSInitFunctions()
{
	UNICODE_STRING routineName;
	
	RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");
        ZwQueryInformationProcess = (ZwQueryInformationProcess_t) MmGetSystemRoutineAddress(&routineName);
}

void DtraceWinOSFbtStack(thread_t *td, uintptr_t *stack)
{

	CONTEXT  Context;
	PETHREAD t;
	PVOID Trapframe;
	
	Context.ContextFlags = CONTEXT_CONTROL;
	RtlCaptureContext(&Context);
	// kernel stack frame
	td->ebp = Context.Ebp;
	t = td->td;
	
	Trapframe = *((PVOID *) ((UINT_PTR) t + KTRAP_FRAME_Offset_KTHREAD)); 
	// user stack frame
	if (Trapframe != NULL && Trapframe < (PVOID) td->kbase && Trapframe >= (PVOID) td->klimit) {
		td->tf->r_ebp = (ULONG) *((PVOID *) ((UINT_PTR) Trapframe + KTRAP_FRAME_I386_OFFSET_EBP));
		td->tf->r_eip = (ULONG)  *((PVOID *) ((UINT_PTR) Trapframe + KTRAP_FRAME_I386_OFFSET_EIP));
		td->tf->r_esp = (ULONG) *((PVOID *) ((UINT_PTR) Trapframe + KTRAP_FRAME_I386_OFFSET_ESP));
	}else {
		td->tf->r_ebp = td->tf->r_eip = td->tf->r_esp = 0;
	}
}
