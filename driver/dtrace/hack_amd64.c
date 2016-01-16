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


modctl_t *winos_find_kernel_module(uintptr_t pc);
rtf_t *winos_kernel_func_rtf(modctl_t *ctl, uintptr_t pc);

/* Dpc Stack Information for the current cpu */
PVOID readKPCR(void)
{
    PVOID KPcr;
    KPcr = KeGetPcr();
    return KPcr;
}

NtReadVirtualMemory_t NtReadVirtualMemory;
NtWriteVirtualMemory_t NtWriteVirtualMemory;
NtProtectVirtualMemory_t NtProtectVirtualMemory;

//static int KPRCB_Offset_Dpc_Stack;		// Dpc Stack Address Offset in KPRCB structure (32 bit only)
static int KTRAP_FRAME_Offset_KTHREAD;		// Trap Frame offset in KTHREAD structure (64 bit only)
int Profile_Stack_Skip_Frames;			// Number of stack frames to skip (for amd64 DPC stacktrace)
static int NtReadVirtMemIndex;
static int NtWriteVirtMemIndex;
static int NtProtVirtMemIndex;
static int OS_Version;

/*
 * Get Address of NtReadVirtualMemory, NtWriteVirtualMemory and NtProtectVirtualMemory.
 * Used in fasttrap provider.
 */
 
typedef struct _KSERVICE_TABLE_DESCRIPTOR {
	unsigned long *ServiceTableBase;
	unsigned long *ServiceCounterTableBase;
	unsigned long NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry, *pServiceDescriptorTableEntry;

pServiceDescriptorTableEntry KeServiceDescriptorTable;

ULONG64 GetNTAddressFromSSDT(PULONG KiServiceTable, ULONG ServiceId)
{
	return (LONGLONG)( KiServiceTable[ServiceId] >> 4 )
	       + (ULONGLONG)KiServiceTable;
}

int VirtFuncFromSSDT()
{
	PUCHAR      pStartSearchAddress   = (PUCHAR)__readmsr(0xC0000082);
	PUCHAR      pEndSearchAddress     = (PUCHAR)( ((ULONG_PTR)pStartSearchAddress + PAGE_SIZE) & (~0x0FFF) );
	PULONG      pFindCodeAddress      = NULL;
	ULONG_PTR   pKeServiceDescriptorTable;
	PULONG KiServiceTable;
	ULONG64 addr;
	ULONG pattern = (OS_Version == 2 ? 0x43f70000 : 0x83f70000);
	
	modctl_t *module = winos_find_kernel_module((uintptr_t) pStartSearchAddress);
	rtf_t *rtf = winos_kernel_func_rtf(module, (uintptr_t) pStartSearchAddress);
	pEndSearchAddress = pStartSearchAddress + (rtf->eaddr - rtf->baddr);
	
	while ( ++pStartSearchAddress < pEndSearchAddress ) {
		if ( (*(PULONG)pStartSearchAddress & 0xFFFF0000) == pattern ) {
			pFindCodeAddress = (PULONG)(pStartSearchAddress - 12);
			KeServiceDescriptorTable = (pServiceDescriptorTableEntry) 
						((ULONG_PTR) pFindCodeAddress + (((*(PULONG) pFindCodeAddress)>>24) + 7) + 
						(ULONG_PTR) (((*(PULONG) (pFindCodeAddress + 1)) & 0x0FFFF) << 8));
			break;
		}
	}
	
	if (KeServiceDescriptorTable == NULL) {
		dprintf("dtrace.sys: VirtFuncFromSSDT()-> KeServiceDescriptorTable is NULL\n");
		return 0;
	}
	KiServiceTable = KeServiceDescriptorTable->ServiceTableBase;
	addr = GetNTAddressFromSSDT(KiServiceTable, NtReadVirtMemIndex);
	NtReadVirtualMemory = (NtReadVirtualMemory_t) addr;
	addr = GetNTAddressFromSSDT(KiServiceTable, NtWriteVirtMemIndex);
	NtWriteVirtualMemory = (NtReadVirtualMemory_t) addr;
	addr = GetNTAddressFromSSDT(KiServiceTable, NtProtVirtMemIndex);
	NtProtectVirtualMemory = (NtProtectVirtualMemory_t) addr;
	if (NtReadVirtualMemory == NULL || NtWriteVirtualMemory == NULL || NtProtectVirtualMemory == NULL) {
		dprintf("dtrace.sys: VirtFuncFromSSDT()-> Nt*VirtualMemory is NULL\n");
		return 0;
	} 
	
	return 1;
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
			KTRAP_FRAME_Offset_KTHREAD = 0x1c8;
			Profile_Stack_Skip_Frames = 10; 
			NtReadVirtMemIndex = 60;
			NtWriteVirtMemIndex = 55;
			NtProtVirtMemIndex = 77;
			status = 1;
			OS_Version = 0;
			break;
		default:
			status = 0;
		}
	} else if (maj == 6 && min == 1) { /* Windows 7, Windows Server 2008 R2 */
		switch(sp) {
		case 0:
		case 1:
			KTRAP_FRAME_Offset_KTHREAD = 0x1d8;
			Profile_Stack_Skip_Frames = 12;
			NtReadVirtMemIndex = 0x3c;
			NtWriteVirtMemIndex = 0x37;
			NtProtVirtMemIndex = 0x4d;
			status = 1;
			OS_Version = 1;
			break;
		default:
			status = 0;
		}
	} else if (maj == 6 && min == 2) { /* Windows 8, Windows Server 2012 */
		switch(sp) {
		case 0:
		case 1:
			KTRAP_FRAME_Offset_KTHREAD = 0x90;
			Profile_Stack_Skip_Frames = 10;
			NtReadVirtMemIndex = 61;
			NtWriteVirtMemIndex = 56;
			NtProtVirtMemIndex = 78;
			status = 1;
			OS_Version = 2;
			break;
		default:
			status = 0;
		}
	} else if (maj == 6 && min == 3) { /* Windows 8.1 */
		switch(sp) {
		case 0:
		case 1:
			KTRAP_FRAME_Offset_KTHREAD = 0x90;
			Profile_Stack_Skip_Frames = 10;
			NtReadVirtMemIndex = 62;
			NtWriteVirtMemIndex = 57;
			NtProtVirtMemIndex = 79;
			status = 1;
			OS_Version = 2;
			break;
		default:
			status = 0;
		}
	} else if (maj == 10 && min == 0) { /* Windows 10 */
		switch(sp) {
		case 0:
			KTRAP_FRAME_Offset_KTHREAD = 0x90;
			Profile_Stack_Skip_Frames = 0;
			NtReadVirtMemIndex = 63;
			NtWriteVirtMemIndex = 58;
			NtProtVirtMemIndex = 80;
			status = 1;
			OS_Version = 2;
			break;
		default:
			status = 0;
		}
	} else
		status = 0;
	if (status) 
		VirtFuncFromSSDT();
	return status;
}

ZwQueryInformationProcess_t ZwQueryInformationProcess;

void DtraceWinOSInitFunctions()
{
	UNICODE_STRING routineName;
	
     	RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");
        ZwQueryInformationProcess = (ZwQueryInformationProcess_t) MmGetSystemRoutineAddress(&routineName);
}

void winos_reg_to_context(CONTEXT *ct, struct reg *rp)
{
	RtlZeroMemory(ct, sizeof(CONTEXT));
	
	ct->Rax = rp->r_rax;
	ct->Rbx = rp->r_rbx;
	ct->Rcx = rp->r_rcx;
	ct->Rdx = rp->r_rdx;
	ct->Rsp = rp->r_rsp;
	ct->Rbp = rp->r_rbp;
	ct->Rsi = rp->r_rsi;
	ct->Rdi = rp->r_rdi;
	ct->Rip = rp->r_rip;
	ct->R8 = rp->r_r8;
	ct->R9 = rp->r_r9;
	ct->R10 = rp->r_r10;
	/*ct->R11 = r->R11;
	ct->R12 = r->R12;
	ct->R13 = r->R13;
	ct->R14 = r->R14;
	ct->R15 = r->R15;*/
	
}
dtrace_user_module_t *user_modules = NULL;

int winos_user_module_mdl(pid_t pid, dtrace_user_module_t *mod)
{
	PEPROCESS proc;
	KAPC_STATE apc;
	dtrace_user_module_t *p = NULL, *prev=NULL;
 	PMDL mdl = NULL;
    	PCHAR buffer = NULL;
    	PVOID buf;
    	NTSTATUS st;
    	
	st = PsLookupProcessByProcessId((HANDLE) pid, &proc);
	if (st == STATUS_SUCCESS) {
		KeStackAttachProcess(proc, &apc);
		p = ExAllocatePoolWithTag(NonPagedPool, sizeof(dtrace_user_module_t), 'Tag1');
	 	if (p == NULL) 
	 		goto err;
	 
	 	p->mdl = 0;
	 	p->buf = 0;
	 	p->imgbase = mod->imgbase;
	 	strcpy(p->name, mod->name);
	 	p->size = mod->size;
	 	p->pid = mod->pid;
	 	p->next = NULL;
	 			
	 	mdl = IoAllocateMdl((PVOID) mod->imgbase, (ULONG) mod->size,  FALSE, TRUE, NULL);
        	if (!mdl) {
           		goto err1;
           	}
           	try {
           		MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
           	} except(EXCEPTION_EXECUTE_HANDLER) {
           		IoFreeMdl(mdl);
           		goto err1;
           	}
           	buffer = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority );
           	if (!buffer) {
           		MmUnlockPages(mdl);
           		IoFreeMdl(mdl);
           	} else {
           		buf = ExAllocatePoolWithTag(NonPagedPool, mod->size, 'Tag1');
           		if (buf != NULL) {
           			RtlCopyMemory(buf, (PVOID) buffer, mod->size);
           			p->buf = (uintptr_t) buf;
           		}
           		MmUnlockPages(mdl);
           		IoFreeMdl(mdl);
           	}
           				
err1:           			
		if (user_modules == NULL) {
			user_modules = p;
		} else {
			p->next = user_modules;
			user_modules = p;
		}
err:				
	 	KeUnstackDetachProcess(&apc);
	 	ObDereferenceObject(proc);
 	}
 	
 	return 1;
}

void winos_free_user_modules()
{
	dtrace_user_module_t *next, *p = user_modules;
	
	for (; p!= NULL; p = next) {
		next = p->next;
           	if (p->buf != 0) {
			ExFreePoolWithTag((PVOID) p->buf, 'Tag1');
           	}
		ExFreePoolWithTag(p, 'Tag1');
	}
	user_modules = NULL;
}

dtrace_user_module_t *winos_find_user_module(uintptr_t pc)
{
	dtrace_user_module_t *ctl;
	
	if (!INKERNEL(pc)) {
		for (ctl=user_modules; ctl!= NULL; ctl = ctl->next) {
			if (pc >= ctl->imgbase && pc < (ctl->imgbase + ctl->size)) {
				return ctl;
			}
		} 
	}

	return NULL;
} 

rtf_t *winos_user_func_rtf(dtrace_user_module_t *ctl, uintptr_t pc)
{
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER) ctl->buf;
	PIMAGE_NT_HEADERS NtHeader; 
	PIMAGE_DATA_DIRECTORY ExcpDataDir;
	rtf_t *ExcpDirectory, *lrtf;
	int low, high, mid, size;
	uintptr_t pcoff, base = (uintptr_t) ctl->buf;
	
	if (MmIsAddressValid((PVOID) base)) {
		NtHeader = ( PIMAGE_NT_HEADERS ) PtrFromRva( DosHeader, DosHeader->e_lfanew );
	} else {
		return NULL;
	}
	
	if( IMAGE_NT_SIGNATURE != NtHeader->Signature ) {
  		return NULL;
	}
	
	ExcpDataDir = &NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	ExcpDirectory =  (rtf_t *)PtrFromRva(base, ExcpDataDir->VirtualAddress );
	size = ExcpDataDir->Size / sizeof(rtf_t);
	pcoff = pc - ctl->imgbase;
	
	low  =  0;
	high  =  size  -  1;
	while (low  <=  high) {
		mid  =  (low  +  high)  /  2;
		lrtf = &ExcpDirectory[mid];
		if (pcoff < lrtf->baddr)
			high = mid - 1;
		else if (pcoff >= lrtf->eaddr)
			low = mid + 1;
		else {
			if (lrtf->unwnd_addr & 1) {
				lrtf = (rtf_t *) (lrtf->unwnd_addr + ctl->imgbase - 1);
			}
			return lrtf;
		}
	}
	
	return NULL;
}

#define REX_W 		0x48
#define ADD_8_OP	0x83
#define ADD_32_OP	0x81
#define ADD_COM_OP	0xc4
#define LEA_OP		0x8b
#define LEA_8_OP	0x65
#define LEA_32_OP	0xa5
#define POP_BASE_OP	0x58
#define POP_MASK	0xf8
#define POP_REX		0x41
#define RET_OP		0xC3
#define RET_IMM16_OP	0xC2
#define JMP_8_OP 	0xeb	
#define JMP_32_OP 	0xe9

static int64_t fuword64(void *base);

int winos_unwind_user_stack(CONTEXT *ct, int frame, uintptr_t out)
{
	CONTEXT lct;
	uintptr_t imgbase, offset, base, pc;
	ULONG64 *reg, *regaddr, *addr;
	unwind_info_t *info;
	unwind_code_t code;
	rtf_t *rtf, *r;
	UCHAR *inst;
	int fp = 0, size, i, regno, mach = 0, f = frame, co;
	ULONG64 *tmp = (ULONG64 *) out;
	dtrace_user_module_t *ctl;
	
	lct = *ct;
	while (frame != 0 && lct.Rip != 0 && !INKERNEL(lct.Rip)) {
		lct = *ct;
		pc = lct.Rip;
		reg = &lct.Rax;
		*tmp++ = pc;
		inst = (UCHAR *) pc;
		
		ctl = winos_find_user_module(pc);
		if (ctl == NULL) {
			return f-frame;
		}
		imgbase = ctl->imgbase;
		
		rtf = winos_user_func_rtf(ctl, pc);

		if (rtf == NULL ) {
			return f - frame;
		}	
		
		offset = pc - (imgbase + rtf->baddr);
		info = (unwind_info_t *) (imgbase + rtf->unwnd_addr);
		/* Rip already in Epilog */
		if (offset > info->pro_size) {
			if (inst[0] == REX_W ) {
				if (inst[1] == ADD_8_OP && inst[2] == ADD_COM_OP) {
					lct.Rsp += inst[3];
					inst += 4;
				} else if (inst[1] == ADD_32_OP && inst[2] == ADD_COM_OP) {
					lct.Rsp += *((ULONG *) &inst[3]); 
					inst += 7;
				}
			} else if ((inst[0] & 0xfe) == REX_W && inst[1] == LEA_OP) {
				if ((inst[2] & 0xf8) == 0x60) {
					fp = (inst[0] & 0x1) << 3 | inst[2] & 0x7;
					lct.Rsp = reg[fp];
					lct.Rsp += inst[3];
					inst += 4;
					
				} else if ((inst[2] & 0xf8) == 0xa0) {
					fp = (inst[0] & 0x1) << 3 | inst[2] & 0x7;
					lct.Rsp = reg[fp];
					lct.Rsp += *((LONG *) &inst[3]); 
					inst += 7;
				}
			}
			do {
				if ((inst[0] & POP_MASK) == 0x58) {
					
					regno = inst[0] & 0x7;
					
					//reg[regno] = *((ULONG64 *)lct.Rsp);
					if ((reg[regno] = fuword64((void *) lct.Rsp)) == -1)
						goto user_ret;
					lct.Rsp +=8;
					inst += 1;
					
				}else if ((inst[0] & 0xf0) == 0x40 && (inst[0] & POP_MASK) == 0x58) {
					regno = inst[0] & 0x3 << 0x1 | inst[1] & 0x7;
					//reg[regno] = *((ULONG64 *)lct.Rsp);
					if ((reg[regno] = fuword64((void *) lct.Rsp)) == -1)
						goto user_ret;
					lct.Rsp += 8;
					inst += 2;
					
				} else
					break;
			} while(1);
			
			if (inst[0] == RET_OP || inst[0] == RET_IMM16_OP) {// || inst[0] == JMP_8_OP || inst[0] == JMP_32_OP) {
				
				//lct.Rip = *((ULONG64*)lct.Rsp);
        			if ((lct.Rip = fuword64((void *) lct.Rsp)) == -1)
					goto user_ret;
        			lct.Rsp += 8;
        			*ct = lct;
        			frame--;
        			continue;
			}
			lct = *ct;
		} 
		/* Rip before Epilog */
chain:		i = 0;
		
		if (info->fp) {
			base = reg[info->fp];
			base -= info->fpoff * 16;
		} else 
			base = lct.Rsp;

		mach = 0;
		while(info->cnt > i) {
			code = info->code[i];
			/* Prologue code already executed: reverse the action */
			if (code.pro_off <= offset) {
				switch(code.op_code) {
				case UWOP_PUSH_NONVOL:
					//reg[code.op_info] = *((ULONG64 *)lct.Rsp);
					if ((reg[code.op_info] = fuword64((void *) lct.Rsp)) == -1)
						goto user_ret;
					lct.Rsp += 8;
					i += 1;
					break;
				case UWOP_ALLOC_LARGE:
					if (code.op_info) {
						size = *((ULONG *) &info->code[i+1]);
						i += 3;
					} else {
						size = 8 * *((USHORT *) &info->code[i+1]);
						i += 2;
					}
					lct.Rsp +=size;
					break;
				case UWOP_ALLOC_SMALL:
					size = (8 * code.op_info) + 8;
					lct.Rsp +=size;
					i += 1;
					break;
				case UWOP_SET_FPREG:
					lct.Rsp = reg[info->fp];
					lct.Rsp -= info->fpoff * 16;
					i += 1;
					break;
				case UWOP_SAVE_NONVOL:
					size = 8 *  *((USHORT *) &info->code[i+1]);
					addr = (ULONG64 *) (base + size);
					reg[code.op_info] = *addr;
					i += 2;
					break;
				case UWOP_SAVE_NONVOL_FAR:
				
					size = *((ULONG *) &info->code[i+1]);
					addr = (ULONG64 *) (base + size);
					reg[code.op_info] = *addr;
					i += 3;
					break;
				//case UWOP_SAVE_XMM:	//not implemented
				case UWOP_EPILOG:
					if (info->ver == 1) 
						i +=2;
					else
						i +=1;
					break;
				//case UWOP_SAVE_XMM_FAR:	//not implemented
				case UWOP_SPARE:
					if (info->ver == 1) 
						i +=3;
					else
						;//spare i +=1;
					break;
				case UWOP_SAVE_XMM128: //not implemented
					i += 2;
					break;
				case UWOP_SAVE_XMM128_FAR:
					i += 3;
					break;
				case UWOP_PUSH_MACHFRAME:
					mach = 1;
					if (code.op_info) {
						//lct.Rip = *((ULONG64 *)(lct.Rsp + 8));
						//lct.Rsp = *((ULONG64 *)(lct.Rsp + 32));
						if ((lct.Rip = fuword64((void *) (lct.Rsp + 8))) == -1 ||
						    (lct.Rsp = fuword64((void *) (lct.Rsp + 32))) == -1) 
						    	goto user_ret;	
					} else {
						//lct.Rip = *((ULONG64 *)(lct.Rsp));
						//lct.Rsp = *((ULONG64 *)(lct.Rsp + 24));
						if ((lct.Rip = fuword64((void *) lct.Rsp)) == -1 ||
						    (lct.Rsp = fuword64((void *) (lct.Rsp + 24))) == -1) 
						    	goto user_ret;
					
					}
					i += 1;
					break;
				default:
					lct.Rip = 0;
					return f - frame;
					break;
				}
			} else {	/* prologue code not yet executed, go to the next code */
				switch(code.op_code) {
				case UWOP_PUSH_NONVOL:
				case UWOP_ALLOC_SMALL:
				case UWOP_PUSH_MACHFRAME:
					i +=1;
					break;
				case UWOP_SET_FPREG:
					base = reg[info->fp];
					base -= info->fpoff * 16;
					i +=1;
					break;
				case UWOP_ALLOC_LARGE:
					if (code.op_info)
						i +=3;
					else
						i +=2;
					break;
				case UWOP_SAVE_NONVOL:
				case UWOP_SAVE_XMM128:
					i +=2;
					break;
				case UWOP_SAVE_NONVOL_FAR:
				case UWOP_SAVE_XMM128_FAR:
					i += 3;
					break;
				//case UWOP_SAVE_XMM:	
				case UWOP_EPILOG:
					if (info->ver == 1) 
						i +=2;
					else
						i +=1;
					break;
				//case UWOP_SAVE_XMM_FAR:	
				case UWOP_SPARE:
					if (info->ver == 1) 
						i +=3;
					else
						;//spare i +=1;
					break;	
				default:
					lct.Rip = 0;
					return f - frame;
					break;
				}
			}
		}
		if (info->flags == UNW_FLAG_CHAININFO) {
			r = (rtf_t *)&(info->code[( info->cnt + 1 ) & ~1]);
			info = (unwind_info_t *) (imgbase + r->unwnd_addr);
			goto chain;
		}else if (mach == 0) {
			//lct.Rip = *((ULONG64 *) lct.Rsp);
			if ((lct.Rip = fuword64((void *) lct.Rsp)) == -1)
				goto user_ret;
			lct.Rsp += 8;
		}
		*ct = lct;
		frame--;
	}
user_ret:	
	return (f - frame);
}

int IsProc32Bit(HANDLE pid)
{	
 	HANDLE hProcess = 0;
	NTSTATUS st;
	ULONG_PTR ptr;
	ULONG ret = 0;
	PEPROCESS proc;
	int wow = 0;
 	st = PsLookupProcessByProcessId(pid, &proc);
 	  if (st == STATUS_SUCCESS) {
 	 	st = ObOpenObjectByPointer(proc,0, NULL, 0,0,KernelMode,&hProcess);
 	 	if (st == STATUS_SUCCESS) {
 	 		if ((st =  ZwQueryInformationProcess(hProcess, 26, &ptr, sizeof(ULONG_PTR), &ret)) == STATUS_SUCCESS) {
 				wow = (ptr == 0 ? 0 : 1);
 			} else
 				dprintf("dtrace.sys: IsProc32Bit() failed\n");
 			
 			ZwClose(hProcess);
 	 	 }
 		ObDereferenceObject(proc);
 	} else 
 		dprintf("dtrace.sys: IsProc32Bit() failed to lookup process for pid (%d)\n", pid);
 	
 	return wow;
 	
}

modctl_t *winos_find_kernel_module(uintptr_t pc)
{
	struct modctl *ctl;
	
	if (INKERNEL(pc)) {
		ctl = modules;
		do {
			if (pc >=  (uintptr_t) ctl->imgbase && pc < ((uintptr_t) ((uintptr_t) ctl->imgbase + ctl->size))) {
				return ctl;
			}
		} while ((ctl = ctl->mod_next) != modules);
	} 
	
	return NULL;
} 

rtf_t *winos_kernel_func_rtf(modctl_t *ctl, uintptr_t pc)
{
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER) ctl->imgbase;
	PIMAGE_NT_HEADERS NtHeader; 
	PIMAGE_DATA_DIRECTORY ExcpDataDir;
	rtf_t *ExcpDirectory, *lrtf;
	int low, high, mid, size;
	uintptr_t pcoff, base = ctl->imgbase;
	
	if (MmIsAddressValid((PVOID) base)) {
	NtHeader = ( PIMAGE_NT_HEADERS ) PtrFromRva( DosHeader, DosHeader->e_lfanew );
	} else {
		return NULL;
	}
	if( IMAGE_NT_SIGNATURE != NtHeader->Signature ) {
  		return NULL;
	}
	
	ExcpDataDir = &NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	
	ExcpDirectory =  (rtf_t *)PtrFromRva(base, ExcpDataDir->VirtualAddress );
	size = ExcpDataDir->Size / sizeof(rtf_t);
	pcoff = pc - base;
	
	low  =  0;
	high  =  size  -  1;
	while (low  <=  high) {
		mid  =  (low  +  high)  /  2;
		lrtf = &ExcpDirectory[mid];
		if (pcoff < lrtf->baddr)
			high = mid - 1;
		else if (pcoff >= lrtf->eaddr)
			low = mid + 1;
		else {  
			//check for indirection
			if (lrtf->unwnd_addr & 1) {
				lrtf = (rtf_t *) (lrtf->unwnd_addr + ctl->imgbase - 1);
			}
			return lrtf;
		}
	}
	
	

	return NULL;
}

void KTRAPFRAME_to_regs(PKTRAP_FRAME trap, struct reg *rp)
{
	rp->r_rip = trap->Rip;
	rp->r_rax = trap->Rax;
	rp->r_rbx = trap->Rbx;
	rp->r_rcx = trap->Rcx;
	rp->r_rdx = trap->Rdx;
	rp->r_rbp = trap->Rbp;
	rp->r_rsp = trap->Rsp;
	rp->r_rsi = trap->Rsi;
	rp->r_rdi = trap->Rdi;
	rp->r_r8 = trap->R8;
	rp->r_r9 = trap->R9;
	rp->r_r10 = trap->R10;
}

void DtraceWinOSDpcStack(thread_t *td)
{
	PKTRAP_FRAME Trapframe = *((PVOID *) ((UINT_PTR) td->td + KTRAP_FRAME_Offset_KTHREAD));
	cpu_data_t *cpu = &CPU[KeGetCurrentProcessorNumber()];
	int n;
	uintptr_t pc = 0;
		
	cpu->cpu_profile_pc = 0;
	cpu->cpu_profile_upc = 0;
	
	if (Trapframe == NULL) {
		cpu->cpu_profile_pc = pc;
	} else if (INKERNEL((uintptr_t) Trapframe)) {
		KTRAPFRAME_to_regs(Trapframe, td->tf);
		if (Trapframe->ExceptionActive == 0) { /* user mode */
			cpu->cpu_profile_upc = Trapframe->Rip;		
		} else if (Trapframe->ExceptionActive == 2) {
			cpu->cpu_profile_pc = pc;
		}
	}
}

/* In 64 bit system, ONLY WAY OF TESTING FASTTRAP.SYS OR FBT.SYS is
 * by attaching a kernel debugger to the OS. This will disable the Patchguard
 * for long as the debugger is attached. we should check for kernel debugger 
 * beginning attached, before loading fasttrap.sys and fbt.sys drivers.Since i 
 * have not found the way to implement this,  only checking that the OS is 
 * started in DEBUG Mode. ie > bcdedit /DEBUG ON.
 * Having said that in Win 7 64 bit if you have the AUTOENABLE policy on for
 * dbgsettings the patchguard is disabled without the kernel debugger being attached.
 * ->Bcdedit /dbgsettings SERIAL DEBUGPORT:1 BAUDRATE:115200 /start AUTOENABLE /noumex
 * THIS DOESNT WORK FOR Win 8.0 or higher.
 */ 
int IsDebuggerAttached(void)
{ 
	int l, ret = 0;
	char *s;
	NTSTATUS status;
	RTL_QUERY_REGISTRY_TABLE QueryTable[2];
	UNICODE_STRING UnicodeString;
	ANSI_STRING AnsiString;
	
	RtlZeroMemory(&UnicodeString, sizeof(UnicodeString));
	RtlZeroMemory(QueryTable, sizeof(QueryTable));
	QueryTable[0].QueryRoutine = NULL;
 	QueryTable[0].Name = L"SystemStartOptions";
 	QueryTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT ;
 	QueryTable[0].EntryContext = &UnicodeString;
 	QueryTable[0].DefaultType   = REG_SZ;
    	QueryTable[0].DefaultData   = L"";
    	QueryTable[0].DefaultLength = 0;
    	   	
 	status = RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, 
 		     L"\\Registry\\Machine\\System\\CurrentControlSet\\Control", 
 		     &QueryTable[0], NULL, NULL);
 		     
 	if (!NT_SUCCESS(status))
 		return ret;
 		
 	l = RtlUnicodeStringToAnsiSize(&UnicodeString);
 	if (l != 0) {
 		RtlInitAnsiString(&AnsiString, NULL);
 		RtlUnicodeStringToAnsiString(&AnsiString, &UnicodeString, TRUE);
 		if (AnsiString.MaximumLength >= AnsiString.Length + 1) {
 			AnsiString.Buffer[AnsiString.Length] = '\0';
 			//s = strstr(AnsiString.Buffer, "DEBUG=AUTOENABLE");
 			s = strstr(AnsiString.Buffer, "DEBUG");
 			if (s != NULL) {
 				ret = 1;
 			} else
 				DbgPrint("DTRACE settings required ->. \nbcdedit /debug ON \n");
 		}
 		RtlFreeAnsiString(&AnsiString);
 	}
 	RtlFreeUnicodeString(&UnicodeString);
 	
 	return ret;
}

/* Fetches 64 bits of data from the user-space address base */
static int64_t fuword64(void *base)
{
	int64_t ret;

	if (MmIsAddressValid(base)) {
		RtlCopyMemory(&ret, base, sizeof(int64_t));
		return ret;
	} else {
		DbgPrint("user stack fuword64 failed %p\n", base);
		return -1;

	}
}