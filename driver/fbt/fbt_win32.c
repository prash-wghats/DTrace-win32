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
 
#include <sys/dtrace_misc.h>
#include <sys/dtrace.h>
#include <stdio.h>
#include <stdlib.h>
#include "fbt_win32.h"

extern void dtrace_hook_int(UCHAR ivec, void (*InterruptHandler)( void ), uintptr_t *paddr);

NTSTATUS FbtClose(PDEVICE_OBJECT DevObj, PIRP Irp);
NTSTATUS FbtOpen(PDEVICE_OBJECT DevObj, PIRP Irp);
void FbtUnload(PDRIVER_OBJECT DrvObj);
NTSTATUS FbtIoctl(PDEVICE_OBJECT DevObj, PIRP Irp);

/* interrupt routine for vector 0x06 (illegal instruction ) */
void interrupt_fbt6( void );
#define INTERRUPT_VEC_F0 0x06

#ifdef _AMD64_
ULONG64 IllInstISRAddress = 0;
#else
ULONG32 IllInstISRAddress = 0;
#endif

static UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\Fbt");
static UNICODE_STRING deviceLink = RTL_CONSTANT_STRING(L"\\DosDevices\\Fbt");

NTSTATUS DriverEntry(PDRIVER_OBJECT DrvObj, PUNICODE_STRING RegPath)
{
	PDEVICE_OBJECT DevObj;
	NTSTATUS status;
	
#if _AMD64_	
 	if (IsDebuggerAttached() == 0) {
 		DbgPrint("fbt.sys : debugger not attached. Load failed\n");
 		return STATUS_INSUFFICIENT_RESOURCES;
 	}
#endif
	status = IoCreateDevice(DrvObj, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN,
	                        FALSE, &DevObj);
	if(NT_SUCCESS(status)) {
		status = IoCreateSymbolicLink (&deviceLink, &deviceName);
		DrvObj->MajorFunction[IRP_MJ_CREATE] = FbtOpen;
		DrvObj->MajorFunction[IRP_MJ_CLOSE] = FbtClose;
		DrvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = FbtIoctl;
		DrvObj->DriverUnload  = FbtUnload;
	}
	if (!NT_SUCCESS(status)) {
		IoDeleteSymbolicLink(&deviceLink);
		if(DevObj)
			IoDeleteDevice( DevObj);
	}
	
	dtrace_hook_int(INTERRUPT_VEC_F0, interrupt_fbt6, (uintptr_t *) &IllInstISRAddress);
	if (fbt_load((void *) RegPath) == -1) {
		dtrace_hook_int(INTERRUPT_VEC_F0, (void(*)(void)) IllInstISRAddress, NULL);
		IoDeleteSymbolicLink(&deviceLink);
		if(DevObj)
			IoDeleteDevice( DevObj);
		return (STATUS_INSUFFICIENT_RESOURCES);
	}
	
	
	
	return status;
}

NTSTATUS FbtClose(PDEVICE_OBJECT DevObj, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DevObj);
	
	fbt_close();
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS FbtOpen(PDEVICE_OBJECT DevObj, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DevObj);
	
	fbt_open();
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

void FbtUnload(PDRIVER_OBJECT DrvObj)
{
	int err;
	LARGE_INTEGER tm;
	
	while ((err = fbt_unload()) != 0) {
		tm.QuadPart = UNLOAD_RETRY_DELAY_TIME;
		dprintf("fbt.sys: Unload failed. Retry in %ds\n", abs(UNLOAD_RETRY_DELAY_TIME)/10000000);
		KeDelayExecutionThread(KernelMode, FALSE, &tm);
		
	}
	if (IllInstISRAddress != 0)
		dtrace_hook_int(INTERRUPT_VEC_F0, (void(*)(void)) IllInstISRAddress, NULL);

	IoDeleteSymbolicLink(&deviceLink);
	IoDeleteDevice(DrvObj->DeviceObject);
}

NTSTATUS FbtIoctl(PDEVICE_OBJECT DevObj, PIRP Irp)
{
	NTSTATUS st = STATUS_SUCCESS;
	PIO_STACK_LOCATION Pio;
	int ilen, olen;
	void *addr;
	UNREFERENCED_PARAMETER(DevObj);
	
	Pio = IoGetCurrentIrpStackLocation(Irp);
	ilen = Pio->Parameters.DeviceIoControl.InputBufferLength;
	olen = Pio->Parameters.DeviceIoControl.OutputBufferLength;
	addr = Pio->Parameters.DeviceIoControl.Type3InputBuffer;

	Irp->IoStatus.Status = st;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return st;
}

int  __cdecl symcmp(const void *a, const void *b);

void fbt_create_probe_mod(modctl_t *lf, char *modname)
{
	PIMAGE_DATA_DIRECTORY datadir;
	PIMAGE_EXPORT_DIRECTORY expdir;
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER) lf->imgbase;
	PIMAGE_NT_HEADERS NtHeader;
	PVOID base = (PVOID) lf->imgbase;
	PULONG funcarr;
	PUSHORT ordarr;
	PULONG namearr;
	DWORD i, j;
	linker_symval_t *sym;
#if _AMD64_
	rtf_t *rtf;
#endif

	if (!INKERNEL((uintptr_t) base)) {
		goto end;
	}
	if (MmIsAddressValid((PVOID) base)) {
		NtHeader = (PIMAGE_NT_HEADERS) PtrFromRva( DosHeader, DosHeader->e_lfanew );
	} else {
		goto end;
	}
	if(IMAGE_NT_SIGNATURE != NtHeader->Signature) {
		goto end;
	}

	datadir = &NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	expdir = (PIMAGE_EXPORT_DIRECTORY) PtrFromRva(base, datadir->VirtualAddress);

	if ( expdir->AddressOfNames == 0 || expdir->AddressOfFunctions == 0 || expdir->AddressOfNameOrdinals == 0 ) {
		lf->fbt_nentries = -1;
		goto end;
	}

	funcarr = (PULONG) PtrFromRva(base, expdir->AddressOfFunctions );
	ordarr = (PUSHORT) PtrFromRva(base, expdir->AddressOfNameOrdinals );
	namearr = (PULONG) PtrFromRva(base, expdir->AddressOfNames );

	sym = fbt_malloc(expdir->NumberOfNames * sizeof(linker_symval_t));
	if (sym == NULL) {
		goto end;
	}
	
	j = 0;
	
	for (i = 0; i < expdir->NumberOfNames; i++ ) {
		ULONG Ordinal = (ULONG) ordarr[i];
		ULONG FuncRva;
		if ( i >= expdir->NumberOfNames || i >= expdir->NumberOfFunctions) {
			goto end;
		}

		FuncRva = funcarr[Ordinal];
		/* check for forwarded functions */
		if (FuncRva < datadir->VirtualAddress || FuncRva >= datadir->VirtualAddress + datadir->Size ) {
			sym[j].value = (uintptr_t)((PCHAR) base+funcarr[Ordinal]);
			sym[j++].index = i;
		}
	}

	if (j == 0) {
		fbt_free(sym);
		goto end;
	}
	
	qsort(sym, j, sizeof(linker_symval_t), symcmp);
	
#ifdef _AMD64_
	for ( i = 0; i < j; i++ ) {
#else	
	for ( i = 0; i < j-1; i++ ) { 
#endif
		sym[i].name = (PCHAR) base+namearr[sym[i].index];
#ifdef _AMD64_
		if ((rtf = winos_kernel_func_rtf(lf, sym[i].value)) != NULL)
			sym[i].size = rtf->eaddr - rtf->baddr;
		else
			sym[i].size = 0;
#else	
		sym[i].size = sym[i+1].value - sym[i].value;
#endif	
	}

#ifndef _AMD64_	
	sym[i].name = (PCHAR) base+namearr[sym[i].index];
	sym[i].size = 0;
#endif	
	for ( i = 0; i < j; i++ ) {
		if (MmIsAddressValid((PVOID) sym[i].value)) {
			fbt_provide_module_function(lf, sym[i].index, &sym[i], modname);
		}
	}
	fbt_free(sym);
end:
 	
 	return;

}

int  __cdecl symcmp(const void *a, const void *b)
{
	return (((linker_symval_t *) a)->value - ((linker_symval_t *) b)->value);
}

void *fbt_malloc(int sz)
{
	return ExAllocatePoolWithTag(PagedPool, sz, 'MYMY');
}

void fbt_free(void *blk)
{
	ExFreePoolWithTag(blk, 'MYMY');
}

int fbt_mdl_copy(PVOID dest, PVOID src, ULONG size)
{
	PMDL mdl = NULL;
	PCHAR buffer = NULL;
	NTSTATUS ntStatus;
	
	mdl = IoAllocateMdl(dest, size,  FALSE, FALSE, NULL);

	if (!mdl) {
		ntStatus = STATUS_INSUFFICIENT_RESOURCES;
		dprintf("fbt.sys: fbt_mdl_copy() IoAllocateMdl failed\n");
		return (0);
	}

	try {

		//
		// Probe and lock the pages of this buffer in physical memory.
		// You can specify IoReadAccess, IoWriteAccess or IoModifyAccess
		// Always perform this operation in a try except block.
		//  MmProbeAndLockPages will raise an exception if it fails.
		//
		MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
	} except(EXCEPTION_EXECUTE_HANDLER) {
		ntStatus = GetExceptionCode();
		dprintf("fbt.sys: fbt_mdl_copy() Exception while locking %d\n", ntStatus);
		IoFreeMdl(mdl);
		return (0);
	}
	
	//
	// Map the physical pages described by the MDL into system space.
	// Note: double mapping the buffer this way causes lot of
	// system overhead for large size buffers.
	//

	buffer = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority );

	if (!buffer) {
		ntStatus = STATUS_INSUFFICIENT_RESOURCES;
		dprintf("fbt.sys: fbt_mdl_copy() MmGetSystemAddressForMdlSafe failed\n");
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		return (0);
	}

	RtlCopyMemory(buffer, src, size);

	MmUnlockPages(mdl);
	IoFreeMdl(mdl);

	return (1);
}

/* functions called from probe context, that should not be probed */
static const char *NoProbeFunctionList[] = {
	"_vsnprintf",
	"_vsnwprintf",
	"CcPinRead",
	"DbgPrint",
	"ExAcquireResourceSharedLite",
	"ExAllocatePoolWithTag",
	"ExFreePoolWithTag",
	//"ExQueueWorkItem",
	"ExSetTimerResolution",
	"IoIs32bitProcess",
	"IoThreadToProcess",
	"KeGetCurrentProcessorNumber",
	"KeAcquireSpinLockAtDpcLevel",
	"KeAcquireSpinLockRaiseToSynch",
	"KeLowerIrql",
	"KeQueryPerformanceCounter",
	"KeQuerySystemTime",
	"KeRaiseIrql",
	"KfLowerIrql",
	"KeReleaseSpinLock",
	"KeReleaseSpinLockFromDpcLevel",
	"KeReleaseInStackQueuedSpinLock",
	"KeAbPostRelease",
	"KeAbPreAcquire",
	"KeBugCheckEx",
	"KeAcquireInStackQueuedSpinLock",
	"KiCheckForKernelApcDelivery",
	"KeWaitForSingleObject",
	"ExpInterlockedPopEntrySList",
 	"ExpInsertPoolTrackerExpansion",
	"MiAllocatePoolPages",
	"PsBoostThreadIoEx",
	"KxWaitForLockOwnerShip",
	"MiSessionPoolVector",
	"ExpAllocateBigPool",
	"ExpReleaseFastMutexContended",
	"ExpAcquireFastMutexContended",
	"memset",
	"KiAcquireQueuedSpinLockInstrumented",
	"MemoryBarrier",
	"MmIsAddressValid",
	"PsGetCurrentProcess",
	"PsGetCurrentThread",
	"PsGetCurrentThreadStackBase",
	"PsGetCurrentThreadStackLimit",
	"PsGetProcessId",
	"PsGetProcessImageFileName",
	"PsGetProcessInheritedFromUniqueProcessId",
	/* In Win 7 Pro 32 bit PsGetThreadFreezeCount has the same
	 * address as PsGetProcessInheritedFromUniqueProcessId ???? */
	"PsGetThreadFreezeCount",
	
	"PsGetThreadId",
	"PsGetThreadProcess",
	"PsGetThreadProcessId",
	"RtlCaptureContext",
	"RtlCaptureStackBackTrace",
	"RtlCopyMemory",
	"RtlEnoughStackSpaceForStackCapture",
	"RtlLookupFunctionEntry",
	"RtlpGetStackLimits",
	"RtlpIsFrameInBoundsEx",
	"RtlpLookupFunctionEntryForStackWalks",
	"RtlpWalkFrameChain",
	"RtlWalkFrameChain",
	"RtlZeroMemory",
	"memcpy"
};

int fbt_win32_noprobe_list(const char *name)
{
	int len, i;
	
	len = sizeof(NoProbeFunctionList) / sizeof(NoProbeFunctionList[0]);
	for (i = 0; i < len; i ++) {
		if (strcmp(name, NoProbeFunctionList[i]) == 0)
			return (1);
	}
	return 0;
}

#ifdef _AMD64_
int fbt_proc(struct trap_frame *tf)
{
	int ret;
	u_int8_t *instr;
	
	ret = dtrace_invop(tf->rip, (uintptr_t *) tf, tf->rax);

	switch(ret) {
	case DTRACE_INVOP_SUB_RSP_8:
		instr = (u_int8_t *) tf->rip;
		tf->rsp -= instr[3];
		tf->rip += 4;
		break;
	case DTRACE_INVOP_SUB_RSP_32:
		instr = (u_int8_t *) tf->rip;
		tf->rsp -= *((ULONG *) &instr[3]);
		tf->rip += 7;
		break;
#if 0
	case DTRACE_INVOP_RET:
		tf->rip = (uintptr_t) *((PVOID *) tf->rsp);
		tf->rsp += 8;
		break;
#else	
	case DTRACE_INVOP_ADD_RSP_8:
		instr = (u_int8_t *) tf->rip;
		tf->rsp += instr[3];
		tf->rip += 4;
		break;
	case DTRACE_INVOP_ADD_RSP_32:
		instr = (u_int8_t *) tf->rip;
		tf->rsp += *((ULONG *) &instr[3]);
		tf->rip += 7;
		break;
#endif	
	default:
		return (0);
	}
	return (1);
}

#else /* I386 */

int fbt_proc(struct trap_frame *tf)
{
	int ret;
	struct reg rp = {0};
	thread_t *td = curthread;
	
	td->tf = &rp;
	DtraceWinOSFbtStack(td, (uintptr_t *) tf);

	ret = dtrace_invop(tf->eip, (uintptr_t *) &tf->usp, tf->eax);
	td->tf = NULL;
	return ret;
}

#endif

