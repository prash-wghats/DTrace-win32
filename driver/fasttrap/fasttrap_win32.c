/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */


 
#include <sys/dtrace_misc.h>
#include <sys/fasttrap_impl.h>
#include "fasttrap_win32.h"

__declspec(dllimport) struct modctl *modules;
__declspec(dllimport) NtReadVirtualMemory_t NtReadVirtualMemory;
__declspec(dllimport) NtWriteVirtualMemory_t NtWriteVirtualMemory;
__declspec(dllimport) NtProtectVirtualMemory_t NtProtectVirtualMemory;

#ifdef _AMD64_
UINT64 FasttrapHookISR = 0;
UINT64 FasttrapRetHookISR = 0;
#else
UINT32 FasttrapHookISR = 0;
UINT32 FasttrapRetHookISR = 0;
#endif

NTSTATUS FasttrapClose(PDEVICE_OBJECT DevObj, PIRP Irp);
NTSTATUS FasttrapOpen(PDEVICE_OBJECT DevObj, PIRP Irp);
void FasttrapUnload(PDRIVER_OBJECT DrvObj);
NTSTATUS FasttrapIoctl(PDEVICE_OBJECT DevObj, PIRP Irp);

int fasttrap_ioctl(void *arg,  int cmd,  int len);
int fasttrap_close();
int fasttrap_open();
int fasttrap_load();
int fasttrap_unload();

int IsNtVirtualFunc();

static UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\Fasttrap");
static UNICODE_STRING deviceLink = RTL_CONSTANT_STRING(L"\\DosDevices\\Fasttrap");


NTSTATUS DriverEntry(PDRIVER_OBJECT DrvObj, PUNICODE_STRING RegPath)
{
	PDEVICE_OBJECT DevObj = NULL;
	NTSTATUS status;
	UNREFERENCED_PARAMETER(RegPath);
	
#if _AMD64_	
 	if (IsDebuggerAttached() == 0) {
 		DbgPrint("fasttrap.sys : debugger not attached. Load failed\n");
 		return STATUS_INSUFFICIENT_RESOURCES;
 	}
#endif
 	
	if (IsNtVirtualFunc() == 0) {
		dprintf("fasttrap.sys : Nt*VirtualMemory functions not found. Load failed\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	
	status = IoCreateDevice(DrvObj, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN,
	                        FALSE, &DevObj);
	if(!NT_SUCCESS(status)) {
		return status;
	}
	
	DrvObj->MajorFunction[IRP_MJ_CREATE] = FasttrapOpen;
	DrvObj->MajorFunction[IRP_MJ_CLOSE] = FasttrapClose;
	DrvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = FasttrapIoctl;
	DrvObj->DriverUnload  = FasttrapUnload;
	
	status = IoCreateSymbolicLink (&deviceLink, &deviceName);
	
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice( DevObj);
		return status;
	}

	fasttrap_load();
	
	if (PsSetCreateProcessNotifyRoutine(CreateProcFunc, FALSE) != STATUS_SUCCESS) {
		dprintf("fasttrap.sys: PsSetCreateProcessNotifyRoutine registrartion failed\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	return status;
}

NTSTATUS FasttrapClose(PDEVICE_OBJECT DevObj, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DevObj);
	
	fasttrap_close();

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS FasttrapOpen(PDEVICE_OBJECT DevObj, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DevObj);
	
	fasttrap_open();

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

void FasttrapUnload(PDRIVER_OBJECT DrvObj)
{
	LARGE_INTEGER tm;
	
	while (fasttrap_unload() != 0) {
		tm.QuadPart = UNLOAD_RETRY_DELAY_TIME;
		dprintf("fasttrap.sys: Unload failed. Retry in %ds\n", abs(UNLOAD_RETRY_DELAY_TIME)/10000000);
		KeDelayExecutionThread(KernelMode, FALSE, &tm);
	}
	
	PsSetCreateProcessNotifyRoutine(CreateProcFunc, TRUE);
	IoDeleteSymbolicLink(&deviceLink);
	IoDeleteDevice(DrvObj->DeviceObject);
}

NTSTATUS FasttrapIoctl(PDEVICE_OBJECT DevObj, PIRP Irp)
{
	NTSTATUS st = STATUS_SUCCESS;
	PIO_STACK_LOCATION Pio;
	int ilen, olen, t;
	void *addr;
	UNREFERENCED_PARAMETER(DevObj);
	
	Pio = IoGetCurrentIrpStackLocation(Irp);
	ilen = Pio->Parameters.DeviceIoControl.InputBufferLength;
	olen = Pio->Parameters.DeviceIoControl.OutputBufferLength;
	addr = Pio->Parameters.DeviceIoControl.Type3InputBuffer;

	if (addr == NULL)
		st =  (0xE0000000 | ENOMEM);
	else {
		t = fasttrap_ioctl(addr, Pio->Parameters.DeviceIoControl.IoControlCode, ilen);
		if (t)
			st = 0xE0000000 | t;
	}

	Irp->IoStatus.Status = st;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return st;
}

/* Fetches 32 bits of data from the user-space address base */
int32_t fuword32(void *base)
{
	int32_t ret;
	
	if (MmIsAddressValid(base)) {
		RtlCopyMemory(&ret, base, sizeof(int32_t));
		return ret;
	} else {
		dprintf("fasttrap.sys: fuword32 failed for %p\n", base);
		return -1;
	}

}

/* Fetches 64 bits of data from the user-space address base */
int64_t fuword64(void *base)
{
	int64_t ret;

	if (MmIsAddressValid(base)) {
		RtlCopyMemory(&ret, base, sizeof(int64_t));
		return ret;
	} else {
		dprintf("fasttrap.sys: fuword64 failed for %p\n", base);
		return -1;

	}
}

/* Stores 32 bits of data to the user-space address base */
int
suword32(void *base, int32_t word)
{
	if (MmIsAddressValid(base)) {
		RtlCopyMemory(base, &word, sizeof(int32_t));
		return 0;
	} else {
		dprintf("fasttrap.sys: suword32 failed for %p\n", base);
		return -1;
	}
}

/* Stores 64 bits of data to the user-space address base */
int
suword64(void *base, int64_t word)
{
	if (MmIsAddressValid(base)) {
		RtlCopyMemory(base, &word, sizeof(int64_t));
		return 0;
	} else {
		dprintf("fasttrap.sys: fuword64 failed for %p\n", base);
		return -1;
	}
}

int IsNtVirtualFunc()
{
	if (NtReadVirtualMemory == NULL || NtWriteVirtualMemory == NULL || NtProtectVirtualMemory == NULL)
		return 0;
	return 1;
}

/* timeout functions */

typedef void (*TimeoutFunc)(void *);
struct timeout_func {
	KTIMER Timer;
	int64_t time;
	PETHREAD Thread;
	TimeoutFunc f;
};

void FTTimeout(PVOID args)
{
	struct timeout_func *to_func = (struct timeout_func *) args;
	LARGE_INTEGER time;
	NTSTATUS st;

	time.QuadPart = -(to_func->time/100);
	KeSetTimer(&to_func->Timer, time, NULL);
	st = KeWaitForSingleObject(&to_func->Timer, Executive, KernelMode, FALSE, NULL);
	
	(void) (to_func->f)(NULL);
	
	ObDereferenceObject(to_func->Thread);
	ExFreePoolWithTag(to_func, 'Tag1');
	PsTerminateSystemThread(0);
}

timeout_id_t timeout(void (*func)(void *), void* unused, hrtime_t nano)
{
	struct timeout_func *to_func;
	OBJECT_ATTRIBUTES ObjectAttributes;
	NTSTATUS st;
	HANDLE thand;
	UNREFERENCED_PARAMETER(unused);
	
	InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	to_func = ExAllocatePoolWithTag(NonPagedPool, sizeof(struct timeout_func), 'Tag1');
	if (to_func == NULL)
		return (timeout_id_t) NULL;
	to_func->time = nano;
	to_func->f = func;
	KeInitializeTimer(&to_func->Timer);
	to_func->Thread = NULL;
	
	st = PsCreateSystemThread(&thand, THREAD_ALL_ACCESS, &ObjectAttributes, NULL, 
		NULL, FTTimeout, (PVOID) to_func);
	
	if (st == STATUS_SUCCESS) {
		/* To wait for the thread to terminate, you need the address of the
		underlying KTHREAD object instead of the handle you get back from PsCreateSystemThread */
		ObReferenceObjectByHandle(thand, THREAD_ALL_ACCESS, NULL, KernelMode, 
			(PVOID*)&to_func->Thread, NULL);
		/* Dont need the handle once we have the address of the KTHREAD */
		ZwClose(thand);
	} else
		dprintf("fasttrap.sys: timeout() Thread creationfailed\n");

	return (timeout_id_t) to_func->Thread;
}

void untimeout(timeout_id_t id)
{
	PETHREAD thr = (PETHREAD) id;
	NTSTATUS st;

	st = KeWaitForSingleObject(thr, Executive, KernelMode, FALSE, NULL);
}

void fasttrap_exec_exit(proc_t *p);
VOID CreateProcFunc(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
{
	proc_t *p;
	UNREFERENCED_PARAMETER(ParentId);
	
	if (Create == FALSE) {
		p = fasttrap_pfind((pid_t) ProcessId);
		if (p == NULL)
			return;

		if (p->p_dtrace_probes || p->p_dtrace_helpers != NULL)
			fasttrap_exec_exit(p);
			
		del_proc_node(p->pid);
	}
}

void fasttrap_winsig(pid_t pid, uintptr_t addr)
{
	CLIENT_ID cid1 = {(HANDLE) pid,  0};
	OBJECT_ATTRIBUTES attr;
	HANDLE hProcess = 0;
	NTSTATUS status;
	UNREFERENCED_PARAMETER(addr);
	
	InitializeObjectAttributes(&attr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &attr, &cid1);
	
	if (status == STATUS_SUCCESS) {
		status = ZwTerminateProcess(hProcess, 0);
		ZwClose(hProcess);
	}
}




#ifdef __i386__
#define	r_pc	r_eip
#else
#define	r_pc	r_rip
#endif

int dtrace_user_probe(struct reg *rp)
{

	int ret = 0;
	thread_t *td = curthread;

	td->ebp = 0;
	if (rp->r_trapno == T_DTRACE_RET) {
		uint8_t step = td->t_dtrace_step;
		uint8_t ret = td->t_dtrace_ret;
		uintptr_t npc = td->t_dtrace_npc;

		if (td->t_dtrace_ast) {
			//aston(curthread);
			//curthread->t_sig_check = 1;
			dprintf("fasttrap.sys: dtrace_user_mode() t_dtrace_ast = %d\n", td->t_dtrace_ast);
		}

		/*
		 * Clear all user tracing flags.
		 */
		td->t_dtrace_ft = 0;

		/*
		 * If we weren't expecting to take a return probe trap, kill
		 * the process as though it had just executed an unassigned
		 * trap instruction.
		 */
		if (step == 0) {
			//tsignal(curthread, SIGILL);
			dprintf("fasttrap.sys: dtrace_user_mode() Not expecting a return probe\n");
			return (1);
		}

		/*
		 * If we hit this trap unrelated to a return probe, we're
		 * just here to reset the AST flag since we deferred a signal
		 * until after we logically single-stepped the instruction we
		 * copied out.
		 */
		if (ret == 0) {
			rp->r_pc = npc;
			return (0);
		}

		/*
		 * We need to wait until after we've called the
		 * dtrace_return_probe_ptr function pointer to set %pc.
		 */
		td->tf = rp;
		(void) fasttrap_return_probe(rp);
		td->tf = NULL;
		rp->r_pc = npc;

	} else if (rp->r_trapno == T_DTRACE_PROBE) {
		;
	} else if (rp->r_trapno == T_BPTFLT) {
		//uint8_t instr;

		/*
		 * The DTrace fasttrap provider uses the breakpoint trap
		 * (int 3). We let DTrace take the first crack at handling
		 * this trap; if it's not a probe that DTrace knowns about,
		 * we call into the trap() routine to handle it like a
		 * breakpoint placed by a conventional debugger.
		 */
		td->tf = rp;
		ret = fasttrap_pid_probe(rp);
		td->tf = NULL;
		/*
		 * If the instruction that caused the breakpoint trap doesn't
		 * look like an int 3 anymore, it may be that this tracepoint
		 * was removed just after the user thread executed it. In
		 * that case, return to user land to retry the instuction.
		 */
		/*if (fuword8((void *)(rp->r_pc - 1), &instr) == 0 &&
		    instr != FASTTRAP_INSTR) {
			rp->r_pc--;
			return;
		}

		trap(rp, addr, cpuid);*/

	} else {
		;//trap(rp, addr, cpuid);
	}
	return (ret);
}

int fasttrap_copyout(void * kaddr, void * uaddr, int len)
{
	if (MmIsAddressValid(uaddr)) {
		RtlCopyMemory((void *)uaddr, (void *)kaddr, len);
		return 0;
	} else {
		dprintf("fastrap.sys: fasttrap_copyout() failed for %p\n", uaddr);
		return 1;
	}
	
}