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
 
#include <ntifs.h>
#include <sys/dtrace_misc.h>
#include <sys/dtrace_win32.h>
#include <sys/dtrace_impl.h>
#include <ntstrsafe.h>

pri_t maxclsyspri;
dtrace_cacheid_t dtrace_predcache_id;
int panic_quiesce;

hrtime_t Hertz;
cpu_data_t *CPU;
cpu_core_t *cpu_core;
struct modctl *modules;
extern PIO_WORKITEM taskq_queue_thread();

typedef struct funcptr {
	task_func_t *f;
} funcptr_t;

funcptr_t taskfunc;

VOID TasqFunc(PDEVICE_OBJECT DeviceObject, PVOID Context)
{
	funcptr_t *g = (funcptr_t *) Context;
	g->f();
}

taskq_t *
taskq_create(const char *name, int nthreads, pri_t pri, int minalloc, int maxalloc, uint_t flags)
{
	PIO_WORKITEM work;
	UNREFERENCED_PARAMETER(name);
	UNREFERENCED_PARAMETER(nthreads);
	UNREFERENCED_PARAMETER(pri);
	UNREFERENCED_PARAMETER(minalloc);
	UNREFERENCED_PARAMETER(maxalloc);
	UNREFERENCED_PARAMETER(flags);
	
	work = (PIO_WORKITEM) taskq_queue_thread();
	if (!work) {
		dprintf("dtrace.sys: tasq_create() failed\n");
		return NULL;
	}
	
	return (taskq_t *) work;
}

taskqid_t taskq_dispatch(taskq_t *pdpc, task_func_t func, void *args, uint_t i)
{
	UNREFERENCED_PARAMETER(i);
	
	taskfunc.f = func;
	IoQueueWorkItem((PIO_WORKITEM) pdpc, TasqFunc, DelayedWorkQueue, (PVOID) &taskfunc);
	
	return 0;	
}	

void taskq_destroy(taskq_t *pdpc)
{
	IoFreeWorkItem((PIO_WORKITEM)  pdpc);
}

void *kmem_alloc(size_t size, int kmflag)
{
	void *p;
	UNREFERENCED_PARAMETER(kmflag);
	
	p = ExAllocatePoolWithTag(NonPagedPool, size, 'Tag1');
	if (p == NULL) 
		dprintf("dtrace.sys: kmem_alloc failed %d\n", size);
	return p;
}

void *kmem_zalloc(size_t size, int kmflag)
{
	void *p;
	UNREFERENCED_PARAMETER(kmflag);
	
	p = ExAllocatePoolWithTag(NonPagedPool, size, 'Tag1');
	if (p == NULL) 
		dprintf("dtrace.sys: kmem_zalloc failed %d\n", size);
	else
		RtlZeroMemory(p, size);
	return p;
}

void kmem_free(void *buf, size_t size)
{
	if (buf == NULL || size == 0) 
		return;
	ExFreePoolWithTag(buf, 'Tag1');
}


uint32_t dtrace_cas32(uint32_t *target, uint32_t cmp, uint32_t new)
{
	LONG tmp;
    	tmp = InterlockedCompareExchange((volatile LONG *)target, (LONG)new, (LONG)cmp);
	if (tmp != *target)
		return cmp;
	else	
		return ~cmp; 
}

void *dtrace_casptr(void *target, void *cmp, void *new)
{
	ULONG *tmp;
    	tmp = InterlockedCompareExchangePointer((VOID **)target, new, cmp);
	if (tmp != *(ULONG **)target)
		return cmp;
	else	
		return (void *) (~(uintptr_t)cmp);
}

/* dtrace_xcall */

typedef struct funcptr_pvoid {
	dtrace_xcall_t f;
	PVOID arg;
} funcptr_pvoid_t;

static funcptr_pvoid_t XcallFunc;

static PRKDPC XcallDpc;
static int XcallCpuCount;
static KEVENT XcallEvent;
static KMUTEX	XcallLock;

VOID XcallDpcFunc(struct _KDPC *Dpc, PVOID DeferredContext,PVOID SystemArgument1,PVOID SystemArgument2)
{
	funcptr_pvoid_t *g = (funcptr_pvoid_t *)SystemArgument1;
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(DeferredContext);
	
	(g->f)(SystemArgument2);
	InterlockedDecrement(&XcallCpuCount);
	
	if (XcallCpuCount <= 0)
		KeSetEvent(&XcallEvent, 0, FALSE);
}

typedef ULONG_PTR (*KeIpiGenericCall_t) (PKIPI_BROADCAST_WORKER BroadcastFunction, ULONG_PTR Context);
KeIpiGenericCall_t KeIpiGenericCall_p = NULL;

void dtrace_init_xcall()
{
	int i;
	UNICODE_STRING routineName;
	
     	RtlInitUnicodeString(&routineName, L"KeIpiGenericCall");
     	KeIpiGenericCall_p  = (KeIpiGenericCall_t) MmGetSystemRoutineAddress(&routineName);
	XcallDpc = (PRKDPC) ExAllocatePoolWithTag(NonPagedPool, sizeof(KDPC)*NCPU, 'Tag1');
	
	KeInitializeEvent(&XcallEvent, NotificationEvent, FALSE);
	mutex_init(&XcallLock);
	
	for (i = 0; i < NCPU; i++) {
		KeInitializeDpc(&XcallDpc[i], XcallDpcFunc, NULL);
	}
}

KIPI_BROADCAST_WORKER IpiGenericCall;
ULONG_PTR IpiGenericCall(ULONG_PTR SystemArgument1)
{
	funcptr_pvoid_t *g = (funcptr_pvoid_t *)SystemArgument1;
	(g->f)(g->arg);
	
	return 0;
	
}

/* interprocessor interrupt (IPI) or cross-call*/
void dtrace_xcall(processorid_t cpu, dtrace_xcall_t func, void *arg)
{
	int i;
	
	mutex_enter(&XcallLock); 
	KeClearEvent(&XcallEvent);
	
	if (cpu == DTRACE_CPUALL) {
		if (KeIpiGenericCall_p == NULL) {
			XcallCpuCount = NCPU;
			for (i=0; i < NCPU; i++) {
				XcallFunc.f = func;
				KeSetTargetProcessorDpc(&XcallDpc[i], (char) i);
				KeSetImportanceDpc(&XcallDpc[i], HighImportance);
				KeInsertQueueDpc(&XcallDpc[i], &XcallFunc, arg);
			}
			KeWaitForSingleObject(&XcallEvent,Executive,KernelMode,0,NULL); 
		} else {
			XcallFunc.f = func;
			XcallFunc.arg = arg;
			KeIpiGenericCall_p(IpiGenericCall, (ULONG_PTR) &XcallFunc);
		}
	} else {
		
		XcallCpuCount = 1;
		XcallFunc.f = func;
		KeSetTargetProcessorDpc(&XcallDpc[cpu], (char) cpu);
		KeSetImportanceDpc(&XcallDpc[cpu], HighImportance);
		KeInsertQueueDpc(&XcallDpc[cpu], &XcallFunc, arg);
		KeWaitForSingleObject(&XcallEvent,Executive,KernelMode,0,NULL);
	}
	
   	mutex_exit(&XcallLock);
}	


int copyin(void * uaddr, void * kaddr, int len)
{
	RtlCopyMemory((void *)kaddr, (void *)uaddr, len);
	return 0;
}

int copyout(void * kaddr, void * uaddr, int len)
{
	RtlCopyMemory((void *)uaddr, (void *)kaddr, len);
	return 0;
}
int copyinstr(void * uaddr, void * kaddr, int len)
{
	RtlStringCbCopyNA((void *)kaddr, len,(void *) uaddr, len);
	return 0;
}	

void dtrace_copy(uintptr_t src, uintptr_t dest, size_t size)
{
	copyin((void *)src, (void *)dest, size);
}

uint64_t dtrace_fuword64_nocheck(void *uaddr)
{
	uint64_t kaddr;
	RtlCopyMemory((void *)&kaddr, uaddr, 8);
	
	return kaddr;
}

uint32_t dtrace_fuword32_nocheck(void *uaddr)
{
	uint32_t kaddr;
	RtlCopyMemory((void *)&kaddr, uaddr, 4);
	
	return kaddr;
}

uint16_t dtrace_fuword16_nocheck(void *uaddr)
{
	uint16_t kaddr;
	RtlCopyMemory((void *)&kaddr, uaddr, 2);
	
	return kaddr;
}

uint8_t dtrace_fuword8_nocheck(void *uaddr)
{
	uint8_t kaddr;
	RtlCopyMemory((void *)&kaddr, uaddr, 1);
	
	return kaddr;
}

/* Cyclic */
VOID CallOutDpc(struct _KDPC *Dpc, PVOID DeferredContext,PVOID SystemArgument1,PVOID SystemArgument2);

void callout_thread(PVOID args)
{
	struct callout *cyc = (struct callout *) args;
	LARGE_INTEGER time;//, timeout;
	dtrace_state_t *s = (dtrace_state_t *) cyc->state;
	NTSTATUS st;
	
	while (cyc->time > 0) {
		time.QuadPart = -(cyc->time/100);
		KeSetTimer(&cyc->Timer, time,NULL);
		st = KeWaitForSingleObject(&cyc->Timer, Executive, KernelMode, FALSE, NULL);
		if (st == STATUS_SUCCESS) 
			(void) (cyc->func)(s);
	}
	KeCancelTimer(&cyc->Timer);
	PsTerminateSystemThread(0);
}

void callout_init(struct callout *cyc, PDEVICE_OBJECT dev)
{
	KeInitializeTimer(&cyc->Timer);
	cyc->Thread = NULL;
}

void callout_reset(struct callout *cyc, int64_t nano)
{
	OBJECT_ATTRIBUTES ObjectAttributes;
	NTSTATUS st;
	HANDLE thand;
	
	InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	cyc->time = nano;
	st = PsCreateSystemThread(&thand, THREAD_ALL_ACCESS, &ObjectAttributes, NULL, NULL, callout_thread, (PVOID) cyc);
	if (st == STATUS_SUCCESS) {
		 /* To wait for the thread to terminate, you need the address of the 
		 underlying KTHREAD object instead of the handle you get back from PsCreateSystemThread */
		ObReferenceObjectByHandle(thand, THREAD_ALL_ACCESS, NULL, KernelMode, (PVOID*)&cyc->Thread, NULL);
		/* Dont need the handle once we have the address of the KTHREAD */
         	ZwClose(thand);
	} else
		dprintf("dtrace.sys: callout_reset() thread creation failed\n");
	
}

void callout_stop(struct callout *cyc)
{
	if (cyc->Thread != NULL) {
		cyc->time = 0;
		KeWaitForSingleObject(cyc->Thread, Executive, KernelMode, FALSE, NULL);
		ObDereferenceObject(cyc->Thread);
	}	
}

/* MUTEX */
void mutex_init(KMUTEX *m)
{
	KeInitializeMutex(m, 0);
}

void mutex_enter(KMUTEX *m)
{
	 KeWaitForSingleObject(m, Executive, KernelMode, FALSE, NULL);   
}

void mutex_exit(KMUTEX *m)
{
	KeReleaseMutex(m, FALSE);
}

int mutex_owned(KMUTEX *m)
{
	int i = KeReadStateMutex(m);
	
	if (i)
		return 0;
	else
		return 1;
}



int bcmp(const void *s1, const void *s2, size_t n)
{
 	if (RtlCompareMemory(s1, s2, n) == n)
 		return 0;
 	return 1;
}






