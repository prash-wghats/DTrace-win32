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
#include <sys/dtrace.h>
#include <ntstrsafe.h>
#include <ntintsafe.h>
#include <errno.h>
#include <stddef.h>
#include <sys/dtrace_win32.h>
#include "cyclic.h"


__declspec(dllimport) int KPRCB_Offset_Dpc_Stack;
__declspec(dllimport) int KTRAP_FRAME_Offset_KTHREAD;

void profile_load(void *dummy);
int profile_unload();

#define CLOCK_RES	10000

NTSTATUS ProfileClose(PDEVICE_OBJECT DevObj, PIRP Irp);
NTSTATUS ProfileOpen(PDEVICE_OBJECT DevObj, PIRP Irp);
void ProfileUnload(PDRIVER_OBJECT DrvObj);
NTSTATUS ProfileIoctl(PDEVICE_OBJECT DevObj, PIRP Irp);

static UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\Profile");
static UNICODE_STRING deviceLink = RTL_CONSTANT_STRING(L"\\DosDevices\\Profile");
static KEVENT CyclicEvent;

NTSTATUS DriverEntry(PDRIVER_OBJECT DrvObj, PUNICODE_STRING RegPath)
{
	PDEVICE_OBJECT DevObj;
	NTSTATUS status;
		
	status = IoCreateDevice(DrvObj, 0, &deviceName, FILE_DEVICE_UNKNOWN, 
			FILE_DEVICE_SECURE_OPEN, FALSE, &DevObj);
			
        if(NT_SUCCESS(status)) {
        	status = IoCreateSymbolicLink (&deviceLink, &deviceName);
        	DrvObj->MajorFunction[IRP_MJ_CREATE] = ProfileOpen;
        	DrvObj->MajorFunction[IRP_MJ_CLOSE] = ProfileClose;
        	DrvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ProfileIoctl;
        	DrvObj->DriverUnload  = ProfileUnload;
        }
         if (!NT_SUCCESS(status)) {
       		IoDeleteSymbolicLink(&deviceLink);
       		if(DevObj) 
       			IoDeleteDevice( DevObj);
       	}
       	
       	KeInitializeEvent(&CyclicEvent, NotificationEvent, FALSE);

    	(void) profile_load((void *) RegPath);
    	 	
    	return status;
}

NTSTATUS ProfileClose(PDEVICE_OBJECT DevObj, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DevObj);
	
	Irp->IoStatus.Status = STATUS_SUCCESS;
    	Irp->IoStatus.Information = 0;
    	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS ProfileOpen(PDEVICE_OBJECT DevObj, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DevObj);
	
	Irp->IoStatus.Status = STATUS_SUCCESS;
    	Irp->IoStatus.Information = 0;
    	IoCompleteRequest(Irp, IO_NO_INCREMENT);
    	
	return STATUS_SUCCESS;
}

void ProfileUnload(PDRIVER_OBJECT DrvObj)
{
	LARGE_INTEGER tm;
	
	while (profile_unload() != 0) {
		tm.QuadPart = UNLOAD_RETRY_DELAY_TIME;
		dprintf("profile.sys: Unload failed. Retry in %ds\n", abs(UNLOAD_RETRY_DELAY_TIME)/10000000);
		KeDelayExecutionThread(KernelMode, FALSE, &tm);
	}
	IoDeleteSymbolicLink(&deviceLink);
	IoDeleteDevice(DrvObj->DeviceObject);
}

NTSTATUS ProfileIoctl(PDEVICE_OBJECT DevObj, PIRP Irp)
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

VOID CycFuncProc(struct _KDPC *Dpc, PVOID DeferredContext,PVOID SystemArgument1,PVOID SystemArgument2)
{
	cyclic_t *cyclic = ((cyclic_t *) DeferredContext);
	void *s = cyclic->cy_arg;
	LARGE_INTEGER time;
	struct reg rp = {0};
	thread_t *td = curthread;
	hrtime_t now = dtrace_gethrtime();
	hrtime_t exp;
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);
	
	td->tf = &rp;
	DtraceWinOSDpcStack(td);
	
	for (;;) {
		if ((exp = cyclic->cy_expire) > now)
			break;
			
		(void) (cyclic->cy_func)(s);
		
		exp += cyclic->cy_interval;
		if (now - exp > NANOSEC) {
			hrtime_t interval = cyclic->cy_interval;
			exp += ((now - exp) / interval + 1) * interval;
		}

		cyclic->cy_expire = exp;
	}	
	td->tf = NULL;
	
	time.QuadPart = -((exp - now) / 100);
	if (cyclic->perodic)
		KeSetTimer(&cyclic->Timer, time, &cyclic->Dpc);
}

#define ONLINE  0
#define OFFLINE  1

VOID CycFuncOmniProc(struct _KDPC *Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	cyclic_t *cyclic = ((cyclic_t *) DeferredContext);
	cyclic_omni_t *c = (cyclic_omni_t *) SystemArgument1;
	cyc_omni_handler_t *omni = &c->omni;
	int type = (int) SystemArgument2;
	cyc_handler_t hdlr;
	cyc_time_t time;
	LARGE_INTEGER nano;
	int cpu = KeGetCurrentProcessorNumber();
	hrtime_t now;
	UNREFERENCED_PARAMETER(Dpc);
	
	if (type == ONLINE) {
		(omni->cyo_online)(omni->cyo_arg, NULL, &hdlr, &time);
		cyclic->cy_func = hdlr.cyh_func;
		cyclic->cy_arg = hdlr.cyh_arg;
		cyclic->cy_interval = time.cyt_interval;
		cyclic->perodic = 1;
		
		now = dtrace_gethrtime();
		
		if (time.cyt_when == 0) {
		/*
		 * If a start time hasn't been explicitly specified, we'll
		 * start on the next interval boundary.
		 */
			cyclic->cy_expire = (now / cyclic->cy_interval + 1) *
		    		cyclic->cy_interval;
		} else {
			cyclic->cy_expire = time.cyt_when;
		}
		nano.QuadPart = -((cyclic->cy_expire - now)/100);
		KeInitializeDpc(&cyclic->Dpc, CycFuncProc, cyclic);
		KeSetTargetProcessorDpc(&cyclic->Dpc, (char) cpu);
		KeInitializeTimer(&cyclic->Timer);
		KeSetTimer(&cyclic->Timer, nano, &cyclic->Dpc);
	} else {
		ASSERT(type == OFFLINE);
		cyclic->perodic = 0;
		KeCancelTimer(&cyclic->Timer);
		(omni->cyo_offline)(omni->cyo_arg, NULL, cyclic->cy_arg);
	}
}

cyclic_id_t cyclic_add(cyc_handler_t *hdlr, cyc_time_t *time)
{
	cyclic_t *cyclic;
	LARGE_INTEGER nano;
	int cpu = KeGetCurrentProcessorNumber();
	ULONG res;
	hrtime_t now;
	
	cyclic_omni_t *c = kmem_zalloc(sizeof(cyclic_omni_t), KM_SLEEP);
	
	if (c == NULL)
		return CYCLIC_NONE;
	if ((cyclic = kmem_zalloc(sizeof(cyclic_t), KM_SLEEP)) == NULL) {
		kmem_free(c, sizeof(cyclic_omni_t));
		return CYCLIC_NONE;
	}
	
	cyclic->cy_func = hdlr->cyh_func;
	cyclic->cy_arg = hdlr->cyh_arg;
	cyclic->cy_interval = time->cyt_interval;
	cyclic->perodic = 1;
	now = dtrace_gethrtime();
	
	if (time->cyt_when == 0) {
		/*
		 * If a start time hasn't been explicitly specified, we'll
		 * start on the next interval boundary.
		 */
		cyclic->cy_expire = (now / cyclic->cy_interval + 1) *
		    cyclic->cy_interval;
	} else {
		cyclic->cy_expire = time->cyt_when;
	}
	
	nano.QuadPart = -(time->cyt_interval/100);
	res = ExSetTimerResolution (CLOCK_RES, TRUE);
	KeInitializeDpc(&cyclic->Dpc, CycFuncProc, cyclic);
	KeSetTargetProcessorDpc(&cyclic->Dpc, (char) cpu);
	KeSetImportanceDpc(&cyclic->Dpc, HighImportance);
	KeInitializeTimer(&cyclic->Timer);
	KeSetTimer(&cyclic->Timer, nano, &cyclic->Dpc);
	c->cyc = cyclic;
	c->type = CYCLIC;
	c->cpus = 1;
	
	return (cyclic_id_t) c;
}

cyclic_id_t
cyclic_add_omni(cyc_omni_handler_t *omni)
{
	PRKDPC dpc;
	cyclic_t *cyclic;
	int cpus = KeNumberProcessors;
	cyclic_omni_t *c = kmem_zalloc(sizeof(cyclic_omni_t), KM_SLEEP);
	int i;
	ULONG res;
	
	if (c == NULL)
		return CYCLIC_NONE;
		
	if ((dpc = kmem_zalloc(sizeof(KDPC)*cpus, KM_SLEEP)) == NULL) {
		kmem_free(c, sizeof(cyclic_omni_t));
		return CYCLIC_NONE;
	}
	
	if ((cyclic = kmem_zalloc(sizeof(cyclic_t)*cpus, KM_SLEEP)) == NULL) {
		kmem_free(c, sizeof(cyclic_omni_t));
		kmem_free(dpc, sizeof(KDPC));
		return CYCLIC_NONE;
	}
	
	c->Odpc = dpc;
	c->type = OMNI_CYCLIC;
	c->cyc = cyclic;
	c->cpus = cpus;
	c->omni = *omni;
	res = ExSetTimerResolution (CLOCK_RES, TRUE);

	for (i = 0; i < cpus; i++) {
		KeInitializeDpc(&c->Odpc[i], CycFuncOmniProc, &c->cyc[i]);
		KeSetTargetProcessorDpc(&c->Odpc[i], (char) i);
		KeSetImportanceDpc(&c->Odpc[i], HighImportance);
		KeInsertQueueDpc(&c->Odpc[i], c, (void *) ONLINE);
	}
	
	return (cyclic_id_t) c;
}

void cyclic_remove(cyclic_id_t id)
{
	cyclic_omni_t *c = (cyclic_omni_t *) id;
	int i,cpus = c->cpus;
	ULONG res;
	
	if (c->type == CYCLIC) {
		c->cyc->perodic = 0;
		if (KeCancelTimer(&c->cyc->Timer) == 0) {
			KeFlushQueuedDpcs();
		} 
		kmem_free(c->cyc, sizeof(cyclic_t));
		kmem_free(c, sizeof(cyclic_omni_t));
	} else {
		ASSERT(c->type == OMNI_CYCLIC);
		
		KeResetEvent(&CyclicEvent);
		for (i = 0; i < cpus; i++) {
			KeInsertQueueDpc(&c->Odpc[i], c, (void *) OFFLINE);
		}
		
		KeFlushQueuedDpcs();
		kmem_free(c->cyc, 1);
		kmem_free(c->Odpc, 1);
		kmem_free(c, sizeof(cyclic_omni_t));
	}
	res = ExSetTimerResolution (0, FALSE);
}
