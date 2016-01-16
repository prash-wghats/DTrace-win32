/*
 * Copyright (c) 2015 PK 
 * All rights reserved. 
 *  
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
#include <ntstrsafe.h>
#include <ntintsafe.h>
#include <errno.h>
#include <stddef.h>
#include <sys/dtrace_misc.h>
#include <sys/dtrace_win32.h>
#include <sys/dtrace_impl.h>
#include <sys/dtrace.h>
#include "hook.h"

extern hrtime_t Hertz;
extern struct modctl *modules;
extern int dtrace_ioctl(void *addr,  int cmd, void *ext, int len, void *oaddr);
extern int dtrace_open(PDEVICE_OBJECT dev, void *state);
extern int dtrace_unload(PDRIVER_OBJECT DrvObj);
extern void dtrace_close(void *data);
extern void dtrace_load(void *dummy);

extern void dtrace_module_loaded(struct modctl *ctl);
extern void int_morecore();
extern void int_freecore();
extern int DtraceWinOSHackData();
extern void DtraceWinOSKernelModuleInfo(void);
extern void DtraceWinOSInitFunctions();
void DtraceGetSystemHertz();
PIO_WORKITEM WorkItem1; // user space scratch memory
PIO_WORKITEM WorkItem2;		// tasq_* functions

static void ProcKernelModuleLoaded(PUNICODE_STRING  FullImageName, HANDLE  ProcessId, PIMAGE_INFO  ImageInfo);
static LONG dtrace_ref = 0;
static UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\Dtrace");
static UNICODE_STRING deviceLink = RTL_CONSTANT_STRING(L"\\DosDevices\\Dtrace");
static UNICODE_STRING deviceHelperLink = RTL_CONSTANT_STRING(L"\\DosDevices\\DtraceHelper");
static UNICODE_STRING fbtsys = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\fbt");
static UNICODE_STRING profilesys = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\profile");
static UNICODE_STRING fttpsys = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\fasttrap");

NTSTATUS DtraceIoctl(PDEVICE_OBJECT DevObj, PIRP Irp)
{
	NTSTATUS st = STATUS_SUCCESS;
	PIO_STACK_LOCATION Pio;
	int ilen, olen, t;
	void *addr, *oaddr;

	Pio = IoGetCurrentIrpStackLocation(Irp);
	ilen = Pio->Parameters.DeviceIoControl.InputBufferLength;
	olen = Pio->Parameters.DeviceIoControl.OutputBufferLength;
	addr = Pio->Parameters.DeviceIoControl.Type3InputBuffer;
	oaddr = Irp->UserBuffer;
		
	t = dtrace_ioctl(addr, Pio->Parameters.DeviceIoControl.IoControlCode, 
	    Pio->FileObject->FsContext, ilen, oaddr);
	if (t)
		st = 0xE0000000 | t;
		
	Irp->IoStatus.Status = st;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return st;
}

NTSTATUS DtraceClose(PDEVICE_OBJECT DevObj, PIRP Irp)
{
	PIO_STACK_LOCATION Pio;
	dtrace_state_t *state;

	Pio = IoGetCurrentIrpStackLocation(Irp);
	state = Pio->FileObject->FsContext;
	if (state != NULL)
		dtrace_close(state);
	
	if (InterlockedDecrement(&dtrace_ref) == 0) {
		free_thread_list();
		free_proc_exiting();
	}
#if defined(__amd64__)
	winos_free_user_modules();
#endif	
	ExFreePoolWithTag(Pio->FileObject->FsContext, 'Tag1');
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DtraceOpen(PDEVICE_OBJECT DevObj, PIRP Irp)
{
	PIO_STACK_LOCATION Pio;
	dtrace_state_t *state;
	NTSTATUS st = STATUS_SUCCESS;

	Pio = IoGetCurrentIrpStackLocation(Irp);
	state = ExAllocatePoolWithTag(NonPagedPool, sizeof(dtrace_state_t), 'Tag1');
	if (state == NULL) {
		st =  STATUS_INSUFFICIENT_RESOURCES;
	} else {
		Pio->FileObject->FsContext = state;
		RtlZeroMemory(state, sizeof(dtrace_state_t));
		if (dtrace_open(DevObj, state))
			st = STATUS_NO_SUCH_DEVICE;
	}

	Irp->IoStatus.Status = st;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	InterlockedIncrement(&dtrace_ref);
	
	return st;
}

PIO_WORKITEM taskq_queue_thread()
{
	return WorkItem2;
}

void DtraceUnload(PDRIVER_OBJECT DrvObj)
{
	NTSTATUS st;
	LARGE_INTEGER tm;
	
	ZwUnloadDriver(&fbtsys);
	ZwUnloadDriver(&profilesys);
	ZwUnloadDriver(&fttpsys);
	
	while (dtrace_ref != 0 || dtrace_unload(DrvObj) != 0) {
		tm.QuadPart = UNLOAD_RETRY_DELAY_TIME;
		dprintf("dtrace.sys: Unload failed. Retry in %ds\n", abs(UNLOAD_RETRY_DELAY_TIME)/10000000);
		KeDelayExecutionThread(KernelMode, FALSE, &tm);
	}
	PsRemoveLoadImageNotifyRoutine(ProcKernelModuleLoaded);
	
	free_thread_list();
	free_proc_list();
	IoFreeWorkItem(WorkItem1);
	int_freecore();
	
	IoDeleteSymbolicLink(&deviceLink);
	IoDeleteSymbolicLink(&deviceHelperLink);
	IoDeleteDevice(DrvObj->DeviceObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DrvObj, PUNICODE_STRING RegPath)
{
	PDEVICE_OBJECT DevObj;
	NTSTATUS status;

	status = IoCreateDevice(DrvObj, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN,
	                        FALSE, &DevObj);
	if(NT_SUCCESS(status)) {
		status = IoCreateSymbolicLink (&deviceLink, &deviceName);
		DrvObj->MajorFunction[IRP_MJ_CREATE] = DtraceOpen;
		DrvObj->MajorFunction[IRP_MJ_CLOSE] = DtraceClose;
		DrvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DtraceIoctl;
		DrvObj->DriverUnload  = DtraceUnload;
	}
	if (!NT_SUCCESS(status)) {
		IoDeleteSymbolicLink(&deviceLink);
		if(DevObj)
			IoDeleteDevice( DevObj);
		return status;
	}
	status = IoCreateSymbolicLink(&deviceHelperLink, &deviceName);
	if (!NT_SUCCESS(status))
		dprintf("DriverEntry: dtrace helper creation failed\n");
		
	DtraceGetSystemHertz();
	DtraceWinOSKernelModuleInfo();
	DtraceWinOSInitFunctions();
	if (DtraceWinOSHackData() == 0)
		dprintf("DriverEntry: DtraceWinOSPortData() hack data failure\n");
	
	if (PsSetLoadImageNotifyRoutine(ProcKernelModuleLoaded) != STATUS_SUCCESS) 
		dprintf("DriverEntry: failed to register PsSetLoadImageNotifyRoutine\n");
	

	WorkItem1 = IoAllocateWorkItem(DevObj);
	WorkItem2 = IoAllocateWorkItem(DevObj);

	int_morecore();
	
	(void) dtrace_load((void *) RegPath);

	return status;
}


void DtraceGetSystemHertz()
{
	LARGE_INTEGER Frequency;
    	
	Hertz = 0;
	KeQueryPerformanceCounter(&Frequency);
	if (Frequency.QuadPart != 0)
		Hertz = Frequency.QuadPart;
}


void DtraceWinOSKernelModuleInfo(void)
{
	PAUX_MODULE_EXTENDED_INFO info = NULL;
	ULONG size = 0, mods, i;
	modctl_t *temp, *prev = NULL;
	char *s, *tmp;
	
	if (AuxKlibInitialize() != STATUS_SUCCESS ||
	   AuxKlibQueryModuleInformation(&size, sizeof(AUX_MODULE_EXTENDED_INFO), NULL) != STATUS_SUCCESS ||
	   size == 0 || (info = ExAllocatePoolWithTag(NonPagedPool, size, 'Tag1')) == NULL ||
	   (AuxKlibQueryModuleInformation(&size, sizeof(AUX_MODULE_EXTENDED_INFO), info) != STATUS_SUCCESS)) {
	   	dprintf("dtrace.sys: failed in DtraceWinOSKernelModuleInfo\n");
	   	if (info != NULL)
	   		ExFreePoolWithTag(info, 'Tag1');
	   	return;
	}
	
	mods = size / sizeof(AUX_MODULE_EXTENDED_INFO);

	modules = ExAllocatePoolWithTag(NonPagedPool, sizeof(modctl_t), 'Tag1');
	RtlZeroMemory(modules, sizeof(modctl_t));
	temp = modules;
	i = 0;
	do {
		temp->imgbase = (uintptr_t) info[i].BasicInfo.ImageBase;
		temp->size = info[i].ImageSize;
		temp->loadcnt = 0;
		temp->nenabled = 0;
		temp->fbt_nentries = 0;
		s = info[i].FullPathName + info[i].FileNameOffset;
		tmp = ExAllocatePoolWithTag(NonPagedPool, strlen(s)+1, 'Tag1');
		if (tmp != NULL) {
			strcpy(tmp, s);
			temp->mod_modname = tmp;
		}
		temp->mod_next = modules;
		if (prev != NULL)
			prev->mod_next = temp;
		prev = temp;
	} while (++i < mods && (temp = ExAllocatePoolWithTag(NonPagedPool, sizeof(modctl_t), 'Tag1')) != NULL);
		
}

void ProcKernelModuleLoaded(PUNICODE_STRING FullImageName, HANDLE  ProcessId, PIMAGE_INFO  ImageInfo)
{
	char buf[256], *s, *sbuf;
	ANSI_STRING AS;
	ULONG l;
	modctl_t *ctl;
	int reloaded = 0;
	
	if (ImageInfo->SystemModeImage) {
		l = RtlUnicodeStringToAnsiSize(FullImageName);
		if (l == 0)
			return;

		RtlInitAnsiString(&AS, NULL);
		RtlUnicodeStringToAnsiString(&AS, FullImageName, TRUE);
		if (AS.MaximumLength >= AS.Length + 1) {
 			AS.Buffer[AS.Length] = '\0';
 		} else {
 			RtlFreeAnsiString(&AS);
 			return;
 		}
 	
		s = strrchr(AS.Buffer, '\\');
		if (s == NULL) {
			RtlFreeAnsiString(&AS);
			return;
		}
		
		s++;
		ctl = modules;
		do {
			if (strcmp(ctl->mod_modname, s) == 0 && ctl->size == ImageInfo->ImageSize) {
				ctl->imgbase = (uintptr_t) ImageInfo->ImageBase;
				ctl->loadcnt++;
				reloaded = 1;
				dprintf("dtrace.sys: module %s reloaded\n", s);
				break;
			}
				
		} while ((ctl = ctl->mod_next) != modules);
		
		if (reloaded == 0) {
			ctl = ExAllocatePoolWithTag(NonPagedPool, sizeof(modctl_t), 'Tag1');
			
			if (ctl == NULL) {
				return;
			}
			sbuf = ExAllocatePoolWithTag(NonPagedPool, strlen(s)+1, 'Tag1');
			RtlFreeAnsiString(&AS);
			
			if (sbuf == NULL) {
				ExFreePoolWithTag(ctl, 'Tag1');
				return;
			}
			strcpy(sbuf, s);
			ctl->imgbase = (uintptr_t) ImageInfo->ImageBase;
			ctl->size = ImageInfo->ImageSize;
			ctl->mod_modname = sbuf;
			ctl->loadcnt = 0;
			ctl->nenabled = 0;
			ctl->fbt_nentries = 0;
			dprintf("dtrace.sys: module %s loaded\n", s);
			
			ctl->mod_next = modules->mod_next;
			modules->mod_next = ctl;
		}	
		dtrace_module_loaded(ctl);
	}
}

