/*
InterruptHook
Copyright (C) 2003  Alexander M.
Copyright (C) 2015  Prashanth K.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/

#include <ntddk.h>
#include "hook.h"

static int mdl_copy(PVOID dest, PVOID src, ULONG size);

VOID
LoadIDT(
		OUT	PIDT		pIdt )
{
	/*__asm
	{
		MOV EAX, [pIdt]
		SIDT [EAX]
	}*/
	__sidt(pIdt);
}

VOID
LoadINTVector(
		IN	PIDT		pIdt,
		IN	UCHAR		iVector,
		OUT	PINT_VECTOR	pVector )
{
#ifdef _AMD64_
		ULONG64 dwBase = (ULONG64)pIdt->dwBase + iVector * sizeof(INT_VECTOR);
#else
		DWORD dwBase = pIdt->dwBase + iVector * sizeof(INT_VECTOR);
#endif
		memcpy( pVector, (const void *)dwBase, sizeof(INT_VECTOR) );
	
//	KdPrint( ( "LoadINTVector: Vector 0x%.2X successfully dumped\n", iVector ));
}

VOID
SaveINTVector(
		IN	PIDT		pIdt,
		IN	UCHAR		iVector,
		IN	PINT_VECTOR	pVector )
{
	
#ifdef _AMD64_
		ULONG64 dwBase = (ULONG64) pIdt->dwBase + iVector * sizeof(INT_VECTOR);
#else
		DWORD dwBase = pIdt->dwBase + iVector * sizeof(INT_VECTOR);
#endif
		KIRQL Irq;
		KeRaiseIrql(HIGH_LEVEL, &Irq); 
		//memcpy( (void *)dwBase, pVector, sizeof(INT_VECTOR) );
		mdl_copy( (void *)dwBase, pVector, sizeof(INT_VECTOR) );
		KeLowerIrql(Irq);
	

//	KdPrint( ( "SaveINTVector: Vector 0x%.2X successfully set\n", iVector ));
}

VOID
HookInterrupt(UCHAR iVec, void (*InterruptHandler)( void ))
{
	IDT			Idt;
	INT_VECTOR	Vec;
	ULONG		i;
	
	LoadIDT( &Idt );

	LoadINTVector(
			&Idt,
			iVec,
			&Vec);

	KdPrint( ( "HookInterrupt: Vector -- %X, 0x%p, 0x%p\n", iVec, VEC_OFFSET_TO_ADDR( Vec ), InterruptHandler));
	ADDR_TO_VEC_OFFSET( Vec, (ULONG64) InterruptHandler);

	//Vec.wSelector = selector;

	SaveINTVector(
			&Idt,
			iVec,
			&Vec );

}

VOID
BackupInterrupt(UCHAR iVec, OUT PINT_VECTOR Vec)
{
	IDT			Idt;
	ULONG		i;

	LoadIDT( &Idt );

	LoadINTVector(
			&Idt,
			iVec,
			Vec);
}

VOID
RestoreInterrupt(UCHAR iVec, IN PINT_VECTOR Vec)
{
	IDT			Idt;
	ULONG		i;

	LoadIDT( &Idt );

	SaveINTVector(
			&Idt,
			iVec,
			Vec);
}

VOID
CopyInterrupt(UCHAR fromVec, UCHAR toVec)
{
	IDT			Idt;
	INT_VECTOR	Vec;
	ULONG		i;

	LoadIDT( &Idt );

	LoadINTVector(
			&Idt,
			fromVec,
			&Vec);

	KdPrint( ( "CopyInterrupt: Vector, 0x%p\n", VEC_OFFSET_TO_ADDR( Vec )));

	SaveINTVector(
			&Idt,
			toVec,
			&Vec );

}

int cpunos;
KEVENT SyncIDT;

VOID hook_init(struct _KDPC *Dpc, PVOID DeferredContext,PVOID SystemArgument1,PVOID SystemArgument2)
{
	UCHAR vec = (UCHAR)SystemArgument1;
	
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(DeferredContext);
	HookInterrupt(vec, (void(*)(void))SystemArgument2);
	InterlockedIncrement(&cpunos);
	if (cpunos >= KeNumberProcessors)
		KeSetEvent(&SyncIDT, 0, FALSE);
}

void dtrace_hook_int(UCHAR ivec, void (*InterruptHandler)( void ), uintptr_t *paddr)
{
	INT_VECTOR OrgVec;
	int i;
	PRKDPC Dpc;

	cpunos = 0;
	if (paddr != 0) {
		BackupInterrupt(ivec, &OrgVec);
#ifdef _AMD64_
   		*(ULONG64 *)paddr = VEC_OFFSET_TO_ADDR(OrgVec);
#else
		*(ULONG32 *)paddr = VEC_OFFSET_TO_ADDR(OrgVec);
#endif
   	}

   	Dpc = (PRKDPC) ExAllocatePoolWithTag(NonPagedPool, sizeof(KDPC)*KeNumberProcessors, 'Tag1');
   	for (i = 0; i < KeNumberProcessors; i++) {
		KeInitializeDpc(&Dpc[i], hook_init, NULL);
	}
	
	KeInitializeEvent(&SyncIDT, NotificationEvent, FALSE);
	for (i=0; i < KeNumberProcessors; i++) {
		KeSetTargetProcessorDpc(&Dpc[i], (char) i);
		KeSetImportanceDpc(&Dpc[i], HighImportance);
		KeInsertQueueDpc(&Dpc[i], (PVOID) ivec, (PVOID)InterruptHandler);
	}
	
	KeWaitForSingleObject(&SyncIDT,Executive,KernelMode,0,NULL);
    	KeClearEvent(&SyncIDT);
   	ExFreePoolWithTag(Dpc, 'Tag1');
}
   
static int mdl_copy(PVOID dest, PVOID src, ULONG size)
{
	PMDL mdl = NULL;
	PCHAR buffer = NULL;
	NTSTATUS ntStatus;
	
	mdl = IoAllocateMdl(dest, size,  FALSE, FALSE, NULL);

	if (!mdl) {
		ntStatus = STATUS_INSUFFICIENT_RESOURCES;
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
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		return (0);
	}

	RtlCopyMemory(buffer, src, size);

	MmUnlockPages(mdl);
	IoFreeMdl(mdl);

	return (1);
}


