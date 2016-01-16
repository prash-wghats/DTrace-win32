/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 *
 * $FreeBSD: release/10.0.0/sys/cddl/dev/dtrace/i386/dtrace_subr.c 238552 2012-07-17 14:36:40Z gnn $
 *
 */
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2011, Joyent, Inc. All rights reserved.
 */

#include <ntifs.h>
#include <sys/dtrace_misc.h>
#include <sys/dtrace_win32.h>
#include <sys/dtrace_impl.h>
#include <ntstrsafe.h>
#include <stddef.h>
#include "hook.h"
#include "dtrace_private.h"


typedef struct dtrace_invop_hdlr {
	int (*dtih_func)(uintptr_t, uintptr_t *, uintptr_t);
	struct dtrace_invop_hdlr *dtih_next;
} dtrace_invop_hdlr_t;

dtrace_invop_hdlr_t *dtrace_invop_hdlr;

int
dtrace_invop(uintptr_t addr, uintptr_t *stack, uintptr_t eax)
{
	dtrace_invop_hdlr_t *hdlr;
	int rval;

	for (hdlr = dtrace_invop_hdlr; hdlr != NULL; hdlr = hdlr->dtih_next)
		if ((rval = hdlr->dtih_func(addr, stack, eax)) != 0)
			return (rval);

	return (0);
}

void
dtrace_invop_add(int (*func)(uintptr_t, uintptr_t *, uintptr_t))
{
	dtrace_invop_hdlr_t *hdlr;

	hdlr = kmem_alloc(sizeof (dtrace_invop_hdlr_t), KM_SLEEP);
	hdlr->dtih_func = func;
	hdlr->dtih_next = dtrace_invop_hdlr;
	dtrace_invop_hdlr = hdlr;
}

void
dtrace_invop_remove(int (*func)(uintptr_t, uintptr_t *, uintptr_t))
{
	dtrace_invop_hdlr_t *hdlr = dtrace_invop_hdlr, *prev = NULL;

	for (;;) {
		if (hdlr == NULL)
			panic("attempt to remove non-existent invop handler");

		if (hdlr->dtih_func == func)
			break;

		prev = hdlr;
		hdlr = hdlr->dtih_next;
	}

	if (prev == NULL) {
		ASSERT(dtrace_invop_hdlr == hdlr);
		dtrace_invop_hdlr = hdlr->dtih_next;
	} else {
		ASSERT(dtrace_invop_hdlr != hdlr);
		prev->dtih_next = hdlr->dtih_next;
	}

	kmem_free(hdlr, 0);
}

int
dtrace_getipl(void)
{
	return 0;
}

void
dtrace_vtime_disable(void)
{
}

void
dtrace_vtime_enable(void)
{
}

static void
dtrace_sync_func(void *args)
{
	UNREFERENCED_PARAMETER(args);
}

void
dtrace_sync(void)
{
	
        dtrace_xcall((uint_t) DTRACE_CPUALL, (dtrace_xcall_t)dtrace_sync_func, NULL);
}

void
dtrace_toxic_ranges(void (*func)(uintptr_t base, uintptr_t limit))
{
	
	(func)(0, (uintptr_t) kernelbase);
}

extern dtrace_id_t      dtrace_probeid_error;   /* special ERROR probe */

void
dtrace_probe_error(dtrace_state_t *state, dtrace_epid_t epid, int which, int fltoffs, int fault, uintptr_t illval)
{
	dtrace_probe( dtrace_probeid_error, (uint64_t)(uintptr_t)state, epid, which, fltoffs, fault );
}


void
dtrace_membar_producer(void)
{
	MemoryBarrier();
}

void
dtrace_membar_consumer(void)
{
	MemoryBarrier();
}

/*
 * Returns nanoseconds since boot.
 */
hrtime_t
dtrace_gethrtime()
{
    	LARGE_INTEGER Frequency;
    	LARGE_INTEGER StartingTime, NanoSeconds;

	StartingTime = KeQueryPerformanceCounter(NULL);
	if (Hertz) {
		NanoSeconds.QuadPart = StartingTime.QuadPart%Hertz;
		NanoSeconds.QuadPart *= NANOSEC;
		NanoSeconds.QuadPart /= Hertz;
		
		StartingTime.QuadPart /= Hertz;
		StartingTime.QuadPart *= NANOSEC;
		StartingTime.QuadPart += NanoSeconds.QuadPart;
		
	} else
		return -1;
	
	return StartingTime.QuadPart;
}

/* Pthread
 * time between jan 1, 1601 and jan 1, 1970 in units of 100 nanoseconds
 */
#define PTW32_TIMESPEC_TO_FILETIME_OFFSET \
	  ( ((int64_t) 27111902 << 32) + (int64_t) 3577643008 )
	  
/* system time in nanoseconds */
hrtime_t
dtrace_gethrestime(void)
{
	LARGE_INTEGER SystemTime, LocalTime;
	hrtime_t ret;
	KeQuerySystemTime(&SystemTime);	// KeQuerySystemTimePrecise 
	ret = ((SystemTime.QuadPart - PTW32_TIMESPEC_TO_FILETIME_OFFSET) * 100UL);
	return ret;
}


dtrace_icookie_t
dtrace_interrupt_disable(void)
{
	KIRQL Irq;
	
	KeRaiseIrql(HIGH_LEVEL, &Irq); 
	return Irq;
}

void
dtrace_interrupt_enable(dtrace_icookie_t reenable)
{
	KeLowerIrql(reenable);	
}

uintptr_t 
dtrace_caller(int ignore)
{
	UNREFERENCED_PARAMETER(ignore);
	return -1; 
}