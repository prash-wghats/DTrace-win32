/*
 * Copyright (c) 2005-2006 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <ntifs.h>
#include <sys/dtrace_misc.h>
#include <sys/dtrace_win32.h>

/*
 * dtrace wants to manage just a single block: dtrace_state_percpu_t * NCPU, and
 * doesn't specify constructor, destructor, or reclaim methods.
 * At present, it always zeroes the block it obtains from kmem_cache_alloc().
 * We'll manage this constricted use of kmem_cache with ordinary _MALLOC and _FREE.
 */
kmem_cache_t *
kmem_cache_create(
    const char *name,		/* descriptive name for this cache */
    size_t bufsize,		/* size of the objects it manages */
    size_t align,		/* required object alignment */
    int (*constructor)(void *, void *, int), /* object constructor */
    void (*destructor)(void *, void *),	/* object destructor */
    void (*reclaim)(void *), /* memory reclaim callback */
    void *private,		/* pass-thru arg for constr/destr/reclaim */
    vmem_t *vmp,		/* vmem source for slab allocation */
    int cflags)		/* cache creation flags */
{
	UNREFERENCED_PARAMETER(name);
	UNREFERENCED_PARAMETER(align);
	UNREFERENCED_PARAMETER(constructor);
	UNREFERENCED_PARAMETER(destructor);
	UNREFERENCED_PARAMETER(reclaim);
	UNREFERENCED_PARAMETER(private);
	UNREFERENCED_PARAMETER(vmp);
	UNREFERENCED_PARAMETER(cflags);
	
	return (kmem_cache_t *)bufsize; /* A cookie that tracks the single object size. */
}

void *
kmem_cache_alloc(kmem_cache_t *cp, int kmflag)
{
	size_t bufsize = (size_t)cp;
	return (void *) kmem_alloc(bufsize, kmflag);;
}

void
kmem_cache_free(kmem_cache_t *cp, void *buf)
{
	UNREFERENCED_PARAMETER(cp);
	kmem_free(buf, sizeof(buf));
}

void
kmem_cache_destroy(kmem_cache_t *cp)
{
	UNREFERENCED_PARAMETER(cp);
}

/*
 * vmem (Solaris "slab" allocator) used by DTrace solely to hand out resource ids
 */
typedef unsigned int u_daddr_t;
#include "blist.h"

/* By passing around blist *handles*, the underlying blist can be resized as needed. */
struct blist_hdl {
	blist_t blist; 
};

vmem_t * 
vmem_create(const char *name, void *base, size_t size, size_t quantum, void *ignore5,
					void *ignore6, vmem_t *source, size_t qcache_max, int vmflag)
{
	
#pragma unused(name,quantum,ignore5,ignore6,source,qcache_max,vmflag)
	blist_t bl;
	struct blist_hdl *p = ExAllocatePoolWithTag(NonPagedPool, sizeof(struct blist_hdl), 'Tag1');
	UNREFERENCED_PARAMETER(name);
	UNREFERENCED_PARAMETER(quantum);
	UNREFERENCED_PARAMETER(ignore5);
	UNREFERENCED_PARAMETER(ignore6);
	UNREFERENCED_PARAMETER(source);
	UNREFERENCED_PARAMETER(qcache_max);
	UNREFERENCED_PARAMETER(vmflag);
	
	ASSERT(quantum == 1);
	ASSERT(NULL == ignore5);
	ASSERT(NULL == ignore6);
	ASSERT(NULL == source);
	ASSERT(0 == qcache_max);
	ASSERT(vmflag & VMC_IDENTIFIER);
	
	size = MIN(128, size); /* Clamp to 128 initially, since the underlying data structure is pre-allocated */
	
	p->blist = bl = blist_create( size );
	blist_free(bl, 0, size);
	if (base) blist_alloc( bl, (daddr_t)(uintptr_t)base ); /* Chomp off initial ID(s) */
	
	return (vmem_t *)p;
}
 
void *
vmem_alloc(vmem_t *vmp, size_t size, int vmflag)
{

	struct blist_hdl *q = (struct blist_hdl *)vmp;
	blist_t bl = q->blist;
	daddr_t p;
	UNREFERENCED_PARAMETER(vmflag);
	
	p = blist_alloc(bl, (daddr_t)size);
	
	if ((daddr_t)-1 == p) {
		blist_resize(&bl, (bl->bl_blocks) << 1, 1);
		q->blist = bl;
		p = blist_alloc(bl, (daddr_t)size);
		if ((daddr_t)-1 == p) 
			panic("vmem_alloc: failure after blist_resize!");
	}
	
	return (void *)(uintptr_t)p;
}

void
vmem_free(vmem_t *vmp, void *vaddr, size_t size)
{
	struct blist_hdl *p = (struct blist_hdl *)vmp;
	
	blist_free( p->blist, (daddr_t)(uintptr_t)vaddr, (daddr_t)size );
}

void
vmem_destroy(vmem_t *vmp)
{
	struct blist_hdl *p = (struct blist_hdl *)vmp;
	
	blist_destroy( p->blist );
	ExFreePoolWithTag(p, 'Tag1');
}