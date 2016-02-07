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
 *
 */ 
 
#include <ntifs.h>
#include <sys/dtrace_misc.h>
#include <sys/dtrace_win32.h>
#include <sys/dtrace_impl.h>
#include "dtrace_private.h"
#include <ntstrsafe.h>
#include <ntintsafe.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>



struct wg_list;
typedef struct wg_list {
	void *data;
	struct wg_list *next;
} wg_list_t;

static wg_list_t *addfrontlist(wg_list_t *head, wg_list_t *newp);
static void freelist(wg_list_t *head);
static wg_list_t *lookuplistbyptr(wg_list_t *head, int type, uintptr_t id);
static wg_list_t *lookuplistbyid(wg_list_t *head, int type, int id);
static wg_list_t *addendlist(wg_list_t *head, wg_list_t *newp);
static wg_list_t *newnodelist(int type);
static void printn(wg_list_t *p, int type, void *args);
static void applytolist(wg_list_t *head, void (*fn) (wg_list_t *, int, void *), int type, void *args);
static wg_list_t *delnodelist(wg_list_t *ilist, wg_list_t *pp);

static proc_t *newnodeproc(uintptr_t proc, int model);

static void *malloc(int sz);
static void free(void *blk);

/* process list head */
wg_list_t *prochead = NULL;
/* thread list head */
wg_list_t *tdhead = NULL;

proc_t *_curproc()
{
	PEPROCESS proc = PsGetCurrentProcess();
	wg_list_t *p;
	proc_t *pp = NULL;
	static proc_t procs;
	
	if (proc == NULL) 
		return NULL;

	p = lookuplistbyptr(prochead, PROC_TYPE, (uintptr_t) proc);
	if (p == NULL) {
		int model;
		
#ifdef __amd64__
		if (IoIs32bitProcess(NULL) == 0) 
			model = DATAMODEL_LP64;
		else
#endif
			model = DATAMODEL_LP32;
			
		pp = newnodeproc((uintptr_t) proc, model);
		
		if (pp == NULL)
			return NULL;
		else
			return pp;
	} else
		return (p->data);
}

thread_t *_curthread()
{
	PETHREAD td = PsGetCurrentThread();
	int tid  = (int) PsGetThreadId(td);
	PVOID proc =  PsGetThreadProcess(td);
	PVOID tdbase = PsGetCurrentThreadStackBase();
	PVOID tdlimit = PsGetCurrentThreadStackLimit();
	int pid = (int) PsGetCurrentProcessId();
	wg_list_t *p, *plist;
	proc_t *pp = NULL;
	static thread_t tds = {0};
	thread_t *tmp = NULL;
	
	p = lookuplistbyptr(tdhead, THREAD_TYPE, (uintptr_t) td);
	if (p != NULL) {
		tmp = (thread_t *) p->data;
		if (tmp->tid != tid || tmp->pid != pid) {
			if (tmp->td_dtrace_sscr != NULL)
				scr_rel_mem(tmp->proc, tmp->td_dtrace_sscr);
			RtlZeroMemory(tmp, sizeof(thread_t));
		} else {
			tmp->kbase = (uintptr_t) tdbase;
			tmp->klimit = (uintptr_t) tdlimit;
			return tmp;
		}
	}
	
	if (proc != NULL) {
		plist = lookuplistbyptr(prochead, PROC_TYPE, (uintptr_t) proc);
		if (plist == NULL) {
			int model;
#ifdef __amd64__
			if (IoIs32bitProcess(NULL) == 0) 
				model = DATAMODEL_LP64;
			else
#endif
				model = DATAMODEL_LP32;
			pp =  newnodeproc((uintptr_t) proc, model);
		} else
			pp = plist->data;
	}
	
	if (p == NULL) {
		p = newnodelist(THREAD_TYPE);
		if (p == NULL) 
			return &tds;
		tdhead = addfrontlist(tdhead, p);
		tmp = (thread_t *) p->data;
	}
	
	tmp->td = td;
	tmp->tid = tid;
	tmp->kbase = (uintptr_t) tdbase;
	tmp->klimit = (uintptr_t) tdlimit;
	tmp->proc = pp;
	
	if (pp) {
		tmp->pid = pp->pid;
		tmp->name = pp->name;
		tmp->p_pid = pp->p_pid;
	}
	
	return (tmp);	
}
		
/* find node of type proc from pid */
proc_t *fasttrap_pfind(pid_t id)
{
	wg_list_t *p;
	
	p = lookuplistbyid(prochead, PROC_TYPE, id);
	if (p != NULL && ((proc_t *)p->data)->exiting == 0)
		return p->data;
	return NULL;
}

/* find/create new node of type proc from pid */
proc_t *pfind(pid_t id)
{
	wg_list_t *p;
	proc_t *tmp;
	PEPROCESS proc = NULL;
	proc_t *pp = NULL;
	
	p = lookuplistbyid(prochead, PROC_TYPE, id);
	if (p != NULL) {
		tmp = (proc_t *) p->data;
		return (proc_t *)(p->data);
	}
	if (PsLookupProcessByProcessId((HANDLE) id, &proc) == STATUS_SUCCESS) {
		int model;
#ifdef __amd64__
		if (IsProc32Bit((HANDLE) id) == 0) 
			model = DATAMODEL_LP64;
		else
#endif
			model = DATAMODEL_LP32;
		
		pp = newnodeproc((uintptr_t) proc, model);
		ObDereferenceObject(proc);
		return pp;
	}
	
	return NULL;
}

/* mark a proc node for deletion */

int del_proc_node(pid_t pid)
{
	wg_list_t *tmp;
	proc_t *p;
	int ret = 0;
		
	tmp = lookuplistbyid(prochead, PROC_TYPE, pid);
	if (tmp != NULL) {
		p = (proc_t *)(tmp->data);
		if (p->scr_mem != NULL)
			scr_rel_page(p);
		p->exiting = 1;
		ret = 1;
	}
	return ret;
}

/* delete a node from list prochead */
int del_thread_node(int tid)
{
	wg_list_t *tmp;
	thread_t *td;
	int ret = 0;
	
	tmp = lookuplistbyid(tdhead, THREAD_TYPE, tid);
	if (tmp != NULL) {
		td = (thread_t *)(tmp->data);
		if (td->td_dtrace_sscr != NULL)
			scr_rel_mem(td->proc, td->td_dtrace_sscr);
		tdhead = delnodelist(tdhead, tmp);
		ret = 1;
	}
	return ret;
}

/* free thread list */
void free_thread_list()
{
	wg_list_t *head = tdhead;
	wg_list_t *next;
	thread_t *td;
	
	for ( ;head != NULL; head = next) {
		next = head->next;
		td = (thread_t *)(head->data);
		if (td->td_dtrace_sscr != NULL)
			scr_rel_mem(td->proc, td->td_dtrace_sscr);
		free(head->data);
		free(head);
	}
	tdhead = NULL;
}

/* free process list */
void free_proc_list()
{
	wg_list_t *head = prochead;
	wg_list_t *next;
	proc_t *p;
	
	for ( ;head != NULL; head = next) {
		next = head->next;
		p = (proc_t *)(head->data);
		if (p->scr_mem != NULL)
			scr_rel_page(p);
		free(head->data);
		free(head);
	}
	prochead = NULL;
}	

/* free process list */
void free_proc_exiting()
{
	wg_list_t *head = prochead;
	wg_list_t *prev = NULL;
	wg_list_t *next;
	proc_t *p;
	while (head != NULL) {
		next = head->next;
		p = (proc_t *)(head->data);
		if (p->exiting) {
			if (prev != NULL)
				prev->next = head->next;
			else
				prochead = head->next;
			free(head->data);
			free(head);
		} else {
			prev = head;
		}
			
		head = next;
	}
			
}	

/* add a proc node to process list */
static proc_t *newnodeproc(uintptr_t proc, int model)
{
	proc_t *tmp;
	int ppid = 0, pid = 0;
	char *s = 0;
	wg_list_t *p=NULL;
		
	pid = (int) PsGetProcessId((PEPROCESS) proc);
	ppid = (int) PsGetProcessInheritedFromUniqueProcessId((PEPROCESS) proc);
	s = PsGetProcessImageFileName((PEPROCESS) proc);	
	p = newnodelist(PROC_TYPE);
	if (p == NULL)
		return NULL;
		
	tmp = (proc_t *) p->data;
	tmp->pid = pid;
	tmp->p_pid = ppid;
	tmp->name= s;
	tmp->proc = (PEPROCESS) proc;
	tmp->p_model = model;
	KeInitializeSpinLock(&tmp->scr_lock);
	prochead = addfrontlist(prochead, p);
	return (prochead->data);
}

/* add newp to front of head and return newp */
static wg_list_t *addfrontlist(wg_list_t *head, wg_list_t *newp)
{
	newp->next = head;
	return newp;
}	

/* free list */
static void freelist(wg_list_t *head)
{
	wg_list_t *next;
	
	for ( ;head != NULL; head = next) {
		next = head->next;
		free(head->data);
		free(head);
	}
}

/* look up in given list head for proc/thread using the PEPROCESS/PETHREAD pointer */
static wg_list_t *lookuplistbyptr(wg_list_t *head, int type, uintptr_t id)
{
	
	for ( ; head != NULL; head = head->next) {
		if (type == THREAD_TYPE) {
			if ((uintptr_t)(((thread_t *)(head->data))->td) == id)
				return head;
		} else {
			if ((uintptr_t)(((proc_t *) (head->data))->proc) == id)
			return head;
		}
	}
	return NULL;
}

/* look up in given list head for proc/thread using the pid/tid id */
static wg_list_t *lookuplistbyid(wg_list_t *head, int type, int id)
{
	
	for ( ; head != NULL; head = head->next) {
		if (type == THREAD_TYPE) {
			if (((thread_t *)(head->data))->tid == id)
				return head;
		} else {
			if (((proc_t *) (head->data))->pid == id)
			return head;
		}
	}
	return NULL;
}

/* add node to end of list head */
static wg_list_t *addendlist(wg_list_t *head, wg_list_t *newp)
{
	wg_list_t *p;
	
	if (head == NULL)
		return newp;
	for (p = head; 	p->next != NULL; p = p->next)
		;
	p->next = newp;
	return head;
}
		
/* return new node of proc/thread type */
static wg_list_t *newnodelist(int type)
{
	wg_list_t *p = malloc(sizeof(wg_list_t));
	
	if (p == NULL)
		return NULL;
		
	if (type == THREAD_TYPE) {
		p->data = malloc(sizeof(thread_t));
		if (p->data == NULL) {
			free(p); 
			return NULL;
		}
		RtlZeroMemory(p->data, sizeof(thread_t));
	} else {
		p->data = malloc(sizeof(proc_t));
		if (p->data == NULL) {
			free(p); 
			return NULL;
		}
		RtlZeroMemory(p->data, sizeof(proc_t));
	}
	
	return p;
}

	
/* delete the node pp from head and return head */
static wg_list_t *delnodelist(wg_list_t *head, wg_list_t *pp)
{
	wg_list_t *p, *prev = NULL;
	
	for (p = head; p != NULL; p = p->next) {
		if (pp == p) {
			if (prev == NULL)
				head = p->next;
			else
				prev->next = p->next;
			free(p);
			return head;
		}
		prev = p;
	}
	return head;
}

/* functions to read and write to process in user space from kernel.
 * Nt*VirtualMemory functions expect function parameter variables to be
 * in user mode memory range. */
 
int
uread(proc_t *p, void *kaddr, size_t len, uintptr_t uaddr)
{
	KAPC_STATE apc;
	int err = 0;

	if (p->scr_var == NULL && (p->scr_var = scr_alloc_mem(p)) == NULL) {
		err = -1;
	} else {
		BYTE *kubase;
		NTSTATUS st;
		
		KeStackAttachProcess(p->proc, &apc);
		kubase = (BYTE *) ((ULONG *)p->scr_var);
		st = NtReadVirtualMemory(NtCurrentProcess(), (PVOID) uaddr, kubase, len, 0);
		
		if (st == STATUS_SUCCESS) {
			RtlCopyMemory(kaddr, (PVOID) kubase, len);
		} else {
			dprintf("dtrace.sys: uread() NtReadVirtualMemory failed: addr %p: code %x\n", uaddr, st);
			err = -1;
		}
		
		KeUnstackDetachProcess(&apc);
	}
	
	return err;
}

int
uwrite(proc_t *p, void *kaddr, size_t len, uintptr_t uaddr)
{
	KAPC_STATE apc;
	int err = 0;
		
	if (p->scr_var == NULL && (p->scr_var = scr_alloc_mem(p)) == NULL)
		err = -1;
	else {
		ULONG oldprot;
		ULONG *kprot;
		SIZE_T *klen;
		PVOID *kuaddr;
		BYTE *kubase;
		NTSTATUS st;
		
		KeStackAttachProcess(p->proc, &apc);
		
		kuaddr = (PVOID *)((PVOID *)p->scr_var);
		klen = (SIZE_T *) ((PVOID *)p->scr_var+1);
		kprot = (ULONG *) ((PVOID *)p->scr_var+2);
		kubase = (BYTE *) ((PVOID *)p->scr_var+3);
		*kuaddr = (PVOID) uaddr;
		*klen = len;
		*kprot = 0;
		
		st = NtProtectVirtualMemory(NtCurrentProcess(), (PVOID *) kuaddr, 
			klen, PAGE_EXECUTE_READWRITE, kprot);
		
		if (st != STATUS_SUCCESS) {
			dprintf("dtrace.sys: uwrite() NtProtectVirtualMemory failed: addr %p: code %x\n", uaddr, st);
			KeUnstackDetachProcess(&apc);
			return -1;
		}
		
		RtlCopyMemory(kubase, kaddr, len);
		
		st = NtWriteVirtualMemory(NtCurrentProcess(), (PVOID) uaddr, kubase, len, 0);
		
		if (st != STATUS_SUCCESS) {
			dprintf("dtrace.sys: uwrite() NtWriteVirtualMemory failed: addr %p: code %x\n", uaddr, st);
			err = -1;
		}
		
		oldprot =*kprot;
		st = NtProtectVirtualMemory(NtCurrentProcess(), (PVOID *) kuaddr, klen, oldprot, kprot);
		
		if (st != STATUS_SUCCESS) {
			dprintf("dtrace.sys: uwrite() NtProtectVirtualMemory failed to reset: addr %p: code %x\n", uaddr, st);
			err = -1;
		}

		KeUnstackDetachProcess(&apc);
	}
	
	return err;
}

/* Allocate user mode sctrach space */

PVOID scr_allocate(proc_t *p);
extern PIO_WORKITEM WorkItem1;

VOID WorkFunc(PDEVICE_OBJECT DeviceObject, PVOID Context)
{
	proc_t *p = (proc_t *) Context;
	UNREFERENCED_PARAMETER(DeviceObject);
		
	(void) scr_allocate(p);
	InterlockedExchange(&p->scr_queued, 0);
}

static LONG FTLock;

PVOID scr_alloc_mem(proc_t *p)
{
	struct scr_page *page;
	uintptr_t vm = 0;
	int i, count;
	
	if (p->scr_mem == NULL) { 
		scr_allocate(p);
	}
	
	KeAcquireSpinLockAtDpcLevel(&p->scr_lock);
	if (p->scr_mem != NULL) {
		page = p->scr_mem;
		do {
			if (page->free_co) {
				vm = page->addr + page->free_list[0]*FTT_SCRATCH_SIZE;
				page->free_co--;
				for (i = 0; i < page->free_co; i++)
					page->free_list[i] = page->free_list[i+1];
				break;
			}
		} while ((page = page->next) != NULL);
	}
	
	KeReleaseSpinLockFromDpcLevel(&p->scr_lock);
	
	if (vm != 0) {
		page = p->scr_mem;
		count = 0;
		do 
			count += page->free_co;
		while ((page = page->next) != NULL);
	/* 
	 * ZwAllocateVirtualMemory doesnt actually load committed page into physical memory until first read or write.
	 * Except the first call (ZwAllocateVirtualMemory), all calls are made under interrupt context, this will 
	 * cause a page fault.
	 */
		if (count < (FTT_PAGE_SIZE/FTT_SCRATCH_SIZE)/2 && InterlockedCompareExchange(&p->scr_queued, 1, 0) == 0) 
			IoQueueWorkItem(WorkItem1, WorkFunc, DelayedWorkQueue, (PVOID) p);
		
		return (PVOID) vm;
	}
	
	return NULL;

}

PVOID scr_allocate(proc_t *p)
{
	struct scr_page *page;
	uintptr_t vm = 0;
	PVOID mem_base = NULL;
	SIZE_T mem_size = FTT_PAGE_SIZE;
	NTSTATUS st;
	KAPC_STATE apc;
	int i;
	
	KeStackAttachProcess(p->proc, &apc);
	
	st = ZwAllocateVirtualMemory(NtCurrentProcess(),&mem_base,0,&mem_size,MEM_COMMIT,PAGE_EXECUTE_READWRITE);
	if (st != STATUS_SUCCESS) {
		dprintf("dtrace.sys: scr_allocate() ZwAllocateVirtualMemory failed %x\n", st);
		KeUnstackDetachProcess(&apc);
		return NULL;
	}
	
	((BYTE *) mem_base)[0] = 0;
	KeUnstackDetachProcess(&apc);
	
	page = ExAllocatePoolWithTag(NonPagedPool, sizeof(struct scr_page), 'Tag1');
	if (page == NULL) {
		return NULL;
	}
	vm = page->addr = (uintptr_t) mem_base;
	page->size = mem_size;
	
	for (i = 0; i < (FTT_PAGE_SIZE / FTT_SCRATCH_SIZE); i++)
		page->free_list[i] = i;
		
	page->free_co = i;
	page->next = NULL;
	
	if (p->scr_mem == NULL)
		p->scr_mem = page;
	else {
		page->next = p->scr_mem;
		p->scr_mem = page;
	}
	
	return (PVOID) vm;
}

void scr_rel_mem(proc_t *p, PVOID addr1)
{
	struct scr_page *page;
	int j;
	uintptr_t addr = (uintptr_t) addr1;
	
	page = p->scr_mem;
	
	while (page != NULL) {
		if (addr >= page->addr && addr < (page->addr + page->size)) {
			j = (addr - page->addr) / FTT_SCRATCH_SIZE;
			page->free_list[page->free_co] = j;
			page->free_co++;
			break;
		}
		page = page->next;
	}
}		

void scr_rel_page(proc_t *p)
{
	KAPC_STATE apc;
	NTSTATUS st;
	struct scr_page *page, *temp;
	
	if (p->scr_mem != NULL) {
		page = p->scr_mem;
		
		KeStackAttachProcess(p->proc, &apc);
		do {
			 st = ZwFreeVirtualMemory(NtCurrentProcess(), (PVOID *) &page->addr, &page->size, MEM_RELEASE);
			 if (st != STATUS_SUCCESS)
			 	dprintf("dtrace.sys: scr_rel_page() ZwFreeVirtualMemory failed %x\n", st);
			 temp = page;
			 page = page->next;
			 ExFreePoolWithTag(temp, 'Tag1');
		} while (page != NULL);
		KeUnstackDetachProcess(&apc);
		p->scr_mem = NULL;
	}
}

/* internal malloc for allocating memory in probe context */
static LONG MLock;
static void *malloc(int sz)
{
	void *p;
	
	while (1) {
		if (InterlockedCompareExchange(&MLock, 1, 0) == 0)
			break;
	}
		
	p =  int_malloc(sz);
	InterlockedExchange(&MLock, 0);
	return p;
}

static LONG FLock;
static void free(void *blk)
{	
	while (1) {
		if (InterlockedCompareExchange(&FLock, 1, 0) == 0)
			break;
	}
	int_free(blk);
	InterlockedExchange(&FLock, 0);
}

/*
 * From,
 * The C Programming Language - BWK, DMR
 * page 164 - 8.7 Example - A Storage Allocator
 */
typedef union header Header;

typedef struct alloc_list {
	PVOID mem;
	struct alloc_list *next;
} alloc_list_t;

static alloc_list_t *exalloc_list = NULL;

typedef long Align; /* for alignment to long boundary */
union header { /* block header */

	struct {
		union header *ptr; /* next block if on free list */
		unsigned size; /* size of this block */
	} s;
	Align x; /* force alignment of blocks */
};

typedef union header Header;

static Header base; /* empty list to get started */
static Header *freep = NULL; /* start of free list */
/* malloc: general-purpose storage allocator */
void *int_malloc(unsigned nbytes)
{
	Header *p, *prevp;
	unsigned nunits;
	nunits = (nbytes+sizeof(Header)-1)/sizeof(Header) + 1;
	if ((prevp = freep) == NULL) { /* no free list yet */
		base.s.ptr = prevp = freep = &base;
		base.s.size = 0;
	}

	for (p = prevp->s.ptr; ; prevp = p, p = p->s.ptr) {
		if (p->s.size >= nunits) { /* big enough */
			if (p->s.size == nunits) /* exactly */
				prevp->s.ptr = p->s.ptr;
			else { /* allocate tail end */
				p->s.size -= nunits;
				p += p->s.size;
				p->s.size = nunits;
			}
			freep = prevp;
			return (void *)(p+1);
		}
		if (p == freep) /* wrapped around free list */
			//if ((p = morecore(nunits)) == NULL)
			return NULL; /* none left */
	}
}

#define NALLOC 100000 /* minimum #units to request */
/* morecore: ask system for more memory */
void int_morecore()
{
	char *cp;
	Header *up;
	
	Header *p, *prevp;
	unsigned nunits, nu;
	alloc_list_t *ex;
	
	nu = NALLOC;
		
	nunits = NALLOC;// (nbytes+sizeof(Header)-1)/sizeof(Header) + 1;
	if ((prevp = freep) == NULL) { /* no free list yet */
		base.s.ptr = prevp = freep = &base;
		base.s.size = 0;
	}

	for (p = prevp->s.ptr; ; prevp = p, p = p->s.ptr) {
		if (p->s.size >= nunits/2) { /* big enough */
			return;
		}
		if (p == freep) {/* wrapped around free list */
			cp = ExAllocatePoolWithTag(NonPagedPool, nunits * sizeof(Header), 'Tag1');
			if (cp != NULL) { /* no space at all */
				up = (Header *) cp;
				up->s.size = nunits;
				int_free((void *)(up+1));
				ex = ExAllocatePoolWithTag(NonPagedPool, sizeof(alloc_list_t), 'Tag1');
				if (ex != NULL) {
					ex->mem = cp;
					if (exalloc_list)
						exalloc_list = ex;
					else {
						ex->next = exalloc_list;
						exalloc_list = ex;
					}
				}
			}
			return;
		}	
	}
}

void int_freecore()
{
	alloc_list_t *ex, *tmp;
	
	ex = exalloc_list;
	
	while (ex != NULL) {
		tmp = ex;
		ex = ex->next;
		ExFreePoolWithTag(tmp->mem, 'Tag1');
		ExFreePoolWithTag(tmp, 'Tag1');
	}
}

/* free: put block ap in free list */
void int_free(void *ap)
{
	Header *bp, *p;
	bp = (Header *)ap - 1; /* point to block header */
	for (p = freep; !(bp > p && bp < p->s.ptr); p = p->s.ptr)
		if (p >= p->s.ptr && (bp > p || bp < p->s.ptr))
			break; /* freed block at start or end of arena */
	if (bp + bp->s.size == p->s.ptr) { /* join to upper nbr */
		bp->s.size += p->s.ptr->s.size;
		bp->s.ptr = p->s.ptr->s.ptr;
	} else
		bp->s.ptr = p->s.ptr;
	if (p + p->s.size == bp) { /* join to lower nbr */
		p->s.size += bp->s.size;
		p->s.ptr = bp->s.ptr;
	} else
		p->s.ptr = bp;
	freep = p;
}

/* Helper functions for reading anonymous tracing data from c:/dtrace/boot/dtrace.dof */

struct list {
	char *name;
	char *value;
	struct list *next;
};
typedef struct list list;

static char *dofbuf = NULL;
static list *root = NULL;

static list *addend(list *ilist, list *newp)
{
	list *p;
	
	if (ilist == NULL)
		return newp;
	for(p=ilist; p->next != NULL; p=p->next) 
		;
	p->next = newp;
	return ilist;
}
	
static list *newitem(char *name, char *value)
{
	list *newl;
	
	newl = kmem_alloc(sizeof(list), KM_SLEEP);
	if (newl == NULL)
		return NULL;
	newl->name  = name;
	newl->value = value;
	newl->next = NULL;
	
	return newl;
}

static UNICODE_STRING anon_name = RTL_CONSTANT_STRING(L"\\DosDevices\\C:\\dtrace\\boot\\dtrace.dof");

list * setup_prop(void)
{
	size_t sz;
	list *dlist = NULL, *ilist=NULL;
	char *b, *e, *c;
	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK io;
	FILE_STANDARD_INFORMATION finfo;
	HANDLE handle;
	LARGE_INTEGER byteOffset;
	
	InitializeObjectAttributes(&ObjectAttributes, &anon_name, OBJ_KERNEL_HANDLE, NULL, NULL);
	
	if (ZwOpenFile(&handle, GENERIC_READ, &ObjectAttributes, &io, 
	   FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT) !=  STATUS_SUCCESS) {
		return 0;
	}
	
	if (ZwQueryInformationFile(handle, &io, &finfo, sizeof(finfo), 
	    FileStandardInformation) != STATUS_SUCCESS) {
		ZwClose(handle);
		return 0;
	} 
	
	sz = finfo.EndOfFile.LowPart;
	
	if (sz == 0 || (dofbuf = kmem_alloc(sz, KM_SLEEP)) == NULL) {
		ZwClose(handle);
		return 0;
	}
	byteOffset.LowPart = byteOffset.HighPart = 0;	
	if (ZwReadFile(handle, NULL, NULL, NULL, &io, dofbuf, sz, &byteOffset, NULL) != STATUS_SUCCESS) {
		kmem_free(dofbuf, 0); 
		ZwClose(handle);
		return 0;
	}
	ZwClose(handle);
		
	b = dofbuf;
	
	while ((c = strchr(b, '=')) != NULL) {
		e = strchr(c + 1, '\n');
		*c = 0;
		*e = 0;
		dlist = newitem(b, c+1);
		if (dlist == NULL) {
	     		goto out;
		}
		ilist = addend(ilist, dlist);
		 
	    	b = e + 1;
	}
	
out:
	root = ilist;
	return root;
}

void free_prop_root(void)
{
	list *dlist, *alist = root;

	if (dofbuf != NULL)
		kmem_free(dofbuf, 0); 
	for( ; alist != NULL; alist = dlist) {
		dlist = alist->next;
		kmem_free(alist, sizeof(list));
	}
}

list *getprop(const char *name)
{
	list *ilist = root;
	
	if (ilist == NULL)
		ilist = setup_prop();
	else if (ilist == (list *) -1)
		return NULL;
	
	
	for( ; ilist != NULL; ilist = ilist->next) {
		if (strcmp(name, ilist->name) == 0) 
			return ilist;
	}
	return NULL;
}

//FreeBSD
static __inline uchar_t
dtrace_dof_char(char c) {
	switch (c) {
	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
		return (c - '0');
	case 'A':
	case 'B':
	case 'C':
	case 'D':
	case 'E':
	case 'F':
		return (c - 'A' + 10);
	case 'a':
	case 'b':
	case 'c':
	case 'd':
	case 'e':
	case 'f':
		return (c - 'a' + 10);
	}
	/* Should not reach here. */
	return (0);
}
///
int ddi_prop_lookup_int_array(char *name, int **data, int *length)
{
	list *ilist;
	int *buf;
	char *p;
	unsigned int len = 0, i;
	dof_hdr_t *dof;
	
	ilist = getprop(name);
	if (ilist == NULL) 
		return DDI_PROP_FAILURE;
	
	len = strlen(ilist->value) / 2;

	buf = kmem_alloc(len * sizeof(int), KM_SLEEP);
	if (buf == NULL)
		return DDI_PROP_FAILURE;
	dof = (dof_hdr_t *) buf;

	p = ilist->value;

	for (i = 0; i < len; i++) {
		buf[i] = (dtrace_dof_char(p[0]) << 4) |
		     dtrace_dof_char(p[1]);
		p += 2;
	}
	*data = buf;
	*length = len;
	
	return DDI_PROP_SUCCESS;
}

void ddi_prop_free(void *buf)
{
	kmem_free(buf, 0);
}
		
