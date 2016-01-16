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
#ifndef DTRACE_WIN32_H
#define DTRACE_WIN32_H

#include <Aux_klib.h>
#include <Ntimage.h>
#include <limits.h>

#define ASSERT3U(x, y, z)		((void) 0)

/*
 * The cpu_core structure consists of per-CPU state available in any context.
 * On some architectures, this may mean that the page(s) containing the
 * NCPU-sized array of cpu_core structures must be locked in the TLB -- it
 * is up to the platform to assure that this is performed properly.  Note that
 * the structure is sized to avoid false sharing.
 */
#define ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))
#define	CPU_CACHE_COHERENCE_SIZE	64
#define	CPUC_SIZE		(sizeof (uint16_t) + sizeof (uint8_t) + \
				sizeof (uintptr_t) + sizeof (KMUTEX))

#define	CPUC_SIZE1		ROUND_UP(CPUC_SIZE, CPU_CACHE_COHERENCE_SIZE)
#define	CPUC_PADSIZE		CPUC_SIZE1 - CPUC_SIZE


typedef struct cpu_cores {
	uint16_t	cpuc_dtrace_flags;	/* DTrace flags */
	uint8_t		cpuc_pad[CPUC_PADSIZE];	/* padding */
	uintptr_t	cpuc_dtrace_illval;	/* DTrace illegal value */
	KMUTEX	cpuc_pid_lock;		/* DTrace pid provider lock */
} cpu_core_t;

typedef struct cpu_data {
	uintptr_t	cpu_dtrace_caller; /* fbt pc ????*/
	uintptr_t	cpu_profile_upc;
	uintptr_t	cpu_profile_pc;
	hrtime_t	cpu_dtrace_nsec;
} cpu_data_t;


/*
 * DTrace flags.
 */
#define	CPU_DTRACE_NOFAULT	0x0001	/* Don't fault */
#define	CPU_DTRACE_DROP		0x0002	/* Drop this ECB */
#define	CPU_DTRACE_BADADDR	0x0004	/* DTrace fault: bad address */
#define	CPU_DTRACE_BADALIGN	0x0008	/* DTrace fault: bad alignment */
#define	CPU_DTRACE_DIVZERO	0x0010	/* DTrace fault: divide by zero */
#define	CPU_DTRACE_ILLOP	0x0020	/* DTrace fault: illegal operation */
#define	CPU_DTRACE_NOSCRATCH	0x0040	/* DTrace fault: out of scratch */
#define	CPU_DTRACE_KPRIV	0x0080	/* DTrace fault: bad kernel access */
#define	CPU_DTRACE_UPRIV	0x0100	/* DTrace fault: bad user access */
#define	CPU_DTRACE_TUPOFLOW	0x0200	/* DTrace fault: tuple stack overflow */
#define CPU_DTRACE_USTACK_FP	0x0400  /* pid provider hint to ustack() */
#define	CPU_DTRACE_ENTRY	0x0800	/* pid provider hint to ustack() */
#define CPU_DTRACE_BADSTACK 0x1000  /* DTrace fault: bad stack */

#define	CPU_DTRACE_FAULT	(CPU_DTRACE_BADADDR | CPU_DTRACE_BADALIGN | \
				CPU_DTRACE_DIVZERO | CPU_DTRACE_ILLOP | \
				CPU_DTRACE_NOSCRATCH | CPU_DTRACE_KPRIV | \
				CPU_DTRACE_UPRIV | CPU_DTRACE_TUPOFLOW | \
				CPU_DTRACE_BADSTACK)
#define	CPU_DTRACE_ERROR	(CPU_DTRACE_FAULT | CPU_DTRACE_DROP)

/* taskq */

typedef uint_t pri_t;

#define TQ_SLEEP 0x00 //can block for memory

typedef KDPC taskq_t;
//typedef void (task_func_pvoid_t)(void *);
typedef void (task_func_t)(void);
typedef uintptr_t taskqid_t;
extern taskq_t	*taskq_create(const char *, int, pri_t, int, int, uint_t);
extern taskqid_t taskq_dispatch(taskq_t *, task_func_t, void *, uint_t);
extern void	taskq_destroy(taskq_t *);

extern pri_t maxclsyspri;

#define NCPU KeNumberProcessors 

#define	IS_P2ALIGNED(v, a) ((((uintptr_t)(v)) & ((uintptr_t)(a) - 1)) == 0)



/* MUTEX */
extern void mutex_init(KMUTEX *m);
extern void mutex_enter(KMUTEX *m);
extern void mutex_exit(KMUTEX *m);
extern int mutex_owned(KMUTEX *m);

/* cyclic */
typedef void (*timeout_t)(void *);
struct callout {
	KTIMER Timer;
	KDPC Dpc;
	timeout_t func;
	void *state;
	int64_t time;
	PETHREAD Thread;
};

void callout_init(struct callout *cyc, PDEVICE_OBJECT dev);
void callout_reset(struct callout *cyc, int64_t nano);
void callout_stop(struct callout *cyc);

/* unix */
extern int copyout(void * kaddr, void * uaddr, int len);
extern int copyin(void *  uaddr, void *  kaddr, int len);
extern int copyinstr(void *  uaddr, void *  kaddr, int len);
/* privlige */
 
boolean_t priv_policy_only(const cred_t *a, int b, boolean_t c);

/* solaris */
typedef int vmem_t; 
typedef struct kmem_cache {
	char		kc_name[32];
	size_t		kc_size;
	int		(*kc_constructor)(void *, void *, int);
	void		(*kc_destructor)(void *, void *);
	void		*kc_private;
} kmem_cache_t;

kmem_cache_t *
kmem_cache_create(
    const char *name,		
    size_t bufsize,		
    size_t align,		
    int (*constructor)(void *, void *, int),
    void (*destructor)(void *, void *),	
    void (*reclaim)(void *), 
    void *private,		
    vmem_t *vmp,		
    int cflags);	
void kmem_cache_destroy(kmem_cache_t *cp);
void kmem_cache_free(kmem_cache_t *cp, void *buf);
void *kmem_cache_alloc(kmem_cache_t *cp, int kmflag);

/* cmn_err FreeBSD */

typedef uintptr_t greg_t;
typedef uintptr_t pc_t;
//typedef uintptr_t dtrace_icookie_t;
#define panic DbgPrint

#define kernelbase MM_SYSTEM_RANGE_START

void dtrace_copy(uintptr_t src, uintptr_t dest, size_t size);
void dtrace_copystr(uintptr_t uaddr, uintptr_t kaddr, size_t size);
hrtime_t dtrace_gethrestime(void);

#define CPU_ON_INTR(a)	0
#define LOCK_LEVEL	5

extern int panic_quiesce;



#define KM_SLEEP	0x00000000
#define KM_NOSLEEP	0x00000001

/*unit allocator */
#define	VMC_IDENTIFIER	0x00040000	/* not backed by memory */
#define	VM_SLEEP	0x00000000	/* same as KM_SLEEP */
#define	VM_BESTFIT	0x00000100

void vmem_free(vmem_t *vmp, void *vaddr, size_t size);
void
vmem_destroy(vmem_t *vmp);
void *
vmem_alloc(vmem_t *vmp, size_t size, int vmflag);
vmem_t * 
vmem_create(const char *name, void *base, size_t size, size_t quantum, void *ignore5,
					void *ignore6, vmem_t *source, size_t qcache_max, int vmflag);


#define	P2PHASEUP(x, align, phase)	((phase) - (((phase) - (x)) & -(align)))

int bcmp(const void *s1, const void *s2, size_t n);

/*
 * Routines used to register interest in cpu's being added to or removed
 * from the system.
 */
typedef enum {
	CPU_INIT,
	CPU_CONFIG,
	CPU_UNCONFIG,
	CPU_ON,
	CPU_OFF,
	CPU_CPUPART_IN,
	CPU_CPUPART_OUT
} cpu_setup_t;

void dtrace_init_xcall();
 

extern hrtime_t dtrace_gethrtime();

extern void *kmem_alloc(size_t size, int kmflag);
extern void *kmem_zalloc(size_t size, int kmflag);
extern void kmem_free(void *buf, size_t size);

extern uintptr_t dtrace_fulword(void *addr);
extern uint32_t dtrace_fuword32(void *uaddr);

#define PAGESIZE	PAGE_SIZE
#define PAGEOFFSET	(PAGESIZE - 1)

void dtrace_vtime_enable(void);
void dtrace_vtime_disable(void);

uint8_t dtrace_fuword8_nocheck(void *);
uint16_t dtrace_fuword16_nocheck(void *);
uint32_t dtrace_fuword32_nocheck(void *);
uint64_t dtrace_fuword64_nocheck(void *);

#define MUTEX_HELD mutex_owned
#define MUTEX_NOT_HELD !mutex_owned
#define KERNELBASE MM_SYSTEM_RANGE_START
#endif  