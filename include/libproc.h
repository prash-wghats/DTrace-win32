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
 */
/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _LIBPROC_H
#define _LIBPROC_H

/* #pragma ident   "@(#)libproc.h  1.46    05/06/08 SMI" */

#include <dtrace_misc.h>
#include <string.h>
#include <rtld_db.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* From Sun's link.h */
#define LM_ID_BASE              0x00


/*
 * Opaque structure tag reference to a process control structure.
 * Clients of libproc cannot look inside the process control structure.
 * The implementation of struct ps_prochandle can change w/o affecting clients.
 */
struct ps_prochandle;
struct modinfo;

/* State values returned by Pstate() */
#define PS_RUN          1       /* process is running */
#define PS_STOP         2       /* process is stopped */
#define PS_LOST         3       /* process is lost to control (EAGAIN) */
#define PS_UNDEAD       4       /* process is terminated (zombie) */
#define PS_DEAD         5       /* process is terminated (core file) */
#define PS_IDLE         6       /* process has not been run */

/* Flags accepted by Pgrab() */
#define PGRAB_RETAIN    0x01    /* Retain tracing flags, else clear flags */
#define PGRAB_FORCE     0x02    /* Open the process w/o O_EXCL */
#define PGRAB_RDONLY    0x04    /* Open the process or core w/ O_RDONLY */
#define PGRAB_NOSTOP    0x08    /* Open the process but do not stop it */

/* Error codes from Pcreate() */
#define C_STRANGE       -1      /* Unanticipated error, errno is meaningful */
#define C_FORK          1       /* Unable to fork */
#define C_PERM          2       /* No permission (file set-id or unreadable) */
#define C_NOEXEC        3       /* Cannot execute file */
#define C_INTR          4       /* Interrupt received while creating */
#define C_LP64          5       /* Program is _LP64, self is _ILP32 */
#define C_NOENT         6       /* Cannot find executable file */

/* Flags accepted by Prelease */
#define PRELEASE_CLEAR  0x10    /* Clear all tracing flags */
#define PRELEASE_RETAIN 0x20    /* Retain final tracing flags */
#define PRELEASE_HANG   0x40    /* Leave the process stopped */
#define PRELEASE_KILL   0x80    /* Terminate the process */

/*
 * Function prototypes for routines in the process control package.
 */

extern struct ps_prochandle *Pcreate(const char *, char *const *, int *, char *, size_t);
extern const char *Pcreate_error(int);

extern struct ps_prochandle *Pgrab(pid_t, int, int *);
extern const char *Pgrab_error(int);

extern  int     Preopen(struct ps_prochandle *);
extern  void    Prelease(struct ps_prochandle *, int);

extern  int     Pstate(struct ps_prochandle *);
extern  const int Pstatus(struct ps_prochandle *);
extern	int		Psetrun(struct ps_prochandle *, int, int);

extern  int     Psetbkpt(struct ps_prochandle *, uintptr_t, ulong_t *);
extern  int     Pdelbkpt(struct ps_prochandle *, uintptr_t, ulong_t);
extern	int		Pxecbkpt(struct ps_prochandle *, ulong_t);
extern  int     Psetflags(struct ps_prochandle *, long);
extern  int     Punsetflags(struct ps_prochandle *, long);

extern rd_event_e rd_event_type(struct ps_prochandle *P);
extern rd_err_e rd_event_enable(rd_agent_t *nop, int i);
extern rd_agent_t *Prd_agent(struct ps_prochandle *P);
extern rd_err_e rd_event_addr(rd_agent_t *nop, rd_event_e ev, rd_notify_t *rdn);
extern rd_err_e rd_event_getmsg(rd_agent_t *rd, rd_event_msg_t *rdm);
extern int Ppid(struct ps_prochandle *P);
extern const char *rd_errstr(rd_err_e err);
extern const char *Pgrab_error(int err);
extern const char *Pcreate_error(int error);
extern int Psignaled(struct ps_prochandle *P);
extern int Pexitcode(struct ps_prochandle *P);
extern void Pupdate_syms(struct ps_prochandle *P);

extern int Pmodel(struct ps_prochandle *P);
extern int Pstopstatus(struct ps_prochandle *P);


#define PR_RLC		0x0001
#define PR_KLC		0x0002

typedef struct prmap {
	uintptr_t	pr_vaddr;	/* Virtual address. */
	size_t		pr_size;	/* Mapping size in bytes */
	size_t		pr_offset;	/* Mapping offset in object */
	char		pr_mapname[PATH_MAX];	/* Mapping filename */
	uint8_t		pr_mflags;	/* Protection flags */
#define	MA_READ		0x01
#define	MA_WRITE	0x02
#define	MA_EXEC		0x04
#define	MA_COW		0x08
#define MA_NEEDS_COPY	0x10
#define	MA_NOCOREDUMP	0x20
} prmap_t;

typedef int proc_sym_f(void *, const GElf_Sym *, const char *);
typedef int proc_map_f(void *, const prmap_t *, const char *);
prmap_t *Paddr_to_map(struct ps_prochandle *, uintptr_t);
prmap_t *Plmid_to_map(struct ps_prochandle *P, Lmid_t ignored, const char *cname);
int Pobject_iter(struct ps_prochandle *P, proc_map_f *func, void *cd) ;
char *Pobjname(struct ps_prochandle *P, uintptr_t addr, char *buffer, size_t bufsize) ;
int Pxlookup_by_name(
		     struct ps_prochandle *P,
		     Lmid_t lmid,		/* link map to match, or -1 (PR_LMID_EVERY) for any */
		     const char *oname,		/* load object name */
		     const char *sname,		/* symbol name */
		     GElf_Sym *symp,		/* returned symbol table entry */
		     void *sip);		/* returned symbol info */
int Plookup_by_addr(struct ps_prochandle *P, uintptr_t addr, char *buf, size_t size, GElf_Sym *symp);
int Psymbol_iter_by_addr(struct ps_prochandle *P, const char *object_name, int which, int mask, proc_sym_f *func, void *cd) ;
prmap_t *Paddr_to_map(struct ps_prochandle *, uintptr_t);
size_t Pread(struct ps_prochandle *P, void *buf, size_t size, size_t addr);
prmap_t *Pname_to_map(struct ps_prochandle *p, const char *name);

/* Values for ELF sections */
#define	PR_SYMTAB	1
#define PR_DYNSYM	2

/* Values for the 'mask' parameter in the iteration functions */
#define	BIND_LOCAL	0x0001
#define BIND_GLOBAL	0x0002
#define BIND_WEAK	0x0004
#define BIND_ANY	(BIND_LOCAL|BIND_GLOBAL|BIND_WEAK)
#define TYPE_NOTYPE	0x0100
#define TYPE_OBJECT	0x0200
#define TYPE_FUNC	0x0400
#define TYPE_SECTION	0x0800
#define TYPE_FILE	0x1000
#define TYPE_ANY	(TYPE_NOTYPE|TYPE_OBJECT|TYPE_FUNC|TYPE_SECTION|\
    			 TYPE_FILE)
    			 
#if _WIN32

#define PS_ALL_MODS	10
#define PS_LOADED_MOD	11

struct ps_module_info {
	uintptr_t imgbase;
	size_t size;
	char name[MAX_SYMBOL_NAME];
};

int Ploadedmod(struct ps_prochandle *P, struct ps_module_info *mod);
int Pmodinfo(struct ps_prochandle *P, struct ps_module_info *mod, int *count);

#endif		 

#ifdef  __cplusplus
}
#endif

#endif  /* _LIBPROC_H */
