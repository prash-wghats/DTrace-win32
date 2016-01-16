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
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#if defined(sun)
#include <sys/modctl.h>
#include <sys/dtrace.h>
#include <sys/kobj.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/conf.h>
#else
#include "fbt_win32.h"
#endif

#define FBT_REX_W 		0x48
#define FBT_8_OP		0x83
#define FBT_32_OP		0x81
#define FBT_SUB_RSP_OP		0xec
#define FBT_ADD_RSP_OP		0xc4

#define FBT_MOV_EDI_EDI0_V0	0x8b
#define FBT_MOV_EDI_EDI1_V0	0xff
#define	FBT_PUSHL_EBP		0x55
#define	FBT_MOVL_ESP_EBP0_V0	0x8b
#define	FBT_MOVL_ESP_EBP1_V0	0xec
#define	FBT_MOVL_ESP_EBP0_V1	0x89
#define	FBT_MOVL_ESP_EBP1_V1	0xe5
#define	FBT_REX_RSP_RBP		0x48

#define	FBT_POPL_EBP		0x5d
#define	FBT_RET			0xc3
#define	FBT_RET_IMM16		0xc2
#define	FBT_LEAVE		0xc9

#ifdef _AMD64_
#define	FBT_PATCHVAL		0xf0
#else
#define	FBT_PATCHVAL		0xf0
#endif

#define	FBT_ENTRY	"entry"
#define	FBT_RETURN	"return"
#define	FBT_ADDR2NDX(addr)	((((uintptr_t)(addr)) >> 4) & fbt_probetab_mask)
#define	FBT_PROBETAB_SIZE	0x8000		/* 32k entries -- 128K total */

typedef struct fbt_probe {
	struct fbt_probe *fbtp_hashnext;
	uint8_t		*fbtp_patchpoint;
	int8_t		fbtp_rval;
	uint8_t		fbtp_patchval;
	uint8_t		fbtp_savedval;
	uintptr_t	fbtp_roffset;
	dtrace_id_t	fbtp_id;
	char		*fbtp_name;
	struct modctl	*fbtp_ctl;
	int		fbtp_loadcnt;
	int		fbtp_symindx;
	int		fbtp_primary;
	struct fbt_probe *fbtp_next;
} fbt_probe_t;


static dtrace_provider_id_t	fbt_id;
static fbt_probe_t		**fbt_probetab;
static int			fbt_probetab_size;
static int			fbt_probetab_mask;
static int			fbt_verbose = 0;



static int
fbt_invop(uintptr_t addr, uintptr_t *stack, uintptr_t rval)
{
#ifdef _AMD64_
	struct trap_frame *tf = (struct trap_frame *) stack;
#endif
	uintptr_t stack0, stack1, stack2, stack3, stack4;
	fbt_probe_t *fbt = fbt_probetab[FBT_ADDR2NDX(addr)];
	int i = 0;

	for (; fbt != NULL; fbt = fbt->fbtp_hashnext) {
		if ((uintptr_t)fbt->fbtp_patchpoint == addr) {
			if (fbt->fbtp_roffset == 0) {
				/*
				 * When accessing the arguments on the stack,
				 * we must protect against accessing beyond
				 * the stack.  We can safely set NOFAULT here
				 * -- we know that interrupts are already
				 * disabled.
				 */
				DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
#ifndef _AMD64_
				CPU[KeGetCurrentProcessorNumber()].cpu_dtrace_caller = stack[i++];		
				stack0 = stack[i++];
				stack1 = stack[i++];
				stack2 = stack[i++];
				stack3 = stack[i++];
				stack4 = stack[i++];
#else
				CPU[KeGetCurrentProcessorNumber()].cpu_dtrace_caller = tf->rsp;				
				stack0 = tf->rcx;
				stack1 = tf->rdx;
				stack2 = tf->r8;
				stack3 = tf->r9;
				stack4 = 0xbad;
#endif
				DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT |
				    CPU_DTRACE_BADADDR);

				dtrace_probe(fbt->fbtp_id, stack0, stack1,
				    stack2, stack3, stack4);

				CPU[KeGetCurrentProcessorNumber()].cpu_dtrace_caller = 0;			
			} else {
#ifdef _AMD64_
				/*
				 * On amd64, we instrument the ret, not the
				 * leave.  We therefore need to set the caller
				 * to assure that the top frame of a stack()
				 * action is correct.
				 */
				DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
				CPU[KeGetCurrentProcessorNumber()].cpu_dtrace_caller = tf->rsp;
				
				DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT |
				    CPU_DTRACE_BADADDR);
#endif

				dtrace_probe(fbt->fbtp_id, fbt->fbtp_roffset,
				    rval, 0, 0, 0);
				CPU[KeGetCurrentProcessorNumber()].cpu_dtrace_caller = 0;
				
			}

			return (fbt->fbtp_rval);
		}
	}

	return (0);
}


void
fbt_provide_module(void *arg, modctl_t *lf)
{
	char modname[MAXPATHLEN];
	size_t len;

	strncpy(modname, lf->mod_modname, sizeof(modname));
	len = strlen(modname);
	if (len > 3 && ((strcmp(modname + len - 4, ".sys") == 0) || (strcmp(modname + len - 4, ".exe") == 0) || 
			(strcmp(modname + len - 4, ".dll") == 0)))
		modname[len - 4] = '\0';

	/*
	 * Employees of dtrace and their families are ineligible.  Void
	 * where prohibited.
	 */
	if (strcmp(modname, "dtrace") == 0)
		return;

	/*
	 * The cyclic timer subsystem can be built as a module and DTrace
	 * depends on that, so it is ineligible too.
	 */
	if (strcmp(modname, "profile") == 0)
		return;
	if (strcmp(modname, "fbt") == 0)
		return;
	if (strcmp(modname, "fasttrap") == 0)
		return;
	/* In user land */
	if (strcmp(modname, "ntdll") == 0)
		return;
		
	/*
	 * To register with DTrace, a module must list 'dtrace' as a
	 * dependency in order for the kernel linker to resolve
	 * symbols like dtrace_register(). All modules with such a
	 * dependency are ineligible for FBT tracing.
	 */
	if (lf->fbt_nentries) {
		/*
		 * This module has some FBT entries allocated; we're afraid
		 * to screw with it.
		 */
		return;
	}

	/*
	 * List the functions in the module and the symbol values.
	 */
	
	(void) fbt_create_probe_mod(lf, modname);
}

int
fbt_provide_module_function(modctl_t *lf, int symindx,
    linker_symval_t *symval, void *opaque)
{
	char *modname = opaque;
	char *name = symval->name;
	fbt_probe_t *fbt, *retfbt;
	int j, size;
	u_int8_t *instr, *limit;

	if (strncmp(name, "dtrace_", 7) == 0 &&
	    strncmp(name, "dtrace_safe_", 12) != 0) {
		/*
		 * Anything beginning with "dtrace_" may be called
		 * from probe context unless it explicitly indicates
		 * that it won't be called from probe context by
		 * using the prefix "dtrace_safe_".
		 */
		return (0);
	}

	if (name[0] == '_' && name[1] == '_')
		return (0);
		
#if defined(windows)
	if (fbt_win32_noprobe_list(name))
		return 0;
#endif	

	size = symval->size;

	instr = (u_int8_t *) symval->value;
	limit = (u_int8_t *) symval->value + symval->size;
#ifdef _AMD64_
	while (instr < limit) {
		if (instr[0] == FBT_REX_W && (instr[1] == FBT_8_OP || instr[1] == FBT_32_OP) && instr[2] == FBT_SUB_RSP_OP)
			break;
		if ((size = dtrace_instr_size(instr)) <= 0)
			break;

		instr += size;
	}

	if (instr >= limit || *instr != FBT_REX_W) {
		/*
		 * We either don't save the frame pointer in this
		 * function, or we ran into some disassembly
		 * screw-up.  Either way, we bail.
		 */
		return (0);
	}
#else
	if ( !(instr[0] == FBT_MOV_EDI_EDI0_V0 && instr[1] == FBT_MOV_EDI_EDI1_V0 && instr[2] == FBT_PUSHL_EBP) && 
	    instr[0] != FBT_PUSHL_EBP)
		return (0);

	if (instr[0] == FBT_PUSHL_EBP &&
	    !(instr[1] == FBT_MOVL_ESP_EBP0_V0 &&
	    instr[2] == FBT_MOVL_ESP_EBP1_V0) &&
	    !(instr[1] == FBT_MOVL_ESP_EBP0_V1 &&
	    instr[2] == FBT_MOVL_ESP_EBP1_V1))   
		return (0);
		
	if (instr[2] == FBT_PUSHL_EBP &&
	    !(instr[3] == FBT_MOVL_ESP_EBP0_V0 &&
	    instr[4] == FBT_MOVL_ESP_EBP1_V0) &&
	    !(instr[3] == FBT_MOVL_ESP_EBP0_V1 &&
	    instr[4] == FBT_MOVL_ESP_EBP1_V1)) 	
		return (0);
#endif

	fbt = kmem_zalloc(sizeof (fbt_probe_t), KM_SLEEP);
	fbt->fbtp_name = name;
	fbt->fbtp_id = dtrace_probe_create(fbt_id, modname,
#if defined(sun)
	    name, FBT_ENTRY, 3, fbt);
#else
#if _AMD64_
	    name, FBT_ENTRY, 6, fbt);
#else
	    name, FBT_ENTRY, 1, fbt);
#endif	    
#endif	
	fbt->fbtp_patchpoint = instr;
	fbt->fbtp_ctl = lf;
	fbt->fbtp_loadcnt = lf->loadcnt;
#ifdef _AMD64_
	if (instr[1] == FBT_8_OP) 
		fbt->fbtp_rval = DTRACE_INVOP_SUB_RSP_8;
	else
		fbt->fbtp_rval = DTRACE_INVOP_SUB_RSP_32;
#else
	if (instr[0] == FBT_PUSHL_EBP)
		fbt->fbtp_rval = DTRACE_INVOP_PUSHL_EBP;
	else
		fbt->fbtp_rval = DTRACE_INVOP_MOV_EDI_EDI0_V0;
#endif	
	fbt->fbtp_savedval = *instr;
	fbt->fbtp_patchval = FBT_PATCHVAL;
	fbt->fbtp_symindx = symindx;

	fbt->fbtp_hashnext = fbt_probetab[FBT_ADDR2NDX(instr)];
	fbt_probetab[FBT_ADDR2NDX(instr)] = fbt;

	lf->fbt_nentries++;

	retfbt = NULL;
again:
	if (instr >= limit)
		return (0);

	/*
	 * If this disassembly fails, then we've likely walked off into
	 * a jump table or some other unsuitable area.  Bail out of the
	 * disassembly now.
	 */
	if ((size = dtrace_instr_size(instr)) <= 0)
		return (0);
		
	/* WINDOWS x86 TODO - size of symbols got by reading the export table is not correct.
	 * It is the distance between consecutive export functions.
	 * should check for start of next function, because it is possible that the function
	 * being traced doesnt return with a ret, and we could end up setting a return trace point 
	 * in a different function.
	 */
#ifdef _AMD64_
#if !defined(windows)
	/*
	 * We only instrument "ret" on amd64 -- we don't yet instrument
	 * ret imm16, largely because the compiler doesn't seem to
	 * (yet) emit them in the kernel...
	 */
	if (*instr != FBT_RET) {
		instr += size;
		goto again;
	}
#else
	if (!(size > 3 && instr[0] == FBT_REX_W && (instr[1] == FBT_8_OP || instr[1] == FBT_32_OP) && instr[2] == FBT_ADD_RSP_OP)) {
		instr += size;
		goto again;
	}
	/*TODO: should check whether this <add rsp, 0xnn> belongs in a epilogue */
#endif
#else
	if (!(size == 1 &&
	    (*instr == FBT_POPL_EBP || *instr == FBT_LEAVE) &&
	    (*(instr + 1) == FBT_RET ||
	    *(instr + 1) == FBT_RET_IMM16))) {
		instr += size;
		goto again;
	}
#endif

	/*
	 * We (desperately) want to avoid erroneously instrumenting a
	 * jump table, especially given that our markers are pretty
	 * short:  two bytes on x86, and just one byte on amd64.  To
	 * determine if we're looking at a true instruction sequence
	 * or an inline jump table that happens to contain the same
	 * byte sequences, we resort to some heuristic sleeze:  we
	 * treat this instruction as being contained within a pointer,
	 * and see if that pointer points to within the body of the
	 * function.  If it does, we refuse to instrument it.
	 */
	for (j = 0; j < sizeof (uintptr_t); j++) {
		caddr_t check = (caddr_t) instr - j;
		uint8_t *ptr;

		if (check < (caddr_t) symval->value)
			break;

		if (check + sizeof (caddr_t) > (caddr_t)limit)
			continue;

		ptr = *(uint8_t **)check;

		if (ptr >= (uint8_t *) symval->value && ptr < limit) {
			instr += size;
			goto again;
		}
	}

	/*
	 * We have a winner!
	 */
	fbt = kmem_zalloc(sizeof (fbt_probe_t), KM_SLEEP);
	fbt->fbtp_name = name;

	if (retfbt == NULL) {
		fbt->fbtp_id = dtrace_probe_create(fbt_id, modname,
#if defined(sun)
		    name, FBT_RETURN, 3, fbt);
#else
#if _AMD64_
	    name, FBT_RETURN, 6, fbt);
#else
	    name, FBT_RETURN, 1, fbt);
#endif
#endif
	} else {
		retfbt->fbtp_next = fbt;
		fbt->fbtp_id = retfbt->fbtp_id;
	}

	retfbt = fbt;
	fbt->fbtp_patchpoint = instr;
	fbt->fbtp_ctl = lf;
	fbt->fbtp_loadcnt = lf->loadcnt;
	fbt->fbtp_symindx = symindx;

#ifndef _AMD64_
	if (*instr == FBT_POPL_EBP) {
		fbt->fbtp_rval = DTRACE_INVOP_POPL_EBP;
	} else {
		ASSERT(*instr == FBT_LEAVE);
		fbt->fbtp_rval = DTRACE_INVOP_LEAVE;
	}
	fbt->fbtp_roffset =
	    (uintptr_t)(instr - (uint8_t *) symval->value) + 1;

#else
#if defined(windows)
	if (instr[1] == FBT_8_OP) 
		fbt->fbtp_rval = DTRACE_INVOP_ADD_RSP_8;
	else
		fbt->fbtp_rval = DTRACE_INVOP_ADD_RSP_32;
	fbt->fbtp_roffset =
	    (uintptr_t)(instr - (uint8_t *) symval->value)+3;
#else
	ASSERT(*instr == FBT_RET);
	fbt->fbtp_rval = DTRACE_INVOP_RET;
	fbt->fbtp_roffset =
	    (uintptr_t)(instr - (uint8_t *) symval->value);
#endif
#endif

	fbt->fbtp_savedval = *instr;
	fbt->fbtp_patchval = FBT_PATCHVAL;
	fbt->fbtp_hashnext = fbt_probetab[FBT_ADDR2NDX(instr)];
	fbt_probetab[FBT_ADDR2NDX(instr)] = fbt;

	lf->fbt_nentries++;

	instr += size;
	
	/* WINDOWS x86 - size of symbols got by reading the export table is not correct.
	 * It is the distance between consecutive export functions. So for now we
	 * bail when we hit the first return.
	 */
#ifdef _AMD64_	
	goto again;
#endif
	return 0;
}

/*ARGSUSED*/
static void
fbt_destroy(void *arg, dtrace_id_t id, void *parg)
{
	fbt_probe_t *fbt = parg, *next, *hash, *last;
	modctl_t *ctl;
	int ndx;

	do {
		ctl = fbt->fbtp_ctl;

		ctl->fbt_nentries--;

		/*
		 * Now we need to remove this probe from the fbt_probetab.
		 */
		ndx = FBT_ADDR2NDX(fbt->fbtp_patchpoint);
		last = NULL;
		hash = fbt_probetab[ndx];

		while (hash != fbt) {
			ASSERT(hash != NULL);
			last = hash;
			hash = hash->fbtp_hashnext;
		}

		if (last != NULL) {
			last->fbtp_hashnext = fbt->fbtp_hashnext;
		} else {
			fbt_probetab[ndx] = fbt->fbtp_hashnext;
		}

		next = fbt->fbtp_next;
		kmem_free(fbt, sizeof (fbt_probe_t));
		fbt = next;
	} while (fbt != NULL);
}


static int
fbt_enable(void *arg, dtrace_id_t id, void *parg)
{
	fbt_probe_t *fbt = parg;
	modctl_t *ctl = fbt->fbtp_ctl;

	/*
	 * Now check that our modctl has the expected load count.  If it
	 * doesn't, this module must have been unloaded and reloaded -- and
	 * we're not going to touch it.
	 */
	if (ctl->loadcnt != fbt->fbtp_loadcnt) {
		if (fbt_verbose) {
			DbgPrint("fbt is failing for probe %s "
			    "(module %s reloaded)",
			    fbt->fbtp_name, ctl->mod_modname);
		}

		return 0;
	}
#if defined(windows)
	/* module may have been unloaded */
	if (MmIsAddressValid((PVOID) ctl->imgbase) == 0) {
		DbgPrint("fbt_enable : module %s may have been unloaded\n", ctl->mod_modname);
		return -1;
	}
#endif
	for (; fbt != NULL; fbt = fbt->fbtp_next)
		fbt_mdl_copy(fbt->fbtp_patchpoint, &fbt->fbtp_patchval, sizeof(fbt->fbtp_patchval));
	
	ctl->nenabled++;
	return 0;
}

static void
fbt_disable(void *arg, dtrace_id_t id, void *parg)
{
	fbt_probe_t *fbt = parg;
	modctl_t *ctl = fbt->fbtp_ctl;

	ASSERT(ctl->nenabled > 0);
	ctl->nenabled--;

	if ((ctl->loadcnt != fbt->fbtp_loadcnt))
		return;
#if defined(windows)
	/* module may have been unloaded, while being probed */
	if (MmIsAddressValid((PVOID) ctl->imgbase) == 0) {
		DbgPrint("fbt_disable : module %s had enabled probes, unloaded\n", ctl->mod_modname);
		return;
	}
#endif
	for (; fbt != NULL; fbt = fbt->fbtp_next)
		fbt_mdl_copy(fbt->fbtp_patchpoint, &fbt->fbtp_savedval, sizeof(fbt->fbtp_savedval));
}

static void
fbt_suspend(void *arg, dtrace_id_t id, void *parg)
{
	fbt_probe_t *fbt = parg;
	modctl_t *ctl = fbt->fbtp_ctl;

	ASSERT(ctl->nenabled > 0);

	if ((ctl->loadcnt != fbt->fbtp_loadcnt))
		return;

	for (; fbt != NULL; fbt = fbt->fbtp_next)
		*fbt->fbtp_patchpoint = fbt->fbtp_savedval;
}

static void
fbt_resume(void *arg, dtrace_id_t id, void *parg)
{
	fbt_probe_t *fbt = parg;
	modctl_t *ctl = fbt->fbtp_ctl;

	ASSERT(ctl->nenabled > 0);

	if ((ctl->loadcnt != fbt->fbtp_loadcnt))
		return;

	for (; fbt != NULL; fbt = fbt->fbtp_next)
		*fbt->fbtp_patchpoint = fbt->fbtp_patchval;
}

#if defined(sun)
/*ARGSUSED*/
static void
fbt_getargdesc(void *arg, dtrace_id_t id, void *parg, dtrace_argdesc_t *desc)
{
	fbt_probe_t *fbt = parg;
	struct modctl *ctl = fbt->fbtp_ctl;
	struct module *mp = ctl->mod_mp;
	ctf_file_t *fp = NULL, *pfp;
	ctf_funcinfo_t f;
	int error;
	ctf_id_t argv[32], type;
	int argc = sizeof (argv) / sizeof (ctf_id_t);
	const char *parent;

	if (!ctl->mod_loaded || (ctl->mod_loadcnt != fbt->fbtp_loadcnt))
		goto err;

	if (fbt->fbtp_roffset != 0 && desc->dtargd_ndx == 0) {
		(void) strcpy(desc->dtargd_native, "int");
		return;
	}

	if ((fp = ctf_modopen(mp, &error)) == NULL) {
		/*
		 * We have no CTF information for this module -- and therefore
		 * no args[] information.
		 */
		goto err;
	}

	/*
	 * If we have a parent container, we must manually import it.
	 */
	if ((parent = ctf_parent_name(fp)) != NULL) {
		struct modctl *mp = &modules;
		struct modctl *mod = NULL;

		/*
		 * We must iterate over all modules to find the module that
		 * is our parent.
		 */
		do {
			if (strcmp(mp->mod_modname, parent) == 0) {
				mod = mp;
				break;
			}
		} while ((mp = mp->mod_next) != &modules);

		if (mod == NULL)
			goto err;

		if ((pfp = ctf_modopen(mod->mod_mp, &error)) == NULL) {
			goto err;
		}

		if (ctf_import(fp, pfp) != 0) {
			ctf_close(pfp);
			goto err;
		}

		ctf_close(pfp);
	}

	if (ctf_func_info(fp, fbt->fbtp_symndx, &f) == CTF_ERR)
		goto err;

	if (fbt->fbtp_roffset != 0) {
		if (desc->dtargd_ndx > 1)
			goto err;

		ASSERT(desc->dtargd_ndx == 1);
		type = f.ctc_return;
	} else {
		if (desc->dtargd_ndx + 1 > f.ctc_argc)
			goto err;

		if (ctf_func_args(fp, fbt->fbtp_symndx, argc, argv) == CTF_ERR)
			goto err;

		type = argv[desc->dtargd_ndx];
	}

	if (ctf_type_name(fp, type, desc->dtargd_native,
	    DTRACE_ARGTYPELEN) != NULL) {
		ctf_close(fp);
		return;
	}
err:
	if (fp != NULL)
		ctf_close(fp);

	desc->dtargd_ndx = DTRACE_ARGNONE;
}
#endif

static dtrace_pattr_t fbt_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
};

static dtrace_pops_t fbt_pops = {
	NULL,
	fbt_provide_module,
	fbt_enable,
	fbt_disable,
	fbt_suspend,
	fbt_resume,
	NULL,
	NULL,
	NULL,
	fbt_destroy
};

static void
fbt_cleanup(void *dummy)
{
	dtrace_invop_remove(fbt_invop);
	kmem_free(fbt_probetab, fbt_probetab_size * sizeof (fbt_probe_t *));
	fbt_probetab = NULL;
	fbt_probetab_mask = 0;
}

int
fbt_load(void *dummy)
{
	
	/* Default the probe table size if not specified. */
	if (fbt_probetab_size == 0)
		fbt_probetab_size = FBT_PROBETAB_SIZE;

	/* Choose the hash mask for the probe table. */
	fbt_probetab_mask = fbt_probetab_size - 1;

	/* Allocate memory for the probe table. */
	fbt_probetab =
		kmem_zalloc(fbt_probetab_size * sizeof (fbt_probe_t *), KM_SLEEP);
		
	dtrace_invop_add(fbt_invop);

	if (dtrace_register("fbt", &fbt_attr, DTRACE_PRIV_USER,
	    NULL, &fbt_pops, NULL, &fbt_id) != 0) {
	    	fbt_cleanup(NULL);
		return -1;
	}
	return 0;
}

int
fbt_unload()
{
	int error = 0;

	/* De-register this DTrace provider. */
	if ((error = dtrace_unregister(fbt_id)) != 0)
		return (error);
	
	/* De-register the invalid opcode handler. */
	dtrace_invop_remove(fbt_invop);
	/* Free the probe table. */
	kmem_free(fbt_probetab, fbt_probetab_size * sizeof (fbt_probe_t *));
	fbt_probetab = NULL;
	fbt_probetab_mask = 0;

	return (error);
}

void fbt_open()
{
	
}

void fbt_close()
{
	
}