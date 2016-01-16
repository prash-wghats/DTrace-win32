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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <dtrace_misc.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <dt_impl.h>
#include <dt_provider.h>
#include <dt_program.h>
#include <dt_string.h>
#include <libpe.h>

#define	ESHDR_NULL	0
#define	ESHDR_DOF	1
#define	ESHDR_NUM	1

#define WIN_STR_OFFSET 4
static const char DOFSECTIONNAME[] = ".SUNW_dof";

#define	PWRITE_SCN(data, size, offset) \
	(dt_write(dtp, fd, (data), (size)) != (size))
		
static const char DTRACE_SHSTRTAB32[] = "\0"
".shstrtab\0"		/* 1 */
".SUNW_dof\0"		/* 11 */
".strtab\0"		/* 21 */
".symtab\0"		/* 29 */
#ifdef __sparc
".rela.SUNW_dof";	/* 37 */
#else
".rel.SUNW_dof";	/* 37 */
#endif

static const char DTRACE_SHSTRTAB64[] = "\0"
".shstrtab\0"		/* 1 */
".SUNW_dof\0"		/* 11 */
".strtab\0"		/* 21 */
".symtab\0"		/* 29 */
".rela.SUNW_dof";	/* 37 */

static const char DOFSTR[] = "__SUNW_dof";
static const char DOFLAZYSTR[] = "___SUNW_dof";

typedef struct dt_link_pair {
	struct dt_link_pair *dlp_next;	/* next pair in linked list */
	void *dlp_str;			/* buffer for string table */
	void *dlp_sym;			/* buffer for symbol table */
} dt_link_pair_t;



typedef struct dof_elf32 {
	uint32_t de_nrel;		/* relocation count */
	IMAGE_RELOCATION *de_rel;		/* array of relocations for x86 */
	uint32_t de_nsym;		/* symbol count */
	IMAGE_SYMBOL *de_sym;		/* array of symbols */
	uint32_t de_strlen;		/* size of of string table */
	char *de_strtab;		/* string table */
	uint32_t de_global;		/* index of the first global symbol */
} dof_elf32_t;

static int
prepare_elf32(dtrace_hdl_t *dtp, const dof_hdr_t *dof, dof_elf32_t *dep)
{
	dof_sec_t *dofs, *s;
	dof_relohdr_t *dofrh;
	dof_relodesc_t *dofr;
	char *strtab;
	int i, j, nrel;
	size_t strtabsz = 1;
	uint32_t count = 0;
	size_t base;
	IMAGE_SYMBOL *sym;
	IMAGE_RELOCATION *rel;

	/*LINTED*/
	dofs = (dof_sec_t *)((char *)dof + dof->dofh_secoff);

	/*
	 * First compute the size of the string table and the number of
	 * relocations present in the DOF.
	 */
	for (i = 0; i < dof->dofh_secnum; i++) {
		if (dofs[i].dofs_type != DOF_SECT_URELHDR)
			continue;

		/*LINTED*/
		dofrh = (dof_relohdr_t *)((char *)dof + dofs[i].dofs_offset);

		s = &dofs[dofrh->dofr_strtab];
		strtab = (char *)dof + s->dofs_offset;
		assert(strtab[0] == '\0');
		strtabsz += s->dofs_size - 1;

		s = &dofs[dofrh->dofr_relsec];
		/*LINTED*/
		dofr = (dof_relodesc_t *)((char *)dof + s->dofs_offset);
		count += s->dofs_size / s->dofs_entsize;
	}

	
	dep->de_nrel = count;
	dep->de_nsym = count;
	
	/* In windows i386 there is an extra '_' in front of the symbols */ 
	dep->de_strlen = strtabsz + count + 1; //__SUNW_dof 
	
	if (dtp->dt_lazyload) {
		dep->de_strlen += sizeof (DOFLAZYSTR);
		dep->de_nsym++;
	} else {
		dep->de_strlen += sizeof (DOFSTR);
		dep->de_nsym++;
	}
	
	if ((dep->de_rel = calloc(dep->de_nrel,
	    sizeof (dep->de_rel[0]))) == NULL) {
		return (dt_set_errno(dtp, EDT_NOMEM));
	}

	if ((dep->de_sym = calloc(dep->de_nsym, sizeof (IMAGE_SYMBOL))) == NULL) {
		free(dep->de_rel);
		return (dt_set_errno(dtp, EDT_NOMEM));
	}

	if ((dep->de_strtab = calloc(dep->de_strlen, 1)) == NULL) {
		free(dep->de_rel);
		free(dep->de_sym);
		return (dt_set_errno(dtp, EDT_NOMEM));
	}

	count = 0;
	strtabsz = 1;
	dep->de_strtab[0] = '\0';
	rel = dep->de_rel;
	sym = dep->de_sym;
	dep->de_global = 0;


	/*
	 * Take a second pass through the DOF sections filling in the
	 * memory we allocated.
	 */
	for (i = 0; i < dof->dofh_secnum; i++) {
		if (dofs[i].dofs_type != DOF_SECT_URELHDR)
			continue;

		/*LINTED*/
		dofrh = (dof_relohdr_t *)((char *)dof + dofs[i].dofs_offset);

		s = &dofs[dofrh->dofr_strtab];
		strtab = (char *)dof + s->dofs_offset;
		bcopy(strtab + 1, dep->de_strtab + strtabsz, s->dofs_size);
		
		base = strtabsz;
		strtabsz += s->dofs_size - 1;
		
		s = &dofs[dofrh->dofr_relsec];
		/*LINTED*/
		dofr = (dof_relodesc_t *)((char *)dof + s->dofs_offset);
		nrel = s->dofs_size / s->dofs_entsize;

		s = &dofs[dofrh->dofr_tgtsec];

		for (j = 0; j < nrel; j++) {

			rel->VirtualAddress = s->dofs_offset +
			    dofr[j].dofr_offset;
			rel->SymbolTableIndex = count + dep->de_global;
			rel->Type = IMAGE_REL_I386_DIR32;

			sym->N.Name.Long = base + dofr[j].dofr_name - 1;
			sym->Value = 0;
			sym->Type = IMAGE_SYM_DTYPE_FUNCTION << N_BTSHFT;//ELF32_ST_INFO(STB_GLOBAL, STT_FUNC);
			sym->StorageClass = IMAGE_SYM_CLASS_EXTERNAL;
			sym->SectionNumber = 0;//SHN_UNDEF;

			rel++;
			sym++;
			count++;
		}
	}

	/*
	 * Add a symbol for the DOF itself. We use a different symbol for
	 * lazily and actively loaded DOF to make them easy to distinguish.
	 */
	sym->N.Name.Long = strtabsz;
	sym->Value = 0;
	sym->Type = 0;//ELF32_ST_INFO(STB_GLOBAL, STT_OBJECT);
	sym->StorageClass = IMAGE_SYM_CLASS_EXTERNAL;
	sym->SectionNumber = ESHDR_DOF;
	sym++;

	if (dtp->dt_lazyload) {
		bcopy(DOFLAZYSTR, dep->de_strtab + strtabsz,
		    sizeof (DOFLAZYSTR));
		strtabsz += sizeof (DOFLAZYSTR);
	} else {
		bcopy(DOFSTR, dep->de_strtab + strtabsz, sizeof (DOFSTR));
		strtabsz += sizeof (DOFSTR);
	}

	assert(count == dep->de_nrel);
	assert(strtabsz == (dep->de_strlen - dep->de_nrel - 1));

	return (0);
}

typedef struct dof_elf64 {
	uint32_t de_nrel;		/* relocation count */
	IMAGE_RELOCATION *de_rel;		/* array of relocations for x86 */
	uint32_t de_nsym;		/* symbol count */
	IMAGE_SYMBOL *de_sym;		/* array of symbols */
	uint32_t de_strlen;		/* size of of string table */
	char *de_strtab;		/* string table */
	uint32_t de_global;		/* index of the first global symbol */
} dof_elf64_t;

static int
prepare_elf64(dtrace_hdl_t *dtp, const dof_hdr_t *dof, dof_elf64_t *dep)
{
	dof_sec_t *dofs, *s;
	dof_relohdr_t *dofrh;
	dof_relodesc_t *dofr;
	char *strtab;
	int i, j, nrel;
	size_t strtabsz = 1;
	uint32_t count = 0;
	size_t base;
	IMAGE_SYMBOL *sym;
	IMAGE_RELOCATION *rel;

	/*LINTED*/
	dofs = (dof_sec_t *)((char *)dof + dof->dofh_secoff);

	/*
	 * First compute the size of the string table and the number of
	 * relocations present in the DOF.
	 */
	for (i = 0; i < dof->dofh_secnum; i++) {
		if (dofs[i].dofs_type != DOF_SECT_URELHDR)
			continue;

		/*LINTED*/
		dofrh = (dof_relohdr_t *)((char *)dof + dofs[i].dofs_offset);

		s = &dofs[dofrh->dofr_strtab];
		strtab = (char *)dof + s->dofs_offset;
		assert(strtab[0] == '\0');
		strtabsz += s->dofs_size - 1;

		s = &dofs[dofrh->dofr_relsec];
		/*LINTED*/
		dofr = (dof_relodesc_t *)((char *)dof + s->dofs_offset);
		count += s->dofs_size / s->dofs_entsize;
	}

	
	dep->de_nrel = count;
	dep->de_nsym = count;
	
	dep->de_strlen = strtabsz; 
	
	if (dtp->dt_lazyload) {
		dep->de_strlen += sizeof (DOFLAZYSTR);
		dep->de_nsym++;
	} else {
		dep->de_strlen += sizeof (DOFSTR);
		dep->de_nsym++;
	}
	
	if ((dep->de_rel = calloc(dep->de_nrel,
	    sizeof (dep->de_rel[0]))) == NULL) {
		return (dt_set_errno(dtp, EDT_NOMEM));
	}

	if ((dep->de_sym = calloc(dep->de_nsym, sizeof (IMAGE_SYMBOL))) == NULL) {
		free(dep->de_rel);
		return (dt_set_errno(dtp, EDT_NOMEM));
	}

	if ((dep->de_strtab = calloc(dep->de_strlen, 1)) == NULL) {
		free(dep->de_rel);
		free(dep->de_sym);
		return (dt_set_errno(dtp, EDT_NOMEM));
	}

	count = 0;
	strtabsz = 1;
	dep->de_strtab[0] = '\0';
	rel = dep->de_rel;
	sym = dep->de_sym;
	dep->de_global = 0;

	/*
	 * Take a second pass through the DOF sections filling in the
	 * memory we allocated.
	 */
	for (i = 0; i < dof->dofh_secnum; i++) {
		if (dofs[i].dofs_type != DOF_SECT_URELHDR)
			continue;

		/*LINTED*/
		dofrh = (dof_relohdr_t *)((char *)dof + dofs[i].dofs_offset);

		s = &dofs[dofrh->dofr_strtab];
		strtab = (char *)dof + s->dofs_offset;
		bcopy(strtab + 1, dep->de_strtab + strtabsz, s->dofs_size);
		base = strtabsz;
		strtabsz += s->dofs_size - 1;

		s = &dofs[dofrh->dofr_relsec];
		/*LINTED*/
		dofr = (dof_relodesc_t *)((char *)dof + s->dofs_offset);
		nrel = s->dofs_size / s->dofs_entsize;

		s = &dofs[dofrh->dofr_tgtsec];

		for (j = 0; j < nrel; j++) {

			rel->VirtualAddress = s->dofs_offset +
			    dofr[j].dofr_offset;
			rel->SymbolTableIndex = count + dep->de_global;
			rel->Type = IMAGE_REL_AMD64_ADDR64;

			sym->N.Name.Long = base + dofr[j].dofr_name - 1;
			sym->Value = 0;
			sym->Type = IMAGE_SYM_DTYPE_FUNCTION << N_BTSHFT;//ELF32_ST_INFO(STB_GLOBAL, STT_FUNC);
			sym->StorageClass = IMAGE_SYM_CLASS_EXTERNAL;
			sym->SectionNumber = 0;//SHN_UNDEF;

			rel++;
			sym++;
			count++;
		}
	}

	/*
	 * Add a symbol for the DOF itself. We use a different symbol for
	 * lazily and actively loaded DOF to make them easy to distinguish.
	 */
	sym->N.Name.Long = strtabsz;
	sym->Value = 0;
	sym->Type = 0;//ELF32_ST_INFO(STB_GLOBAL, STT_OBJECT);
	sym->StorageClass = IMAGE_SYM_CLASS_EXTERNAL;
	sym->SectionNumber = ESHDR_DOF;
	sym++;

	if (dtp->dt_lazyload) {
		bcopy(DOFLAZYSTR, dep->de_strtab + strtabsz,
		    sizeof (DOFLAZYSTR));
		strtabsz += sizeof (DOFLAZYSTR);
	} else {
		bcopy(DOFSTR, dep->de_strtab + strtabsz, sizeof (DOFSTR));
		strtabsz += sizeof (DOFSTR);
	}

	assert(count == dep->de_nrel);
	assert(strtabsz == dep->de_strlen);

	return (0);
}

/*
 * Write out an ELF32 file prologue consisting of a header, section headers,
 * and a section header string table.  The DOF data will follow this prologue
 * and complete the contents of the given ELF file.
 */
static int
dump_elf32(dtrace_hdl_t *dtp, const dof_hdr_t *dof, int fd)
{
	struct {
		IMAGE_FILE_HEADER ehdr;
		IMAGE_SECTION_HEADER shdr;
	} pe_file;
	int j, k, found ;
	IMAGE_SECTION_HEADER *shp;
	dof_elf32_t de;
	int ret = 0, str_size, off, len, i, sz;
	char s[8] = {0};
	uint_t nshdr;
	
	if (prepare_elf32(dtp, dof, &de) != 0)
		return (-1); /* errno is set for us */
		
	/* i386 - Add a leading underscore to all symbols processed by dtrace */
	for (i = 0; i < de.de_nsym; i++) {
		off = de.de_sym[i].N.Name.Long;
		sz = de.de_strlen - off - 1;
		memmove(&de.de_strtab[off+1], &de.de_strtab[off], sz);
		de.de_strtab[off] = '_';
		for (k = i+1 ; k < de.de_nsym; k++) {
			de.de_sym[k].N.Name.Long++;
		}
		len = strlen(&de.de_strtab[off]);
		if (len < 9) {
			strncpy(de.de_sym[i].N.ShortName, &de.de_strtab[off], len);
		} else de.de_sym[i].N.Name.Long += WIN_STR_OFFSET;
	}
		
	/*
	 * If there are no relocations, we only need enough sections for
	 * the shstrtab and the DOF.
	 */

	bzero(&pe_file, sizeof (pe_file));	
	pe_file.ehdr.Machine = IMAGE_FILE_MACHINE_I386;
	pe_file.ehdr.NumberOfSections = 1;
	pe_file.ehdr.TimeDateStamp = 0;
	pe_file.ehdr.PointerToSymbolTable = sizeof(IMAGE_FILE_HEADER) + 
	    sizeof(IMAGE_SECTION_HEADER) + dof->dofh_filesz + (sizeof(IMAGE_RELOCATION) * de.de_nrel);
	pe_file.ehdr.NumberOfSymbols = de.de_nsym;
	pe_file.ehdr.SizeOfOptionalHeader = 0;
	pe_file.ehdr.Characteristics = IMAGE_FILE_LINE_NUMS_STRIPPED | IMAGE_FILE_32BIT_MACHINE;
	
	
	itoa(de.de_strlen+WIN_STR_OFFSET, s, 10);
	shp = &pe_file.shdr;
	bzero(shp, sizeof (IMAGE_SECTION_HEADER));
	
	shp->Name[0] = '/';
	strcpy(&shp->Name[1], s);
	shp->Misc.VirtualSize = 0;
	shp->VirtualAddress = 0;
	shp->SizeOfRawData = dof->dofh_filesz;
	shp->PointerToRawData = sizeof(IMAGE_FILE_HEADER)+sizeof(IMAGE_SECTION_HEADER);
	shp->PointerToRelocations = de.de_nrel ? sizeof(IMAGE_FILE_HEADER)+sizeof(IMAGE_SECTION_HEADER)+ dof->dofh_filesz : 0;
	shp->PointerToLinenumbers = 0;
	shp->NumberOfRelocations = de.de_nrel;
	shp->NumberOfLinenumbers = 0;
	shp->Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_ALIGN_8BYTES | IMAGE_SCN_MEM_READ;
	
	str_size = de.de_strlen + sizeof(DOFSECTIONNAME)+WIN_STR_OFFSET;
	if (de.de_nrel == 0) {
		if (dt_write(dtp, fd, &pe_file, sizeof (pe_file)) != sizeof (pe_file) ||
			PWRITE_SCN(dof, dof->dofh_filesz, shp->PointerToRawData) ||
			PWRITE_SCN(de.de_sym, de.de_nsym*sizeof(IMAGE_SYMBOL), pe_file.ehdr.PointerToSymbolTable) ||
			PWRITE_SCN(&str_size, sizeof(int), 0) ||
			PWRITE_SCN(de.de_strtab, de.de_strlen, 0) ||
			PWRITE_SCN(DOFSECTIONNAME, sizeof(DOFSECTIONNAME), 0)) {
			ret = dt_set_errno(dtp, errno);
		}
	} else {
		if (dt_write(dtp, fd, &pe_file, sizeof (pe_file)) != sizeof (pe_file) ||
			PWRITE_SCN(dof, dof->dofh_filesz, shp->PointerToRawData) ||
			PWRITE_SCN(de.de_rel, de.de_nrel*sizeof(IMAGE_RELOCATION), shp->PointerToRelocations) || 
			PWRITE_SCN(de.de_sym, de.de_nsym*sizeof(IMAGE_SYMBOL), pe_file.ehdr.PointerToSymbolTable) ||
			PWRITE_SCN(&str_size, sizeof(int), 0) ||
			PWRITE_SCN(de.de_strtab, de.de_strlen, 0) ||
			PWRITE_SCN(DOFSECTIONNAME, sizeof(DOFSECTIONNAME), 0)) {
			ret = dt_set_errno(dtp, errno);
		}
	}
	
	free(de.de_strtab);
	free(de.de_sym);
	free(de.de_rel);

	return (ret);
}


/*
 * Write out an ELF64 file prologue consisting of a header, section headers,
 * and a section header string table.  The DOF data will follow this prologue
 * and complete the contents of the given ELF file.
 */
static int
dump_elf64(dtrace_hdl_t *dtp, const dof_hdr_t *dof, int fd)
{
	struct {
		IMAGE_FILE_HEADER ehdr;
		IMAGE_SECTION_HEADER shdr;
	} pe_file;
	
	int j, k, found ;
	IMAGE_SECTION_HEADER *shp;
	dof_elf64_t de;
	int ret = 0, str_size, off, len, i;
	char s[8] = {0};
	uint_t nshdr;
	
	if (prepare_elf64(dtp, dof, &de) != 0)
		return (-1); /* errno is set for us */
		
	for (i = 0; i < de.de_nsym; i++) {
		off = de.de_sym[i].N.Name.Long;
		len = strlen(&de.de_strtab[off]);
		if (len < 9) {
			strcpy(de.de_sym[i].N.ShortName, &de.de_strtab[off]); 
		} else de.de_sym[i].N.Name.Long += WIN_STR_OFFSET;
	}
		
	/*
	 * If there are no relocations, we only need enough sections for
	 * the shstrtab and the DOF.
	 */
	bzero(&pe_file, sizeof (pe_file));	
	pe_file.ehdr.Machine = IMAGE_FILE_MACHINE_AMD64;
	pe_file.ehdr.NumberOfSections = 1;
	pe_file.ehdr.TimeDateStamp = 0;
	pe_file.ehdr.PointerToSymbolTable = sizeof(IMAGE_FILE_HEADER) + 
	    sizeof(IMAGE_SECTION_HEADER) + dof->dofh_filesz + (sizeof(IMAGE_RELOCATION) * de.de_nrel);
	pe_file.ehdr.NumberOfSymbols = de.de_nsym;
	pe_file.ehdr.SizeOfOptionalHeader = 0;
	pe_file.ehdr.Characteristics = IMAGE_FILE_LINE_NUMS_STRIPPED;
	
	
	itoa(de.de_strlen + WIN_STR_OFFSET, s, 10);
	shp = &pe_file.shdr;
	bzero(shp, sizeof (IMAGE_SECTION_HEADER));
	
	shp->Name[0] = '/';
	strcpy(&shp->Name[1], s);
	shp->Misc.VirtualSize = 0;
	shp->VirtualAddress = 0;
	shp->SizeOfRawData = dof->dofh_filesz;
	shp->PointerToRawData = sizeof(IMAGE_FILE_HEADER)+sizeof(IMAGE_SECTION_HEADER);
	shp->PointerToRelocations = de.de_nrel ? sizeof(IMAGE_FILE_HEADER)+sizeof(IMAGE_SECTION_HEADER)+ dof->dofh_filesz : 0;
	shp->PointerToLinenumbers = 0;
	shp->NumberOfRelocations = de.de_nrel;
	shp->NumberOfLinenumbers = 0;
	shp->Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_ALIGN_8BYTES | IMAGE_SCN_MEM_READ;
	
	str_size = de.de_strlen + sizeof(DOFSECTIONNAME)+WIN_STR_OFFSET;
	if (de.de_nrel == 0) {
		if (dt_write(dtp, fd, &pe_file, sizeof (pe_file)) != sizeof (pe_file) ||
			PWRITE_SCN(dof, dof->dofh_filesz, shp->PointerToRawData) ||
			PWRITE_SCN(de.de_sym, de.de_nsym*sizeof(IMAGE_SYMBOL), pe_file.ehdr.PointerToSymbolTable) ||
			PWRITE_SCN(&str_size, sizeof(int), 0) ||
			PWRITE_SCN(de.de_strtab, de.de_strlen, 0) ||
			PWRITE_SCN(DOFSECTIONNAME, sizeof(DOFSECTIONNAME), 0)) {
			ret = dt_set_errno(dtp, errno);
		}
	} else {
		if (dt_write(dtp, fd, &pe_file, sizeof (pe_file)) != sizeof (pe_file) ||
			PWRITE_SCN(dof, dof->dofh_filesz, shp->PointerToRawData) ||
			PWRITE_SCN(de.de_rel, de.de_nrel*sizeof(IMAGE_RELOCATION), shp->PointerToRelocations) || 
			PWRITE_SCN(de.de_sym, de.de_nsym*sizeof(IMAGE_SYMBOL), pe_file.ehdr.PointerToSymbolTable) ||
			PWRITE_SCN(&str_size, sizeof(int), 0) ||
			PWRITE_SCN(de.de_strtab, de.de_strlen, 0) ||
			PWRITE_SCN(DOFSECTIONNAME, sizeof(DOFSECTIONNAME), 0)) {
			ret = dt_set_errno(dtp, errno);
		}
	}
	
	free(de.de_strtab);
	free(de.de_sym);
	free(de.de_rel);

	return (ret);
}



static int
dt_symtab_lookup(Pe_table *data_sym, int nsym, DWORD addr, uint_t scnno,
    IMAGE_SYMBOL *sym)
{
	int i = 0, ret = -1, o = 0, m, l;
	DWORD symval, oldval = 0;
	IMAGE_SYMBOL s, *arr_sym = (IMAGE_SYMBOL *) data_sym->d_buf;
	
	for (i = 0; i < nsym; i++) {
		o = ((arr_sym[i].Type) & N_TMASK);
		m = (IMAGE_SYM_DTYPE_FUNCTION << N_BTSHFT);
		l = ISFCN(arr_sym[i].Type);
		if ( l && arr_sym[i].SectionNumber == scnno) {
			symval = arr_sym[i].Value;
			
			if (symval >= oldval && symval <= addr) {
				ret = 0;
				s = arr_sym[i];
				oldval = symval;
			}
		}
	}
	
	if (ret == 0)
		*sym = s;
	return (ret);
}

#if defined(__arm__)
/* XXX */
static int
dt_modtext(dtrace_hdl_t *dtp, char *p, int isenabled, GElf_Rela *rela,
    uint32_t *off)
{
printf("%s:%s(%d): DOODAD\n",__FUNCTION__,__FILE__,__LINE__);
	return (0);
}
#elif defined(__mips__)
/* XXX */
static int
dt_modtext(dtrace_hdl_t *dtp, char *p, int isenabled, GElf_Rela *rela,
    uint32_t *off)
{
printf("%s:%s(%d): DOODAD\n",__FUNCTION__,__FILE__,__LINE__);
	return (0);
}
#elif defined(__powerpc__)
/* The sentinel is 'xor r3,r3,r3'. */
#define DT_OP_XOR_R3	0x7c631a78

#define DT_OP_NOP		0x60000000
#define DT_OP_BLR		0x4e800020

/* This captures all forms of branching to address. */
#define DT_IS_BRANCH(inst)	((inst & 0xfc000000) == 0x48000000)
#define DT_IS_BL(inst)	(DT_IS_BRANCH(inst) && (inst & 0x01))

/* XXX */
static int
dt_modtext(dtrace_hdl_t *dtp, char *p, int isenabled, GElf_Rela *rela,
    uint32_t *off)
{
	uint32_t *ip;

	if ((rela->r_offset & (sizeof (uint32_t) - 1)) != 0)
		return (-1);

	/*LINTED*/
	ip = (uint32_t *)(p + rela->r_offset);

	/*
	 * We only know about some specific relocation types.
	 */
	if (GELF_R_TYPE(rela->r_info) != R_PPC_REL24 &&
	    GELF_R_TYPE(rela->r_info) != R_PPC_PLTREL24)
		return (-1);

	/*
	 * We may have already processed this object file in an earlier linker
	 * invocation. Check to see if the present instruction sequence matches
	 * the one we would install below.
	 */
	if (isenabled) {
		if (ip[0] == DT_OP_XOR_R3) {
			(*off) += sizeof (ip[0]);
			return (0);
		}
	} else {
		if (ip[0] == DT_OP_NOP) {
			(*off) += sizeof (ip[0]);
			return (0);
		}
	}

	/*
	 * We only expect branch to address instructions.
	 */
	if (!DT_IS_BRANCH(ip[0])) {
		dt_dprintf("found %x instead of a branch instruction at %llx\n",
		    ip[0], (u_longlong_t)rela->r_offset);
		return (-1);
	}

	if (isenabled) {
		/*
		 * It would necessarily indicate incorrect usage if an is-
		 * enabled probe were tail-called so flag that as an error.
		 * It's also potentially (very) tricky to handle gracefully,
		 * but could be done if this were a desired use scenario.
		 */
		if (!DT_IS_BL(ip[0])) {
			dt_dprintf("tail call to is-enabled probe at %llx\n",
			    (u_longlong_t)rela->r_offset);
			return (-1);
		}

		ip[0] = DT_OP_XOR_R3;
		(*off) += sizeof (ip[0]);
	} else {
		if (DT_IS_BL(ip[0]))
			ip[0] = DT_OP_NOP;
		else
			ip[0] = DT_OP_BLR;
	}

	return (0);
}

#elif defined(__sparc)

#define	DT_OP_RET		0x81c7e008
#define	DT_OP_NOP		0x01000000
#define	DT_OP_CALL		0x40000000
#define	DT_OP_CLR_O0		0x90102000

#define	DT_IS_MOV_O7(inst)	(((inst) & 0xffffe000) == 0x9e100000)
#define	DT_IS_RESTORE(inst)	(((inst) & 0xc1f80000) == 0x81e80000)
#define	DT_IS_RETL(inst)	(((inst) & 0xfff83fff) == 0x81c02008)

#define	DT_RS2(inst)		((inst) & 0x1f)
#define	DT_MAKE_RETL(reg)	(0x81c02008 | ((reg) << 14))

/*ARGSUSED*/
static int
dt_modtext(dtrace_hdl_t *dtp, char *p, int isenabled, GElf_Rela *rela,
    uint32_t *off)
{
	uint32_t *ip;

	if ((rela->r_offset & (sizeof (uint32_t) - 1)) != 0)
		return (-1);

	/*LINTED*/
	ip = (uint32_t *)(p + rela->r_offset);

	/*
	 * We only know about some specific relocation types.
	 */
	if (GELF_R_TYPE(rela->r_info) != R_SPARC_WDISP30 &&
	    GELF_R_TYPE(rela->r_info) != R_SPARC_WPLT30)
		return (-1);

	/*
	 * We may have already processed this object file in an earlier linker
	 * invocation. Check to see if the present instruction sequence matches
	 * the one we would install below.
	 */
	if (isenabled) {
		if (ip[0] == DT_OP_NOP) {
			(*off) += sizeof (ip[0]);
			return (0);
		}
	} else {
		if (DT_IS_RESTORE(ip[1])) {
			if (ip[0] == DT_OP_RET) {
				(*off) += sizeof (ip[0]);
				return (0);
			}
		} else if (DT_IS_MOV_O7(ip[1])) {
			if (DT_IS_RETL(ip[0]))
				return (0);
		} else {
			if (ip[0] == DT_OP_NOP) {
				(*off) += sizeof (ip[0]);
				return (0);
			}
		}
	}

	/*
	 * We only expect call instructions with a displacement of 0.
	 */
	if (ip[0] != DT_OP_CALL) {
		dt_dprintf("found %x instead of a call instruction at %llx\n",
		    ip[0], (u_longlong_t)rela->r_offset);
		return (-1);
	}

	if (isenabled) {
		/*
		 * It would necessarily indicate incorrect usage if an is-
		 * enabled probe were tail-called so flag that as an error.
		 * It's also potentially (very) tricky to handle gracefully,
		 * but could be done if this were a desired use scenario.
		 */
		if (DT_IS_RESTORE(ip[1]) || DT_IS_MOV_O7(ip[1])) {
			dt_dprintf("tail call to is-enabled probe at %llx\n",
			    (u_longlong_t)rela->r_offset);
			return (-1);
		}


		/*
		 * On SPARC, we take advantage of the fact that the first
		 * argument shares the same register as for the return value.
		 * The macro handles the work of zeroing that register so we
		 * don't need to do anything special here. We instrument the
		 * instruction in the delay slot as we'll need to modify the
		 * return register after that instruction has been emulated.
		 */
		ip[0] = DT_OP_NOP;
		(*off) += sizeof (ip[0]);
	} else {
		/*
		 * If the call is followed by a restore, it's a tail call so
		 * change the call to a ret. If the call if followed by a mov
		 * of a register into %o7, it's a tail call in leaf context
		 * so change the call to a retl-like instruction that returns
		 * to that register value + 8 (rather than the typical %o7 +
		 * 8); the delay slot instruction is left, but should have no
		 * effect. Otherwise we change the call to be a nop. We
		 * identify the subsequent instruction as the probe point in
		 * all but the leaf tail-call case to ensure that arguments to
		 * the probe are complete and consistent. An astute, though
		 * largely hypothetical, observer would note that there is the
		 * possibility of a false-positive probe firing if the function
		 * contained a branch to the instruction in the delay slot of
		 * the call. Fixing this would require significant in-kernel
		 * modifications, and isn't worth doing until we see it in the
		 * wild.
		 */
		if (DT_IS_RESTORE(ip[1])) {
			ip[0] = DT_OP_RET;
			(*off) += sizeof (ip[0]);
		} else if (DT_IS_MOV_O7(ip[1])) {
			ip[0] = DT_MAKE_RETL(DT_RS2(ip[1]));
		} else {
			ip[0] = DT_OP_NOP;
			(*off) += sizeof (ip[0]);
		}
	}

	return (0);
}

#elif defined(__i386) || defined(__amd64)

#define	DT_OP_NOP		0x90
#define	DT_OP_RET		0xc3
#define	DT_OP_CALL		0xe8
#define	DT_OP_JMP32		0xe9
#define	DT_OP_REX_RAX		0x48
#define	DT_OP_XOR_EAX_0		0x33
#define	DT_OP_XOR_EAX_1		0xc0

static int
dt_modtext(dtrace_hdl_t *dtp, char *p, int isenabled, IMAGE_RELOCATION *rel,
    uint32_t *off)
{
	uint8_t *ip = (uint8_t *)(p + rel->VirtualAddress - 1);
	uint8_t ret;

	/*
	 * On x86, the first byte of the instruction is the call opcode and
	 * the next four bytes are the 32-bit address; the relocation is for
	 * the address operand. We back up the offset to the first byte of
	 * the instruction. For is-enabled probes, we later advance the offset
	 * so that it hits the first nop in the instruction sequence.
	 */
	(*off) -= 1;

	/*
	 * We only know about some specific relocation types. Luckily
	 * these types have the same values on both 32-bit and 64-bit
	 * x86 architectures.
	 */
	/*if (GELF_R_TYPE(rela->r_info) != R_386_PC32 &&
	    GELF_R_TYPE(rela->r_info) != R_386_PLT32)
		return (-1);*/

	/*
	 * We may have already processed this object file in an earlier linker
	 * invocation. Check to see if the present instruction sequence matches
	 * the one we would install. For is-enabled probes, we advance the
	 * offset to the first nop instruction in the sequence to match the
	 * text modification code below.
	 */
	if (!isenabled) {
		if ((ip[0] == DT_OP_NOP || ip[0] == DT_OP_RET) &&
		    ip[1] == DT_OP_NOP && ip[2] == DT_OP_NOP &&
		    ip[3] == DT_OP_NOP && ip[4] == DT_OP_NOP)
			return (0);
	} else if (dtp->dt_oflags & DTRACE_O_LP64) {
		if (ip[0] == DT_OP_REX_RAX &&
		    ip[1] == DT_OP_XOR_EAX_0 && ip[2] == DT_OP_XOR_EAX_1 &&
		    (ip[3] == DT_OP_NOP || ip[3] == DT_OP_RET) &&
		    ip[4] == DT_OP_NOP) {
			(*off) += 3;
			return (0);
		}
	} else {
		if (ip[0] == DT_OP_XOR_EAX_0 && ip[1] == DT_OP_XOR_EAX_1 &&
		    (ip[2] == DT_OP_NOP || ip[2] == DT_OP_RET) &&
		    ip[3] == DT_OP_NOP && ip[4] == DT_OP_NOP) {
			(*off) += 2;
			return (0);
		}
	}

	/*
	 * We expect either a call instrution with a 32-bit displacement or a
	 * jmp instruction with a 32-bit displacement acting as a tail-call.
	 */
	if (ip[0] != DT_OP_CALL && ip[0] != DT_OP_JMP32) {
		dt_dprintf("found %x instead of a call or jmp instruction at "
		    "%llx\n", ip[0], (u_longlong_t)rel->VirtualAddress);
		return (-1);
	}

	ret = (ip[0] == DT_OP_JMP32) ? DT_OP_RET : DT_OP_NOP;

	/*
	 * Establish the instruction sequence -- all nops for probes, and an
	 * instruction to clear the return value register (%eax/%rax) followed
	 * by nops for is-enabled probes. For is-enabled probes, we advance
	 * the offset to the first nop. This isn't stricly necessary but makes
	 * for more readable disassembly when the probe is enabled.
	 */
	if (!isenabled) {
		ip[0] = ret;
		ip[1] = DT_OP_NOP;
		ip[2] = DT_OP_NOP;
		ip[3] = DT_OP_NOP;
		ip[4] = DT_OP_NOP;
	} else if (dtp->dt_oflags & DTRACE_O_LP64) {
		ip[0] = DT_OP_REX_RAX;
		ip[1] = DT_OP_XOR_EAX_0;
		ip[2] = DT_OP_XOR_EAX_1;
		ip[3] = ret;
		ip[4] = DT_OP_NOP;
		(*off) += 3;
	} else {
		ip[0] = DT_OP_XOR_EAX_0;
		ip[1] = DT_OP_XOR_EAX_1;
		ip[2] = ret;
		ip[3] = DT_OP_NOP;
		ip[4] = DT_OP_NOP;
		(*off) += 2;
	}

	return (0);
}

#else
#error unknown ISA
#endif

/*PRINTFLIKE5*/
static int
dt_link_error(dtrace_hdl_t *dtp, Pe_object *pe, int fd, dt_link_pair_t *bufs,
    const char *format, ...)
{
	va_list ap;
	dt_link_pair_t *pair;

	va_start(ap, format);
	dt_set_errmsg(dtp, NULL, NULL, NULL, 0, format, ap);
	va_end(ap);

	if (pe != NULL)
		(void) pe_end(pe);

	if (fd >= 0)
		(void) close(fd);

	while ((pair = bufs) != NULL) {
		bufs = pair->dlp_next;
		dt_free(dtp, pair->dlp_str);
		dt_free(dtp, pair->dlp_sym);
		dt_free(dtp, pair);
	}

	return (dt_set_errno(dtp, EDT_COMPILER));
}

static int
process_obj(dtrace_hdl_t *dtp, const char *obj, int *eprobesp)
{
	static const char *dt_prefix;
	static const char dt_enabled[] = "enabled";
	static const char dt_symprefix[] = "_$dtrace";
	static const char dt_symfmt[] = "%s%ld.%s";
	int fd, i, ndx, eprobe, mod = 0;
	IMAGE_FILE_HEADER pehdr;
	IMAGE_RELOCATION rel;
	IMAGE_SECTION_HEADER scn_hdr;
	char *s, *p, *r;
	char pname[DTRACE_PROVNAMELEN];

	dt_provider_t *pvp;
	dt_probe_t *prp;
	uint32_t off, eclass, emachine1, emachine2;
	size_t symsize, nsym, isym, istr, len;
	key_t objkey;
	dt_link_pair_t *pair, *bufs = NULL;
	dt_strtab_t *strtab;
	Pe_object *pe = NULL;
	Pe_table *data_sym, *data_str, data_tgt;
	char name[MAX_SYM_NAME];
	IMAGE_SYMBOL rsym, fsym, dsym;
	int nsec, secno;
	
	if (dtp->dt_oflags & DTRACE_O_LP64)
		dt_prefix = "__dtrace";
	else
		dt_prefix = "___dtrace";
		
	if ((fd = open(obj, _O_RDWR|_O_BINARY, 0)) == -1) {
		return (dt_link_error(dtp, pe, fd, bufs,
		    "failed to open %s: %s", obj, strerror(errno)));
	}
	if ((pe = pe_init(fd)) == NULL) 
		 return (dt_link_error(dtp, pe, fd, bufs,
		    "failed to read %s: %s", obj, "Read header failed"));
		    
	if (pe_getflhdr(pe, &pehdr) == NULL) {
		return (dt_link_error(dtp, pe, fd, bufs,
		    "failed to process %s: %s", obj, "Read header failed"));
	}

	if (dtp->dt_oflags & DTRACE_O_LP64) {
		eclass = IMAGE_FILE_MACHINE_AMD64;
		symsize = sizeof (IMAGE_SYMBOL);
	} else {
		eclass = IMAGE_FILE_MACHINE_I386;

		symsize = sizeof (IMAGE_SYMBOL);
	}

	if (pehdr.Machine != eclass) {
		return (dt_link_error(dtp, pe, fd, bufs,
		    "incorrect ELF class for object file: %s", obj));
	}


	/*
	 * We use this token as a relatively unique handle for this file on the
	 * system in order to disambiguate potential conflicts between files of
	 * the same name which contain identially named local symbols.
	 */
	if ((objkey = ftok(obj, 0)) == (int)-1) {
		return (dt_link_error(dtp, pe, fd, bufs,
		    "failed to generate unique key for object file: %s", obj));
	}

	nsec = pehdr.NumberOfSections;
	secno = 0;
	data_sym = pe_getsymtab(pe);
	data_str = pe_getstrtab(pe);
	isym = pehdr.NumberOfSymbols;
	
	while (++secno <= nsec && pe_getscnhdr(pe, secno, &scn_hdr) != NULL) {
		/*
		 * Skip any non-relocation sections.
		 */
		if (scn_hdr.NumberOfRelocations == 0) 
			continue;

		if (pe_getscn(pe, secno, &data_tgt) == NULL)
			goto err;
		/*
		 * We're looking for relocations to symbols matching this form:
		 *
		 *   __dtrace[enabled]_<prov>___<probe>
		 *
		 * For the generated object, we need to record the location
		 * identified by the relocation, and create a new relocation
		 * in the generated object that will be resolved at link time
		 * to the location of the function in which the probe is
		 * embedded. In the target object, we change the matched symbol
		 * so that it will be ignored at link time, and we modify the
		 * target (text) section to replace the call instruction with
		 * one or more nops.
		 *
		 * If the function containing the probe is locally scoped
		 * (static), we create an alias used by the relocation in the
		 * generated object. The alias, a new symbol, will be global
		 * (so that the relocation from the generated object can be
		 * resolved), and hidden (so that it is converted to a local
		 * symbol at link time). Such aliases have this form:
		 *
		 *   $dtrace<key>.<function>
		 *
		 * We take a first pass through all the relocations to
		 * populate our string table and count the number of extra
		 * symbols we'll require.
		 */
		strtab = dt_strtab_create(1);
		nsym = 0;
		isym = pehdr.NumberOfSymbols;
		istr = data_str->d_size;
			
		for (i = 0; i < scn_hdr.NumberOfRelocations; i++) {

			if (pe_getrel(pe, i, scn_hdr.PointerToRelocations, &rel) == NULL) {
				continue;
			}
			if (pe_getsym(pe, rel.SymbolTableIndex, &rsym) == NULL) {
				dt_strtab_destroy(strtab);
				goto err;
			}
			s = pe_getsymname(pe, &rsym, name, MAX_SYM_NAME);

			if (strncmp(s, dt_prefix, strlen (dt_prefix)) != 0)
				continue;

			if (dt_symtab_lookup(data_sym, isym, rel.VirtualAddress,
			    secno, &fsym) != 0) {
				dt_strtab_destroy(strtab);
				goto err;
			}
			
			s = pe_getsymname(pe, &fsym, name, MAX_SYM_NAME);
			
			if (fsym.StorageClass != IMAGE_SYM_CLASS_STATIC)
				continue;
			
			/*
			 * If this symbol isn't of type function, we've really
			 * driven off the rails or the object file is corrupt.
			 */
			if (ISFCN(fsym.Type) == 0) {
				dt_strtab_destroy(strtab);
				return (dt_link_error(dtp, pe, fd, bufs,
				    "expected %s to be of type function", s));
			}

			len = snprintf(NULL, 0, dt_symfmt, dt_symprefix,
			    objkey, s) + 1;
			if ((p = dt_alloc(dtp, len)) == NULL) {
				dt_strtab_destroy(strtab);
				goto err;
			}
			(void) snprintf(p, len, dt_symfmt, dt_symprefix,
			    objkey, s);

			if (dt_strtab_index(strtab, p) == -1) {
				nsym++;
				(void) dt_strtab_insert(strtab, p);
			}

			dt_free(dtp, p);
		}

		/*
		 * If needed, allocate the additional space for the symbol
		 * table and string table copying the old data into the new
		 * buffers, and marking the buffers as dirty. We inject those
		 * newly allocated buffers into the libelf data structures, but
		 * are still responsible for freeing them once we're done with
		 * the elf handle.
		 */
		if (nsym > 0) {
			/*
			 * The first byte of the string table is reserved for
			 * the \0 entry.
			 */
			 
			len = dt_strtab_size(strtab) - 1;

			assert(len > 0);
			assert(dt_strtab_index(strtab, "") == 0);

			dt_strtab_destroy(strtab);

			if ((pair = dt_alloc(dtp, sizeof (*pair))) == NULL)
				goto err;

			if ((pair->dlp_str = dt_alloc(dtp, data_str->d_size +
			    len)) == NULL) {
				dt_free(dtp, pair);
				goto err;
			}

			if ((pair->dlp_sym = dt_alloc(dtp, data_sym->d_size +
			    nsym * symsize)) == NULL) {
				dt_free(dtp, pair->dlp_str);
				dt_free(dtp, pair);
				goto err;
			}

			pair->dlp_next = bufs;
			bufs = pair;

			bcopy(data_str->d_buf, pair->dlp_str, data_str->d_size);
			
			free(data_str->d_buf);
			data_str->d_buf = pair->dlp_str;
			data_str->d_size += len;
			
			bcopy(data_sym->d_buf, pair->dlp_sym, data_sym->d_size);
			
			free(data_sym->d_buf);
			data_sym->d_buf = pair->dlp_sym;
			data_sym->d_size += nsym * symsize;
			pehdr.NumberOfSymbols += nsym;
			pe_update_flhdr(pe, &pehdr);
			nsym += isym;
		} else {
			dt_strtab_destroy(strtab);
		}

		/*
		 * Now that the tables have been allocated, perform the
		 * modifications described above.
		 */
		for (i = 0; i < scn_hdr.NumberOfRelocations; i++) {
			char proben[MAX_SYM_NAME];
			
			if (pe_getrel(pe, i, scn_hdr.PointerToRelocations, &rel) == NULL) {
				continue;
			}
			
			if (pe_getsym(pe, rel.SymbolTableIndex, &rsym) == NULL) {
				dt_strtab_destroy(strtab);
				goto err;
			}
			s = pe_getsymname(pe, &rsym, proben, MAX_SYM_NAME);
			
			if (strncmp(s, dt_prefix, strlen (dt_prefix)) != 0)
				continue;

			s += strlen (dt_prefix);

			/*
			 * Check to see if this is an 'is-enabled' check as
			 * opposed to a normal probe.
			 */
			if (strncmp(s, dt_enabled,
			    sizeof (dt_enabled) - 1) == 0) {
				s += sizeof (dt_enabled) - 1;
				eprobe = 1;
				*eprobesp = 1;
				dt_dprintf("is-enabled probe\n");
			} else {
				eprobe = 0;
				dt_dprintf("normal probe\n");
			}

			if (*s++ != '_')
				goto err;

			if ((p = strstr(s, "___")) == NULL ||
			    p - s >= sizeof (pname))
				goto err;

			bcopy(s, pname, p - s);
			pname[p - s] = '\0';

			p = strhyphenate(p + 3); /* strlen("___") */

			if (dt_symtab_lookup(data_sym, isym, rel.VirtualAddress,
			    secno, &fsym) != 0)
				goto err;

			assert(ISFCN(fsym.Type));

			/*
			 * If a NULL relocation name is passed to
			 * dt_probe_define(), the function name is used for the
			 * relocation. The relocation needs to use a mangled
			 * name if the symbol is locally scoped; the function
			 * name may need to change if we've found the global
			 * alias for the locally scoped symbol (we prefer
			 * global symbols to locals in dt_symtab_lookup()).
			 */
			s = pe_getsymname(pe, &fsym, name, MAX_SYM_NAME);

			r = NULL;

			if (fsym.StorageClass == IMAGE_SYM_CLASS_STATIC) {
				dsym = fsym;
				dsym.N.Name.Long = istr;
				dsym.N.Name.Short = 0;
				dsym.StorageClass = IMAGE_SYM_CLASS_EXTERNAL;
				dsym.NumberOfAuxSymbols = 0;
				(void) pe_update_sym(pe, isym, &dsym);

				r = (char *)data_str->d_buf + istr-4;
				istr += 1 + sprintf(r, dt_symfmt,
				    dt_symprefix, objkey, s);
				isym++;
				assert(isym <= nsym);

			} else if (strncmp(s, dt_symprefix,
			    strlen(dt_symprefix)) == 0) {
				r = s;
				if ((s = strchr(s, '.')) == NULL)
					goto err;
				s++;
			}

			if ((pvp = dt_provider_lookup(dtp, pname)) == NULL) {
				return (dt_link_error(dtp, pe, fd, bufs,
				    "no such provider %s", pname));
			}

			if ((prp = dt_probe_lookup(pvp, p)) == NULL) {
				return (dt_link_error(dtp, pe, fd, bufs,
				    "no such probe %s", p));
			}

			off = rel.VirtualAddress - fsym.Value;
			if (dt_modtext(dtp, data_tgt.d_buf, eprobe,
			    &rel, &off) != 0)
				goto err;
				

			if ((dtp->dt_oflags & DTRACE_O_LP64) == 0) {
				s++;
				r == NULL ? r : ++r;
			}
	
			if (dt_probe_define(pvp, prp, s, r, off, eprobe) != 0) {
				return (dt_link_error(dtp, pe, fd, bufs,
				    "failed to allocate space for probe"));
			}

			/*
			 * Our linker doesn't understand the SUNW_IGNORE ndx and
			 * will try to use this relocation when we build the
			 * final executable. Since we are done processing this
			 * relocation, remove it from the file.
			 */
			if (rsym.SectionNumber != IMAGE_SYM_ABSOLUTE) {
				rsym.SectionNumber = IMAGE_SYM_ABSOLUTE;
				pe_update_sym(pe, rel.SymbolTableIndex, &rsym);
			} 
			pe_delete_rel(pe, i, scn_hdr.PointerToRelocations, scn_hdr.NumberOfRelocations, &rel); 
			scn_hdr.NumberOfRelocations--;
			pe_update_scnhdr(pe,secno, &scn_hdr);
			--i;

			mod = 1;

			/*
			 * This symbol may already have been marked to
			 * be ignored by another relocation referencing
			 * the same symbol or if this object file has
			 * already been processed by an earlier link
			 * invocation.
			 */
#ifndef illumos
#define SHN_SUNW_IGNORE	IMAGE_SYM_CLASS_NULL
#endif
			/*if (rsym.st_shndx != SHN_SUNW_IGNORE) {
				rsym.st_shndx = SHN_SUNW_IGNORE;
				(void) gelf_update_sym(data_sym, ndx, &rsym);
			}*/
		}
	}

	if (mod && pe_update(pe, PE_C_WRITE) == -1)
		goto err;

	(void) pe_end(pe);
	(void) close(fd);

	while ((pair = bufs) != NULL) {
		bufs = pair->dlp_next;
#ifdef illumos
		dt_free(dtp, pair->dlp_str);
		dt_free(dtp, pair->dlp_sym);
#endif		
		dt_free(dtp, pair);
	}

	return (0);

err:
	return (dt_link_error(dtp, pe, fd, bufs,
	    "an error was encountered while processing %s", obj));
}

int
dtrace_program_link(dtrace_hdl_t *dtp, dtrace_prog_t *pgp, uint_t dflags,
    const char *file, int objc, char *const objv[])
{
	char tfile[PATH_MAX];
	char drti[PATH_MAX];
	dof_hdr_t *dof;
	int fd, status, i, cur;
	char *cmd, tmp;
	size_t len;
	int eprobes = 0, ret = 0;

#if 0
	if (access(file, R_OK) == 0) {
		fprintf(stderr, "dtrace: target object (%s) already exists. "
		    "Please remove the target\ndtrace: object and rebuild all "
		    "the source objects if you wish to run the DTrace\n"
		    "dtrace: linking process again\n", file);
		/*
		 * Several build infrastructures run DTrace twice (e.g.
		 * postgres) and we don't want the build to fail. Return
		 * 0 here since this isn't really a fatal error.
		 */
		return (0);
	}
#endif

	/*
	 * A NULL program indicates a special use in which we just link
	 * together a bunch of object files specified in objv and then
	 * unlink(2) those object files.
	 */
	if (pgp == NULL) {
		const char *fmt = "%s -o %s -r";

		len = snprintf(&tmp, 1, fmt, dtp->dt_ld_path, file) + 1;

		for (i = 0; i < objc; i++)
			len += strlen(objv[i]) + 1;

		cmd = alloca(len);

		cur = snprintf(cmd, len, fmt, dtp->dt_ld_path, file);

		for (i = 0; i < objc; i++)
			cur += snprintf(cmd + cur, len - cur, " %s", objv[i]);

		if ((status = system(cmd)) == -1) {
			return (dt_link_error(dtp, NULL, -1, NULL,
			    "failed to run %s: %s", dtp->dt_ld_path,
			    strerror(errno)));
		}

		if (status == -1) {
			return (dt_link_error(dtp, NULL, -1, NULL,
			    "failed to link %s: %s failed due to error %d",
			    file, dtp->dt_ld_path, errno));
		}

		for (i = 0; i < objc; i++) {
			if (strcmp(objv[i], file) != 0)
				(void) unlink(objv[i]);
		}

		return (0);
	}

	for (i = 0; i < objc; i++) {
		if (process_obj(dtp, objv[i], &eprobes) != 0)
			return (-1); /* errno is set for us */
	}

	/*
	 * If there are is-enabled probes then we need to force use of DOF
	 * version 2.
	 */
	if (eprobes && pgp->dp_dofversion < DOF_VERSION_2)
		pgp->dp_dofversion = DOF_VERSION_2;

	if ((dof = dtrace_dof_create(dtp, pgp, dflags)) == NULL)
		return (-1); /* errno is set for us */

	if (dtp->dt_lazyload) {
		if ((fd = open(file, O_RDWR | O_CREAT | O_TRUNC | O_BINARY, 0666)) < 0)
			return (dt_link_error(dtp, NULL, -1, NULL,
			    "failed to open %s: %s", file, strerror(errno)));
	} else {
		snprintf(tfile, sizeof(tfile), "%s.XXXXXX", file);
		if ((fd = mkstemp(tfile)) == -1)
			return (dt_link_error(dtp, NULL, -1, NULL,
			    "failed to create temporary file %s: %s",
			    tfile, strerror(errno)));
	}


	/*
	 * If -xlinktype=DOF has been selected, just write out the DOF.
	 * Otherwise proceed to the default of generating and linking ELF.
	 */
	switch (dtp->dt_linktype) {
	case DT_LTYP_DOF:
		if (dt_write(dtp, fd, dof, dof->dofh_filesz) < dof->dofh_filesz)
			ret = errno;

		if (close(fd) != 0 && ret == 0)
			ret = errno;

		if (ret != 0) {
			return (dt_link_error(dtp, NULL, -1, NULL,
			    "failed to write %s: %s", file, strerror(ret)));
		}

		return (0);

	case DT_LTYP_ELF:
		break; /* fall through to the rest of dtrace_program_link() */

	default:
		return (dt_link_error(dtp, NULL, -1, NULL,
		    "invalid link type %u\n", dtp->dt_linktype));
	}


	if (dtp->dt_oflags & DTRACE_O_LP64)
		status = dump_elf64(dtp, dof, fd);
	else
		status = dump_elf32(dtp, dof, fd);


	if (status != 0)
		return (dt_link_error(dtp, NULL, -1, NULL,
		    "failed to write %s: %s", tfile,
		    strerror(dtrace_errno(dtp))));


	if (!dtp->dt_lazyload) {

		const char *fmt = "%s %s -o %s -r %s %s";
		const char *ldi386 = "-m i386pe", *ldx64 = "", *ldop;
		
		if (dtp->dt_oflags & DTRACE_O_LP64) {
			(void) snprintf(drti, sizeof (drti), 
			    "%s/amd64/drti.o", _dtrace_libdir);
			    ldop = ldx64;
		} else {
			(void) snprintf(drti, sizeof (drti), 
			    "%s/i386/drti.o", _dtrace_libdir);
			    ldop = ldi386;
		}

		len = snprintf(NULL, 0, fmt, dtp->dt_ld_path, ldop, file, tfile,
		    drti) + 1;

		cmd = alloca(len);

		(void) snprintf(cmd, len, fmt, dtp->dt_ld_path, ldop, file, tfile,
		    drti);

		if ((status = system(cmd)) == -1) {
			ret = dt_link_error(dtp, NULL, fd, NULL,
			    "failed to run %s: %s", dtp->dt_ld_path,
			    strerror(errno));
			goto done;
		}


		(void) close(fd); /* release temporary file */
		unlink(tfile);


		/*
		 * Now that we've linked drti.o, reduce the global __SUNW_dof
		 * symbol to a local symbol. This is needed to so that multiple
		 * generated object files (for different providers, for
		 * instance) can be linked together. This is accomplished using
		 * the -Blocal flag with Sun's linker, but GNU ld doesn't appear
		 * to have an equivalent option.
		 */
		if (dtp->dt_oflags & DTRACE_O_LP64) 
			fmt = "objcopy --localize-symbol=__SUNW_dof %s";
		else
			fmt = "objcopy --localize-symbol=___SUNW_dof %s";
		
		len = snprintf(NULL, 0, fmt, file) + 1;
		cmd = alloca(len);
		(void) snprintf(cmd, len, fmt, file);
				
		if ((status = system(cmd)) == -1) {
			ret = dt_link_error(dtp, NULL, -1, NULL,
			    "failed to run %s: %s", "dtp->dt_objcopy_path",
			    strerror(errno));
			goto done;
		}

		/* In 64 bit, when using msvc, final linking with the dtrace produced object
		 * file will give the following error:
		 * "invalid or corrupt file: file contains invalid .pdata contributions"
		 * So we remove the .pdata section from the dtrace produced file.
		 * (Hopefully without to much damage).
		 */
		if (dtp->dt_oflags & DTRACE_O_LP64) {
			fmt = "objcopy -R .pdata %s";
			len = snprintf(NULL, 0, fmt, file) + 1;
			cmd = alloca(len);
			(void) snprintf(cmd, len, fmt, file);
			if ((status = system(cmd)) == -1) {
				ret = dt_link_error(dtp, NULL, -1, NULL,
			    		"failed to run %s: %s", "dtp->dt_objcopy_path",
			    	strerror(errno));
				goto done;
			}
		}
			
	} else {
		(void) close(fd);
	}
	


done:
	dtrace_dof_destroy(dtp, dof);

	return (ret);
}

