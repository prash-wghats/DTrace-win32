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
 * Copyright (C) 2016  Prashanth K.
 */ 
 
/* Helper library to read and write to PE format */

#ifndef	_LIBPE_H
#define	_LIBPE_H

#include <windows.h>

#define PE_C_WRITE 1
enum {
	PE_TYPE_OBJ = 1,
	PE_TYPE_EXE,
	PE_TYPE_DLL,
	PE_TYPE_UNKNOWN = -1
};

enum {
	PE_ARCH_I386 = 1,
	PE_ARCH_AMD64,
	PE_ARCH_UNKNOWN = -1
};

typedef struct pe_table {
	void *d_buf;
	int d_size;
} Pe_table;

struct pe_object;
typedef struct pe_object Pe_object;


char *pe_strptr(Pe_object *pe, size_t section, size_t offset);
char *pe_nextscn(Pe_object *elf, char *scn);
IMAGE_FILE_HEADER *pe_getflhdr(Pe_object *pe, IMAGE_FILE_HEADER *hdrr);
IMAGE_SECTION_HEADER *pe_getscnhdr(Pe_object *pe, int secno, IMAGE_SECTION_HEADER *sechdr) ;
Pe_table *pe_getscn(Pe_object *pe, int secno, Pe_table *tab);
Pe_object *pe_init(int fd);
char * pe_getscnname(Pe_object *pe, int secno);
int pe_getarch(Pe_object *pe);

void pe_end(Pe_object *pe);
char * pe_errmsg(int code);
int pe_errno();

int pe_gettype(Pe_object *pe);
int pe_getarch(Pe_object *pe);
int pe_getsecnofromaddr(Pe_object *pe, int addr);
int pe_getsecva(Pe_object *pe, int secno);
void *pe_getsymbyname(Pe_object *pe, const char *name, IMAGE_SYMBOL *rsym);
Pe_object *pe_init(int fd);
IMAGE_SYMBOL *pe_getsymarr(Pe_object *pe, int *co);
char *pe_getsymname(Pe_object *pe, IMAGE_SYMBOL *sym, char *name, int len);
IMAGE_FILE_HEADER *pe_getflhdr(Pe_object *pe, IMAGE_FILE_HEADER *hdr);
Pe_table *pe_getsymtab(Pe_object *pe);
Pe_table *pe_getstrtab(Pe_object *pe);
IMAGE_RELOCATION *pe_getrel(Pe_object *pe, int index, DWORD offset, IMAGE_RELOCATION *rel);
IMAGE_SYMBOL *pe_getsym(Pe_object *pe, int index, IMAGE_SYMBOL *sym);
IMAGE_SECTION_HEADER *pe_getscnhdr(Pe_object *pe, int secno, IMAGE_SECTION_HEADER *sechdr);
IMAGE_SECTION_HEADER *pe_update_scnhdr(Pe_object *pe, int secno, IMAGE_SECTION_HEADER *sechdr);
char * pe_getscnnamescn(Pe_object *pe, IMAGE_SECTION_HEADER *scnhdr);
char * pe_getscnname(Pe_object *pe, int secno);
IMAGE_SYMBOL *pe_update_sym(Pe_object *pe, int index, IMAGE_SYMBOL *sym);
IMAGE_FILE_HEADER * pe_update_flhdr(Pe_object *pe, IMAGE_FILE_HEADER *hdr);
Pe_table *pe_getscn(Pe_object *pe, int secno, Pe_table *tab);
IMAGE_RELOCATION *pe_update_rel(Pe_object *pe, int index, DWORD offset, IMAGE_RELOCATION *rel);
int pe_delete_rel(Pe_object *pe, int index, DWORD offset, int count, IMAGE_RELOCATION *rel);
int pe_update(Pe_object *pe, int flags);
void pe_end(Pe_object *pe);

char *pe_strptr(Pe_object *pe, size_t section, size_t offset);
char *pe_nextscn(Pe_object *elf, char *scn);
char *pe_errmsg(int err);

#endif