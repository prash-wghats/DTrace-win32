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


#include <windows.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys\types.h>
#include <sys\stat.h>
#include <libpe.h>

typedef struct pe_object{
	int fd;			//handle to the file
	int type;		//image type; DLL, EXE or OBJ
	int arch;		//x32 or x64
	int size;		//total size of file
	char *data;		//image content from the beginning to start of Symbol Table
	int data_size;		//size of the above image content
	Pe_table symtab;	//size and data for symbol table
	Pe_table strtab;	//size and data for string table.
} Pe_object;

/* pe_gettype: return type of image <dll, exe or obj>*/
int pe_gettype(Pe_object *pe)
{
	if (pe == NULL)
		return -1;
	else
		return pe->type;
}

/* pe_getarch: return image architecture <i386 / amd64> */
int pe_getarch(Pe_object *pe)
{
	if (pe == NULL)
		return -1;
	else
		return pe->arch;
}

/* pe_getsecnofromaddr: get the section number <1 - n> containing the address addr*/
int pe_getsecnofromaddr(Pe_object *pe, int addr) 
{
	PIMAGE_OPTIONAL_HEADER ohdr = NULL;
	PIMAGE_DOS_HEADER dos;
	PIMAGE_FILE_HEADER hdr;
	PIMAGE_NT_HEADERS nthdr;
	PIMAGE_SECTION_HEADER sechdr;
	int i;
	
	if (pe == NULL)
		return -1;
	
	dos = (PIMAGE_DOS_HEADER) pe->data;
	if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
		nthdr = (PIMAGE_NT_HEADERS) (pe->data + dos->e_lfanew);
		hdr =  &nthdr->FileHeader;
	} else
		hdr =  (PIMAGE_FILE_HEADER) pe->data;
	
	sechdr = (PIMAGE_SECTION_HEADER) ((char *) hdr + 
		    (sizeof(IMAGE_FILE_HEADER) + hdr->SizeOfOptionalHeader));
	
	for (i = 0; i < hdr->NumberOfSections; i++) {
		sechdr = &sechdr[i];
		if (addr >= sechdr->VirtualAddress && 
		    addr < (sechdr->VirtualAddress + sechdr->Misc.VirtualSize))
			return (i + 1);
	}
	return 0;
}

/* pe_getsecva: return the virtual address of section */
int pe_getsecva(Pe_object *pe, int secno)
{
	PIMAGE_OPTIONAL_HEADER ohdr = NULL;
	PIMAGE_DOS_HEADER dos;
	PIMAGE_FILE_HEADER hdr;
	PIMAGE_NT_HEADERS nthdr;
	PIMAGE_SECTION_HEADER sechdr;
	int l, i, off;
	char *s;
	
	if (pe == NULL)
		return -1;
		
	dos = (PIMAGE_DOS_HEADER) pe->data;
	if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
		nthdr = (PIMAGE_NT_HEADERS) (pe->data + dos->e_lfanew);
		hdr =  &nthdr->FileHeader;
	} else
		hdr =  (PIMAGE_FILE_HEADER) pe->data;
	
	sechdr = (PIMAGE_SECTION_HEADER) ((char *) hdr + 
		    (sizeof(IMAGE_FILE_HEADER) + hdr->SizeOfOptionalHeader));
	
	if (secno > 0 && secno <= hdr->NumberOfSections) {
		sechdr = &sechdr[secno-1];
		return sechdr->VirtualAddress;
	}
	return 0;
}

/* pe_getsymbyname: find the symbol from name.
 *  A copy is returned
 */  
void *pe_getsymbyname(Pe_object *pe, const char *name, IMAGE_SYMBOL *rsym)
{
	PIMAGE_OPTIONAL_HEADER ohdr = NULL;
	PIMAGE_DOS_HEADER dos;
	PIMAGE_FILE_HEADER hdr;
	PIMAGE_NT_HEADERS nthdr;
	PIMAGE_SECTION_HEADER sechdr;
	IMAGE_SYMBOL *sym;
	int l, i, off;
	char *s;
	
	if (pe == NULL)
		return NULL;
		
	dos = (PIMAGE_DOS_HEADER) pe->data;
	if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
		nthdr = (PIMAGE_NT_HEADERS) (pe->data + dos->e_lfanew);
		hdr = &nthdr->FileHeader;
	} else
		hdr = (PIMAGE_FILE_HEADER) pe->data;
	
	sechdr = (PIMAGE_SECTION_HEADER) ((char *) hdr + 
		    (sizeof(IMAGE_FILE_HEADER) + hdr->SizeOfOptionalHeader));
	
	sym = pe->symtab.d_buf;
	l = strlen(name);
	
	if (l < 9) {
		for (i = 0; i < hdr->NumberOfSymbols; i++) {
			if (sym[i].N.Name.Short == 0) 
				continue;
			if (strncmp(name, sym[i].N.ShortName, 8) == 0) 
				break;
		}
	} else {
		for (i = 0; i < hdr->NumberOfSymbols; i++) {
			if (sym[i].N.Name.Short != 0) 
				continue;
		off = sym[i].N.Name.Long;
		if (off < 4 || (off + l) > pe->strtab.d_size)
			continue;
		s = &((char *)pe->strtab.d_buf)[sym[i].N.Name.Long - 4];
		if (strncmp(s, name, l) == 0)
			break;
		}
	} 
	
	if (i < hdr->NumberOfSymbols) {
		memcpy(rsym, &sym[i], sizeof(IMAGE_SYMBOL));
		return rsym;
	}
	
	return NULL;
}

/* pe_init: Intialize libpe for file fd,
 *   fd is the file handle for the image, returned
 *   by open(...).
 */
Pe_object *pe_init(int fd)
{
	PIMAGE_FILE_HEADER hdr;
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS nthdr;
	int r , sz = 0, type = 0, str_sz = 0, off, arch = 0, sym_sz;
	char *buf, *tmp;
	struct stat st;
	Pe_object *pe;
	
	
	if (fstat(fd, &st) ==  -1) {
		return (NULL);
	}
	sz = st.st_size;
	
	if (sz < sizeof(PIMAGE_DOS_HEADER)) {
		return NULL;
	}
	
	if ((pe = malloc(sizeof(*pe))) == NULL)
		return NULL;
		
	pe->data = NULL;
	pe->symtab.d_buf = 0;
	pe->strtab.d_buf = 0;
	pe->fd = fd;
	
	if ((buf = malloc(sz)) == NULL) {
		free(pe);
		return NULL;
	}
			
	if ((r = read(fd, buf, sz)) != sz) {
		goto err;
	}
		
	type = PE_TYPE_OBJ;
	
	dos = (PIMAGE_DOS_HEADER) buf;
	if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
		if (dos->e_lfanew + sizeof(IMAGE_FILE_HEADER) > sz) {
			goto err;
		}
		nthdr = (PIMAGE_NT_HEADERS) (buf + dos->e_lfanew);
		if (nthdr->Signature != IMAGE_NT_SIGNATURE) {
			goto err;
		}
		hdr = &nthdr->FileHeader;
		if (hdr->Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
			type = PE_TYPE_EXE;
		else if (hdr->Characteristics & IMAGE_FILE_DLL)
			type = PE_TYPE_DLL;
		else
			type = PE_TYPE_UNKNOWN;
			
		if (hdr->Machine == IMAGE_FILE_MACHINE_I386)
			arch = PE_ARCH_I386;
		else if (hdr->Machine == IMAGE_FILE_MACHINE_AMD64)
			arch = PE_ARCH_AMD64;
		else
			arch = PE_ARCH_UNKNOWN;
			
			
	} else
		 hdr =  (PIMAGE_FILE_HEADER) buf;
		
	if (hdr->PointerToSymbolTable != 0) {
		if (hdr->PointerToSymbolTable > sz) {
			goto err;
		}
		
		sym_sz = hdr->NumberOfSymbols * sizeof(IMAGE_SYMBOL);
		if (hdr->PointerToSymbolTable + sym_sz > sz) {
			goto err;
		} else
			pe->symtab.d_size = sym_sz;
			
		tmp = malloc(sym_sz);
		if (tmp == NULL)
			goto err;
			
		memcpy(tmp, buf + hdr->PointerToSymbolTable, sym_sz);
		pe->symtab.d_buf = tmp;
		
		if ((off = hdr->PointerToSymbolTable + sym_sz) + 4 < sz) {
			//size of string table includes the size field 
			memcpy(&str_sz, buf + off, 4);
			pe->strtab.d_size = str_sz;
			tmp = malloc(str_sz - 4);
			
			if (tmp == NULL)
				goto err1;
				
			memcpy(tmp, (buf + hdr->PointerToSymbolTable + sym_sz + 4), str_sz - 4);	
			pe->strtab.d_buf = tmp;
		}
	}
	pe->data = buf;
	pe->data_size = hdr->PointerToSymbolTable;
	pe->size = sz;
	pe->type = type;	
	pe->arch = arch;
	
	return pe;
err1:
	free(pe->symtab.d_buf);
err:
	free(pe);
	free(buf);
	
	return NULL;
}

/* pe_getsymarr: return a pointer to symbol table.
 *   Any changes made will be writen to the image file.
 *   when the pe object is closed.
 *   *co = number of symbols in the symbol table.
 */   
IMAGE_SYMBOL *pe_getsymarr(Pe_object *pe, int *co)
{
	if (pe == NULL)
		return NULL;
		
	*co = pe->symtab.d_size / sizeof(IMAGE_SYMBOL);
	if (pe->symtab.d_size == 0 || *co < 1)
		return NULL;
	return pe->symtab.d_buf;
}

/* pe_getsymname: return name of the symbol */
char *pe_getsymname(Pe_object *pe, IMAGE_SYMBOL *sym, char *buf, int len)
{
	char  *s, *s1, *n;
	int off, l;
	
	if (pe == NULL)
		return NULL;
		
	if (sym->N.Name.Short != 0) {
		if (len < 9)
			return NULL;
		memcpy(buf, sym->N.ShortName, 8);
		buf[8] = '\0'; 
	} else {
		off = sym->N.Name.Long;
		s1 = s = &((char *)pe->strtab.d_buf)[sym->N.Name.Long-4];
		while (off < pe->strtab.d_size && *s != '\0') {
			s++;
			off++;
		}
		if (*s != '\0')
			return NULL;
		l = s - s1;
		if (len < (l+1))
			return NULL;
		memcpy(buf, s1, l);
		buf[l] = '\0'; 
	} 
	
	return buf;
}

/* pe_getflhdr: return file header.
 *  A copy of the file header is returned
 */
IMAGE_FILE_HEADER *pe_getflhdr(Pe_object *pe, IMAGE_FILE_HEADER *phdr)
{
	PIMAGE_FILE_HEADER hdr;
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS nthdr;
	
	if (pe == NULL)
		return NULL;
	if (pe->data_size < sizeof(IMAGE_FILE_HEADER))
		return NULL;
		
	dos = (PIMAGE_DOS_HEADER) pe->data;
	if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
		nthdr = (PIMAGE_NT_HEADERS) (pe->data + dos->e_lfanew);
		hdr = &nthdr->FileHeader;
	} else
		hdr = (PIMAGE_FILE_HEADER) pe->data;
	
	memcpy(phdr, hdr, sizeof(IMAGE_FILE_HEADER));
	return phdr;
}

/* pe_getsymtab: return symbol table.
 *  Any changes made to the buffer will be
 *  written to the image file when pe handle
 *  is closed
 */
Pe_table *pe_getsymtab(Pe_object *pe)
{
	if (pe == NULL)
		return NULL;
		
	return &pe->symtab;
}

/* pe_getstrtab: return string table.
*  Any changes made to the buffer will be
 *  written to the image file when pe handle
 *  is closed
 */
Pe_table *pe_getstrtab(Pe_object *pe)
{
	if (pe == NULL)
		return NULL;
		
	return &pe->strtab;
}

/* pe_getsym: returns symbol at index from the symbol table.
 *   A copy is returned
 */
IMAGE_SYMBOL *pe_getsym(Pe_object *pe, int index, IMAGE_SYMBOL *sym)
{
	if (pe == NULL)
		return NULL;
	if (pe->symtab.d_size < (sizeof(IMAGE_SYMBOL) * (index + 1)))
		return NULL;
		
	memcpy(sym, &((IMAGE_SYMBOL *)pe->symtab.d_buf)[index], sizeof(IMAGE_SYMBOL));
	return sym;
}

/* pe_getscnhdr: return a copy of section header for given section number */
IMAGE_SECTION_HEADER *pe_getscnhdr(Pe_object *pe, int secno, IMAGE_SECTION_HEADER *sechdr) 
{
	PIMAGE_FILE_HEADER hdr;
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS nthdr;
	IMAGE_FILE_HEADER flhdr;
	char *data;
	
	if (pe == NULL)
		return NULL;
	if (pe_getflhdr(pe, &flhdr) == NULL || flhdr.NumberOfSections < secno)
		return NULL;
	if (pe->data_size < sizeof(IMAGE_FILE_HEADER) + 
	    (sizeof(IMAGE_SECTION_HEADER) * secno))
		return NULL;
		
	dos = (PIMAGE_DOS_HEADER) pe->data;
	if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
		nthdr = (PIMAGE_NT_HEADERS) (pe->data + dos->e_lfanew);
		hdr =  &nthdr->FileHeader;
	} else
		hdr =  (PIMAGE_FILE_HEADER) pe->data;
		
	memcpy(sechdr, (char *) hdr + (sizeof(IMAGE_FILE_HEADER) + 
	    hdr->SizeOfOptionalHeader + ((secno - 1) * sizeof(IMAGE_SECTION_HEADER))),
	    sizeof(IMAGE_SECTION_HEADER));
	    
	return sechdr;
}

/* pe_update_scnhdr: update the image section header for given section number */
IMAGE_SECTION_HEADER *pe_update_scnhdr(Pe_object *pe, int secno, IMAGE_SECTION_HEADER *sechdr) 
{
	PIMAGE_FILE_HEADER hdr;
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS nthdr;
	char *data;
	
	if (pe == NULL)
		return NULL;
	if (pe->data_size < sizeof(IMAGE_FILE_HEADER)+ (sizeof(IMAGE_SECTION_HEADER) * secno))
		return NULL;
		
	dos = (PIMAGE_DOS_HEADER) pe->data;
	if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
		nthdr = (PIMAGE_NT_HEADERS) (pe->data + dos->e_lfanew);
		hdr = &nthdr->FileHeader;
		
	} else
		hdr = (PIMAGE_FILE_HEADER) pe->data;
		
	memcpy(((char *) hdr + sizeof(IMAGE_FILE_HEADER) + 
	    ((secno-1) * sizeof(IMAGE_SECTION_HEADER))), 
	    sechdr, sizeof(IMAGE_SECTION_HEADER));
	return sechdr;
}

/* pe_getscnnamescn: return the section name for given section header.
 *  the returned string should be freed by the caller
 */
char *pe_getscnnamescn(Pe_object *pe, IMAGE_SECTION_HEADER *scnhdr)
{
	char *data, *n, *buf;
	int off, len;
	
	if (pe == NULL)
		return NULL;
		
	if (scnhdr->Name[0] == '/') {
		off = atoi(&scnhdr->Name[1]) - 4;
		if (off < 0)
			return NULL;
		buf = (char *) pe->strtab.d_buf;
		len = strlen(&buf[off]);
		n = malloc(len + 1);
		if (n == NULL)
			return 0;
		strcpy(n, &buf[off]);
	} else {
		n = malloc(9);
		if (n == NULL)
			return 0;
		strncpy(n, scnhdr->Name, 8);
		n[8] = 0;
	}
	return n;
}

/* pe_getscnname: return the section name for given section no.
 *  the returned string should be freed by the caller
 */
char *pe_getscnname(Pe_object *pe, int secno)
{
	PIMAGE_FILE_HEADER hdr;
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS nthdr;
	char  *n, *buf;
	int off, len;
	PIMAGE_SECTION_HEADER scnhdr;
	
	if (pe == NULL)
		return NULL;
	if (pe->data_size < sizeof(IMAGE_FILE_HEADER))
		return NULL;
	if (pe->data_size < sizeof(IMAGE_FILE_HEADER)+ 
	    (sizeof(IMAGE_SECTION_HEADER) * secno))
		return NULL;
		
	dos = (PIMAGE_DOS_HEADER) pe->data;
	if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
		nthdr = (PIMAGE_NT_HEADERS) (pe->data + dos->e_lfanew);
		hdr = &nthdr->FileHeader;
	} else
		hdr = (PIMAGE_FILE_HEADER) pe->data;
	
	scnhdr = (PIMAGE_SECTION_HEADER ) ((char *) hdr + sizeof(IMAGE_FILE_HEADER)
		     + hdr->SizeOfOptionalHeader + ((secno - 1) * 
		     sizeof(IMAGE_SECTION_HEADER)));
		 
	if (scnhdr->Name[0] == '/') {
		off = atoi(&scnhdr->Name[1]) - 4;
		if (off < 0)
			return NULL;
		buf = (char *) pe->strtab.d_buf;
		len = strlen(&buf[off]);
		n = malloc(len+1);
		if (n == NULL)
			return 0;
		strcpy(n, &buf[off]);
	} else {
		n = malloc(9);
		if (n == NULL)
			return 0;
		strncpy(n, scnhdr->Name, 8);
		n[8] = 0;
	}
	return n;
	
}

/* pe_update_sym: update the image symbol table at index */
IMAGE_SYMBOL *pe_update_sym(Pe_object *pe, int index, IMAGE_SYMBOL *sym)
{
	if (pe == NULL)
		return NULL;
	if (pe->symtab.d_size < (sizeof(IMAGE_SYMBOL) * index+1))
		return NULL;
		
	memcpy(&((IMAGE_SYMBOL *)pe->symtab.d_buf)[index], sym, sizeof(IMAGE_SYMBOL));
	return sym;
}

/* pe_update_flhdr: update the image file header */
IMAGE_FILE_HEADER * pe_update_flhdr(Pe_object *pe, IMAGE_FILE_HEADER *hdr)
{
	PIMAGE_FILE_HEADER ohdr;
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS nthdr;
	char *data;
	
	if (pe == NULL)
		return NULL;
	if (pe->data_size < sizeof(IMAGE_FILE_HEADER))
		return NULL;
	
	dos = (PIMAGE_DOS_HEADER) pe->data;
	if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
		nthdr = (PIMAGE_NT_HEADERS) (pe->data + dos->e_lfanew);
		ohdr =  &nthdr->FileHeader;
		
	} else
		ohdr =  (PIMAGE_FILE_HEADER) pe->data;
		
	memcpy((char *) ohdr, hdr, sizeof(IMAGE_FILE_HEADER));
	
	return hdr;	
} 	

/* pe_getscn: return section data for section number secno
 *  Any changes made to the buffer will be
 *  written to the image file when pe handle
 *  is closed.
 *  The size of the section is given by
 *   -> VirtualSize ? VirtualSize : SizeOfRawData
 */
Pe_table *pe_getscn(Pe_object *pe, int secno, Pe_table *tab)
{
	IMAGE_SECTION_HEADER *sechdr;
	PIMAGE_FILE_HEADER hdr;
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS nthdr;
	DWORD off, sz;
	
	if (pe == NULL)
		return NULL;
	if (pe->data_size < sizeof(IMAGE_FILE_HEADER))
		return NULL;
		
	dos = (PIMAGE_DOS_HEADER) pe->data;
	if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
		nthdr = (PIMAGE_NT_HEADERS) (pe->data + dos->e_lfanew);
		hdr =  &nthdr->FileHeader;
		
	} else
		hdr = (PIMAGE_FILE_HEADER) pe->data;
	
	if (pe->data_size < sizeof(IMAGE_FILE_HEADER) + (sizeof(IMAGE_SECTION_HEADER) * secno))
		return NULL;
	sechdr = (IMAGE_SECTION_HEADER *) ((char *) hdr + sizeof(IMAGE_FILE_HEADER) + 
		hdr->SizeOfOptionalHeader + ((secno - 1) * sizeof(IMAGE_SECTION_HEADER)));
		
	off = sechdr->PointerToRawData;
	sz = sechdr->Misc.VirtualSize ? sechdr->Misc.VirtualSize : sechdr->SizeOfRawData;
	
	if (pe->data_size < off+sz)
		return NULL;
		
	tab->d_size = sz;
	tab->d_buf = (pe->data + off);
	return tab;
}

/* Relocation index are 0 based.*/

/* pe_getrel: return the relocation at index from the relocation table
 *   at address <offset>.
 *   A copy is returned.
 */
IMAGE_RELOCATION *pe_getrel(Pe_object *pe, int index, DWORD offset, IMAGE_RELOCATION *rel)
{
	IMAGE_SECTION_HEADER *sec;
	IMAGE_RELOCATION *rela;
	
	if (pe == NULL)
		return NULL;
	if (pe->data_size < (offset + (sizeof(IMAGE_RELOCATION) * (index))))
		return NULL;
		
	rela = (IMAGE_RELOCATION *) &(((char *) pe->data)[offset]);
	memcpy(rel, &rela[index], sizeof(IMAGE_RELOCATION));
	return rel;
}
/* pe_update_rel: update relocation data at given index for the relocation table at offset */
IMAGE_RELOCATION *pe_update_rel(Pe_object *pe, int index, DWORD offset, IMAGE_RELOCATION *rel)
{
	IMAGE_SECTION_HEADER *sec;
	IMAGE_RELOCATION *rela;
	
	if (pe == NULL)
		return NULL;
	if (pe->data_size < offset+(sizeof(IMAGE_RELOCATION) * (index)))
		return NULL;
		
	rela = (IMAGE_RELOCATION *) &(((char *) pe->data)[offset]);
	memcpy(&rela[index], rel, sizeof(IMAGE_RELOCATION));
	return rel;	
}

/* pe_delete_rel: delete relocation data at index for relocation table at offset
 *   of size count;
 */
int pe_delete_rel(Pe_object *pe, int index, DWORD offset, int count, IMAGE_RELOCATION *rel)
{
	IMAGE_SECTION_HEADER *sec;
	IMAGE_RELOCATION *rela;
	int mov = count - index - 1;
	
	if (pe == NULL)
		return -1;
	if ((pe->data_size < offset + (sizeof(IMAGE_RELOCATION) * index)))
		return -1;
		
	rela = (IMAGE_RELOCATION *) &(((char *) pe->data)[offset]);
	if ((index + 1) == count) {
		memset(&rela[index], sizeof(IMAGE_RELOCATION), 0);
		return 0;
	}
	memmove(&rela[index], &rela[index + 1], sizeof(IMAGE_RELOCATION) * mov);
	memset(&rela[count - 1], sizeof(IMAGE_RELOCATION), 0);
	
	return 0;	
}

/* pe_update: update the image file */
int pe_update(Pe_object *pe, int flags)
{
	if (pe == NULL)
		return -1;
	if (lseek(pe->fd, 0, 0) == -1)
		return -1;
		
	if (write(pe->fd, pe->data, pe->data_size) != pe->data_size ||
	    write(pe->fd, pe->symtab.d_buf, pe->symtab.d_size) != pe->symtab.d_size ||
	    write(pe->fd, &pe->strtab.d_size, 4) != 4 ||
	    write(pe->fd, pe->strtab.d_buf, pe->strtab.d_size - 4) != pe->strtab.d_size - 4)
		return -1;
	return 0;
}

/* pe_end: close the pe handle to the image file */
void pe_end(Pe_object *pe)
{
	if (pe != NULL) {
		free(pe->strtab.d_buf);
		free(pe->symtab.d_buf);
		free(pe->data);
		free(pe);
	}
}

char *pe_strptr(Pe_object *pe, size_t section, size_t offset)
{
	return NULL;
}

char *pe_nextscn(Pe_object *elf, char *scn)
{
	return NULL;
}

char *pe_errmsg(int err)
{
	return NULL;
}
	