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
 
#ifndef	_MYTYPE_H
#define	_MYTYPE_H

#include <windows.h>
#include <winbase.h>
#include <winioctl.h>
#include <dbghelp.h>
#include <stdio.h>


#define MAX_SYMBOL_NAME 255

#if __MINGW32__
#include <stdint.h>
#include <strings.h>
#include <unistd.h>
#include <sys/param.h>
#else
#pragma warning(disable:4274) 

char *basename (const char *name);
#define PATH_MAX            512
#define snprintf _snprintf
#define alloca _alloca
#define strtoull   _strtoui64
#define strncasecmp  _strnicmp
#define strcasecmp  _stricmp
#define ftruncate    _chsize
#define lseek64 _lseeki64

#define MAXPATHLEN  255

#define EOVERFLOW 132
#define ENOTSUP           129
#define EALREADY 103

#define INT32_MAX 2147483647
#define UINT32_MAX 0xffffffffU  /* 4294967295U */
#define UINT16_MAX 65535
#define INT32_MIN (-2147483647 - 1)
#define UINT8_MAX 255
#define INT64_MAX 9223372036854775807LL
#define UINT64_MAX 0xffffffffffffffffULL /* 18446744073709551615ULL */
#define INT64_C(val) val##LL
#define UINT64_C(val) val##ULL


typedef long long  intmax_t;
typedef unsigned long long   uintmax_t;
typedef signed char int8_t;
typedef unsigned char   uint8_t;
typedef short  int16_t;
typedef unsigned short  uint16_t;
typedef int  int32_t;
typedef unsigned   uint32_t;
typedef long long  int64_t;
typedef unsigned long long   uint64_t;
typedef long long off64_t; 
typedef unsigned long long   uintmax_t;

#if _M_IX86
typedef int pid_t;
typedef int ssize_t;
#else
/* pid_t should be uint32_t. process id in windows is DWORD type.
 * But pid_t in mingw 64 is int64_t type.While testing for equality of
 * pid type cast it to DWORD type
 */
typedef int64_t pid_t;
typedef int64_t ssize_t;
#endif
#endif

#undef BYTE_ORDER
#define _BIG_INDIAN 	2
#define _LITTLE_ENDIAN 	1
#define BYTE_ORDER	_LITTLE_ENDIAN

/*
 * POSIX Extensions
 */
typedef int key_t;
typedef	unsigned char	uchar_t; 
typedef	unsigned short	ushort_t;
typedef	unsigned int	uint_t;  
typedef	unsigned long	ulong_t; 
typedef	char		*caddr_t;
typedef	unsigned int	processorid_t; 
typedef pid_t	uid_t;
typedef pid_t	zoneid_t;
typedef pid_t 	id_t;
typedef ulong_t	Lmid_t;
typedef uint64_t u_longlong_t;
typedef int64_t hrtime_t;
typedef uchar_t	KIRQL;
typedef int cred_t;

#define B_TRUE 1
#define B_FALSE 0

#define PR_MODEL_ILP32 0
#define PR_MODEL_ILP64 1
#define PR_MODEL_LP64 1

#define NBBY 8
#define _SC_CPUID_MAX -1
#define _SC_NPROCESSORS_MAX -2
typedef	unsigned short	u_short;
typedef	unsigned int	u_int;  
//typedef	unsigned int	u_long;
typedef int64_t	longlong_t;

#define SEC			1
#define MILLISEC	1000
#define MICROSEC	1000000
#define NANOSEC		1000000000
//#define EOVERFLOW	84
//#define EALREADY	37
#define bzero(b,len) (memset((b), '\0', (len)), (void) 0)
#define bcopy(s, d, len) (memcpy((d), (s), (len)))
#define bcmp(s, d, len) (memcmp((d), (s), (len)))
typedef int 	boolean_t;

#define	roundup(x, y)	((((x)+((y)-1))/(y))*(y))  /* to any y */
#ifndef MAX
#define	MAX(a, b) 		((a) < (b) ? (b) : (a))
#endif

#ifndef MIN
#define	MIN(a, b) 		((a) > (b) ? (b) : (a))
#endif

#define P2ROUNDUP(x, align)             (-(-(x) & -(align)))

/////// LIBELF

#define	ELF32_ST_BIND(info)		((info) >> 4)
#define ELF32_ST_TYPE(info)		((info) & 0xf)
#define	ELF64_ST_BIND(info)		((info) >> 4)
#define	ELF64_ST_TYPE(info)		((info) & 0xf)
#define	ELF64_ST_INFO(bind, type)	(((bind) << 4) + ((type) & 0xf))
#define	ELF64_ST_VISIBILITY(oth)	((oth) & 0x3)

#define GELF_ST_BIND			ELF64_ST_BIND
#define	GELF_ST_INFO			ELF64_ST_INFO
#define	GELF_ST_TYPE			ELF64_ST_TYPE
#define	GELF_ST_VISIBILITY		ELF64_ST_VISIBILITY

#define	STB_LOCAL	0	/* Local symbol */
#define	STB_GLOBAL	1	/* Global symbol */
#define	STT_FUNC	2	/* Function. */
#define	SHN_UNDEF	     0		/* Undefined, missing, irrelevant*/
#define	STT_NOTYPE	0	/* Unspecified type. */
#define	STT_NUM		7
#define	STT_SECTION	3	/* Section. */
#define	STB_WEAK	2	/* like global - lower precedence */
#define	STT_TLS		6	/* TLS object. */
#define	SHT_PROGBITS		1	/* program defined information */
#define	STT_OBJECT	1	/* Data object. */
#define	SHN_ABS		0xfff1		/* Absolute values. */

typedef uint8_t         Elf_Byte;
 typedef uint32_t        Elf32_Addr;
 typedef uint32_t        Elf32_Off;
 typedef int32_t         Elf32_SOff;
 typedef int32_t         Elf32_Sword;
 typedef uint32_t        Elf32_Word;
 typedef uint16_t        Elf32_Half;
 typedef uint64_t        Elf32_Lword;
 typedef uint64_t        Elf64_Addr;
 typedef uint64_t        Elf64_Off;
 typedef int64_t         Elf64_SOff;
 typedef int32_t         Elf64_Shalf;
 typedef int32_t         Elf64_Sword;
 typedef uint32_t        Elf64_Word;
 typedef int64_t         Elf64_Sxword;
 typedef uint64_t        Elf64_Xword;
 typedef uint64_t        Elf64_Lword;
 typedef uint16_t        Elf64_Half;

/*
 * Symbol table entries.
 */

typedef struct {
	Elf32_Word	st_name;	/* String table index of name. */
	Elf32_Addr	st_value;	/* Symbol value. */
	Elf32_Word	st_size;	/* Size of associated object. */
	unsigned char	st_info;	/* Type and binding information. */
	unsigned char	st_other;	/* Reserved (not used). */
	Elf32_Half	st_shndx;	/* Section index of symbol. */
} Elf32_Sym;

typedef struct {
        Elf64_Word      st_name;        /* Symbol name (.strtab index) */
        Elf_Byte        st_info;        /* type / binding attrs */
        Elf_Byte        st_other;       /* unused */
        Elf64_Half      st_shndx;       /* section index of symbol */
        Elf64_Addr      st_value;       /* value of symbol */
        Elf64_Xword     st_size;        /* size of symbol */
#ifdef __amd64__
	int		model;
#endif
} Elf64_Sym;

typedef Elf64_Addr      GElf_Addr;      /* Addresses */
typedef Elf64_Half      GElf_Half;      /* Half words (16 bit) */
typedef Elf64_Off       GElf_Off;       /* Offsets */
typedef Elf64_Sword     GElf_Sword;     /* Signed words (32 bit) */
typedef Elf64_Sxword    GElf_Sxword;    /* Signed long words (64 bit) */
typedef Elf64_Word      GElf_Word;      /* Unsigned words (32 bit) */
typedef Elf64_Xword     GElf_Xword;     /* Unsigned long words (64 bit) */
typedef Elf64_Sym       GElf_Sym;       /* Symbol table entries */

////////LIBELF

#define ARRAY_SIZE 1024

hrtime_t gethrtime(void);
hrtime_t gethrestime(void);
char *cleanddpath(char *str);
BOOL SetPrivilege(HANDLE hToken,	// access token handle
		  LPCTSTR lpszPrivilege,	// name of privilege to enable/disable
		  BOOL bEnablePrivilege	// to enable or disable privilege
    );
size_t strlcpy(char * dst, const char *src, size_t siz);
char *strndup(const char *s, size_t n);
char *strsep(char **stringp, const char *delim);
FILE *tempfile(void);
void update_errno();

#define ELFCLASS32 1
#define ELFCLASS64 2
int gelf_getclass(const char *name, uintptr_t base);

int gmatch(const char *s, const char *p);
int ftok(const char *path, int id);

#endif