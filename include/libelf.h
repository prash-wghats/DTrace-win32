#ifndef	_LIBELF_H
#define	_LIBELF_H

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


#endif