/*
InterruptHook
Copyright (C) 2003  Alexander M.
Copyright (C) 2015  PK.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/

#ifndef HOOK_H
#define HOOK_H

#pragma once
#include <windef.h>

#ifdef _AMD64_
#pragma pack(1)
typedef struct tagIDT
{
	WORD	wLimit;
	PVOID	dwBase;
} IDT, *PIDT;

typedef struct tagINT_VECTOR
{
	WORD	wLowLOffset;
	WORD	wSelector;
	WORD	bAccess;
	WORD	wLowHOffset;
	ULONG	wHighOffset;
	ULONG	unused;
} INT_VECTOR, *PINT_VECTOR;
#pragma pack()

#define VEC_OFFSET_TO_ADDR( _vec ) \
	_vec.wLowLOffset | (ULONG64)_vec.wHighOffset << 32 | (ULONG64)_vec.wLowHOffset << 16

#define ADDR_TO_VEC_OFFSET( _vec, _qword ) \
	_vec.wLowLOffset = (WORD)_qword; \
	_vec.wLowHOffset = (WORD)(_qword >> 16); \
	_vec.wHighOffset = (DWORD)( (ULONG64)_qword >> 32 );
	
#else // i386

#pragma pack(1)
typedef struct tagIDT
{
	WORD	wLimit;
	DWORD	dwBase;
} IDT, *PIDT;

typedef struct tagINT_VECTOR
{
	WORD	wLowOffset;
	WORD	wSelector;
	BYTE	bAccess;
	BYTE	wUnused;
	WORD	wHighOffset;
} INT_VECTOR, *PINT_VECTOR;
#pragma pack()



#define VEC_OFFSET_TO_ADDR( _vec ) \
	_vec.wLowOffset | _vec.wHighOffset << 16

#define ADDR_TO_VEC_OFFSET( _vec, _dword ) \
	_vec.wLowOffset = (WORD)_dword; \
	_vec.wHighOffset = (WORD)( (DWORD)_dword >> 16 );

#define VEC_GET_DPL( _vec ) \
	( _vec.bAccess & 0x60 ) >> 4
#define VEC_SET_DPL( _vec, _value ) \
	_vec.bAccess &= 0x9F; \
	_value << 4; \
	_vec.bAccess |= (BYTE)_value;
#define VEC_IS_PRESENT( _vec ) \
	_vec.bAccess >> 7
#define VEC_SET_PRESENT( _vec ) \
	_vec.bAccess |= 0x80;
#define VEC_GET_TYPE( _vec ) \
	_vec.bAccess & 0xF0
#define SELECTOR_GET_RPL( _sel ) \
	_sel & 0x3
#define SELECT_SET_RPL( _sel, _rpl ) \
	_sel &= 0xFFC; \
	_sel |= (WORD)_rpl;
#endif

VOID
LoadIDT(
		OUT	PIDT pIdt );

VOID
LoadINTVector(
		IN	PIDT		pIdt,
		IN	UCHAR		iVector,
		OUT	PINT_VECTOR	pVector );

VOID
SaveINTVector(
		IN	PIDT		pIdt,
		IN	UCHAR		iVector,
		IN	PINT_VECTOR	pVector );

VOID
HookInterrupt(UCHAR iVec, void (*InterruptHandler)( void ));

VOID
CopyInterrupt(UCHAR fromVec, UCHAR toVec);

VOID
BackupInterrupt(UCHAR iVec, OUT PINT_VECTOR Vec);

VOID
RestoreInterrupt(UCHAR iVec, IN PINT_VECTOR Vec);

extern void dtrace_hook_int(UCHAR ivec, void (*InterruptHandler)( void ), uintptr_t *paddr);

#endif