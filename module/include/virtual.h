/*
 * virtual.h
 *
 * Copyright (C) 2006  Insigma Co., Ltd
 *
 * This software has been developed while working on the Linux Unified Kernel
 * project (http://www.longene.org) in the Insigma Research Institute, 
 * which is a subdivision of Insigma Co., Ltd (http://www.insigma.com.cn).
 * 
 * The project is sponsored by Insigma Co., Ltd.
 *
 * The authors can be reached at linux@insigma.com.cn.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of  the GNU General  Public License as published by the
 * Free Software Foundation; either version 2 of the  License, or (at your
 * option) any later version.
 *
 * Revision History:
 *   Jan 2006 - Created.
 */

/* 
 * virtual.h:
 * Refered to ReactOS code
 */
 
#ifndef _VIRTUAL_H
#define _VIRTUAL_H

#include "win32.h"
#include <asm/page.h>
#include <asm/pgtable.h>

#ifdef CONFIG_UNIFIED_KERNEL

typedef struct _MEMORY_BASIC_INFORMATION {
	PVOID BaseAddress;
	PVOID AllocationBase;
	DWORD AllocationProtect;
	DWORD RegionSize;
	DWORD State;
	DWORD Protect;
	DWORD Type;
} MEMORY_BASIC_INFORMATION,*PMEMORY_BASIC_INFORMATION;

typedef const int CINT;

#define _PAGE_NOACCESS			0x00000001     
#define _PAGE_READONLY			0x00000002
#define _PAGE_READWRITE			0x00000004     
#define _PAGE_WRITECOPY			0x00000008     
#define _PAGE_EXECUTE			0x00000010     
#define _PAGE_EXECUTE_READ		0x00000020     
#define _PAGE_EXECUTE_READWRITE		0x00000040     
#define _PAGE_EXECUTE_WRITECOPY		0x00000080     
#define _PAGE_GUARD			0x00000100     
#define _PAGE_NOCACHE			0x00000200     
#define _PAGE_WRITECOMBINE		0x00000400

#define MEM_COMMIT			0x00001000     
#define MEM_RESERVE			0x00002000     
#define MEM_DECOMMIT			0x00004000     
#define MEM_RELEASE			0x00008000     
#define MEM_FREE			0x00010000     
#define MEM_PRIVATE			0x00020000     
#define MEM_MAPPED			0x00040000     
#define MEM_RESET			0x00080000     
#define MEM_TOP_DOWN			0x00100000
#define MEM_SYSTEM			0x80000000
#define MEM_4MB_PAGES			0x80000000     
#define	MEM_IMAGE			_SEC_IMAGE

#define MAP_RESERVE     0x10000000
#define MAP_TOP_DOWN    0x20000000

#define	WIN32_TASK_SIZE	0x80000000
#define	WIN32_STACK_LIMIT	0x200000
#define	WIN32_UNMAPPED_BASE	0x20000000
#define	WIN32_LOWEST_ADDR	0x100000
#define	WIN32_SYSTEM_HEAP_SIZE	0x1000000

#define	PAGE_ALLOC_MASK \
	(_PAGE_NOACCESS | _PAGE_READONLY | _PAGE_READWRITE \
	 | _PAGE_EXECUTE | _PAGE_EXECUTE_READ | _PAGE_EXECUTE_READWRITE)
#define	PAGE_PROT_MASK \
	(_PAGE_NOACCESS | _PAGE_READONLY | _PAGE_READWRITE | _PAGE_WRITECOPY \
	 | _PAGE_EXECUTE | _PAGE_EXECUTE_READ | _PAGE_EXECUTE_READWRITE | _PAGE_EXECUTE_WRITECOPY)
#define PAGE_ALL_MASK	\
	(_PAGE_PROT_MASK | _PAGE_GUARD | _PAGE_NOCACHE | _PAGE_WRITECOMBINE)

#define MEMORY_AREA_INVALID              (0)
#define MEMORY_AREA_SECTION_VIEW         (1)
#define MEMORY_AREA_CONTINUOUS_MEMORY    (2)
#define MEMORY_AREA_NO_CACHE             (3)
#define MEMORY_AREA_IO_MAPPING           (4)
#define MEMORY_AREA_SYSTEM               (5)
#define MEMORY_AREA_MDL_MAPPING          (7)
#define MEMORY_AREA_VIRTUAL_MEMORY       (8)
#define MEMORY_AREA_CACHE_SEGMENT        (9)
#define MEMORY_AREA_SHARED_DATA          (10)
#define MEMORY_AREA_KERNEL_STACK         (11)
#define MEMORY_AREA_PAGED_POOL           (12)
#define MEMORY_AREA_NO_ACCESS            (13)
#define MEMORY_AREA_PEB_OR_TEB           (14)

#define	RESERVE_PAGE_SIZE	(16 * PAGE_SIZE)
#define	RESERVE_PAGE_SHIFT	(PAGE_SHIFT + 4)
#define	RESERVE_PAGE_MASK	(~(RESERVE_PAGE_SIZE - 1))

typedef LARGE_INTEGER PHYSICAL_ADDRESS, *PPHYSICAL_ADDRESS;

unsigned long win32_do_mmap_pgoff(struct task_struct *task, struct file *filp,
		unsigned long addr, unsigned long size, unsigned long prot,
		unsigned long flags, unsigned long pgoff);

NTSTATUS SERVICECALL
NtQueryVirtualMemory (IN HANDLE ProcessHandle,
		IN PVOID Address,
		IN CINT VirtualMemoryInformationClass,
		OUT PVOID VirtualMemoryInformation,
		IN ULONG Length,
		OUT PULONG UnsafeResultLength);

NTSTATUS SERVICECALL
NtAllocateVirtualMemory(IN HANDLE ProcessHandle,
			IN OUT PVOID*  UBaseAddress,
			IN ULONG ZeroBits,
			IN OUT PULONG URegionSize,
			IN ULONG AllocationType,
			IN ULONG Protect);

NTSTATUS SERVICECALL
NtWriteVirtualMemory(IN HANDLE ProcessHandle,
		IN PVOID BaseAddress,
		IN PVOID Buffer,
		IN ULONG NumberOfBytesToWrite,
		OUT PULONG NumberOfBytesWritten OPTIONAL);

NTSTATUS SERVICECALL
NtReadVirtualMemory(IN HANDLE ProcessHandle,
		IN PVOID BaseAddress,
		OUT PVOID Buffer,
		IN ULONG NumberOfBytesToRead,
		OUT PULONG NumberOfBytesRead OPTIONAL);

NTSTATUS SERVICECALL
NtFreeVirtualMemory(IN HANDLE ProcessHandle,
		IN PVOID*  PBaseAddress,
		IN PULONG PRegionSize,
		IN ULONG FreeType);

#endif /* CONFIG_UNIFIED_KERNEL */
#endif /* _VIRTUAL_H */
