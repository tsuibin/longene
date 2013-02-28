/*
 * section.h
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
 * section.h: section syscall functions
 * Refered to Kernel-win32 code
 */

#ifndef _SECTION_H
#define _SECTION_H

#include <linux/module.h>
#include <linux/sched.h>
#include "file.h"

#ifdef CONFIG_UNIFIED_KERNEL
/*
 * BaseAddress need to aligned to 64k
 */
#define	BASE_ADDRESS_ALIGN	(PAGE_SIZE << 4)

#define _SEC_FILE			0x00800000     
#define _SEC_IMAGE			0x01000000     
#define _SEC_VLM			0x02000000     
#define _SEC_RESERVE			0x04000000     
#define _SEC_COMMIT			0x08000000     
#define _SEC_NOCACHE			0x10000000     

#define	SECTION_EXTEND_SIZE	0x10
#define	SECTION_MAP_READ	0x04
#define	SECTION_MAP_WRITE	0x02
#define	SECTION_QUERY		0x01
#define	SECTION_MAP_EXECUTE	0x08
#define	SECTION_ALL_ACCESS	0xf001f

/*
 * PE Image File Section
 * TODO. not implemented in this version
 */
struct win32_image_section
{
	unsigned long           wis_rva;        /* relative virtual address */
	off_t                   wis_fpos;       /* file position */
	size_t                  wis_size;       /* section size */
	size_t                  wis_rawsize;    /* raw data size */
	unsigned long           wis_padrva;     /* padding RVA */
	unsigned long           wis_flags;      /* specific flags */
	unsigned long           wis_protect;    /* specific protects */
	unsigned long           wis_character;  /* characteristics */
};

/*
 * memory map section object definition
 */
struct win32_section {
	struct win32_file	*ws_wfile;	/* the wine file object */
	struct file		*ws_file;	/* linux file struct */

	unsigned long		ws_alloctype;	/* Allocation type */
	unsigned long		ws_protect;	/* page protect */
	unsigned long		ws_access;	/* Desired access */
	unsigned long		ws_flags;	/* MAP_PRIVATE etc. */
	unsigned long		ws_len;		/* section len */
	unsigned long		ws_pagelen;	/* page len, aligned to PAGE_SIZE */

	int		(*ws_mmap)(struct task_struct *tsk, struct win32_section *,
			unsigned long *, unsigned long, unsigned long, unsigned long);	/* mmap func */

	/* TODO: this field used for PE Image */
	unsigned long		ws_imagebase;
	unsigned long		ws_realbase;
	int			ws_nsecs;
	struct win32_image_section	*ws_sections;
	struct win32_image_section	*ws_sectend;
	unsigned long		ws_stackresv;
	unsigned long		ws_stackcommit;
	unsigned short		ws_subsystem;
	unsigned short		ws_majorver;
	unsigned short		ws_minorver;
	unsigned short		ws_executable;
	unsigned long		ws_entrypoint;
	unsigned short		ws_imagecharacter;
	unsigned short		ws_machine;
	int			ws_secoff;

	int		(*ws_munmap)(struct win32_section *);
};

typedef struct _SECTION_BASIC_INFORMATION
{
    PVOID           BaseAddress;
    ULONG           Attributes;
    LARGE_INTEGER   Size;
} SECTION_BASIC_INFORMATION, *PSECTION_BASIC_INFORMATION;

typedef struct _SECTION_IMAGE_INFORMATION
{
    ULONG     EntryPoint;
    ULONG     Unknown1;
    ULONG_PTR StackReserve;
    ULONG_PTR StackCommit;
    ULONG     Subsystem;
    USHORT    MinorSubsystemVersion;
    USHORT    MajorSubsystemVersion;
    ULONG     Unknown2;
    ULONG     Characteristics;
    USHORT    ImageNumber;
    BOOLEAN   Executable;
    UCHAR     Unknown3;
    ULONG     Unknown4[3];
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;

extern POBJECT_TYPE section_object_type;
int data_section_setup(struct win32_section *ws);
int image_section_setup(struct win32_section *ws);

NTSTATUS
SERVICECALL
NtCreateSection(
		OUT PHANDLE  SectionHandle,
		IN ACCESS_MASK  DesiredAccess,
		IN POBJECT_ATTRIBUTES  ObjectAttributes OPTIONAL,
		IN PLARGE_INTEGER  MaximumSize OPTIONAL,
		IN ULONG  SectionPageProtection,
		IN ULONG  AllocationAttributes,
		IN HANDLE  FileHandle OPTIONAL
		);

NTSTATUS
SERVICECALL
NtMapViewOfSection(
		IN HANDLE  SectionHandle,
		IN HANDLE  ProcessHandle,
		IN OUT PVOID  *BaseAddress,
		IN ULONG  ZeroBits,
		IN ULONG  CommitSize,
		IN OUT PLARGE_INTEGER  SectionOffset  OPTIONAL,
		IN OUT PSIZE_T  ViewSize,
		IN SECTION_INHERIT  InheritDisposition,
		IN ULONG  AllocationType,
		IN ULONG  Protect
		);

NTSTATUS
SERVICECALL
NtUnmapViewOfSection(
		IN HANDLE  ProcessHandle,
		IN PVOID  BaseAddress
		);

NTSTATUS
STDCALL
map_section_view(
		IN PVOID  SectionObject,
		IN struct eprocess*  Process,
		IN OUT PVOID  *BaseAddress,
		IN ULONG  ZeroBits,
		IN ULONG  CommitSize,
		IN OUT PLARGE_INTEGER  SectionOffset  OPTIONAL,
		IN OUT PSIZE_T  ViewSize,
		IN SECTION_INHERIT  InheritDisposition,
		IN ULONG  AllocationType,
		IN ULONG  Protect
		);

NTSTATUS
STDCALL
unmap_section_view(struct eprocess *process, struct mm_struct *mm, unsigned long addr);

#endif /* CONFIG_UNIFIED_KERNEL */
#endif /* _SECTION_H */
