/*
 * semaphore.h
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
 * semaphore.h: win32 semaphore definition
 * Refered to Kernel-win32 code
 */

#ifndef _SEMAPHORE_H
#define _SEMAPHORE_H

#include "win32.h"
#include "io.h"
#include "ke.h"

#ifdef CONFIG_UNIFIED_KERNEL

#define SEMAPHORE_QUERY_STATE (0x0001)
#define SEMAPHORE_MODIFY_STATE (0x0002)
#define SEMAPHORE_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3)

#define SEMAPHORE_INCREMENT	1

VOID STDCALL
semaphore_init(struct ksemaphore* Semaphore,
		LONG Count,
		LONG Limit);

VOID
init_semaphore_implement(VOID);

NTSTATUS SERVICECALL
NtCreateSemaphore(OUT PHANDLE                   SemaphoreHandle,
		IN  ACCESS_MASK               DesiredAccess,
		IN  POBJECT_ATTRIBUTES        ObjectAttributes  OPTIONAL,
		IN  LONG                      InitialCount,
		IN  LONG                      MaximumCount);

NTSTATUS SERVICECALL
NtOpenSemaphore(OUT PHANDLE             SemaphoreHandle,
		IN  ACCESS_MASK         DesiredAccess,
		IN  POBJECT_ATTRIBUTES  ObjectAttributes);

LONG STDCALL
release_semaphore(struct ksemaphore *Semaphore,
		KPRIORITY Increment,
		LONG Adjustment,
		BOOLEAN Wait);

NTSTATUS SERVICECALL
NtReleaseSemaphore(IN  HANDLE SemaphoreHandle,
		IN  LONG   ReleaseCount,
		OUT PLONG  PreviousCount  OPTIONAL);

#endif /* CONFIG_UNIFIED_KERNEL */
#endif /* _SEMAPHORE_H */
