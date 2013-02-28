/*
 * mutex.h
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
 * mutex.h: win32 mutex definition
 * Refered to Kernel-win32 code
 */

#ifndef _MUTEX_H
#define _MUTEX_H

#include <linux/module.h>
#include "object.h"
#include "ke.h"

#ifdef CONFIG_UNIFIED_KERNEL

#define MUTANT_QUERY_STATE	0x0001
#define MUTANT_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | MUTANT_QUERY_STATE)
#define MUTANT_INCREMENT	1

#define init_fast_mutex(mutex) {	\
	(mutex)->Count = 1;		\
	(mutex)->Owner = NULL;		\
	atomic_set(&(mutex)->Contention, 0);	\
	event_init(&(mutex)->Event, SynchronizationEvent, FALSE);	\
}
	
VOID STDCALL
mutant_init(IN struct kmutant* Mutant,
		IN BOOLEAN InitialOwner);

VOID
init_mutant_implement(VOID);

NTSTATUS SERVICECALL
NtCreateMutant(OUT PHANDLE MutantHandle,
               IN ACCESS_MASK DesiredAccess,
               IN POBJECT_ATTRIBUTES ObjectAttributes  OPTIONAL,
               IN BOOLEAN InitialOwner);

NTSTATUS SERVICECALL
NtOpenMutant(OUT PHANDLE 		MutantHandle,
             IN  ACCESS_MASK 		DesiredAccess,
             IN  POBJECT_ATTRIBUTES 	ObjectAttributes);

LONG STDCALL
release_mutant(IN struct kmutant *Mutant,
	IN KPRIORITY Increment,
	IN BOOLEAN Abandon,
	IN BOOLEAN Wait);

NTSTATUS SERVICECALL
NtReleaseMutant(IN HANDLE MutantHandle,
                IN PLONG  PreviousCount  OPTIONAL);

VOID
delete_mutant(PVOID ObjectBody);

VOID
acquire_fmutex_unsafe(PFAST_MUTEX FastMutex);

VOID
release_fmutex_unsafe(PFAST_MUTEX FastMutex);
#endif /* CONFIG_UNIFIED_KERNEL */
#endif /* _MUTEX_H */
