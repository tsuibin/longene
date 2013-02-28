/*
 * semaphore.c
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
 * semaphore.c: semaphore syscall functions
 * Refered to Kernel-win32 code
 */

#include "semaphore.h"
#include "unistr.h"
#include "apc.h"
#include "objwait.h"

#ifdef CONFIG_UNIFIED_KERNEL

POBJECT_TYPE semaphore_object_type = NULL;
EXPORT_SYMBOL(semaphore_object_type);

static GENERIC_MAPPING semaphore_mapping = {
	STANDARD_RIGHTS_READ    | SEMAPHORE_QUERY_STATE,
	STANDARD_RIGHTS_WRITE   | SEMAPHORE_MODIFY_STATE,
	STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE | SEMAPHORE_QUERY_STATE,
	SEMAPHORE_ALL_ACCESS};

static WCHAR semaphore_type_name[] = {'S', 'e', 'm', 'a', 'p', 'h', 'o', 'r', 'e', 0};

extern HANDLE base_dir_handle;

VOID
init_semaphore_implement(VOID)
{
	OBJECT_TYPE_INITIALIZER ObjectTypeInitializer;
	UNICODE_STRING Name;

	memset(&ObjectTypeInitializer, 0, sizeof(ObjectTypeInitializer));
	init_unistr(&Name, (PWSTR)semaphore_type_name);
	ObjectTypeInitializer.Length = sizeof(ObjectTypeInitializer);
	ObjectTypeInitializer.DefaultNonPagedPoolCharge = sizeof(struct ksemaphore);
	ObjectTypeInitializer.GenericMapping = semaphore_mapping;
	ObjectTypeInitializer.PoolType = NonPagedPool;
	ObjectTypeInitializer.ValidAccessMask = SEMAPHORE_ALL_ACCESS;
	ObjectTypeInitializer.UseDefaultObject = TRUE;
	create_type_object(&ObjectTypeInitializer, &Name, &semaphore_object_type);
}

VOID
STDCALL
semaphore_init(struct ksemaphore* Semaphore,
		LONG Count,
		LONG Limit)
{
	INIT_DISP_HEADER(&Semaphore->header,
		SemaphoreObject,
		sizeof(struct ksemaphore) / sizeof(ULONG),
		Count);

	Semaphore->limit = Limit;
}
EXPORT_SYMBOL(semaphore_init);

/*
 * open a semaphore object, creating if non-existent
 */
NTSTATUS
SERVICECALL
NtCreateSemaphore(OUT PHANDLE SemaphoreHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
		IN LONG InitialCount,
		IN LONG MaximumCount)
{
        HANDLE hSemaphore;
	struct ksemaphore* Semaphore;
	POBJECT_ATTRIBUTES obj_attr = NULL;
	NTSTATUS status = STATUS_SUCCESS;

	ktrace("\n");
	if (ObjectAttributes) {
		if ((ULONG)ObjectAttributes < TASK_SIZE) {
			if (copy_object_attr_from_user(ObjectAttributes, &obj_attr))
				return STATUS_NO_MEMORY;
		}
		else {
			obj_attr = ObjectAttributes;
		}
	}

	if (obj_attr) {
		if (obj_attr->RootDirectory)
		obj_attr->RootDirectory = base_dir_handle;
	}

	status = create_object(KernelMode,
			semaphore_object_type,
			obj_attr,
			KernelMode,
			NULL,
			sizeof(struct ksemaphore),
			0,
			0,
			(PVOID *)&Semaphore);

	if (ObjectAttributes && (ULONG)ObjectAttributes < TASK_SIZE)
		kfree(obj_attr);

	if (!NT_SUCCESS(status))
		return status;

	semaphore_init(Semaphore,
			InitialCount,
			MaximumCount);

	status = insert_object((PVOID)Semaphore,
			NULL,
			DesiredAccess,
			0,
			NULL,
			&hSemaphore);

	if (status == STATUS_OBJECT_NAME_EXISTS) {
		goto semaphore_exists;
	}

	if (!NT_SUCCESS(status))
		return status;

semaphore_exists:
	deref_object(Semaphore);

	if (SemaphoreHandle) {
		if ((ULONG)SemaphoreHandle < TASK_SIZE) {
        		if((copy_to_user(SemaphoreHandle, &hSemaphore, sizeof(HANDLE))))
				return STATUS_NO_MEMORY;
		}
		else
			*SemaphoreHandle = hSemaphore;
	}

	ktrace("*** [%d] (%d,%d) = %p\n",
		current->pid, InitialCount, MaximumCount, hSemaphore);

	return status;
}
EXPORT_SYMBOL(NtCreateSemaphore);

/*
 * open a semaphore object, failing if non-existent
 */
NTSTATUS
SERVICECALL
NtOpenSemaphore(OUT PHANDLE SemaphoreHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	HANDLE hSemaphore;
	POBJECT_ATTRIBUTES obj_attr = NULL;
	NTSTATUS status = STATUS_SUCCESS;

	ktrace("\n");
	if (ObjectAttributes) {
		if ((ULONG)ObjectAttributes < TASK_SIZE) {
			if (copy_object_attr_from_user(ObjectAttributes, &obj_attr))
				return STATUS_NO_MEMORY;
		}
		else {
			obj_attr = ObjectAttributes;
		}
	}

	if (obj_attr) {
		if (obj_attr->RootDirectory)
			obj_attr->RootDirectory = base_dir_handle;
	}

	status = open_object_by_name(obj_attr,
			semaphore_object_type,
			NULL,
			KernelMode,
			DesiredAccess,
			NULL,
			&hSemaphore);

	if (ObjectAttributes && (ULONG)ObjectAttributes < TASK_SIZE)
		kfree(obj_attr);

	if (!NT_SUCCESS(status))
		return status;

	if (SemaphoreHandle) {
		if ((ULONG)SemaphoreHandle < TASK_SIZE) {
			if ((copy_to_user(SemaphoreHandle, &hSemaphore, sizeof(HANDLE))))
				return STATUS_NO_MEMORY;
		}
		else
			*SemaphoreHandle = hSemaphore;
	}

	return status;
}
EXPORT_SYMBOL(NtOpenSemaphore);

LONG
STDCALL
release_semaphore(struct ksemaphore *Semaphore,
		KPRIORITY Increment,
		LONG Adjustment,
		BOOLEAN Wait)
{
	struct ethread *thread = get_current_ethread();
	LONG old;

	local_irq_disable();

	old = Semaphore->header.signal_state;
	Semaphore->header.signal_state = old + Adjustment;
	if (Semaphore->header.signal_state > Semaphore->limit)
	{
		Semaphore->header.signal_state = Semaphore->limit;
	}

	if (old == 0 && !list_empty(&Semaphore->header.wait_list_head))
		wait_test(&Semaphore->header, Increment);

	if (Wait == FALSE)
		local_irq_enable();
	else
		thread->tcb.wait_next = TRUE;
	
	/* FIXME: shouldn't return a NTSTATUS here */
	if (old + Adjustment > Semaphore->limit || Adjustment <= 0) return STATUS_SEMAPHORE_LIMIT_EXCEEDED;
	else return old;
}
EXPORT_SYMBOL(release_semaphore);

/*
 * release a semaphore (increment count up to max limit)
 */
NTSTATUS
SERVICECALL
NtReleaseSemaphore(IN HANDLE SemaphoreHandle,
		IN LONG ReleaseCount,
		OUT PLONG PreviousCount OPTIONAL)
{
        struct ksemaphore* semaphore;
	LONG old;
	NTSTATUS status = STATUS_SUCCESS;

	ktrace("\n");
	if (ReleaseCount <= 0 || ReleaseCount > 0x7FFFFFFF)
		return STATUS_UNSUCCESSFUL;
	status = ref_object_by_handle(SemaphoreHandle,
			SEMAPHORE_MODIFY_STATE,
			semaphore_object_type,
			KernelMode,
			(PVOID *)&semaphore,
			NULL);

	if (!NT_SUCCESS(status))
		return status;

	old = release_semaphore(semaphore,
			IO_NO_INCREMENT,
			ReleaseCount,
			FALSE);
	deref_object(semaphore);

	if (PreviousCount) {
		if ((ULONG)PreviousCount < TASK_SIZE) {
			if ((copy_to_user(PreviousCount, &old, sizeof(LONG))))
				return STATUS_NO_MEMORY;
		}
		else
			*PreviousCount = old;
	}

	return status;
}
EXPORT_SYMBOL(NtReleaseSemaphore);
#endif
