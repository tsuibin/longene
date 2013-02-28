/*
 * mutex.c
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
 * mutex.c: mutex syscall functions
 * Refered to Kernel-win32 code
 */

#include "mutex.h"
#include "event.h"
#include "unistr.h"

#ifdef CONFIG_UNIFIED_KERNEL

POBJECT_TYPE mutant_object_type = NULL;
EXPORT_SYMBOL(mutant_object_type);

static GENERIC_MAPPING mutant_mapping = {
	STANDARD_RIGHTS_READ    | SYNCHRONIZE | MUTANT_QUERY_STATE,
	STANDARD_RIGHTS_WRITE   | SYNCHRONIZE,
	STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE | MUTANT_QUERY_STATE,
	MUTANT_ALL_ACCESS};

static WCHAR mutant_type_name[] = {'M', 'u', 't', 'a', 'n', 't', 0};

extern void display_object_dir(POBJECT_DIRECTORY DirectoryObject, LONG Depth);

extern HANDLE base_dir_handle;

VOID
init_mutant_implement(VOID)
{
	OBJECT_TYPE_INITIALIZER ObjectTypeInitializer;
	UNICODE_STRING Name;

	memset(&ObjectTypeInitializer, 0, sizeof(ObjectTypeInitializer));
	init_unistr(&Name, (PWSTR)mutant_type_name);
	ObjectTypeInitializer.Length = sizeof(ObjectTypeInitializer);
	ObjectTypeInitializer.DefaultNonPagedPoolCharge = sizeof(struct kmutant);
	ObjectTypeInitializer.GenericMapping = mutant_mapping;
	ObjectTypeInitializer.PoolType = NonPagedPool;
	ObjectTypeInitializer.ValidAccessMask = MUTANT_ALL_ACCESS;
	ObjectTypeInitializer.UseDefaultObject = TRUE;
	ObjectTypeInitializer.DeleteProcedure = delete_mutant;
	create_type_object(&ObjectTypeInitializer, &Name, &mutant_object_type);
}

VOID
STDCALL
mutant_init(IN struct kmutant* Mutant,
		IN BOOLEAN InitialOwner)
{
	ULONG Signaled = TRUE;
	struct ethread* thread = NULL;

	if (InitialOwner == TRUE) {
		Signaled = FALSE;

		thread = get_current_ethread(); 

		local_irq_disable();
		list_add_tail(&Mutant->mutant_list_entry, &thread->tcb.mutant_list_head);
		local_irq_enable();
	}

	INIT_DISP_HEADER(&Mutant->header,
			MutantObject,
			sizeof(struct kmutant) / sizeof(ULONG),
			Signaled);

	Mutant->owner_thread = (struct kthread *)thread;
	Mutant->abandoned = FALSE;
	Mutant->apc_disable = 0;
}
EXPORT_SYMBOL(mutant_init);
		
/*
 * open a mutex object, creating if non-existent
 */
NTSTATUS
SERVICECALL
NtCreateMutant(OUT PHANDLE MutantHandle,
               IN ACCESS_MASK DesiredAccess,
               IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
               IN BOOLEAN InitialOwner)
{
	HANDLE hMutant;
	struct kmutant* Mutant;
	NTSTATUS Status = STATUS_SUCCESS;
	POBJECT_ATTRIBUTES	obj_attr = NULL;

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

	Status = create_object(KernelMode,
			mutant_object_type,
			obj_attr,
			KernelMode,
			NULL,
			sizeof(struct kmutant),
			0,
			0,
			(PVOID *)&Mutant);

	if (ObjectAttributes && (ULONG)ObjectAttributes < TASK_SIZE)
		kfree(obj_attr);

	if (!NT_SUCCESS(Status))
		return Status;

	mutant_init(Mutant, InitialOwner);

	Status = insert_object((PVOID)Mutant,
			NULL,
			DesiredAccess,
			0,
			NULL,
			&hMutant);

	if (Status == STATUS_OBJECT_NAME_EXISTS) {
		goto mutant_exists;
	}

	if (!NT_SUCCESS(Status))
		return Status;

mutant_exists:
	deref_object(Mutant);

	if (MutantHandle) {
		if ((ULONG)MutantHandle < TASK_SIZE) {
			if (copy_to_user(MutantHandle, &hMutant, sizeof(HANDLE)))
				Status = STATUS_NO_MEMORY;
		}
		else
			*MutantHandle = hMutant;
	}

	return Status;
} /* end NtCreateMutant() */
EXPORT_SYMBOL(NtCreateMutant);

/*
 * open a mutex object, failing if non-existent
 */
NTSTATUS
SERVICECALL
NtOpenMutant(OUT PHANDLE MutantHandle,
             IN ACCESS_MASK DesiredAccess,
             IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	HANDLE hMutant;
	POBJECT_ATTRIBUTES obj_attr = NULL;
	NTSTATUS Status = STATUS_SUCCESS;
	
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

	Status = open_object_by_name(obj_attr,
			mutant_object_type,
			NULL,
			KernelMode,
			DesiredAccess,
			NULL,
			&hMutant);

	if (ObjectAttributes && (ULONG)ObjectAttributes < TASK_SIZE)
		kfree(obj_attr);

	if (!NT_SUCCESS(Status))
		return Status;

	if (MutantHandle) {
		if ((ULONG)MutantHandle < TASK_SIZE) {
			if ((copy_to_user(MutantHandle, &hMutant, sizeof(HANDLE))))
			return STATUS_NO_MEMORY;
		}
		else
			*MutantHandle = hMutant;
	}
	
	return Status;
} /* end NtOpenMutant() */
EXPORT_SYMBOL(NtOpenMutant);

LONG
STDCALL
release_mutant(IN struct kmutant *Mutant,
	IN KPRIORITY Increment,
	IN BOOLEAN Abandon,
	IN BOOLEAN Wait)
{
	struct ethread *thread = get_current_ethread();
	LONG prev;

	local_irq_disable();
	prev = Mutant->header.signal_state;

	if (Abandon == FALSE)
		Mutant->header.signal_state++;
	else {
		Mutant->header.signal_state = 1;
		Mutant->abandoned = TRUE;
	}

	if (Mutant->header.signal_state == 1) {
		if (prev <= 0) {
			list_del(&Mutant->mutant_list_entry);

			thread->tcb.kernel_apc_disable += Mutant->apc_disable;
		}

		Mutant->owner_thread = NULL;

		if (!list_empty(&Mutant->header.wait_list_head))
			wait_test(&Mutant->header, Increment);
	}

	if (Wait == FALSE)
		local_irq_enable();
	else
		thread->tcb.wait_next = TRUE;

	return prev;
}
EXPORT_SYMBOL(release_mutant);

/*
 * release the state of a mutex
 */
NTSTATUS
SERVICECALL
NtReleaseMutant(IN HANDLE MutantHandle,
                OUT PLONG PreviousCount OPTIONAL)
{
	struct ethread *thread = get_current_ethread();
	struct kmutant *mutant;
	LONG prev;
	NTSTATUS status = STATUS_SUCCESS;

	ktrace("\n");
	if(!thread)
		return STATUS_UNSUCCESSFUL;

	status = ref_object_by_handle(MutantHandle,
				MUTANT_QUERY_STATE,
				mutant_object_type,
				KernelMode,
				(PVOID *)&mutant,
				NULL);

	if (!NT_SUCCESS(status))
		return status;

	prev = release_mutant(mutant,
			MUTANT_INCREMENT,
			FALSE,
			FALSE);
	deref_object(mutant);

	if (PreviousCount) {
		if ((ULONG)PreviousCount < TASK_SIZE) {
			if ((copy_to_user(PreviousCount, &prev, sizeof(ULONG))))
				return STATUS_NO_MEMORY;
		}
		else
			*PreviousCount = prev;
	}

	return status;
} /* end NtReleaseMutant() */
EXPORT_SYMBOL(NtReleaseMutant);

VOID
delete_mutant(PVOID ObjectBody)
{
	release_mutant((struct kmutant *)ObjectBody,
			MUTANT_INCREMENT,
			TRUE,
			FALSE);
}
EXPORT_SYMBOL(delete_mutant);

VOID
acquire_fmutex_unsafe(PFAST_MUTEX FastMutex)
{
	atomic_inc(&FastMutex->Contention);
	while (xchg(&FastMutex->Count, 0) == 0)
		wait_for_single_object(&FastMutex->Event,
				Executive,
				KernelMode,
				FALSE,
				NULL);
	atomic_dec(&FastMutex->Contention);
	FastMutex->Owner = (struct kthread *)get_current_ethread(); 
}

VOID
release_fmutex_unsafe(PFAST_MUTEX FastMutex)
{
	FastMutex->Owner = NULL;
	xchg(&FastMutex->Count, 1);
	if (atomic_read(&FastMutex->Contention) > 0)
		set_event(&FastMutex->Event, 0, FALSE);
}
#endif
