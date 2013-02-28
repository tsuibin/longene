/*
 * ntobj.c
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
 * ntobj.c:
 * Refered to ReactOS code
 */
#include "handle.h"
#include "thread.h"

#ifdef CONFIG_UNIFIED_KERNEL
extern POBJECT_TYPE process_object_type;
extern POBJECT_TYPE thread_object_type;
extern POBJECT_TYPE symbol_link_type;

NTSTATUS
SERVICECALL
NtDuplicateObject(IN HANDLE SourceProcessHandle,
		IN HANDLE SourceHandle,
		IN HANDLE TargetProcessHandle,
		OUT PHANDLE TargetHandle OPTIONAL,
		IN ACCESS_MASK DesiredAccess,
		IN ULONG InheritHandle,
		IN ULONG Options)
{
	struct eprocess *SourceProcess, *TargetProcess;
	HANDLE hTarget;
	MODE previous_mode;
	NTSTATUS Status;

	ktrace("\n");
	Status = ref_object_by_handle(SourceProcessHandle,
			PROCESS_DUP_HANDLE,
			NULL,
			KernelMode,
			(PVOID *)&SourceProcess,
			NULL);
	if (!NT_SUCCESS(Status))
		return Status;

	Status = ref_object_by_handle(TargetProcessHandle,
			PROCESS_DUP_HANDLE,
			NULL,
			KernelMode,
			(PVOID *)&TargetProcess,
			NULL);
	if (!NT_SUCCESS(Status))
		goto cleanup_source;

	if (SourceHandle == NtCurrentThread() || SourceHandle == NtCurrentProcess()) {
		PVOID ObjectBody;
		POBJECT_TYPE ObjectType;

		ObjectType = (SourceHandle == NtCurrentThread()) ? thread_object_type : process_object_type;

		Status = ref_object_by_handle(SourceHandle,
					0,
					ObjectType,
					KernelMode,
					&ObjectBody,
					NULL);
		if (!NT_SUCCESS(Status))
			goto cleanup_target;

		if (Options & DUPLICATE_SAME_ACCESS)
			DesiredAccess = ((ObjectType == thread_object_type) ? THREAD_ALL_ACCESS : PROCESS_ALL_ACCESS);
		else {
			/* FIXME */
#if 0
			if (DesiredAccess & GENERIC_ANY)
				RtlMapGenericMask(&DesiredAccess, &ObjectType->TypeInfo.GenericMapping);
#endif
		}

		Status = create_handle(TargetProcess,
				ObjectBody,
				DesiredAccess,
				InheritHandle,
				&hTarget);

		deref_object(ObjectBody);
		if (!NT_SUCCESS(Status))
			goto cleanup_target;

		if (Options & DUPLICATE_CLOSE_SOURCE)
			delete_handle(SourceProcess->object_table, SourceHandle);
	}
	else {
		Status = duplicate_object(SourceProcess,
				TargetProcess,
				SourceHandle,
				&hTarget,
				DesiredAccess,
				InheritHandle,
				Options);
		if (!NT_SUCCESS(Status))
			goto cleanup_target;
	}

	if (TargetHandle) {
		previous_mode = (unsigned long)TargetHandle > TASK_SIZE ? KernelMode: UserMode;
		if (previous_mode == UserMode) {
			if (copy_to_user(TargetHandle, &hTarget, sizeof(HANDLE))) {
				Status = STATUS_NO_MEMORY;
				goto cleanup_target;
			}
		}
		else
			*TargetHandle = hTarget;
	}
		
cleanup_target:
	deref_object(TargetProcess);
cleanup_source:
	deref_object(SourceProcess);
	return Status;
} /* end NtDuplicateObject */
EXPORT_SYMBOL(NtDuplicateObject);

NTSTATUS
SERVICECALL
NtSetInformationObject(IN HANDLE ObjectHandle,
		IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
		IN PVOID ObjectInformation,
		IN ULONG Length)
{
	PVOID ObjectBody;
	OBJECT_HANDLE_ATTRIBUTE_INFORMATION Information;
	NTSTATUS Status;

	ktrace("\n");
	if (ObjectInformationClass != ObjectHandleInformation ||
			Length != sizeof(OBJECT_HANDLE_ATTRIBUTE_INFORMATION))
		return STATUS_INVALID_PARAMETER;

	if ((ULONG)ObjectInformation < TASK_SIZE) {
		if (copy_from_user(&Information, ObjectInformation,
					sizeof(OBJECT_HANDLE_ATTRIBUTE_INFORMATION)))
			return STATUS_NO_MEMORY;
	}
	else
		Information = *(POBJECT_HANDLE_ATTRIBUTE_INFORMATION)ObjectInformation;

	Status = ref_object_by_handle(ObjectHandle,
			0,
			NULL,
			KernelMode,
			&ObjectBody,
			NULL);
	if (!NT_SUCCESS(Status))
		return Status;

	Status = set_handle_attr(ObjectHandle, &Information);

	deref_object(ObjectBody);

	return Status;
} /* end NtSetInformationObject */
EXPORT_SYMBOL(NtSetInformationObject);

NTSTATUS
SERVICECALL
NtQueryObject(IN HANDLE ObjectHandle,
	IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
	OUT PVOID ObjectInformation,
	IN ULONG Length,
	OUT PULONG ResultLength OPTIONAL)
{
	OBJECT_HANDLE_INFORMATION HandleInfo;
	POBJECT_HEADER ObjectHeader;
	ULONG InfoLength;
	PVOID ObjectBody;
	MODE previous_mode;
	NTSTATUS Status;

	previous_mode = (unsigned long)ObjectInformation > TASK_SIZE ? KernelMode : UserMode;

	Status = ref_object_by_handle(ObjectHandle,
			0,
			NULL,
			KernelMode,
			&ObjectBody,
			&HandleInfo);
	if (!NT_SUCCESS(Status))
		return Status;

	ObjectHeader = BODY_TO_HEADER(ObjectBody);

	switch (ObjectInformationClass) {
		case ObjectBasicInformation:
			if (Length != sizeof(OBJECT_BASIC_INFORMATION)) {
				Status = STATUS_INFO_LENGTH_MISMATCH;
				goto out;
			}
			else {
				OBJECT_BASIC_INFORMATION BasicInfo;

				BasicInfo.Attributes = HandleInfo.HandleAttributes;
				BasicInfo.GrantedAccess = HandleInfo.GrantedAccess;
				BasicInfo.HandleCount = ObjectHeader->HandleCount;
				BasicInfo.PointerCount = ObjectHeader->PointerCount;
				BasicInfo.PagedPoolUsage = 0;
				BasicInfo.NonPagedPoolUsage = 0;
				BasicInfo.NameInformationLength = 0;
				BasicInfo.TypeInformationLength = 0;
				BasicInfo.SecurityDescriptorLength = 0;
				if (ObjectHeader->Type == symbol_link_type)
					BasicInfo.CreateTime.QuadPart = 
						((POBJECT_SYMBOLIC_LINK)ObjectBody)->CreationTime.QuadPart;
				else
					BasicInfo.CreateTime.QuadPart = (ULONGLONG)0;
				InfoLength = sizeof(OBJECT_BASIC_INFORMATION);

				/* Just for debug, so that we can know its type */
				BasicInfo.Reserved[0] = ((struct object *)ObjectBody)->header.type;
				if (previous_mode == UserMode) {
					if (copy_to_user(ObjectInformation, &BasicInfo, InfoLength)) {
						Status = STATUS_NO_MEMORY;
						goto out;
					}
				}
				else
					*(POBJECT_BASIC_INFORMATION)ObjectInformation = BasicInfo;
			}
			break;

		case ObjectNameInformation:
			if (Length < 0) {
				Status = STATUS_INFO_LENGTH_MISMATCH;
				goto out;
			}
			else {
				OBJECT_NAME_INFORMATION NameInfo;

				if (previous_mode == UserMode) {
					if (copy_from_user(&NameInfo, ObjectInformation,
							sizeof(OBJECT_NAME_INFORMATION))) {
						Status = STATUS_NO_MEMORY;
						goto out;
					}
				}

				Status = query_name_string(ObjectBody,
						&NameInfo,
						Length,
						&InfoLength);

				if (previous_mode == UserMode) {
					if (copy_to_user(ObjectInformation, &NameInfo, sizeof(NameInfo))) {
						Status = STATUS_NO_MEMORY;
						goto out;
					}
				}
				else
					*(POBJECT_NAME_INFORMATION)ObjectInformation = NameInfo;
			}
			break;

		case ObjectHandleInformation:
			if (Length != sizeof(OBJECT_HANDLE_ATTRIBUTE_INFORMATION)) {
				Status = STATUS_INFO_LENGTH_MISMATCH;
				goto out;
			}
			else {
				OBJECT_HANDLE_ATTRIBUTE_INFORMATION ObjectInfo;

				Status = query_handle_attr(ObjectHandle, &ObjectInfo);

				InfoLength = sizeof(OBJECT_HANDLE_ATTRIBUTE_INFORMATION);

				if (previous_mode == UserMode) {
					if (copy_to_user(ObjectInformation, &ObjectInfo, InfoLength)) {
						Status = STATUS_NO_MEMORY;
						goto out;
					}
				}
				else
					*(POBJECT_HANDLE_ATTRIBUTE_INFORMATION)ObjectInformation = ObjectInfo;
			}
			break;
		default:
			Status = STATUS_NOT_IMPLEMENTED;
			goto out;
	}

	deref_object(ObjectBody);

	if (ResultLength) {
		if (previous_mode == UserMode) {
			if (copy_to_user(ResultLength, &InfoLength, sizeof(ULONG)))
				return STATUS_NO_MEMORY;
		}
		else
			*ResultLength = InfoLength;
	}

	return Status;

out:
	deref_object(ObjectBody);
	return Status;
} /* end NtQueryObject */
EXPORT_SYMBOL(NtQueryObject);

NTSTATUS
SERVICECALL
NtMakeTemporaryObject(IN HANDLE ObjectHandle)
{
	PVOID ObjectBody;
	NTSTATUS Status;

	ktrace("\n");
	Status = ref_object_by_handle(ObjectHandle,
			0,
			NULL,
			KernelMode,
			&ObjectBody,
			NULL);
	if (!NT_SUCCESS(Status))
		return Status;

	set_permanent_object(ObjectBody, FALSE);

	deref_object(ObjectBody);

	return Status;
} /* end NtMakeTemporaryObject */
EXPORT_SYMBOL(NtMakeTemporaryObject);

NTSTATUS
SERVICECALL
NtMakePermanentObject(IN HANDLE ObjectHandle)
{
	PVOID ObjectBody;
	NTSTATUS Status;

	ktrace("\n");
	Status = ref_object_by_handle(ObjectHandle,
			0,
			NULL,
			KernelMode,
			&ObjectBody,
			NULL);
	if (!NT_SUCCESS(Status))
		return Status;

	set_permanent_object(ObjectBody, TRUE);

	deref_object(ObjectBody);

	return Status;
} /* end NtMakePermanentObject */
EXPORT_SYMBOL(NtMakePermanentObject);
#endif
