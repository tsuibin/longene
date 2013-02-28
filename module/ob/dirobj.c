/*
 * dirobj.c
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
 * dirobj.c:
 * Refered to ReactOS code
 */
#include "object.h"
#include "unistr.h"

#ifdef CONFIG_UNIFIED_KERNEL

#define DIRECTORY_QUERY (0x0001)

NTSTATUS SERVICECALL
NtCreateDirectoryObject(OUT PHANDLE DirectoryHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	POBJECT_DIRECTORY Directory;
	HANDLE hDirectory;
	OBJECT_ATTRIBUTES obj_attr;
	UNICODE_STRING obj_name;
	KPROCESSOR_MODE PreviousMode = KernelMode;
	NTSTATUS Status = STATUS_SUCCESS;
	
	if ((ULONG)ObjectAttributes < TASK_SIZE) {
		if ((copy_from_user(&obj_attr, ObjectAttributes, sizeof(OBJECT_ATTRIBUTES))))
			return STATUS_NO_MEMORY;
		if ((copy_from_user(&obj_name, ObjectAttributes->ObjectName, sizeof(UNICODE_STRING))))
			return STATUS_NO_MEMORY;
	} else {
		obj_attr = *ObjectAttributes;
		obj_name = *ObjectAttributes->ObjectName;
	}
	obj_attr.ObjectName = &obj_name;
	
	*DirectoryHandle = NULL;

	Status = create_object(PreviousMode,
			dir_object_type,
			&obj_attr,
			PreviousMode,
			NULL,
			sizeof(OBJECT_DIRECTORY),
			0,
			0,
			(PVOID*)&Directory);

	if (NT_SUCCESS(Status)) {
		Status = insert_object((PVOID)Directory,
				NULL,
				DesiredAccess,
				0,
				NULL,
				&hDirectory);
		deref_object(Directory);

		if (NT_SUCCESS(Status)) {
			if ((ULONG)DirectoryHandle < TASK_SIZE) {
				if (copy_to_user(DirectoryHandle, &hDirectory, sizeof(HANDLE)))
					return STATUS_NO_MEMORY;
			} else
				*DirectoryHandle = hDirectory;
		}
	}

	return Status;
} /* end NtCreateDirectoryObject */
EXPORT_SYMBOL(NtCreateDirectoryObject);

NTSTATUS
SERVICECALL
NtOpenDirectoryObject(OUT PHANDLE DirectoryHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	HANDLE hDirectory;
	OBJECT_ATTRIBUTES obj_attr;
	UNICODE_STRING obj_name;
	MODE previous_mode;
	NTSTATUS status = STATUS_SUCCESS;
	
	previous_mode = (unsigned long)ObjectAttributes > TASK_SIZE ? KernelMode : UserMode;
	if (previous_mode == UserMode) {
		if ((copy_from_user(&obj_attr, ObjectAttributes, sizeof(OBJECT_ATTRIBUTES))))
			return STATUS_NO_MEMORY;
		if ((copy_from_user(&obj_name, ObjectAttributes->ObjectName, sizeof(UNICODE_STRING))))
			return STATUS_NO_MEMORY;
	} else {
		obj_attr = *ObjectAttributes;
		obj_name = *ObjectAttributes->ObjectName;
	}
	obj_attr.ObjectName = &obj_name;

	status = open_object_by_name(&obj_attr,
			dir_object_type,
			NULL,
			KernelMode,
			DesiredAccess,
			NULL,
			&hDirectory);
	if (!NT_SUCCESS(status))
		return status;

	if (previous_mode == UserMode) {
		if ((copy_to_user(DirectoryHandle, &hDirectory, sizeof(HANDLE))))
			return STATUS_NO_MEMORY;
	} else
		*DirectoryHandle = hDirectory;

	return status;
} /* end NtOpenDirectoryObject */
EXPORT_SYMBOL(NtOpenDirectoryObject);

NTSTATUS
SERVICECALL
NtQueryDirectoryObject(IN HANDLE DirectoryHandle,
		OUT PVOID Buffer,
		IN ULONG BufferLength,
		IN BOOLEAN ReturnSingleEntry,
		IN BOOLEAN RestartScan,
		IN OUT PULONG Context,
		OUT PULONG ReturnLength OPTIONAL)
{
	PVOID TempBuffer;
	ULONG SkipEntries, SkipEntries2, Bucket, EntrySize;
	ULONG RequiredSize = 0;
	ULONG NextEntry = 0;
	ULONG EntriesFound = 0;
	POBJECT_DIRECTORY Directory;
	POBJECT_DIRECTORY_ENTRY DirectoryEntry;
	POBJECT_HEADER ObjectHeader;
	POBJECT_HEADER_NAME_INFO NameInfo;
	UNICODE_STRING ObjectName;
	POBJECT_DIRECTORY_INFORMATION DirInfo;
	NTSTATUS Status = STATUS_SUCCESS;
	MODE previous_mode;

	previous_mode = (unsigned long)Buffer > TASK_SIZE ? KernelMode : UserMode;
	if (RestartScan) {
		if (previous_mode == UserMode) {
			if (copy_from_user(&SkipEntries, Context, sizeof(ULONG)))
				return STATUS_NO_MEMORY;
		} else
			SkipEntries = *Context;
	} else
		SkipEntries = 0;
	SkipEntries2 = SkipEntries;

	Status = ref_object_by_handle(DirectoryHandle,
			DIRECTORY_QUERY,
			dir_object_type,
			KernelMode,
			(PVOID *)&Directory,
			NULL);
	if (!NT_SUCCESS(Status))
		return Status;

	for (Bucket = 0; Bucket < NUMBER_HASH_BUCKETS; Bucket++) {
		DirectoryEntry = Directory->HashBuckets[Bucket];

		while (DirectoryEntry) {
			if (SkipEntries == NextEntry++) {
				EntriesFound ++;

				if (ReturnSingleEntry)
					goto found;
				else
					SkipEntries++;
			}
			DirectoryEntry = DirectoryEntry->ChainLink;
		}
	}

	if (EntriesFound == 0) {
		*Context = 0;
		deref_object(Directory);
		return STATUS_NO_MORE_ENTRIES;
	}

found:
	TempBuffer = kmalloc(EntriesFound * sizeof(OBJECT_DIRECTORY_INFORMATION), GFP_KERNEL);
	if (!TempBuffer) {
		deref_object(Directory);
		return STATUS_NO_MEMORY;
	}

	if (previous_mode == UserMode) {
		if (copy_from_user(TempBuffer, Buffer, EntriesFound * sizeof(OBJECT_DIRECTORY_INFORMATION))) {
			deref_object(Directory);
			return STATUS_NO_MEMORY;
		}
	}
	else
		TempBuffer = Buffer;

	DirInfo = (POBJECT_DIRECTORY_INFORMATION)TempBuffer;

	Status = STATUS_NO_MORE_ENTRIES;
	NextEntry = 0;
	for (Bucket = 0; Bucket < NUMBER_HASH_BUCKETS; Bucket++) {
		DirectoryEntry = Directory->HashBuckets[Bucket];

		while (DirectoryEntry) {
			if (SkipEntries2 == NextEntry++) {
				ObjectHeader = BODY_TO_HEADER(DirectoryEntry->Object);
				NameInfo = HEADER_TO_OBJECT_NAME(ObjectHeader);

				if (NameInfo)
					ObjectName = NameInfo->Name;
				else
					init_unistr(&ObjectName, NULL);

				EntrySize = sizeof(OBJECT_DIRECTORY_INFORMATION) +
					(ObjectName.Length + sizeof(WCHAR)) +
					(ObjectHeader->Type->Name.Length + sizeof(WCHAR));

				if (RequiredSize + EntrySize > BufferLength) {
					if (ReturnSingleEntry) {
						RequiredSize += EntrySize;
						Status = STATUS_BUFFER_TOO_SMALL;
					} else 
						Status = STATUS_MORE_ENTRIES;

					NextEntry--;
					goto done;
				}

				DirInfo->ObjectName.Length = ObjectName.Length;
				DirInfo->ObjectName.MaximumLength = 
					(USHORT)(ObjectName.Length + sizeof(WCHAR));
				memcpy(DirInfo->ObjectName.Buffer, ObjectName.Buffer, ObjectName.Length);

				DirInfo->ObjectTypeName.Length = ObjectHeader->Type->Name.Length;
				DirInfo->ObjectTypeName.MaximumLength = 
					(USHORT)(ObjectHeader->Type->Name.Length + sizeof(WCHAR));
				memcpy(DirInfo->ObjectTypeName.Buffer, ObjectHeader->Type->Name.Buffer,
					ObjectHeader->Type->Name.Length);

				Status = STATUS_SUCCESS;

				RequiredSize += EntrySize;
				DirInfo++;

				if (ReturnSingleEntry) 
					goto done;
				else
					SkipEntries2++;
			}

			DirectoryEntry = DirectoryEntry->ChainLink;
		}
	}

done:
	if (!NT_SUCCESS(Status))
		goto out;

	if (previous_mode == UserMode) {
		if (copy_to_user(Buffer,
				TempBuffer,
				NextEntry * sizeof(OBJECT_DIRECTORY_INFORMATION))) {
			Status = STATUS_NO_MEMORY;
			goto out;
		}
	} else
		memcpy(Buffer, TempBuffer, NextEntry * sizeof(OBJECT_DIRECTORY_INFORMATION));

	if (previous_mode == UserMode) {
		if (copy_to_user(Context, &NextEntry, sizeof(ULONG))) {
			Status = STATUS_NO_MEMORY;
			goto out;
		}
	} else
		*Context = NextEntry;

	if (ReturnLength) {
		if (previous_mode == UserMode) {
			if (copy_to_user(ReturnLength, &RequiredSize, sizeof(ULONG))) {
				Status = STATUS_NO_MEMORY;
				goto out;
			}
		} else
			*ReturnLength = RequiredSize;
	}

out:
	deref_object(Directory);
	kfree(TempBuffer);
	return Status;
} /* end NtQueryDirectoryObject */
EXPORT_SYMBOL(NtQueryDirectoryObject);

NTSTATUS delete_object_dir(PVOID dir)
{
	int i;
	NTSTATUS    ret = STATUS_SUCCESS;
	POBJECT_DIRECTORY_ENTRY head_entry;
	POBJECT_DIRECTORY_ENTRY entry;

	if (!dir)
		dir = name_space_root;

	if (BODY_TO_HEADER(dir)->Type != dir_object_type)
		return STATUS_INVALID_PARAMETER;

	for (i = 0; i < NUMBER_HASH_BUCKETS; i++) {
		head_entry = (POBJECT_DIRECTORY_ENTRY)((POBJECT_DIRECTORY)dir)->HashBuckets[i];

		/* 
		 * Walk the chain of directory entries for this hash bucket, looking 
		 * for either a match, or the insertion point if no match in the chain.
		 */
		while ((entry = head_entry)) {
			POBJECT_HEADER	header = BODY_TO_HEADER(entry->Object);
			POBJECT_HEADER_NAME_INFO name_info = HEADER_TO_OBJECT_NAME(header);

			if (name_info)
				name_info->Directory = NULL;

			if (BODY_TO_HEADER(entry->Object)->Type != dir_object_type)
				delete_object(header);
			else
				ret = delete_object_dir(entry->Object);

			head_entry = entry->ChainLink;
			kfree(entry);
		}
	}
	delete_object(BODY_TO_HEADER(dir));

	return ret;
} /* end delete_object_dir */
#endif
