/*
 * namespc.c
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
 * namespc.c:
 * Refered to ReactOS code
 */
#include "handle.h"
#include "unistr.h"

#ifdef CONFIG_UNIFIED_KERNEL

#define OBJECT_TYPE_CREATE 0x0001
#define OBJECT_TYPE_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x1)

#define DIRECTORY_QUERY (0x0001)
#define DIRECTORY_TRAVERSE (0x0002)
#define DIRECTORY_CREATE_OBJECT (0x0004)
#define DIRECTORY_CREATE_SUBDIRECTORY (0x0008)
#define DIRECTORY_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0xF)
#define EVENT_QUERY_STATE (0x0001)
#define SEMAPHORE_QUERY_STATE (0x0001)
#define SYMBOLIC_LINK_QUERY 0x0001
#define SYMBOLIC_LINK_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x1)

POBJECT_TYPE dir_object_type = NULL;
EXPORT_SYMBOL(dir_object_type);
POBJECT_TYPE type_object_type = NULL;
EXPORT_SYMBOL(type_object_type);

POBJECT_DIRECTORY name_space_root = NULL;
EXPORT_SYMBOL(name_space_root);
POBJECT_DIRECTORY type_object_dir = NULL;
EXPORT_SYMBOL(type_object_dir);

HANDLE base_dir_handle = NULL;
EXPORT_SYMBOL(base_dir_handle);

HANDLE device_handle = NULL;
EXPORT_SYMBOL(device_handle);

extern struct handle_table *kernel_handle_table;
extern NTSTATUS delete_object_dir(PVOID dir);

static GENERIC_MAPPING dir_mapping =
{
	STANDARD_RIGHTS_READ | DIRECTORY_QUERY | DIRECTORY_TRAVERSE,
	STANDARD_RIGHTS_WRITE | DIRECTORY_CREATE_OBJECT | DIRECTORY_CREATE_SUBDIRECTORY,
	STANDARD_RIGHTS_EXECUTE | DIRECTORY_QUERY | DIRECTORY_TRAVERSE,
	DIRECTORY_ALL_ACCESS
};

static GENERIC_MAPPING type_mapping =
{
	STANDARD_RIGHTS_READ,
	STANDARD_RIGHTS_WRITE,
	STANDARD_RIGHTS_EXECUTE,
	0x000F0001
};

static WCHAR   type_type_name[] = {'T', 'y', 'p', 'e', 0};
static WCHAR   dir_type_name[] = {'D', 'i', 'r', 'e', 'c', 't', 'o', 'r', 'y', 0};
static WCHAR   root_dir_name[] = {'\\', 0};
static WCHAR   type_dir_name[] = {'\\', 'O', 'b', 'j', 'e', 'c', 't', 'T', 'y', 'p', 'e', 's', 0};
static WCHAR   base_dir_name[] = {'\\', 'B', 'a', 's', 'e', 'N', 'a', 'm', 'e', 'd', 'O', 'b', 'j', 'e', 'c', 't', 's', 0};
static WCHAR   dir_driver[] = {'\\', 'D', 'r', 'i', 'v', 'e', 'r', 0};
static WCHAR   dir_device[] = {'\\', 'D', 'e', 'v', 'i', 'c', 'e', 0};

UNICODE_STRING	TypeObjectTypeNameInfo;

BOOLEAN init_object()
{
	OBJECT_TYPE_INITIALIZER ObjectTypeInitializer;
	UNICODE_STRING Name;
	OBJECT_ATTRIBUTES ObjectAttributes;
	HANDLE Handle;

	create_handle_table(NULL, 0, NULL);

	/* Create the Type Type */
	memset(&ObjectTypeInitializer, 0, sizeof(ObjectTypeInitializer));
	init_unistr(&Name, (PWSTR)type_type_name);
	ObjectTypeInitializer.Length = sizeof(ObjectTypeInitializer);
	ObjectTypeInitializer.ValidAccessMask = OBJECT_TYPE_ALL_ACCESS;
	ObjectTypeInitializer.UseDefaultObject = TRUE;
	ObjectTypeInitializer.MaintainTypeList = TRUE;
	ObjectTypeInitializer.PoolType = NonPagedPool;
	ObjectTypeInitializer.GenericMapping = type_mapping;
	ObjectTypeInitializer.DefaultNonPagedPoolCharge = sizeof(OBJECT_TYPE);
	create_type_object(&ObjectTypeInitializer, &Name, &type_object_type);

	/* Create the Directory Type */
	memset(&ObjectTypeInitializer, 0, sizeof(ObjectTypeInitializer));
	init_unistr(&Name, (PWSTR)dir_type_name);
	ObjectTypeInitializer.Length = sizeof(ObjectTypeInitializer);
	ObjectTypeInitializer.ValidAccessMask = DIRECTORY_ALL_ACCESS;
	ObjectTypeInitializer.UseDefaultObject = FALSE;
	ObjectTypeInitializer.MaintainTypeList = FALSE;
	ObjectTypeInitializer.GenericMapping = dir_mapping;
	ObjectTypeInitializer.DefaultNonPagedPoolCharge = sizeof(OBJECT_DIRECTORY);
	create_type_object(&ObjectTypeInitializer, &Name, &dir_object_type);

	/* FIXME Initialize the resource that protects the object name space directory structure */
#if 0
	ExInitializeResourceLite(&ObpRootDirectoryMutex);
#endif

	/* Create an directory object for the root directory */
	init_unistr(&Name, (PWSTR)root_dir_name);
	INIT_OBJECT_ATTR(&ObjectAttributes,
			&Name,
			OBJ_CASE_INSENSITIVE | OBJ_PERMANENT,
			NULL,
			NULL);
	create_object(KernelMode,
			dir_object_type,
			&ObjectAttributes,
			KernelMode,
			NULL,
			sizeof(OBJECT_DIRECTORY),
			0,
			0,
			(PVOID*)&name_space_root);
	insert_object((PVOID)name_space_root,
			NULL,
			DIRECTORY_ALL_ACCESS,
			0,
			NULL,
			NULL);

	/* Create an directory object for the directory of object types */
	init_unistr(&Name, (PWSTR)type_dir_name);
	INIT_OBJECT_ATTR(&ObjectAttributes,
			&Name,
			OBJ_CASE_INSENSITIVE | OBJ_PERMANENT,
			NULL,
			NULL);
	create_object(KernelMode,
			dir_object_type,
			&ObjectAttributes,
			KernelMode,
			NULL,
			sizeof(OBJECT_DIRECTORY),
			0,
			0,
			(PVOID*)&type_object_dir);
	insert_object((PVOID)type_object_dir,
			NULL,
			DIRECTORY_ALL_ACCESS,
			0,
			NULL,
			NULL);

	init_unistr(&Name, (PWSTR)type_type_name);
	lookup_obdir_entry(type_object_dir, &Name, 0);
	insert_obdir_entry(type_object_dir, type_object_type);
	init_unistr(&Name, (PWSTR)dir_type_name);
	lookup_obdir_entry(type_object_dir, &Name, 0);
	insert_obdir_entry(type_object_dir, dir_object_type);

	init_unistr(&Name, (PWSTR)base_dir_name);
	INIT_OBJECT_ATTR(&ObjectAttributes,
			&Name,
			0,
			NULL,
			NULL);
	NtCreateDirectoryObject(&Handle, 0, &ObjectAttributes);
	base_dir_handle = Handle;

	init_unistr(&Name, (PWSTR)dir_driver);
	INIT_OBJECT_ATTR(&ObjectAttributes,
			&Name,
			0,
			NULL,
			NULL);
	NtCreateDirectoryObject(&Handle, 0, &ObjectAttributes);

	init_unistr(&Name, (PWSTR)dir_device);
	INIT_OBJECT_ATTR(&ObjectAttributes,
			&Name,
			0,
			NULL,
			NULL);
	NtCreateDirectoryObject(&Handle, 0, &ObjectAttributes);
	device_handle = Handle;

	return TRUE;
} /* end init_object */

void exit_object(void)
{
	delete_object_dir(name_space_root);
} /* end exit_object */

NTSTATUS
STDCALL
create_type_object(POBJECT_TYPE_INITIALIZER ObjectTypeInitializer,
		PUNICODE_STRING type_type_name,
		POBJECT_TYPE *ObjectType)
{
	POBJECT_HEADER Header;
	POBJECT_TYPE LocalObjectType;
	NTSTATUS Status;

	/* Allocate the Object */
	Status = alloc_object(NULL, 
			type_type_name,
			type_object_type, 
			OBJECT_ALLOC_SIZE(sizeof(OBJECT_TYPE)),
			&Header);
	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	LocalObjectType = (POBJECT_TYPE)&Header->Body;

	/* Check if this is the first Object Type */
	if (!type_object_type) {
		type_object_type = LocalObjectType;
		Header->Type = type_object_type;
	}

	/* Set it up */
	LocalObjectType->TypeInfo = *ObjectTypeInitializer;
	LocalObjectType->Name = *type_type_name;

	/* Insert it into the Object Directory */
	if (type_object_dir) {
		lookup_obdir_entry(type_object_dir, type_type_name, 0);
		insert_obdir_entry(type_object_dir, LocalObjectType);
		ref_object(type_object_dir);
	}

	*ObjectType = LocalObjectType;

	return Status;
} /* end create_type_object */ 
EXPORT_SYMBOL(create_type_object);
#endif
