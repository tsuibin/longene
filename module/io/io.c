/*
 * io.c
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
 * io.c: IO functions
 */
#include "io.h"
#include "handle.h"
#include "unistr.h"

#ifdef CONFIG_UNIFIED_KERNEL

extern POBJECT_TYPE file_object_type;
extern POBJECT_TYPE file_ctrl_object_type;
extern POBJECT_TYPE dir_object_type;
extern POBJECT_DIRECTORY file_ctrl_root;
extern POBJECT_TYPE symbol_link_type;
extern HANDLE	file_ctrl_root_handle;

#define DOSDRIVER_NAME_LEN  16
#define DOSDRIVER_LETTER_OFF    4
static WCHAR dosdriver_link_name[DOSDRIVER_NAME_LEN] = {'\\', '?', '?', '\\', ' ', ':', 0};
static WCHAR dosdriver_target_name[PAGE_SIZE];

static WCHAR	FileName[] = {'F', 'i', 'l', 'e', 0};
static WCHAR   FileRoot[] = {'\\', 'F', 'i', 'l', 'e', 'S', 'y', 's', 't', 'e', 'm', 0};
static WCHAR   DosRoot[] = {'\\', '?', '?', 0};
static WCHAR   DosDeviceLink[] = {'\\', 'D', 'o', 's', 'D', 'e', 'v', 'i', 'c', 'e', 's', 0};

static WCHAR   FileControlTypeName[] = {'F', 'i', 'l', 'e', 'C', 'o', 'n', 't', 'r', 'o', 'l', 0};
static WCHAR   FileControlRootName[] = {'F', 'i', 'l', 'e', 'C', 'o', 'n', 't', 'r', 'o', 'l', 0};

static WCHAR   DosCLinkName[] = {'\\', '?', '?', '\\', 'C', ':', 0};
static WCHAR   DriveC[] = {'/', 'd', 'r', 'i', 'v', 'e', '_', 'c', '/', 0};
static WCHAR   DosZLinkName[] = {'\\', '?', '?', '\\', 'Z', ':', 0};
static WCHAR   DosZTargetName[] = {'/', 0};

extern char *rootdir;

VOID
init_io(VOID)
{
	OBJECT_TYPE_INITIALIZER ObjectTypeInitializer;
	UNICODE_STRING Name;
	OBJECT_ATTRIBUTES ObjectAttributes;
	UNICODE_STRING dir_type_name;
	UNICODE_STRING LinkName;
	HANDLE Handle;
    LONG i, len;
    PWCHAR DosCTargetName;

	ktrace("\n");
	/* Initialize the File object type  */
	memset(&ObjectTypeInitializer, 0, sizeof(ObjectTypeInitializer));
	init_unistr(&Name, (PWSTR)FileName);
	ObjectTypeInitializer.Length = sizeof(ObjectTypeInitializer);
	ObjectTypeInitializer.DefaultNonPagedPoolCharge = sizeof(FILE_OBJECT);
	ObjectTypeInitializer.OpenProcedure = NULL; /* FIXME: io_open_file*/
	ObjectTypeInitializer.CloseProcedure = NULL; /* FIXME: io_close_file */
	ObjectTypeInitializer.DeleteProcedure = io_delete_file;
	ObjectTypeInitializer.CreateProcedure = NULL; /* FIXME: io_create_file */
	ObjectTypeInitializer.SecurityProcedure = NULL;	/* FIXME: io_security_fil */
	ObjectTypeInitializer.QueryNameProcedure = NULL;	/* FIXME: io_query_name_file */
	create_type_object(&ObjectTypeInitializer, &Name, &file_object_type);

	/* Initialize the File Control object type  */
	memset(&ObjectTypeInitializer, 0, sizeof(ObjectTypeInitializer));
	init_unistr(&Name, (PWSTR)FileControlTypeName);
	ObjectTypeInitializer.Length = sizeof(ObjectTypeInitializer);
	ObjectTypeInitializer.DefaultNonPagedPoolCharge = sizeof(FILE_CONTROL_OBJECT);
	ObjectTypeInitializer.SecurityProcedure = NULL;	/* io_security_fil */
	ObjectTypeInitializer.QueryNameProcedure = NULL;	/* io_query_name_file */
	create_type_object(&ObjectTypeInitializer, &Name, &file_ctrl_object_type);

	/*
	 * Create the '\FileSystem' object directory
	 */
	init_unistr(&dir_type_name, (PWSTR)FileRoot);
	INIT_OBJECT_ATTR(&ObjectAttributes,
			&dir_type_name,
			0,
			NULL,
			NULL);
	NtCreateDirectoryObject(&Handle, 0, &ObjectAttributes);
	/*
	 * Create the '\??' directory
	 */
	init_unistr(&dir_type_name, (PWSTR)DosRoot);
	INIT_OBJECT_ATTR(&ObjectAttributes,
			&dir_type_name,
			0,
			NULL,
			NULL);
	NtCreateDirectoryObject(&Handle, 0, &ObjectAttributes);

	/*
	 * Create link from '\DosDevices' to '\??' directory
	 */
	init_unistr(&dir_type_name, (PWSTR)DosRoot);
	init_unistr(&LinkName, (PWSTR)DosDeviceLink);
	io_create_symbol_link(&LinkName, &dir_type_name);


	init_unistr(&dir_type_name, (PWSTR)FileControlRootName);
	INIT_OBJECT_ATTR(&ObjectAttributes,
			&dir_type_name,
			0,
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
			(PVOID *)&file_ctrl_root);
	create_handle(NULL,
			file_ctrl_root,
			0,
			ObjectAttributes.Attributes & OBJ_INHERIT,
			&file_ctrl_root_handle);

	/* Create link from '\\??\\C:' to '\\root\\.wine\\drive_c' directory */
    len = strlen(rootdir);
    DosCTargetName = (PWCHAR)kmalloc(len * 2 + 32, GFP_KERNEL);
    for (i = 0; i < len; i++)
        DosCTargetName[i] = (WCHAR)rootdir[i];
    if (rootdir[i - 1] == '/')
        i--;
    wcscpy(DosCTargetName + i, DriveC);
	init_unistr(&dir_type_name, (PWSTR)DosCTargetName);
	init_unistr(&LinkName, (PWSTR)DosCLinkName);
	io_create_symbol_link(&LinkName, &dir_type_name);

	/* Create link from '\\??\\Z:' to '\\root' directory */
	init_unistr(&dir_type_name, (PWSTR)DosZTargetName);
	init_unistr(&LinkName, (PWSTR)DosZLinkName);
	io_create_symbol_link(&LinkName, &dir_type_name);
}

void create_dosdriver_symlink(int index, char *target_str)
{
	char    *p = target_str;
	WCHAR   *q = dosdriver_target_name;
	BOOLEAN locked;
	NTSTATUS    status;
	unsigned long   access;
	UNICODE_STRING  target, link;
	POBJECT_SYMBOLIC_LINK object = NULL;

	while (*p)
		*q++ = (WCHAR)*p++;
	*q = '\0';

	dosdriver_link_name[DOSDRIVER_LETTER_OFF] = (WCHAR)(index + 'A');

	init_unistr(&link, (PWSTR)dosdriver_link_name);
	init_unistr(&target, (PWSTR)dosdriver_target_name);

	status = lookup_object_name(NULL,
			&link,
			0,
			symbol_link_type,
			KernelMode,
			NULL,
			NULL,
			NULL,
			(PACCESS_STATE)&access,
			&locked,
			(PVOID *)&object);

	if (status == STATUS_OBJECT_NAME_NOT_FOUND) {
		/* not found object */
		io_create_symbol_link(&link, &target);
	}
	else if (status == STATUS_SUCCESS && object ) {
		/* found object, replace target */
		kfree(object->TargetName.Buffer);
		object->TargetName.Buffer = (WCHAR *)kmalloc(target.MaximumLength, GFP_KERNEL);
		copy_unistr(&object->TargetName, &target);
		deref_object(object);
	}
}
EXPORT_SYMBOL(create_dosdriver_symlink);
#endif
