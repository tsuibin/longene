/*
 * symlink.c
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
 * symlink.c:
 * Refered to ReactOS code
 */
#include "object.h"
#include "unistr.h"
#include "io.h"

#ifdef CONFIG_UNIFIED_KERNEL

#define	SYMBOLIC_LINK_QUERY 0x0001
#define	SYMBOLIC_LINK_ALL_ACCESS	(STANDARD_RIGHTS_REQUIRED | 0x1)

extern BOOLEAN is_dos_driver(PUNICODE_STRING Name);

POBJECT_TYPE symbol_link_type = NULL;
EXPORT_SYMBOL(symbol_link_type);

static GENERIC_MAPPING symbol_link_mapping =
{
	STANDARD_RIGHTS_READ | SYMBOLIC_LINK_QUERY,
	STANDARD_RIGHTS_WRITE,
	STANDARD_RIGHTS_EXECUTE | SYMBOLIC_LINK_QUERY,
	SYMBOLIC_LINK_ALL_ACCESS
};

extern VOID STDCALL init_unistr(PUNICODE_STRING, PWSTR);
static WCHAR   LinkName[] = {'S', 'y', 'm', 'b', 'o', 'l', 'i', 'c', 'L', 'i', 'n', 'k', 0};

VOID
delete_symbol_link(PVOID ObjectBody)
{
	POBJECT_SYMBOLIC_LINK SymlinkObject = (POBJECT_SYMBOLIC_LINK)ObjectBody;

	if (SymlinkObject->TargetName.Buffer) {
		kfree(SymlinkObject->TargetName.Buffer);
		SymlinkObject->TargetName.Buffer = NULL;
	}
} /* end delete_symbol_link */

NTSTATUS
parse_symbol_link(
		IN PVOID ParseObject,
		IN PVOID ObjectType,
		IN PACCESS_STATE AccessState,
		IN KPROCESSOR_MODE AccessMode,
		IN ULONG Attributes,
		IN OUT PUNICODE_STRING CompleteName,
		IN OUT PUNICODE_STRING RemainingPath,
		IN OUT PVOID Context OPTIONAL,
		IN PSECURITY_QUALITY_OF_SERVICE SecurityQos OPTIONAL,
		OUT PVOID *NextObject
		)
{
	POBJECT_SYMBOLIC_LINK SymlinkObject = (POBJECT_SYMBOLIC_LINK)ParseObject;
	UNICODE_STRING TargetPath;
	POBJECT_HEADER_NAME_INFO NameInfo = HEADER_TO_OBJECT_NAME(BODY_TO_HEADER(ParseObject));

	if (!RemainingPath) {
		return STATUS_INVALID_PARAMETER;
	}

	/* Stop parsing if the entire path has been parsed and
	 * the desired object is a symbolic link object. */
	if (!RemainingPath->Length && (Attributes & OBJ_OPENLINK)) {
		return STATUS_SUCCESS;
	}

	/* build the expanded path */
	TargetPath.MaximumLength = SymlinkObject->TargetName.MaximumLength;
	TargetPath.MaximumLength += RemainingPath->MaximumLength;
	TargetPath.Length = SymlinkObject->TargetName.Length + RemainingPath->Length;
	TargetPath.Buffer = kmalloc(TargetPath.MaximumLength, GFP_KERNEL);
	memcpy(TargetPath.Buffer, SymlinkObject->TargetName.Buffer, SymlinkObject->TargetName.Length);
	TargetPath.Buffer[TargetPath.Length / sizeof(WCHAR)] = (WCHAR)'\0';
	if (RemainingPath->Length) {
		WCHAR	*wc;

		memcpy((char *)TargetPath.Buffer + SymlinkObject->TargetName.Length,
				RemainingPath->Buffer, RemainingPath->Length);
		if (Context) {
			for (wc = (WCHAR *)((char *)TargetPath.Buffer + SymlinkObject->TargetName.Length); *wc; wc++)
				if (*wc == (WCHAR)'\\')
					*wc = (WCHAR)'/';
		}
	}

	/* transfer target path buffer into FullPath */
	kfree(CompleteName->Buffer);
	*CompleteName = TargetPath;

	/* reinitialize RemainingPath for reparsing */
	*RemainingPath = TargetPath;

	if (NameInfo && is_dos_driver(&NameInfo->Name)) {
		*NextObject = ParseObject;
		return STATUS_REPARSE_OBJECT;
	} else {
		return STATUS_REPARSE;
	}
} /* end parse_symbol_link */

VOID 
init_symbol_link(VOID)
{
	UNICODE_STRING Name;
	OBJECT_TYPE_INITIALIZER ObjectTypeInitializer;

	/* Create the object type for the "SymbolicLink" object. */
	memset(&ObjectTypeInitializer, 0, sizeof(OBJECT_TYPE_INITIALIZER));
	init_unistr(&Name, (PWSTR)LinkName);
	ObjectTypeInitializer.DefaultPagedPoolCharge = sizeof(OBJECT_SYMBOLIC_LINK);
	ObjectTypeInitializer.ValidAccessMask = SYMBOLIC_LINK_ALL_ACCESS;
	ObjectTypeInitializer.GenericMapping = symbol_link_mapping;
	ObjectTypeInitializer.DeleteProcedure = delete_symbol_link;
	ObjectTypeInitializer.ParseProcedure = parse_symbol_link;
	create_type_object(&ObjectTypeInitializer, &Name, &symbol_link_type);
} /* end init_symbol_link */

NTSTATUS SERVICECALL
NtCreateSymbolicLinkObject(OUT PHANDLE LinkHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes,
		IN PUNICODE_STRING LinkTarget)
{
	HANDLE hLink;
	POBJECT_SYMBOLIC_LINK SymbolicLink;
	UNICODE_STRING CapturedLinkTarget;
	POBJECT_ATTRIBUTES obj_attr = NULL;
	MODE previous_mode;
	NTSTATUS Status = STATUS_SUCCESS;

	ktrace("\n");
	previous_mode = (unsigned long)ObjectAttributes > TASK_SIZE ? KernelMode : UserMode;
	if (ObjectAttributes) {
		if (previous_mode == UserMode) {
			if (copy_object_attr_from_user(ObjectAttributes, &obj_attr))
				return STATUS_NO_MEMORY;
		}
		else
			obj_attr = ObjectAttributes;
	}

	Status = capture_unistr(&CapturedLinkTarget,
			KernelMode,
			PagedPool,
			FALSE,
			LinkTarget);
	if (!NT_SUCCESS(Status)) {
		goto cleanup;
	}

	Status = create_object(KernelMode,
			symbol_link_type,
			obj_attr,
			KernelMode,
			NULL,
			sizeof(OBJECT_SYMBOLIC_LINK),
			0,
			0,
			(PVOID*)&SymbolicLink);
	if (NT_SUCCESS(Status)) {
		SymbolicLink->TargetName.Length = 0;
		SymbolicLink->TargetName.MaximumLength = LinkTarget->Length + sizeof(WCHAR);
		SymbolicLink->TargetName.Buffer =
			kmalloc(SymbolicLink->TargetName.MaximumLength, GFP_KERNEL);
		copy_unistr(&SymbolicLink->TargetName, &CapturedLinkTarget);

		Status = insert_object((PVOID)SymbolicLink,
				NULL,
				DesiredAccess,
				0,
				NULL,
				&hLink);
		if (NT_SUCCESS(Status)) {
			if (previous_mode == UserMode) {
				if (copy_to_user(LinkHandle, &hLink, sizeof(HANDLE))) {
					Status = STATUS_NO_MEMORY;
					goto cleanup;
				}
			}
			else
				*LinkHandle = hLink;
		}
		deref_object(SymbolicLink);
	}

	release_unistr(&CapturedLinkTarget,
			KernelMode,
			FALSE);

cleanup:
	if (obj_attr && previous_mode == UserMode)
		kfree(obj_attr);

	return Status;
} /* end NtCreateSymbolicLinkObject */
EXPORT_SYMBOL(NtCreateSymbolicLinkObject);

NTSTATUS SERVICECALL
NtOpenSymbolicLinkObject(OUT PHANDLE LinkHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	HANDLE hLink;
	OBJECT_ATTRIBUTES Attributes;
	UNICODE_STRING Name;
	NTSTATUS Status = STATUS_SUCCESS;
	MODE previous_mode;

	ktrace("\n");
	previous_mode = (unsigned long)ObjectAttributes > TASK_SIZE ? KernelMode : UserMode;
	if (previous_mode == UserMode) {
		if ((copy_from_user(&Attributes, ObjectAttributes, sizeof(OBJECT_ATTRIBUTES))))
			return STATUS_NO_MEMORY;
		if ((copy_from_user(&Name, ObjectAttributes->ObjectName, sizeof(UNICODE_STRING))))
			return STATUS_NO_MEMORY;
	}
	else {
		Attributes = *ObjectAttributes;
		Name = *ObjectAttributes->ObjectName;
	}
	Attributes.ObjectName = &Name;

	Status = open_object_by_name(&Attributes,
			symbol_link_type,
			NULL,
			KernelMode,
			DesiredAccess,
			NULL,
			&hLink);
	if (NT_SUCCESS(Status)) {
		if (LinkHandle) {
			if (previous_mode == UserMode) {
				if (copy_to_user(LinkHandle, &hLink, sizeof(HANDLE)))
					return STATUS_NO_MEMORY;
			}
			else
				*LinkHandle = hLink;
		}
	}

	return Status;
} /* end NtOpenSymbolicLinkObject */
EXPORT_SYMBOL(NtOpenSymbolicLinkObject);

NTSTATUS SERVICECALL
NtQuerySymbolicLinkObject(IN HANDLE LinkHandle,
		OUT PUNICODE_STRING LinkTarget,
		OUT PULONG ResultLength  OPTIONAL)
{
	UNICODE_STRING SafeLinkTarget;
	POBJECT_SYMBOLIC_LINK SymlinkObject;
	NTSTATUS Status = STATUS_SUCCESS;
	MODE previous_mode;

	ktrace("()\n");
	previous_mode = (unsigned long)LinkTarget > TASK_SIZE ? KernelMode : UserMode;
	if (previous_mode == UserMode) {
		if (copy_from_user(&SafeLinkTarget, LinkTarget, sizeof(UNICODE_STRING)))
			return STATUS_NO_MEMORY;
	}
	else
		SafeLinkTarget = *LinkTarget;

	Status = ref_object_by_handle(LinkHandle,
			SYMBOLIC_LINK_QUERY,
			symbol_link_type,
			KernelMode,
			(PVOID *)&SymlinkObject,
			NULL);
	if (NT_SUCCESS(Status)) {
		ULONG LengthRequired = SymlinkObject->TargetName.Length + sizeof(WCHAR);

		if (SafeLinkTarget.MaximumLength >= LengthRequired) {
			/* don't pass TargetLink to copy_unistr here because the caller
			   might have modified the structure which could lead to a copy into
			   kernel memory! */
			copy_unistr(&SafeLinkTarget, &SymlinkObject->TargetName);
			SafeLinkTarget.Buffer[SafeLinkTarget.Length / sizeof(WCHAR)] = L'\0';
			/* copy back the new UNICODE_STRING structure */
			if (previous_mode == UserMode) {
				if (copy_to_user(LinkTarget, &SafeLinkTarget, sizeof(SafeLinkTarget))) {
					deref_object(SymlinkObject);
					return STATUS_NO_MEMORY;
				}
			}
			else
				*LinkTarget = SafeLinkTarget;
		}
		else
			Status = STATUS_BUFFER_TOO_SMALL;

		if (ResultLength) {
			if (previous_mode == UserMode) {
				if (copy_to_user(ResultLength, &LengthRequired, sizeof(ULONG))) {
					deref_object(SymlinkObject);
					return STATUS_NO_MEMORY;
				}
			}
			else
				*ResultLength = LengthRequired;
		}
		deref_object(SymlinkObject);
	}

	return Status;
} /* end NtQuerySymbolicLinkObject */
EXPORT_SYMBOL(NtQuerySymbolicLinkObject);
#endif
