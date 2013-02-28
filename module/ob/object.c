/*
 * object.c
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
 * object.c:
 * Refered to ReactOS code
 */
#include "object.h"
#include "handle.h"
#include "unistr.h"

#ifdef CONFIG_UNIFIED_KERNEL

extern POBJECT_TYPE file_ctrl_object_type;
extern POBJECT_DIRECTORY file_ctrl_root;

#define	GetCurrentProcess()	(HANDLE)-1

extern POBJECT_TYPE symbol_link_type;
extern POBJECT_TYPE type_object_type;
extern struct handle_table *kernel_handle_table;

extern NTSTATUS
parse_symbol_link(
		IN PVOID ParseObject,
		IN PVOID ObjectType,
		IN OUT PACCESS_STATE AccessState,
		IN KPROCESSOR_MODE AccessMode,
		IN ULONG Attributes,
		IN OUT PUNICODE_STRING CompleteName,
		IN OUT PUNICODE_STRING RemainingName,
		IN OUT PVOID Context OPTIONAL,
		IN PSECURITY_QUALITY_OF_SERVICE SecurityQos OPTIONAL,
		OUT PVOID *Object
		);

NTSTATUS translate_object_name(PUNICODE_STRING ObjectName)
{
	PWCHAR	wc, buf;
	BOOLEAN	Locked;
	PVOID	NullObject = NULL;
	NTSTATUS	Status;
	unsigned long Context = TRANSLATE_NAME;

	if ((ULONG)ObjectName->Buffer == (ULONG)ObjectName + sizeof(UNICODE_STRING)) {
		buf = (PWSTR)kmalloc(ObjectName->MaximumLength, GFP_KERNEL);
		memcpy(buf, ObjectName->Buffer, ObjectName->MaximumLength);
		ObjectName->Buffer = buf;
	}

	Status = lookup_object_name(NULL,
			ObjectName,
			OBJ_CASE_INSENSITIVE,
			file_ctrl_object_type,
			(KPROCESSOR_MODE)UserMode,
			(void *)Context,
			NULL,
			NULL,
			NULL,
			&Locked,
			&NullObject);
	if (Status)
		return Status;

	/* change ObjectName from \root\file to /root/file */
	for (wc = ObjectName->Buffer;
			wc < ObjectName->Buffer + ObjectName->Length / sizeof(WCHAR);
			wc++) {
		if (*wc == (WCHAR)'\\')
			*wc = (WCHAR)'/';
	}
	return STATUS_SUCCESS;
} /*end translate_object_name */
EXPORT_SYMBOL(translate_object_name);

NTSTATUS
lookup_object_name(
		IN HANDLE RootDirectoryHandle OPTIONAL,
		IN PUNICODE_STRING ObjectName,
		IN ULONG Attributes,
		IN POBJECT_TYPE ObjectType,
		IN KPROCESSOR_MODE AccessMode,
		IN PVOID ParseContext OPTIONAL,
		IN PSECURITY_QUALITY_OF_SERVICE SecurityQos OPTIONAL,
		IN PVOID InsertObject OPTIONAL,
		IN OUT PACCESS_STATE AccessState,
		OUT PBOOLEAN DirectoryLocked,
		OUT PVOID *FoundObject
		)
{
	POBJECT_DIRECTORY RootDirectory;
	POBJECT_DIRECTORY Directory = NULL;
	POBJECT_DIRECTORY ParentDirectory = NULL;
	POBJECT_HEADER ObjectHeader;
	POBJECT_HEADER_NAME_INFO NameInfo;
	PVOID Object;
	UNICODE_STRING RemainingName;
	UNICODE_STRING ComponentName;
	PWCH NewName;
	NTSTATUS Status;
	BOOLEAN Reparse;
	ULONG MaxReparse = OBJ_MAX_REPARSE_ATTEMPTS;
	OB_PARSE_METHOD ParseProcedure;
	extern POBJECT_TYPE file_object_type;
	
	ktrace("root %p, insert object %p, name %d\n",
		RootDirectoryHandle, InsertObject, ObjectName->Length);
	*DirectoryLocked = FALSE;
	*FoundObject = NULL;
	Status = STATUS_SUCCESS;
	Object = NULL;

	/*  Check if the caller has given us a directory to search.
	 *   Otherwise we'll search the root object directory */
	if (RootDirectoryHandle) {
		/*  reference the directory object */
		Status = ref_object_by_handle(RootDirectoryHandle,
				0,
				NULL,
				AccessMode,
				(PVOID *)&RootDirectory,
				NULL);

		if (!NT_SUCCESS(Status))
			return Status;

		ObjectHeader = BODY_TO_HEADER(RootDirectory);

		/* if the name starts with a "\" and it does not file_object_type, the syntax is bad */
		if (ObjectName->Buffer
				&& *ObjectName->Buffer == OBJ_NAME_PATH_SEPARATOR
				&& ObjectHeader->Type != file_object_type) {
			Status = STATUS_OBJECT_PATH_SYNTAX_BAD;
			goto DereferenceRoot;
		}

		if (ObjectHeader->Type && ObjectHeader->Type != dir_object_type) {
			/* do not have the directory of the object types */
			if (!ObjectHeader->Type->TypeInfo.ParseProcedure) {
				/* if it doesn't have a parse routine, nothing we can do */
				Status = STATUS_INVALID_HANDLE;
				goto DereferenceRoot;
			} else {
				MaxReparse = OBJ_MAX_REPARSE_ATTEMPTS;
				while (TRUE) {
					RemainingName = *ObjectName;

					/* call parse routine */
					Status = ObjectHeader->Type->TypeInfo.ParseProcedure(
							RootDirectory,
							ObjectType,
							AccessState,
							AccessMode,
							Attributes,
							ObjectName,
							&RemainingName,
							ParseContext,
							SecurityQos,
							&Object);

					if (Status != STATUS_REPARSE) {
						/* the status was not to do a reparse */
						if (Status != STATUS_SUCCESS)	/* parse error */
							Object = NULL;
						else if (!Object)	/* parse ok, but object not found */
							Status = STATUS_OBJECT_NAME_NOT_FOUND;

						*FoundObject = Object;
						goto DereferenceRoot;
					} else if (!ObjectName->Length
							|| !ObjectName->Buffer
							|| *ObjectName->Buffer == OBJ_NAME_PATH_SEPARATOR) {
						/* reparse. Restart the parse relative to the root directory. */
						deref_object(RootDirectory);
						RootDirectory = name_space_root;
						RootDirectoryHandle = NULL;

						break;
					} else if (--MaxReparse) {
						continue;
					} else {
						*FoundObject = Object;
						if (!Object)
							Status = STATUS_OBJECT_NAME_NOT_FOUND;

						goto DereferenceRoot;
					}
				}
			}
		} else if (!ObjectName->Length || !ObjectName->Buffer) {
			/* if the caller has given us the directory of object types. 
			 * And the caller didn't specify a name, return the root object directroy. */
			Status = ref_object_by_pointer(RootDirectory,
					0,
					ObjectType,
					AccessMode);
			if (NT_SUCCESS(Status))
				*FoundObject = RootDirectory;

			goto DereferenceRoot;
		}
	} else {
		/* Otherwise the caller did not specify a directory to search. 
		 * So we'll default to the object root directory */
		RootDirectory = name_space_root;

		/* name is empty or not start with a "\", it is illformed. */
		if (!ObjectName->Length || !ObjectName->Buffer
				|| *ObjectName->Buffer != OBJ_NAME_PATH_SEPARATOR)
			return STATUS_OBJECT_PATH_SYNTAX_BAD;

		if (ObjectName->Length == sizeof(OBJ_NAME_PATH_SEPARATOR)) {
			/* search for root directory */
			if (!RootDirectory) {
#if 0
				/* If there is not a root directory. return InsertObject */
				if (InsertObject) {
					Status = ref_object_by_pointer(InsertObject,
							0,
							ObjectType,
							AccessMode);

					if (NT_SUCCESS(Status))
						*FoundObject = InsertObject;

					return Status;
				} else
					return STATUS_INVALID_PARAMETER;
#endif
			} else {
				/* return RootDirectory */
				Status = ref_object_by_pointer(RootDirectory,
						0,
						ObjectType,
						AccessMode);
				if (NT_SUCCESS(Status))
					*FoundObject = RootDirectory;

				return Status;
			}
		}
	}

	/*
	 * At this point either
	 *
	 * the user specified a directory that is not the object
	 * type directory and got repase back to the root directory
	 *
	 * the user specified the object type directory and gave us
	 * a name to actually look up
	 *
	 * the user did not specify a search directory (default
	 * to root object directory) and if the name did start off
	 * with the dos device prefix we've munged outselves back to
	 * it to the dos device directory for the process
	 */
	Reparse = TRUE;
	MaxReparse = OBJ_MAX_REPARSE_ATTEMPTS;
	while (Reparse) {
		RemainingName = *ObjectName;
		Reparse = FALSE;

		while (TRUE) {
			Object = NULL;

			/* trim leader "\" */
			if (RemainingName.Length
					&& *RemainingName.Buffer == OBJ_NAME_PATH_SEPARATOR) {
				RemainingName.Buffer++;
				RemainingName.Length -= sizeof(OBJ_NAME_PATH_SEPARATOR);
			}

			/* calculate the first component of the remaining name. */
			ComponentName = RemainingName;
			while (RemainingName.Length) {
				if (*RemainingName.Buffer == OBJ_NAME_PATH_SEPARATOR)
					break;

				RemainingName.Buffer++;
				RemainingName.Length -= sizeof(OBJ_NAME_PATH_SEPARATOR);
			}

			ComponentName.Length -= RemainingName.Length;
			if (!ComponentName.Length) {
				Status = STATUS_OBJECT_NAME_INVALID;
				break;
			}

			/* lock root directory */
			if (!*DirectoryLocked) {
				*DirectoryLocked = TRUE;
				Directory = RootDirectory;
			}

			/*  look the object in this directory, if not find it, return NULL. */
			Object = lookup_obdir_entry(Directory, &ComponentName, Attributes);

			if (!Object) {
				/* We didn't find the object */
				if (RemainingName.Length) {
					/* for search path */
					Status = STATUS_OBJECT_PATH_NOT_FOUND;
					break;
				}

				if (!InsertObject) {
					/* for search object */
					Status = STATUS_OBJECT_NAME_NOT_FOUND;
					break;
				}

				/*  The object does not exist and are allowed to create one. */
				NewName = kmalloc(ComponentName.Length + sizeof(WCHAR), GFP_KERNEL);
				if ((!NewName) || !insert_obdir_entry(Directory, InsertObject)) {
					if (NewName)
						kfree(NewName);
					Status = STATUS_INSUFFICIENT_RESOURCES;
					break;
				}

				ref_object(Directory);
				/* FIXME */
#if 0
				ref_object(InsertObject);
#endif
				ObjectHeader = BODY_TO_HEADER(InsertObject);
				NameInfo = HEADER_TO_OBJECT_NAME(ObjectHeader);

				/* copy object name info */
				memcpy(NewName, ComponentName.Buffer, ComponentName.Length);
				if (NameInfo->Name.Buffer)
					kfree(NameInfo->Name.Buffer);
				NameInfo->Name.Buffer = NewName;
				NameInfo->Name.Length = ComponentName.Length;
				NameInfo->Name.MaximumLength = ComponentName.Length + sizeof(WCHAR);

				Object = InsertObject;
				Status = STATUS_SUCCESS;

				break;
			}

			/* found the component name within the directory. */
			ObjectHeader = BODY_TO_HEADER(Object);
			if (ObjectHeader->Type)
				ParseProcedure = ObjectHeader->Type->TypeInfo.ParseProcedure;
			else
				ParseProcedure = NULL;

			if (ParseProcedure == (OB_PARSE_METHOD)parse_symbol_link && !RemainingName.Length) {
				ref_object(Object);
				Status = STATUS_SUCCESS;
				break;
			}

			/* if parse routine is exist and find object 
			 * the parse routine is for symbolic links, actually call the parse routine */
			if (ParseProcedure && (!InsertObject || (ParseProcedure == (OB_PARSE_METHOD)parse_symbol_link))) {
				/* Reference the object and then free the directory lock */
				ref_object(Object);

				*DirectoryLocked = FALSE;

				Status = ParseProcedure(
						Object,
						(PVOID)ObjectType,
						AccessState,
						AccessMode,
						Attributes,
						ObjectName,
						&RemainingName,
						ParseContext,
						SecurityQos,
						&Object);

				/* We can now decrement the object reference count */
				deref_object(&ObjectHeader->Body);

				/* Check if we have some reparsing to do */
				if (Status == STATUS_REPARSE) {
					if (--MaxReparse) {
						Reparse = TRUE;

						/* Check if we have a reparse object or the name
						 * starts with a "\" */
						if (*ObjectName->Buffer == OBJ_NAME_PATH_SEPARATOR) {
							/* reparse from RootDirectoryObject */
							if (RootDirectoryHandle) {
								deref_object(RootDirectory);
								RootDirectoryHandle = NULL;
							}

							/* And where we start is the root directory object */
							ParentDirectory = NULL;
							RootDirectory = name_space_root;
						} else if (RootDirectory == name_space_root) {
							Object = NULL;
							Status = STATUS_OBJECT_NAME_NOT_FOUND;
							Reparse = FALSE;
						}
					} else {
						Object = NULL;
						Status = STATUS_OBJECT_NAME_NOT_FOUND;
					}
				} else if (Status == STATUS_REPARSE_OBJECT) {
					Object = InsertObject;
				} else if (!NT_SUCCESS(Status)) {
					Object = NULL;
				} else if (!Object) {
					Status = STATUS_OBJECT_NAME_NOT_FOUND;
				}

				break;
			} else {
				/* At this point we do not have a parse routine or if there
				 * is a parse routine it is not for symbolic links or there
				 * may not be a specified insert object */
				if (!RemainingName.Length) {
					if (!InsertObject) {
						/* opening an existing object. */
						Status = ref_object_by_pointer(Object,
								0,
								ObjectType,
								AccessMode);

						if (!NT_SUCCESS(Status))
							Object = NULL;
					}

					break;
				} else {
					/* the find object is a Directroy, search in this Directory */
					if (ObjectHeader->Type == dir_object_type) {
						ParentDirectory = Directory;
						Directory = (POBJECT_DIRECTORY)Object;
					} else {
						/* there has been a mismatch */
						Status = STATUS_OBJECT_TYPE_MISMATCH;
						Object = NULL;

						break;
					}
				}
			}
		}
	}

	/*
	 * At this point we've parsed the object name as much as possible
	 * going through symbolic links as necessary.  So now set the
	 * output object pointer, and if we really did not find an object
	 * then we might need to modify the error status.  If the
	 * status was repase or some success status then translate it
	 * to name not found.
	 */
	if (!(*FoundObject = Object)) {
		if (Status == STATUS_REPARSE)
			Status = STATUS_OBJECT_NAME_NOT_FOUND;
		else if (Status == STATUS_REPARSE_OBJECT)
			Status = STATUS_SUCCESS;
		else if (NT_SUCCESS(Status))
			Status = STATUS_OBJECT_NAME_NOT_FOUND;
	}

	/*
	 * If the caller gave us a root directory to search (and we didn't
	 * zero out this value) then free up our reference
	 */
	if (RootDirectoryHandle) {
		deref_object(RootDirectory);
		RootDirectoryHandle = NULL;
	}

out:
	return Status;

DereferenceRoot:
	deref_object(RootDirectory);
	goto out;
} /* end lookup_object_name */
EXPORT_SYMBOL(lookup_object_name);

/* FIXME: SD function
 * Not implemented and temporarily put here */
int release_sec_descpt(
	IN PSECURITY_DESCRIPTOR CapturedSecurityDescriptor,
	IN KPROCESSOR_MODE CurrentMode,
	IN BOOLEAN CaptureIfKernelMode
	)
{
	/* TODO:
	 * Now, there is nothing to be done */
	return 0;
} /* end release_sec_descpt */
EXPORT_SYMBOL(release_sec_descpt);

/* FIXME: SD function
 * Not implemented and temporarily put here */
int capture_sec_descpt(
	IN PSECURITY_DESCRIPTOR OriginalSecurityDescriptor,
	IN KPROCESSOR_MODE CurrentMode,
	IN BOOLEAN CaptureIfKernel,
	OUT PSECURITY_DESCRIPTOR *CapturedSecurityDescriptor
	)
{
	/* TODO:
	 * Now, there is nothing to be done */
	return 0;
} /* end capture_sec_descpt */
EXPORT_SYMBOL(capture_sec_descpt);

int capture_object_name(IN OUT PUNICODE_STRING CapturedName,
                     IN PUNICODE_STRING ObjectName,
                     IN KPROCESSOR_MODE AccessMode)
{
	if(ObjectName->Length) {
		CapturedName->Length = ObjectName->Length;
		CapturedName->MaximumLength = ObjectName->Length + sizeof(WCHAR);
		CapturedName->Buffer = (WCHAR *)kmalloc(CapturedName->MaximumLength, GFP_KERNEL);

		memcpy(CapturedName->Buffer, ObjectName->Buffer, ObjectName->Length);
		CapturedName->Buffer[ObjectName->Length / sizeof(WCHAR)] = 0;
	}
	
	return 0;
} /* end capture_object_name */

void release_captured_attr(IN POBJECT_CREATE_INFORMATION ObjectCreateInfo)
{
	/* Release the SD, it's the only thing we allocated */
	if(ObjectCreateInfo->SecurityDescriptor) {
		release_sec_descpt(ObjectCreateInfo->SecurityDescriptor,
				ObjectCreateInfo->ProbeMode,
				TRUE);
		ObjectCreateInfo->SecurityDescriptor = NULL;                                        
	}
} /* end release_captured_attr */
EXPORT_SYMBOL(release_captured_attr);

int capture_object_attr(IN POBJECT_ATTRIBUTES ObjectAttributes,
		IN KPROCESSOR_MODE AccessMode,
		IN POBJECT_TYPE ObjectType,
		IN POBJECT_CREATE_INFORMATION ObjectCreateInfo,
		OUT PUNICODE_STRING ObjectName)
{
	int ret = 0;
	PSECURITY_DESCRIPTOR sec_descriptor;
	PUNICODE_STRING obj_name = NULL;

	/* Zero out object create information */
	memset(ObjectCreateInfo, 0, sizeof(OBJECT_CREATE_INFORMATION));

	/* Check and set attributes */
	if (ObjectAttributes) {
		if(ObjectAttributes->Length != sizeof(OBJECT_ATTRIBUTES))
			return STATUS_INVALID_PARAMETER;

		/* Set some create information */
		ObjectCreateInfo->RootDirectory = ObjectAttributes->RootDirectory;
		ObjectCreateInfo->Attributes = ObjectAttributes->Attributes;
		obj_name = ObjectAttributes->ObjectName;
		sec_descriptor = ObjectAttributes->SecurityDescriptor;
		
		/* Validate the security descriptor */
		if(sec_descriptor) {
			ret = capture_sec_descpt(sec_descriptor, 
					AccessMode, 
					TRUE, 
					&ObjectCreateInfo->SecurityDescriptor);
			if (ret) {
				ObjectCreateInfo->SecurityDescriptor = NULL;
				release_captured_attr(ObjectCreateInfo);
				return ret;
			}
			ObjectCreateInfo->SecurityDescriptorCharge = 0;
			ObjectCreateInfo->ProbeMode = AccessMode;
		}
		
		/* Validate the QoS*/
		if(ObjectAttributes->SecurityQualityOfService) {
			ObjectCreateInfo->SecurityQualityOfService = 
				*(PSECURITY_QUALITY_OF_SERVICE)ObjectAttributes->SecurityQualityOfService;
			ObjectCreateInfo->SecurityQos = 
				&ObjectCreateInfo->SecurityQualityOfService;
		}
	}

	/* Capture name */
	if (obj_name) {
		if ((ret = capture_object_name(ObjectName, obj_name, AccessMode)))
			release_captured_attr(ObjectCreateInfo);
	}
	else {
		if(ObjectCreateInfo->RootDirectory)
			ret = STATUS_OBJECT_NAME_INVALID;
	}

	return ret;
} /* capture_object_attr */
EXPORT_SYMBOL(capture_object_attr);

int alloc_object(POBJECT_CREATE_INFORMATION ObjectCreateInfo,
                  PUNICODE_STRING ObjectName,
                  POBJECT_TYPE ObjectType,
                  ULONG ObjectSize,
                  POBJECT_HEADER *ObjectHeader)
{
	ULONG size = ObjectSize;
	BOOLEAN has_name_info = false, has_handle_info = false, has_creator_info = false;
	POBJECT_HEADER header;
	POBJECT_HEADER_HANDLE_INFO handle_info;
	POBJECT_HEADER_NAME_INFO name_info;
	POBJECT_HEADER_CREATOR_INFO creator_info;

	/* Determine the header size */
	if(ObjectName->Buffer) {
		size += sizeof(OBJECT_HEADER_NAME_INFO);
		has_name_info = TRUE;
	}

	if(ObjectType) {
		if(ObjectType->TypeInfo.MaintainHandleCount) {
			size += sizeof(OBJECT_HEADER_HANDLE_INFO);
			has_handle_info = TRUE;
		}
		if(ObjectType->TypeInfo.MaintainTypeList) {
			size += sizeof(OBJECT_HEADER_CREATOR_INFO);
			has_creator_info = TRUE;
		}
	}
	
	header = (POBJECT_HEADER)kmalloc(size, GFP_KERNEL);
	if(!header)
		return STATUS_NO_MEMORY;

	/* Initialize the optional Info */
	if(has_handle_info) {
		handle_info = (POBJECT_HEADER_HANDLE_INFO)header;
		handle_info->SingleEntry.HandleCount = 0;
		header = (POBJECT_HEADER)(handle_info + 1);
	}

	if(has_name_info) {
		name_info = (POBJECT_HEADER_NAME_INFO)header;
		name_info->Name = *ObjectName;
		name_info->Directory = NULL;
		header = (POBJECT_HEADER)(name_info + 1);
	}

	if(has_creator_info) {
		creator_info = (POBJECT_HEADER_CREATOR_INFO)header;
		INIT_LIST_HEAD(&creator_info->TypeList);
		header = (POBJECT_HEADER)(creator_info + 1);
	}

	/* Initialize the object header */
	memset(header, 0, ObjectSize);

	atomic_set(&header->HandleCount, 0);
	atomic_set(&header->PointerCount, 1);
	header->Type = ObjectType;
	header->Flags = OB_FLAG_CREATE_INFO;

	/* Set the offset for the Info */
	if(has_handle_info) {
		header->HandleInfoOffset = sizeof(OBJECT_HEADER_HANDLE_INFO)
			+ has_name_info * sizeof(OBJECT_HEADER_NAME_INFO)
			+ has_creator_info * sizeof(OBJECT_HEADER_CREATOR_INFO);
	}

	if(has_name_info) {
		header->NameInfoOffset = sizeof(OBJECT_HEADER_NAME_INFO)
			+ has_creator_info * sizeof(OBJECT_HEADER_CREATOR_INFO);
	}

	if(has_creator_info)
		header->Flags |= OB_FLAG_CREATE_INFO;

	if(ObjectCreateInfo && (ObjectCreateInfo->Attributes & OBJ_PERMANENT))
		header->Flags |= OB_FLAG_PERMANENT;
	if(ObjectCreateInfo && (ObjectCreateInfo->Attributes & OBJ_EXCLUSIVE))
		header->Flags |= OB_FLAG_EXCLUSIVE;

	header->ObjectCreateInfo = ObjectCreateInfo;

	*ObjectHeader = header;
	return 0;
} /* end alloc_object */

int create_object(IN KPROCESSOR_MODE ObjectAttributesAccessMode OPTIONAL,
		IN POBJECT_TYPE Type,
		IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
		IN KPROCESSOR_MODE AccessMode,
		IN OUT PVOID ParseContext OPTIONAL,
		IN ULONG ObjectSize,
		IN ULONG PagedPoolCharge OPTIONAL,
		IN ULONG NonPagedPoolCharge OPTIONAL,
		OUT PVOID *Object) 
{
	int ret;
	POBJECT_CREATE_INFORMATION obj_create_info;
	UNICODE_STRING obj_name = {0, 0, NULL};
	POBJECT_HEADER header;

	/* Allocate a buffer for the object create information */
	obj_create_info = (POBJECT_CREATE_INFORMATION)kmalloc(sizeof(OBJECT_CREATE_INFORMATION), 
			GFP_KERNEL);
	if (!obj_create_info)
		return STATUS_NO_MEMORY;
	
	/* Capture Attributes */
	ret = capture_object_attr(ObjectAttributes, 
			AccessMode, 
			Type,
			obj_create_info,
			&obj_name);

	/* Allocate a generic object */
	if(!ret) {
		ret = alloc_object(obj_create_info, 
				&obj_name, 
				Type, 
				OBJECT_ALLOC_SIZE(ObjectSize), 
				&header);

		if(!ret) {
			*Object = &header->Body;
			return ret;
		}
		release_captured_attr(obj_create_info);
		if(obj_name.Buffer)
			kfree(obj_name.Buffer);
	}

	/* Free buffer */
	kfree(obj_create_info);
	return ret;
} /* end create_object */
EXPORT_SYMBOL(create_object);

NTSTATUS open_object_by_pointer(IN PVOID Object,
		IN ULONG HandleAttributes,
		IN PACCESS_STATE PassedAccessState,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_TYPE ObjectType,
		IN KPROCESSOR_MODE AccessMode,
		OUT PHANDLE Handle)
{
	NTSTATUS ret;
	
	ret = ref_object_by_pointer(Object, 0, ObjectType, AccessMode);
	if (!NT_SUCCESS(ret))
		return ret;

	ret = create_handle(current->ethread ? get_current_eprocess() : NULL,
			Object,
			DesiredAccess,
			(BOOLEAN)(HandleAttributes & OBJ_INHERIT),
			Handle);

	deref_object(Object);

	return ret;
} /* end open_object_by_pointer */
EXPORT_SYMBOL(open_object_by_pointer);

NTSTATUS open_object_by_name(IN POBJECT_ATTRIBUTES ObjectAttributes,
		   IN POBJECT_TYPE ObjectType,
		   IN OUT PVOID ParseContext,
		   IN KPROCESSOR_MODE AccessMode,
		   IN ACCESS_MASK DesiredAccess,
		   IN PACCESS_STATE PassedAccessState,
		   OUT PHANDLE Handle)
{
	NTSTATUS ret;
	UNICODE_STRING obj_name;
	PVOID object = NULL;
	OBJECT_CREATE_INFORMATION obj_create_info;
	BOOLEAN	locked;
	PACCESS_STATE	access = NULL;

	/* search object */
	ret = capture_object_attr(ObjectAttributes, 
			AccessMode, 
			ObjectType, 
			&obj_create_info, 
			&obj_name);
	if (!NT_SUCCESS(ret))
		return ret; /* error */

	ret = lookup_object_name(
			obj_create_info.RootDirectory,
			&obj_name,
			obj_create_info.Attributes,
			ObjectType,
			(KPROCESSOR_MODE)KernelMode,
			NULL,
			NULL,
			NULL,
			access,
			&locked,
			&object
			);
	release_captured_attr(&obj_create_info);
	if (obj_name.Buffer)
		kfree(obj_name.Buffer);

	if (!NT_SUCCESS(ret))
		return ret;
	
	if (!object)
		return STATUS_OBJECT_NAME_NOT_FOUND;

	ret = create_handle(current->ethread ? get_current_eprocess() : NULL,
			object,
			DesiredAccess,
			FALSE,
			Handle);

	deref_object(object);

	return ret;
} /* end open_object_by_name */
EXPORT_SYMBOL(open_object_by_name);

PVOID
lookup_obdir_entry(
		IN POBJECT_DIRECTORY Directory,
		IN PUNICODE_STRING Name,
		IN ULONG Attributes
		)
{
	POBJECT_DIRECTORY_ENTRY *HeadDirectoryEntry;
	POBJECT_DIRECTORY_ENTRY DirectoryEntry;
	POBJECT_HEADER ObjectHeader;
	POBJECT_HEADER_NAME_INFO NameInfo;
	PWCH Buffer;
	WCHAR Wchar;
	ULONG HashIndex;
	ULONG WcharLength;
	BOOLEAN CaseInSensitive;

	if (!Directory || !Name)
		return NULL;

	CaseInSensitive = (Attributes & OBJ_CASE_INSENSITIVE) ? TRUE : FALSE;

	/* check object name */
	Buffer = Name->Buffer;
	WcharLength = Name->Length / sizeof(*Buffer);
	if (!WcharLength || !Buffer)
		return NULL;

	/* Compute the HASH value */
	HashIndex = 0;
	while (WcharLength--) {
		Wchar = *Buffer++;
		HashIndex += (HashIndex << 1) + (HashIndex >> 1);

		if (Wchar < 'a')
			HashIndex += Wchar;
		else if (Wchar > 'z')
			HashIndex += Wchar;	/* FIXME: RtlUpcaseUnicodeChar(Wchar); */
		else
			HashIndex += (Wchar - ('a'-'A'));
	}

	HashIndex %= NUMBER_HASH_BUCKETS;
	HeadDirectoryEntry = (POBJECT_DIRECTORY_ENTRY *)&Directory->HashBuckets[HashIndex];
	Directory->LookupBucket = HeadDirectoryEntry;

	/* Walk the chain of directory entries for this hash bucket, looking
	 * for either a match, or the insertion point if no match in the chain. */
	while ((DirectoryEntry = *HeadDirectoryEntry) != NULL) {
		ObjectHeader = BODY_TO_HEADER(DirectoryEntry->Object);
		NameInfo = HEADER_TO_OBJECT_NAME(ObjectHeader);

		if (NameInfo) {
			/* Compare strings using appropriate function. */
			if ((Name->Length == NameInfo->Name.Length) &&
					equal_unistr(Name, &NameInfo->Name, CaseInSensitive))
				break;	/* match */
		}

		HeadDirectoryEntry = &DirectoryEntry->ChainLink;
	}

	if (DirectoryEntry) {
		/* found an entry that matched and DirectoryEntry points to that entry. */
		Directory->LookupFound = TRUE;
		if (HeadDirectoryEntry != Directory->LookupBucket) {
			*HeadDirectoryEntry = DirectoryEntry->ChainLink;
			DirectoryEntry->ChainLink = *(Directory->LookupBucket);
			*(Directory->LookupBucket) = DirectoryEntry;
		}

		return DirectoryEntry->Object;
	} else {
		/* did not find an entry that matched and DirectoryEntry is NULL. */
		Directory->LookupFound = FALSE;

		return NULL;
	}
} /* end lookup_obdir_entry */
EXPORT_SYMBOL(lookup_obdir_entry);

BOOLEAN
insert_obdir_entry(
		IN POBJECT_DIRECTORY Directory,
		IN PVOID Object
		)
{
	POBJECT_DIRECTORY_ENTRY	*HeadDirectoryEntry;
	POBJECT_DIRECTORY_ENTRY	NewDirectoryEntry;
	POBJECT_HEADER_NAME_INFO	NameInfo;

	/* have a directory and that the last search was successful */
	if (!Directory || Directory->LookupFound)
		return FALSE;

	HeadDirectoryEntry = Directory->LookupBucket;
	if (!HeadDirectoryEntry)
		return FALSE;

	/* check the object name */
	if (!(NameInfo = HEADER_TO_OBJECT_NAME(BODY_TO_HEADER(Object))))
		return FALSE;

	NewDirectoryEntry = (POBJECT_DIRECTORY_ENTRY)kmalloc(sizeof(OBJECT_DIRECTORY_ENTRY), GFP_KERNEL);
	if (!NewDirectoryEntry)
		return FALSE;

	/* insert at the bucket chain head */
	NewDirectoryEntry->ChainLink = *HeadDirectoryEntry;
	*HeadDirectoryEntry = NewDirectoryEntry;
	NewDirectoryEntry->Object = Object;

	NameInfo->Directory = Directory;

	Directory->LookupFound = TRUE;

	return TRUE;
} /* end insert_obdir_entry */
EXPORT_SYMBOL(insert_obdir_entry);

NTSTATUS
insert_object(
		IN PVOID Object,
		IN PACCESS_STATE AccessState OPTIONAL,
		IN ACCESS_MASK DesiredAccess OPTIONAL,
		IN ULONG ObjectPointerBias,
		OUT PVOID *NewObject OPTIONAL,
		OUT PHANDLE Handle
	     )
{
	POBJECT_CREATE_INFORMATION ObjectCreateInfo;
	POBJECT_HEADER ObjectHeader;
	PUNICODE_STRING ObjectName;
	POBJECT_TYPE ObjectType;
	POBJECT_HEADER_NAME_INFO NameInfo;
	PVOID InsertObject;
	HANDLE NewHandle;
	BOOLEAN DirectoryLocked;
	OB_OPEN_REASON OpenReason;
	NTSTATUS Status = STATUS_SUCCESS;
	NTSTATUS ReturnStatus;

	ktrace("\n");
	ObjectHeader = BODY_TO_HEADER(Object);
	ObjectCreateInfo = ObjectHeader->ObjectCreateInfo;
	ObjectType = ObjectHeader->Type;
	NameInfo = HEADER_TO_OBJECT_NAME(ObjectHeader);

	ObjectName = NULL;
	if (NameInfo && NameInfo->Name.Buffer)
		ObjectName = &NameInfo->Name;

	/* Set some local state variables */
	DirectoryLocked = FALSE;
	InsertObject = Object;
	OpenReason = ObCreateHandle;

	/* Check if we have an object name.  If so then lookup the name */
	if (ObjectName) {
		/* for file_ctrl_object_type, rename */
		if (ObjectType == file_ctrl_object_type) {
			PWCHAR	wc;

			/* change ObjectName from \root\file to /root/file */
			for (wc = ObjectName->Buffer;
					wc < ObjectName->Buffer + ObjectName->Length / sizeof(WCHAR);
					wc++) {
				if (*wc == (WCHAR)'\\')
					*wc = (WCHAR)'/';
			}
		}

		Status = lookup_object_name(ObjectCreateInfo->RootDirectory,
				ObjectName,
				ObjectCreateInfo->Attributes,
				ObjectType,
				(KPROCESSOR_MODE)(ObjectHeader->Flags & OB_FLAG_KERNEL_OBJECT
						  ? KernelMode : UserMode),
				ObjectCreateInfo->ParseContext,
				ObjectCreateInfo->SecurityQos,
				Object,
				AccessState,
				&DirectoryLocked,
				&InsertObject);

		if (NT_SUCCESS(Status) && InsertObject && InsertObject != Object) {
			if (ObjectType == BODY_TO_HEADER(InsertObject)->Type) {
				if (NewObject)
					*NewObject = InsertObject;	/* return the found object */
				Status = STATUS_OBJECT_NAME_EXISTS;
			} else
				Status = STATUS_OBJECT_TYPE_MISMATCH;
		}
	}

	ReturnStatus = Status;
	/* FIXME: ObjectHeader->ObjectCreateInfo = NULL; */

	if (!Handle)
		return ReturnStatus;

	/* Create a named handle for the object */
	Status = create_handle(current->ethread ? get_current_eprocess() : NULL,
			InsertObject,
			DesiredAccess,
			ObjectCreateInfo->Attributes & OBJ_INHERIT,
			&NewHandle);

	/* release_captured_attr(ObjectCreateInfo); */

	if (!NT_SUCCESS(Status)) {
		if(Handle)
			*Handle = NULL;
		ReturnStatus = Status;
	} else
		if(Handle)
			*Handle = NewHandle;

	return ReturnStatus;
} /* end insert_object */
EXPORT_SYMBOL(insert_object);

BOOLEAN
delete_obdir_entry (
		IN POBJECT_DIRECTORY Directory
		)
{
	POBJECT_DIRECTORY_ENTRY *HeadDirectoryEntry;
	POBJECT_DIRECTORY_ENTRY DirectoryEntry;

	if (!Directory || !Directory->LookupFound)
		return FALSE;

	/* Also make sure that the lookup bucket is valid */
	HeadDirectoryEntry = Directory->LookupBucket;
	if (!HeadDirectoryEntry)
		return FALSE;
	DirectoryEntry = *HeadDirectoryEntry;
	if (!DirectoryEntry)
		return FALSE;

	/* Unlink the entry from the head of the bucket chain and free the memory for the entry. */
	*HeadDirectoryEntry = DirectoryEntry->ChainLink;
	DirectoryEntry->ChainLink = NULL;

	kfree(DirectoryEntry);
	deref_object(Directory);

	return TRUE;
} /* end delete_obdir_entry */
EXPORT_SYMBOL(delete_obdir_entry);

VOID
deref_object(IN PVOID Object)
{
	POBJECT_HEADER header = BODY_TO_HEADER(Object);

	if (atomic_dec_return(&header->PointerCount) == 0 && !(header->Flags & OB_FLAG_PERMANENT))
		delete_object(header);
} /* end deref_object */
EXPORT_SYMBOL(deref_object);

NTSTATUS
delete_object(POBJECT_HEADER Header)
{
	PVOID header_location = Header;
	POBJECT_HEADER_CREATOR_INFO creator_info;
	POBJECT_HEADER_NAME_INFO name_info;
	POBJECT_HEADER_HANDLE_INFO handle_info;

	if (Header->Type && Header->Type->TypeInfo.DeleteProcedure)
		Header->Type->TypeInfo.DeleteProcedure(&Header->Body);

	name_info = HEADER_TO_OBJECT_NAME(Header);
#if 0
	if (name_info && name_info->Directory) {
		lookup_obdir_entry(name_info->Directory, &name_info->Name, OBJ_CASE_INSENSITIVE);
		delete_obdir_entry(name_info->Directory);
	}
#endif

	if (name_info && name_info->Name.Buffer && Header->Type != type_object_type)
		kfree(name_info->Name.Buffer);

	if (Header->ObjectCreateInfo) {
		release_captured_attr(Header->ObjectCreateInfo);
		kfree(Header->ObjectCreateInfo);
	}

	/* To find the header, walk backwards from how we allocated */
	if ((creator_info = HEADER_TO_CREATOR_INFO(Header)))
		header_location = creator_info;
	if (name_info)
		header_location = name_info;
	if ((handle_info = HEADER_TO_HANDLE_INFO(Header)))
		header_location = handle_info;

	kfree(header_location);

	return STATUS_SUCCESS;
} /* end delete_object */

NTSTATUS
ref_object_by_pointer(IN PVOID Object,
			IN ACCESS_MASK DesiredAccess,
			IN POBJECT_TYPE ObjectType,
			IN KPROCESSOR_MODE AccessMode)
{
	POBJECT_HEADER header = BODY_TO_HEADER(Object);

	if (ObjectType && header->Type != ObjectType)
		return STATUS_OBJECT_TYPE_MISMATCH;

	if (atomic_read(&header->PointerCount) == 0 && !(header->Flags & OB_FLAG_PERMANENT))
		return STATUS_UNSUCCESSFUL;

	atomic_inc(&header->PointerCount);

	return STATUS_SUCCESS;
} /* end ref_object_by_pointer */
EXPORT_SYMBOL(ref_object_by_pointer);

NTSTATUS
duplicate_object(struct eprocess *SourceProcess,
		struct eprocess *TargetProcess,
		HANDLE SourceHandle,
		PHANDLE TargetHandle,
		ACCESS_MASK DesiredAccess,
		BOOLEAN InheritHandle,
		ULONG Options)
{
	struct handle_table *SourceHandleTable;
	struct handle_table_entry *SourceHandleEntry;
	struct handle_table_entry NewHandleEntry;
	POBJECT_HEADER ObjectHeader;
	PVOID ObjectBody;
	LONG ExSourceHandle;
	LONG ExTargetHandle;

	if (is_kernel_handle(SourceHandle, KernelMode)) {
		SourceHandleTable = kernel_handle_table;
		SourceHandle = KERNEL_HANDLE_TO_HANDLE(SourceHandle);
	}
	else
		SourceHandleTable = SourceProcess->object_table;

	ExSourceHandle = HANDLE_TO_EX_HANDLE(SourceHandle);
	SourceHandleEntry = map_handle_to_pointer(SourceHandleTable, ExSourceHandle);
	if (!SourceHandleEntry)
		return STATUS_INVALID_HANDLE;

	ObjectHeader = EX_HTE_TO_HDR(SourceHandleEntry);
	ObjectBody = &ObjectHeader->Body;

	NewHandleEntry.u1.object = SourceHandleEntry->u1.object;
	if (InheritHandle)
		NewHandleEntry.u1.obattributes |= EX_HANDLE_ENTRY_INHERITABLE;
	else
		NewHandleEntry.u1.obattributes &= ~EX_HANDLE_ENTRY_INHERITABLE;

	if (Options & DUPLICATE_SAME_ACCESS)
		NewHandleEntry.u2.granted_access = SourceHandleEntry->u2.granted_access;
	else {
		/* FIXME */
/*		if (DesiredAccess & GENERIC_ANY) {
			RtlMapGenericMask(&DesiredAccess, &ObjectHeader->Type->TypeInfo.GenericMapping);
		}
*/
		NewHandleEntry.u2.granted_access = SourceHandleEntry->u2.granted_access;
	}

	if (atomic_inc_return(&ObjectHeader->HandleCount) < 2)
		return STATUS_UNSUCCESSFUL;

	ref_object(ObjectBody);

	unlock_handle_table_entry(SourceHandleTable, SourceHandleEntry); 

	ExTargetHandle = create_ex_handle(TargetProcess->object_table, &NewHandleEntry);
	if (ExTargetHandle != EX_INVALID_HANDLE) {
		if (Options & DUPLICATE_CLOSE_SOURCE)
			delete_handle(SourceHandleTable, SourceHandle);

		*TargetHandle = EX_HANDLE_TO_HANDLE(ExTargetHandle);

		return STATUS_SUCCESS;
	}
	else {
		atomic_dec_return(&ObjectHeader->HandleCount);

		deref_object(ObjectBody);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
} /* end duplicate_object */

NTSTATUS
set_handle_attr(HANDLE Handle,
		POBJECT_HANDLE_ATTRIBUTE_INFORMATION HandleInfo)
{
	struct handle_table *HandleTable;
	struct handle_table_entry *HandleTableEntry;
	LONG ExHandle;

	if (is_kernel_handle(Handle, KernelMode)) {
		HandleTable = kernel_handle_table;
		ExHandle = HANDLE_TO_EX_HANDLE(KERNEL_HANDLE_TO_HANDLE(Handle));
	}
	else {
		struct eprocess *process = get_current_eprocess();

		HandleTable = process->object_table;
		ExHandle = HANDLE_TO_EX_HANDLE(Handle);
	}

	HandleTableEntry = map_handle_to_pointer(HandleTable, ExHandle);
	if (!HandleTableEntry)
		return STATUS_INVALID_HANDLE;

	if (HandleInfo->Inherit)
		HandleTableEntry->u1.obattributes |= EX_HANDLE_ENTRY_INHERITABLE;
	else
		HandleTableEntry->u1.obattributes &= ~EX_HANDLE_ENTRY_INHERITABLE;

	if (HandleInfo->ProtectFromClose)
		HandleTableEntry->u1.obattributes |= EX_HANDLE_ENTRY_PROTECTFROMCLOSE;
	else
		HandleTableEntry->u1.obattributes &= ~EX_HANDLE_ENTRY_PROTECTFROMCLOSE;

	unlock_handle_table_entry(HandleTable, HandleTableEntry);

	return STATUS_SUCCESS;
} /* end set_handle_attr */

NTSTATUS
query_handle_attr(HANDLE Handle,
		POBJECT_HANDLE_ATTRIBUTE_INFORMATION HandleInfo)
{
	struct handle_table *HandleTable;
	struct handle_table_entry *HandleTableEntry;
	LONG ExHandle;

	if (is_kernel_handle(Handle, KernelMode)) {
		HandleTable = kernel_handle_table;
		ExHandle = HANDLE_TO_EX_HANDLE(KERNEL_HANDLE_TO_HANDLE(Handle));
	}
	else {
		struct eprocess *process = get_current_eprocess();

		HandleTable = process->object_table;
		ExHandle = HANDLE_TO_EX_HANDLE(Handle);
	}

	HandleTableEntry = map_handle_to_pointer(HandleTable, ExHandle);
	if (!HandleTableEntry)
		return STATUS_INVALID_HANDLE;

	HandleInfo->Inherit = (HandleTableEntry->u1.obattributes & EX_HANDLE_ENTRY_INHERITABLE) != 0;
	HandleInfo->ProtectFromClose = (HandleTableEntry->u1.obattributes & EX_HANDLE_ENTRY_PROTECTFROMCLOSE) != 0;

	unlock_handle_table_entry(HandleTable, HandleTableEntry);

	return STATUS_SUCCESS;
} /* end query_handle_attr */

VOID
set_permanent_object(IN PVOID ObjectBody, IN BOOLEAN Permanent)
{
	POBJECT_HEADER ObjectHeader = BODY_TO_HEADER(ObjectBody);

	if (atomic_read(&ObjectHeader->PointerCount) < 0)
		return;

	if (Permanent)
		ObjectHeader->Flags |= OB_FLAG_PERMANENT;
	else {
		POBJECT_HEADER_NAME_INFO name_info = HEADER_TO_OBJECT_NAME(ObjectHeader);

		ObjectHeader->Flags &= ~OB_FLAG_PERMANENT;
		if (atomic_read(&ObjectHeader->HandleCount) == 0 && 
				name_info && name_info->Directory) {
			lookup_obdir_entry(name_info->Directory, &name_info->Name, OBJ_CASE_INSENSITIVE);
			delete_obdir_entry(name_info->Directory);
		}
	}
} /* end set_permanent_object */
EXPORT_SYMBOL(set_permanent_object);

VOID
make_temp_object(IN PVOID ObjectBody)
{
	set_permanent_object(ObjectBody, FALSE);
} /* end make_temp_object */
EXPORT_SYMBOL(make_temp_object);

NTSTATUS
query_name_string(IN PVOID Object,
		OUT POBJECT_NAME_INFORMATION ObjectNameInfo,
		IN ULONG Length,
		OUT PULONG ReturnLength)
{
	POBJECT_HEADER ObjectHeader;
	POBJECT_HEADER_NAME_INFO NameInfo;
	POBJECT_DIRECTORY Directory;
	ULONG NameSize, NewLength;
	PWSTR ObjectName;
	NTSTATUS Status = STATUS_SUCCESS;

	ObjectHeader = BODY_TO_HEADER(Object);
	NameInfo = HEADER_TO_OBJECT_NAME(ObjectHeader);

	if (ObjectHeader->Type->TypeInfo.QueryNameProcedure) {
		Status = ObjectHeader->Type->TypeInfo.QueryNameProcedure(Object,
							ObjectNameInfo,
							Length,
							ReturnLength);

		return Status;
	}

	if (!NameInfo || !NameInfo->Name.Buffer) {
		*ReturnLength = sizeof(OBJECT_NAME_INFORMATION);

		if (*ReturnLength > Length)
			return STATUS_INFO_LENGTH_MISMATCH;

		ObjectNameInfo->Name.Length = 0;
		ObjectNameInfo->Name.MaximumLength = 0;
		ObjectNameInfo->Name.Buffer = NULL;

		return Status;
	}

	if (Object == name_space_root)
		NameSize = sizeof(UNICODE_PATH_SEP);
	else {
		Directory = NameInfo->Directory;
		NameSize = sizeof(UNICODE_PATH_SEP) + NameInfo->Name.Length;

		while (Directory && Directory != name_space_root) {
			NameInfo = HEADER_TO_OBJECT_NAME(BODY_TO_HEADER(Directory));

			if (NameInfo && NameInfo->Directory) {
				NameSize += sizeof(UNICODE_PATH_SEP) + NameInfo->Name.Length;

				Directory = NameInfo->Directory;
			} else {
				NameSize += sizeof(UNICODE_NO_PATH) + sizeof(UNICODE_PATH_SEP);
				break;
			}
		}
	}
	NewLength = NameSize + sizeof(UNICODE_NULL) + sizeof(OBJECT_NAME_INFORMATION);
	if (NewLength > Length)
		return STATUS_INFO_LENGTH_MISMATCH;
	
	NameInfo = HEADER_TO_OBJECT_NAME(ObjectHeader);
	ObjectName = (PWSTR)((ULONG_PTR)ObjectNameInfo + NewLength);
	*--ObjectName = UNICODE_NULL;

	*ReturnLength = NewLength;

	if (Object == name_space_root) {
		*--ObjectName = UNICODE_PATH_SEP;
		ObjectNameInfo->Name.Length = (USHORT)NameSize;
		ObjectNameInfo->Name.MaximumLength = (USHORT)(NameSize + sizeof(UNICODE_NULL));
		ObjectNameInfo->Name.Buffer = ObjectName;

		return Status;
	} else {
		ObjectName = (PWSTR)((ULONG_PTR)ObjectName - NameInfo->Name.Length);
		ObjectName = NameInfo->Name.Buffer;

		Directory = NameInfo->Directory;
		while (Directory && Directory != name_space_root) {
			NameInfo = HEADER_TO_OBJECT_NAME(BODY_TO_HEADER(Directory));

			*--ObjectName = UNICODE_PATH_SEP;

			if (NameInfo && NameInfo->Name.Buffer) {
				ObjectName = (PWSTR)((ULONG_PTR)ObjectName - NameInfo->Name.Length);
				memmove(ObjectName, NameInfo->Name.Buffer, NameInfo->Name.Length);

				Directory = NameInfo->Directory;
			} else {
				ObjectName -= sizeof(UNICODE_NO_PATH);
				ObjectName = (PWSTR)UNICODE_NO_PATH;
				break;
			}
		}

		*--ObjectName = UNICODE_PATH_SEP;
		ObjectNameInfo->Name.Length = (USHORT)NameSize;
		ObjectNameInfo->Name.MaximumLength = (USHORT)(NameSize + sizeof(UNICODE_NULL));
		memcpy(ObjectNameInfo->Name.Buffer, ObjectName, ObjectNameInfo->Name.Length);
	}

	return Status;
} /* query_name_string */
EXPORT_SYMBOL(query_name_string);

LONG
copy_object_attr_from_user(
		POBJECT_ATTRIBUTES	UserObjectAttr,
		POBJECT_ATTRIBUTES	*KernelObjectAttr
		)
{
	LONG	Length;
	NTSTATUS	Status;
	BOOLEAN		HaveName;
	POBJECT_ATTRIBUTES	Local;

	if ((ULONG)UserObjectAttr >= TASK_SIZE || *KernelObjectAttr)
		return STATUS_INVALID_PARAMETER;

	HaveName = UserObjectAttr->ObjectName ? TRUE : FALSE;

	Length = sizeof(OBJECT_ATTRIBUTES) + sizeof(UNICODE_STRING);
	Length += HaveName ? UserObjectAttr->ObjectName->MaximumLength : 0;
	Local = (POBJECT_ATTRIBUTES)kmalloc(Length, GFP_KERNEL);
	if (!Local)
		return STATUS_NO_MEMORY;

	Status = STATUS_NO_MEMORY;
	if (copy_from_user(Local, UserObjectAttr, sizeof(*Local)))
		goto cleanup;

	if (HaveName) {
		Local->ObjectName = (PUNICODE_STRING)(Local + 1);
		if (copy_from_user(Local->ObjectName, UserObjectAttr->ObjectName, sizeof(UNICODE_STRING)))
			goto cleanup;

		Local->ObjectName->Buffer = (PWSTR)(Local->ObjectName + 1);
		if (copy_from_user(Local->ObjectName->Buffer,
					UserObjectAttr->ObjectName->Buffer,
					UserObjectAttr->ObjectName->MaximumLength))
			goto cleanup;
	}

	*KernelObjectAttr = Local;
	return STATUS_SUCCESS;

cleanup:
	kfree(Local);
	return Status;
}
EXPORT_SYMBOL(copy_object_attr_from_user);

void *grab_object(void *obj)
{
	if (!obj)
		return NULL;
	ref_object(obj);
	return obj;
}

/* release an object (i.e. decrement its refcount) */
void release_object(void *object)
{
	struct object *obj = (struct object *)object;
	POBJECT_HEADER obj_header = BODY_TO_HEADER(object);
	POBJECT_HEADER_NAME_INFO obj_name = HEADER_TO_OBJECT_NAME(obj_header);

	if (atomic_dec_return(&obj_header->PointerCount) == 0 && !(obj_header->Flags & OB_FLAG_PERMANENT)) {
		/* if the refcount is 0, nobody can be in the wait queue */
		if (obj_header->ops)
			obj_header->ops->destroy(obj);
#if 0
#ifdef DEBUG_OBJECTS
		list_remove(&obj->obj_list);
		if (obj_header->ops)
			memset(obj, 0xaa, BODY_TO_HEADER(obj)->ops->size);
#endif
		kfree(obj);   /* how to free OBJECT_HEADER?
						   should we close the fd in kernel? */
#endif
		if (obj_name && obj_name->Directory && !(obj_header->Flags & OB_FLAG_PERMANENT)) {
			lookup_obdir_entry(obj_name->Directory, &obj_name->Name, OBJ_CASE_INSENSITIVE);
			delete_obdir_entry(obj_name->Directory);
		}
		delete_object(obj_header);
	}
}

void *alloc_wine_object(const struct object_ops *ops)
{
	UNICODE_STRING name = {0, 0, NULL};
	POBJECT_HEADER ObjectHeader;

	alloc_object(NULL /*ObjectCreateInfo*/, &name, NULL /*ObjectType*/, 
			OBJECT_ALLOC_SIZE(ops->size), &ObjectHeader);
	ObjectHeader->ops = ops;
	return &ObjectHeader->Body;
}

void objattr_get_name(const struct object_attributes *objattr, struct unicode_str *name)
{
	name->len = ((objattr->name_len) / sizeof(WCHAR)) * sizeof(WCHAR);
	name->str = (const WCHAR *)objattr + (sizeof(*objattr) + objattr->sd_len) / sizeof(WCHAR);
}

void *create_wine_object(HANDLE namespace, const struct object_ops *ops,
		const struct unicode_str *name, struct object *parent)
{
	PVOID object, new_object;
	UNICODE_STRING obj_name;
	OBJECT_ATTRIBUTES obj_attr;
	int ret;

	obj_name.Length = (USHORT)name->len;
	obj_name.MaximumLength = obj_name.Length + sizeof(WCHAR);
	obj_name.Buffer = (PWSTR)name->str;
	INIT_OBJECT_ATTR(&obj_attr, &obj_name, 0, namespace, NULL);

	ret = create_object(KernelMode,
					NULL,
					&obj_attr,
					KernelMode,
					NULL,
					ops->size,
					0,
					0,
					(PVOID *)&object);
	if (!NT_SUCCESS(ret))
		return NULL;

	ret = insert_object(object,
					NULL,
					0,
					0,
					&new_object,
					NULL);
	if (ret == STATUS_OBJECT_NAME_EXISTS) {
		release_object(object);
		grab_object(new_object);

		set_error(STATUS_OBJECT_NAME_EXISTS);
		return new_object;
	}
	if (!NT_SUCCESS(ret))
		return NULL;

	BODY_TO_HEADER(object)->ops = ops;
	if (parent) grab_object(parent);

	return object;
}

struct object *find_object(HANDLE RootDirectory, const struct unicode_str *name, unsigned int attributes)
{
	UNICODE_STRING obj_name;
	BOOLEAN locked;
	void *object;

	obj_name.Length = (USHORT)name->len;
	obj_name.MaximumLength = obj_name.Length + sizeof(WCHAR);
	obj_name.Buffer = (PWSTR)name->str;
	lookup_object_name(
				RootDirectory,
				&obj_name,
				attributes,
				NULL,
				(KPROCESSOR_MODE)KernelMode,
				NULL,
				NULL,
				NULL,
				NULL,
				&locked,
				&object
				);

	return object;
}

HANDLE open_object(HANDLE RootDirectory, const struct unicode_str *name,
       const struct object_ops* ops, unsigned int access, unsigned int attr)
{
	UNICODE_STRING obj_name;
	OBJECT_ATTRIBUTES obj_attr;
	HANDLE handle;

	obj_name.Length = (USHORT)name->len;
	obj_name.MaximumLength = obj_name.Length + sizeof(WCHAR);
	obj_name.Buffer = (PWSTR)name->str;
	INIT_OBJECT_ATTR(&obj_attr, &obj_name, 0, RootDirectory, NULL);
	open_object_by_name(&obj_attr,
					NULL,
					NULL,
					KernelMode,
					attr,
					NULL,
					&handle);
	return handle;
}

/* stubs from Wine server */
struct object *find_object_index(const struct namespace *namespace, unsigned int index)
{
	return NULL;
}

void make_object_static(struct object *obj)
{
}

/* unlink a named object from its namespace, without freeing the object itself */
void unlink_named_object(struct object *obj)
{
}

void *create_named_object(HANDLE namespace, const struct object_ops *ops,
				const struct unicode_str *name, unsigned int attributes)
{
	struct object *obj;

	if (!name || !name->len)
		return alloc_wine_object(ops);

	if ((obj = find_object(namespace, name, attributes))) {
		if (attributes & OBJ_OPENIF && BODY_TO_HEADER(obj)->ops == ops)
			set_error(STATUS_OBJECT_NAME_EXISTS);
		else {
			release_object(obj);
			obj = NULL;
			if (attributes & OBJ_OPENIF)
				set_error(STATUS_OBJECT_TYPE_MISMATCH);
			else
				set_error(STATUS_OBJECT_NAME_COLLISION);
		}
		return obj;
	}
	if ((obj = create_wine_object(namespace, ops, name, NULL)))
		clear_error();
	return obj;
}
#endif
