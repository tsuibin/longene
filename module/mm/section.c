/*
 * section.c
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
 * section.c: section syscall functions
 * Refered to Kernel-win32 code
 */
#include <linux/mman.h>
#include <linux/fs.h>
#include "section.h"
#include "thread.h"
#include "unistr.h"
#include "virtual.h"
#include "area.h"

#ifdef CONFIG_UNIFIED_KERNEL

extern int  data_section_map(struct win32_section *, unsigned long *,
		unsigned long, unsigned long, unsigned long);

extern unsigned long prot_to_linux(unsigned long win);

static WCHAR	section_type_name[] = {'S', 'e', 'c', 't', 'i', 'o', 'n', 0};
POBJECT_TYPE	section_object_type = NULL;
EXPORT_SYMBOL(section_object_type);
extern POBJECT_TYPE	file_object_type;
extern POBJECT_TYPE	process_object_type;
extern HANDLE base_dir_handle;

static GENERIC_MAPPING section_mapping = {
	STANDARD_RIGHTS_READ | SECTION_MAP_READ | SECTION_QUERY,
	STANDARD_RIGHTS_WRITE | SECTION_MAP_WRITE,
	STANDARD_RIGHTS_EXECUTE | SECTION_MAP_EXECUTE,
	SECTION_ALL_ACCESS};

static void delete_section(PVOID section);

VOID
init_section_implement(VOID)
{
	OBJECT_TYPE_INITIALIZER ObjectTypeInitializer;
	UNICODE_STRING Name;

	/* Initialize the Section object type  */
	memset(&ObjectTypeInitializer, 0, sizeof(ObjectTypeInitializer));
	init_unistr(&Name, (PWSTR)section_type_name);
	ObjectTypeInitializer.Length = sizeof(ObjectTypeInitializer);
	ObjectTypeInitializer.DefaultPagedPoolCharge = sizeof(struct win32_section);
	ObjectTypeInitializer.PoolType = PagedPool;
	ObjectTypeInitializer.UseDefaultObject = TRUE;
	ObjectTypeInitializer.GenericMapping = section_mapping;
	ObjectTypeInitializer.DeleteProcedure = delete_section;
	create_type_object(&ObjectTypeInitializer, &Name, &section_object_type);
} /* end init_section_implement */

/*
 * open a section object, maybe creating if non-existent
 */
NTSTATUS SERVICECALL
NtCreateSection(
		OUT PHANDLE  SectionHandle,
		IN ACCESS_MASK  DesiredAccess,
		IN POBJECT_ATTRIBUTES  ObjectAttributes OPTIONAL,
		IN PLARGE_INTEGER  MaximumSize OPTIONAL,
		IN ULONG  Protect,
		IN ULONG  AllocationAttributes,
		IN HANDLE  FileHandle OPTIONAL
		)
{
	HANDLE	hSection;
	size_t	size = 0;
	struct win32_file	*wfile = NULL;
	struct win32_section	*section;
	struct ethread	*thread;
	POBJECT_ATTRIBUTES	obj_attr = NULL;
	LARGE_INTEGER	max_size;
	NTSTATUS	Status;
	MODE	previous_mode;

	ktrace("()\n");
	if (!(thread = get_current_ethread()))
		return STATUS_UNSUCCESSFUL;

	/* FIXME */
	previous_mode = (unsigned long)ObjectAttributes > TASK_SIZE ? KernelMode : UserMode;

	if (ObjectAttributes) {
		if (previous_mode == UserMode) {
			if (copy_object_attr_from_user(ObjectAttributes, &obj_attr))
				return STATUS_NO_MEMORY;
		}
		else
			obj_attr = ObjectAttributes;
	}
	
	if (obj_attr && obj_attr->RootDirectory)
		obj_attr->RootDirectory = base_dir_handle;

	if (MaximumSize) {
		if (previous_mode == UserMode) {
			Status = STATUS_NO_MEMORY;
			if (copy_from_user(&max_size, MaximumSize, sizeof(max_size)))
				goto cleanup_object_attr;
			MaximumSize = &max_size;
		}
		Status = STATUS_INVALID_PARAMETER;
		if (MaximumSize->u.HighPart)
			goto cleanup_object_attr;
		size = MaximumSize->u.LowPart;
	}

	/* gain access to the file */
	if (FileHandle) {
		Status = ref_object_by_handle(
				FileHandle,
				DesiredAccess,
				file_object_type,
				KernelMode,
				(PVOID *)&wfile,
				NULL
				);
		if (!NT_SUCCESS(Status))
			goto cleanup_object_attr;
	}
	
	/* create a section object */
	Status = create_object(
			KernelMode,
			section_object_type,
			obj_attr,
			KernelMode,
			NULL,
			sizeof(struct win32_section),
			0,
			0,
			(PVOID *)&section
		      );
	if (Status)
		goto cleanup_wfile;

	Status = insert_object(
			(PVOID)section,
			NULL,
			0,
			0,
			NULL,
			&hSection
			);
	if (Status == STATUS_OBJECT_NAME_EXISTS) {
		deref_object(section);
		goto section_exists;
	}

	deref_object(section);
	if (Status)
		goto cleanup_wfile;

	/* setup section */
	if (wfile)
		ref_object(wfile);
	section->ws_wfile = wfile;	/* attach file */
	section->ws_len = size;

	section->ws_flags = 0;
	section->ws_alloctype = AllocationAttributes;
	if (AllocationAttributes & _SEC_IMAGE) {
		if (!wfile || image_section_setup(section) < 0) {
			Status = STATUS_NO_SUCH_FILE;
			goto cleanup_handle;
		}
	}
	else {
		if ((Protect & PAGE_PROT_MASK) != Protect || !(Protect & PAGE_PROT_MASK)) {
			Status = STATUS_INVALID_PAGE_PROTECTION;
			kdebug("FIXME: some protect not implemention! Protect %x\n", Protect);
			goto cleanup_handle;
		}

		section->ws_protect = prot_to_linux(Protect);

		/* anonymous map, map len is need */
		if (!wfile && !section->ws_len) {
			Status = STATUS_NOT_MAPPED_VIEW;
			goto cleanup_handle;
		}
		if (!wfile && (!obj_attr->ObjectName || !obj_attr->ObjectName->Length)) {
			Status = STATUS_OBJECT_NAME_INVALID;
			goto cleanup_handle;
		}

		if (!wfile && (AllocationAttributes & _SEC_RESERVE))
			section->ws_flags |= MAP_RESERVE;

		if ((Protect & _PAGE_WRITECOPY) || (Protect & _PAGE_EXECUTE_WRITECOPY))
			/* copy on write */
			section->ws_flags |= MAP_PRIVATE;
		else
			/* shared map */
			section->ws_flags |= MAP_SHARED;

		/* get the file size, when paramter len is 0 */
		if (!section->ws_len && wfile)
			section->ws_len = wfile->wf_file->f_dentry->d_inode->i_size;
		section->ws_pagelen = PAGE_ALIGN(section->ws_len);

		/* TODO
		if (section->ws_len < wfile->wf_file->f_dentry->d_inode->i_size)
			grow_file(wfile);
		*/

		if (data_section_setup(section) < 0) {
			Status = STATUS_NOT_MAPPED_VIEW;
			goto cleanup_handle;
		}
	}

	Status = STATUS_SUCCESS;

section_exists:
	if (previous_mode == UserMode) {
		if (copy_to_user(SectionHandle, &hSection, sizeof(hSection))) {
			Status = STATUS_INVALID_ADDRESS;
			goto cleanup_handle;
		}
	}
	else
		*SectionHandle = hSection;

	goto cleanup_wfile;

cleanup_handle:
	NtClose(hSection);
cleanup_wfile:
	if (wfile)
		deref_object((PVOID)wfile);
cleanup_object_attr:
	if (obj_attr && previous_mode == UserMode)
		kfree(obj_attr);

	return Status;
} /* end NtCreateSection() */
EXPORT_SYMBOL(NtCreateSection);

/*
 * map a view of the section to the process's address space
 */
NTSTATUS
SERVICECALL
NtMapViewOfSection(
		IN HANDLE  SectionHandle,
		IN HANDLE  ProcessHandle,
		IN OUT PVOID  *BaseAddress,
		IN ULONG  ZeroBits,
		IN ULONG  CommitSize,
		IN OUT PLARGE_INTEGER  SectionOffset  OPTIONAL,
		IN OUT PSIZE_T  ViewSize,
		IN SECTION_INHERIT  InheritDisposition,
		IN ULONG  AllocationType,
		IN ULONG  Protect
		)
{
	NTSTATUS	Status;
	size_t		size = 0;
	MODE		previous_mode;
	unsigned long	addr = 0L;
	struct win32_section	*section;
	struct ethread	*thread;
	struct eprocess *process;
	LARGE_INTEGER	sec_off = { .QuadPart = 0LL };

	ktrace("\n");
	if (!(thread = get_current_ethread()))
		return STATUS_UNSUCCESSFUL;

	/* FIXME */
	previous_mode = (unsigned long)BaseAddress > TASK_SIZE ? KernelMode : UserMode;

	if (!BaseAddress)
		return STATUS_INVALID_PARAMETER;
	if (!ViewSize)
		return STATUS_INVALID_PARAMETER;

	if (previous_mode == UserMode) {
		if (copy_from_user(&addr, BaseAddress, sizeof(PVOID)))
			return STATUS_INVALID_ADDRESS;
		if (copy_from_user(&size, ViewSize, sizeof(size)))
			return STATUS_INVALID_ADDRESS;
		if (SectionOffset && copy_from_user(&sec_off, SectionOffset, sizeof(sec_off)))
			return STATUS_INVALID_ADDRESS;
	}
	else {
		addr = (unsigned long)*BaseAddress;
		size = (size_t)*ViewSize;
		if (SectionOffset)
			sec_off = *SectionOffset;
	}

	if (addr > WIN32_TASK_SIZE || size > WIN32_TASK_SIZE)
		return STATUS_INVALID_PARAMETER;

	/* TODO: not support 64bit offset */
	if (sec_off.u.HighPart)
		return STATUS_INVALID_PARAMETER;

	/* access the section object */
	Status = ref_object_by_handle(
			SectionHandle,
			SECTION_ALL_ACCESS,
			section_object_type,
			KernelMode,
			(PVOID *)&section,
			NULL
			);
	if (Status)
		return Status;
	
	if (!ProcessHandle || ProcessHandle == NtCurrentProcess()) {
		process = thread->threads_process;
		ref_object((PVOID)process);
	}
	else {
		Status = ref_object_by_handle(
				ProcessHandle,
				PROCESS_ALL_ACCESS,
				process_object_type,
				KernelMode,
				(PVOID *)&process,
				NULL
				);
		if (Status)
			goto cleanup_section;
	}
	
	Status = map_section_view(
			(PVOID)section,
			process,
			(PVOID *)&addr,
			ZeroBits,
			CommitSize,
			SectionOffset ? (PLARGE_INTEGER)&sec_off : NULL,
			(PSIZE_T)&size,
			InheritDisposition,
			AllocationType,
			Protect
			);

	if (!NT_SUCCESS(Status))
		goto cleanup_process;

	Status = STATUS_INVALID_ADDRESS;
	if (previous_mode == UserMode) {
		if (copy_to_user(BaseAddress, &addr, sizeof(PVOID)))
			goto cleanup_process;
		if (copy_to_user(ViewSize, &size, sizeof(PVOID)))
			goto cleanup_process;
	}
	else {
		*BaseAddress = (PVOID)addr;
		*ViewSize = size;
	}

	Status = STATUS_SUCCESS;

cleanup_process:
	deref_object(process);

cleanup_section:
	deref_object(section);

	return Status;
} /* end NtMapViewOfSection() */
EXPORT_SYMBOL(NtMapViewOfSection);

/*
 * unmap a mapped view of the file
 * - the view must start _exactly_ on the address
 */
NTSTATUS SERVICECALL
NtUnmapViewOfSection(
		IN HANDLE  ProcessHandle,
		IN PVOID  BaseAddress
		)
{
	struct mm_struct	*mm;
	struct eprocess	*process;
	struct ethread	*thread;
	NTSTATUS	ret;

	ktrace("\n");
	if (!ProcessHandle || ProcessHandle == NtCurrentProcess()) {
		mm = current->mm;
		process = get_current_eprocess();
		ref_object((PVOID)process);
	} else {
		ret = ref_object_by_handle(
				ProcessHandle,
				PROCESS_ALL_ACCESS,
				process_object_type,
				KernelMode,
				(PVOID *)&process,
				NULL
				);
		if (!NT_SUCCESS(ret))
			return ret;
		thread = get_first_thread(process);
		if (!thread) {
			ret = STATUS_THREAD_NOT_IN_PROCESS;
			goto out;
		}
		mm = thread->et_task->mm;
	}

	ret = unmap_section_view(process, mm, (unsigned long)BaseAddress);

out:
	deref_object(process);
	return ret;
} /* NtUnmapViewOfSection() */
EXPORT_SYMBOL(NtUnmapViewOfSection);

NTSTATUS SERVICECALL
NtOpenSection(PHANDLE   SectionHandle,
		ACCESS_MASK  DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes)
{
	HANDLE hSection;
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

	if (obj_attr && obj_attr->RootDirectory)
		obj_attr->RootDirectory = base_dir_handle;

	Status = open_object_by_name(obj_attr,
			section_object_type,
			NULL,
			KernelMode,
			DesiredAccess,
			NULL,
			&hSection);

	if (!NT_SUCCESS(Status))
		goto cleanup;

	if (previous_mode == UserMode) {
		if (copy_to_user(SectionHandle, &hSection, sizeof(HANDLE))) {
			Status = STATUS_INVALID_ADDRESS;
			goto cleanup;
		}
	}
	else 
		*SectionHandle = hSection;

cleanup:
	if (obj_attr && previous_mode == UserMode)
		kfree(obj_attr);
	return Status;
} /* end NtOpenSection */ 
EXPORT_SYMBOL(NtOpenSection);

NTSTATUS SERVICECALL
NtExtendSection(IN HANDLE 		SectionHandle,
                IN PLARGE_INTEGER 	NewMaximumSize)
{	
	ktrace("\n");
	return STATUS_NOT_IMPLEMENTED;
} /* end NtExtendSection */
EXPORT_SYMBOL(NtExtendSection);

/* 
 * NtQuerySection
 */
NTSTATUS SERVICECALL
NtQuerySection(IN HANDLE SectionHandle,
		IN SECTION_INFORMATION_CLASS SectionInformationClass,
		OUT PVOID SectionInformation,
		IN ULONG SectionInformationLength,
		OUT PULONG ResultLength  OPTIONAL)
{
	struct win32_section    *ws;
	struct ethread  *thread;
	long len;
	NTSTATUS	Status;
	MODE previous_mode;
	PSECTION_IMAGE_INFORMATION	sii = NULL;
	PSECTION_BASIC_INFORMATION	sbi = NULL;

	ktrace("\n");
	previous_mode = (unsigned long)SectionInformation > TASK_SIZE ? KernelMode : UserMode;

	if (!(thread = get_current_ethread())) {
		return STATUS_UNSUCCESSFUL;
	}

	Status = ref_object_by_handle(
			SectionHandle,
			SECTION_ALL_ACCESS,
			section_object_type,
			KernelMode,
			(PVOID *)&ws,
			NULL
			);
	if (!NT_SUCCESS(Status))
		return Status;

	switch (SectionInformationClass) {
		case SectionBasicInformation:
			if (!(sbi = kmalloc(sizeof(SECTION_BASIC_INFORMATION), GFP_KERNEL))) {
				Status = STATUS_NO_MEMORY;
				goto cleanup_section;
			}

			sbi->Attributes = ws->ws_alloctype;
			if (ws->ws_alloctype & _SEC_IMAGE) {
				sbi->BaseAddress = 0;
				sbi->Size.QuadPart = 0LL;
			}
			else {
				sbi->BaseAddress = (void *)ws->ws_sections->wis_rva;
				sbi->Size.QuadPart = (long long)ws->ws_sections->wis_size;
			}

			if (ResultLength) {
				len = sizeof(SECTION_BASIC_INFORMATION);
				if (copy_to_user(ResultLength, &len, sizeof(long))) {
					Status = STATUS_INVALID_ADDRESS;
					goto cleanup_sbi;
				}
				else
					*ResultLength = len;
			}

			if (copy_to_user(SectionInformation, sbi, sizeof(*sbi))) {
				Status = STATUS_INVALID_ADDRESS;
				goto cleanup_sbi;
			}
			else
				memcpy(SectionInformation, sbi, sizeof(*sbi));

			break;
		case SectionImageInformation:
			if (!(sii = kmalloc(sizeof(SECTION_IMAGE_INFORMATION), GFP_KERNEL))) {
				Status = STATUS_NO_MEMORY;
				goto cleanup_section;
			}

			if(ws->ws_alloctype & _SEC_IMAGE) {
				sii->EntryPoint = ws->ws_entrypoint;
				sii->StackReserve = ws->ws_stackresv;
				sii->StackCommit = ws->ws_stackcommit;
				sii->Subsystem= ws->ws_subsystem;
				sii->MinorSubsystemVersion = ws->ws_minorver;
				sii->MajorSubsystemVersion = ws->ws_majorver;
				sii->Characteristics = ws->ws_imagecharacter;
				sii->ImageNumber = ws->ws_machine;
				sii->Executable = ws->ws_executable;
			}

			if (ResultLength) {
				len = sizeof(SECTION_IMAGE_INFORMATION);
				if (previous_mode == UserMode) {
					if (copy_to_user(ResultLength, &len, sizeof(long))){
						Status = STATUS_INVALID_ADDRESS;
						goto cleanup_sii;
					}
				}
				else
					*ResultLength = len;
			}
			if (previous_mode == UserMode) {
				if (copy_to_user(SectionInformation, sii, sizeof(*sii))) {
					Status = STATUS_INVALID_ADDRESS;
					goto cleanup_sii;
				}
			}
			else
				memcpy(SectionInformation, sii, sizeof(*sii));
			break;
		default:
			break;
	}

cleanup_sii:
	if (sii)
		kfree(sii);
	goto cleanup_section;

cleanup_sbi:
	if (sbi)
		kfree(sbi);

cleanup_section:
	deref_object((PVOID)ws);

	return Status;
} /* end NtQuerySection */
EXPORT_SYMBOL(NtQuerySection);

/*
 * destroy a section (discard its private data)
 */
static void delete_section(PVOID section)
{
	struct win32_section	*ws = section;

	/* discard the association with the file object */
	if (ws->ws_wfile)
		deref_object(ws->ws_wfile);

	if (ws->ws_sections)
		kfree(ws->ws_sections);
} /* end SectionDestructor() */

/*
 * map_section_view
 * map a view of the section to the process's address space
 */
NTSTATUS
STDCALL
map_section_view(
		IN PVOID  SectionObject,
		IN struct eprocess*  Process,
		IN OUT PVOID  *BaseAddress,
		IN ULONG  ZeroBits,
		IN ULONG  CommitSize,
		IN OUT PLARGE_INTEGER  SectionOffset  OPTIONAL,
		IN OUT PSIZE_T  ViewSize,
		IN SECTION_INHERIT  InheritDisposition,
		IN ULONG  AllocationType,
		IN ULONG  Protect
		)
{
	NTSTATUS	status;
	size_t		size;
	unsigned long	offset;
	unsigned long	addr;
	unsigned long	flags = 0;
	struct win32_section	*section = SectionObject;
	struct vm_area_struct	*vma;
	struct ethread	*thread;
	struct task_struct *tsk;

	if (!(thread = get_first_thread(Process)))
		return STATUS_THREAD_NOT_IN_PROCESS;

	/* map offset, aligned to PAGE_SIZE */
	if ((offset = SectionOffset ? SectionOffset->u.LowPart : 0))
		offset &= PAGE_MASK;

	/* map size */
	size = PAGE_ALIGN(*ViewSize);

	tsk = thread->et_task;

	/* get the win32_section struct */
	flags |= section->ws_flags;

	if (offset >= section->ws_len || offset + size > section->ws_pagelen) {
		status = STATUS_INVALID_PARAMETER;
		goto out;
	}

	/* map total section len */
	if (!size)
		size = section->ws_pagelen - offset;

	if ((addr = (unsigned long)*BaseAddress)) {
		/* fixed address map, align to 64k */
		addr = (addr + BASE_ADDRESS_ALIGN - 1) & ~(BASE_ADDRESS_ALIGN - 1);
		if ((vma = find_vma(tsk->mm, addr)) && vma->vm_start < addr + size) {
			status = STATUS_INVALID_ADDRESS;
			goto out;
		}
		flags |= MAP_FIXED;
	}

	if (section->ws_mmap) {
		/* do the mmap operation */
		status = section->ws_mmap(tsk, section, &addr, size, flags, offset >> PAGE_SHIFT);
		if (NT_SUCCESS(status)) {
			*BaseAddress = (PVOID)addr;
			insert_mapped_area(Process, addr, addr + size, Protect, section);
		}
	} else
		status = STATUS_UNSUCCESSFUL;

out:
	return status;
} /* end map_section_view() */
EXPORT_SYMBOL(map_section_view);

NTSTATUS STDCALL
unmap_section_view(struct eprocess *process, struct mm_struct *mm, unsigned long addr)
{
	struct win32_area_struct *ma;
	struct win32_section *ws;
	NTSTATUS ret;

	if (!(ma = find_mapped_area(process, addr, addr)) || ma->start != addr)
		return STATUS_NOT_MAPPED_VIEW;

	ws = (struct win32_section *)ma->section_object;
	if (ws && ws->ws_munmap)
		ret = ws->ws_munmap(ws);
	else {
		down_write(&mm->mmap_sem);
		ret = do_munmap(mm, addr, ws ? ws->ws_pagelen : ma->end - addr);
		up_write(&mm->mmap_sem);
	}

	remove_win32_area(ma);

	return STATUS_SUCCESS;
}
#endif /* CONFIG_UNIFIED_KERNEL */
