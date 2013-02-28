/*
 * file.c
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
 * file.c: file syscall functions
 * Refered to Kernel-win32 code
 */
#include <linux/file.h>
#include <linux/smp_lock.h>
#include <linux/fs.h>
#include "file.h"
#include "process.h"
#include "thread.h"

#ifdef CONFIG_UNIFIED_KERNEL

POBJECT_TYPE file_object_type = NULL;
EXPORT_SYMBOL(file_object_type);
POBJECT_TYPE file_ctrl_object_type = NULL;
EXPORT_SYMBOL(file_ctrl_object_type);
POBJECT_DIRECTORY file_ctrl_root = NULL;
EXPORT_SYMBOL(file_ctrl_root);
HANDLE	file_ctrl_root_handle = NULL;
EXPORT_SYMBOL(file_ctrl_root_handle);

static int  file_check_sharing(struct win32_file *, struct win32_file_ctrl *);

extern int unistr2charstr(PWSTR unistr, LPCSTR chstr);
extern NTSTATUS translate_object_name(PUNICODE_STRING ObjectName);

/*
 * open a file object, maybe creating if non-existent
 */
NTSTATUS
SERVICECALL
NtCreateFile(
		OUT PHANDLE	FileHandle,
		IN ACCESS_MASK	DesiredAccess,
		IN POBJECT_ATTRIBUTES	ObjectAttributes,
		OUT PIO_STATUS_BLOCK	IoStatusBlock,
		IN PLARGE_INTEGER	AllocationSize OPTIONAL,
		IN ULONG	FileAttributes,
		IN ULONG	ShareAccess,
		IN ULONG	CreateDisposition,
		IN ULONG	CreateOptions,
		IN PVOID	EaBuffer OPTIONAL,
		IN ULONG	EaLength
	    )
{
	HANDLE	hFile;
	int	flags;
	char	*filename;
	NTSTATUS	ret = STATUS_SUCCESS;
	struct win32_file	*Object;
	struct win32_file_ctrl	*ControlObject, *TempObject = NULL;
	struct ethread	*thread;
	POBJECT_ATTRIBUTES	obj_attr = NULL;
	IO_STATUS_BLOCK		io_status;
	LARGE_INTEGER		alloc_size;
	OBJECT_ATTRIBUTES	ControlObjectAttributes;
	MODE	previous_mode;
	int fd;
	struct file *f;

	ktrace("\n");
	/* FIXME */
	previous_mode = (unsigned long)ObjectAttributes > TASK_SIZE ? KernelMode : UserMode;

	thread = get_current_ethread();
	if (!thread)
		return STATUS_UNSUCCESSFUL;

	if (!ObjectAttributes)
		return STATUS_INVALID_PARAMETER;

	if (!IoStatusBlock)
		return STATUS_INVALID_PARAMETER;

    memset(&ControlObjectAttributes, 0, sizeof(OBJECT_ATTRIBUTES));
	if (previous_mode == UserMode) {
		/* copy Object Attributes from user space */
		if (copy_object_attr_from_user(ObjectAttributes, &obj_attr)) {
			return STATUS_NO_MEMORY;
		}
		ObjectAttributes = obj_attr;

		if (copy_from_user(&io_status, IoStatusBlock, sizeof(io_status)))
			goto cleanup_object_attr;
		IoStatusBlock = &io_status;

		if (AllocationSize) {
			if (copy_from_user(&alloc_size, AllocationSize, sizeof(alloc_size)))
				goto cleanup_object_attr;
			AllocationSize = &alloc_size;
		}
	}

	ret = translate_object_name(ObjectAttributes->ObjectName);
	if (!NT_SUCCESS(ret))
		goto cleanup_object_attr;

	memcpy(&ControlObjectAttributes, ObjectAttributes, sizeof(OBJECT_ATTRIBUTES));
	ControlObjectAttributes.RootDirectory = file_ctrl_root_handle;

	/* create and insert FileControl Object */
	ret = create_object(KernelMode,
			file_ctrl_object_type,
			&ControlObjectAttributes,
			KernelMode,
			NULL,
			sizeof(struct win32_file_ctrl),
			0,
			0,
			(PVOID *)&ControlObject);
	if (!NT_SUCCESS(ret))
		goto cleanup_object_attr;

	INIT_LIST_HEAD(&ControlObject->wfc_accessors);
	spin_lock_init(&ControlObject->wfc_lock);

	ret = insert_object(ControlObject,
			NULL,
			STANDARD_RIGHTS_REQUIRED,
			0,
			(PVOID *)&TempObject,
			NULL);
	if (ret == STATUS_OBJECT_NAME_EXISTS) {
		deref_object(ControlObject);
		ControlObject = TempObject;
	}

	/* create and insert File Object */
	ObjectAttributes->ObjectName = NULL;
	ret = create_object(KernelMode,
			file_object_type,
			ObjectAttributes,
			KernelMode,
			NULL,
			sizeof(struct win32_file),
			0,
			0,
			(PVOID *)&Object);
	if (!NT_SUCCESS(ret))
		goto cleanup_ctrl_obj;

	ret = insert_object(Object,
			NULL,
			STANDARD_RIGHTS_REQUIRED,
			0,
			NULL,
			&hFile);
	deref_object(Object);
	if (!NT_SUCCESS(ret))
		goto cleanup_ctrl_obj;

	Object->wf_access	= DesiredAccess;
	Object->wf_sharing	= ShareAccess;
	Object->wf_attrs	= FileAttributes;
	Object->wf_control	= ControlObject;
	ref_object(ControlObject);

	spin_lock(&ControlObject->wfc_lock);

	/* check that we can share access */
	ret = file_check_sharing(Object, ControlObject);
	if (ret < 0)
		goto cleanup_ctrl_lock;

	/* determine Linux file open parameters */
	switch (CreateDisposition) {
		case FILE_CREATE:
			flags = O_CREAT | O_EXCL;
			break;
		case FILE_OVERWRITE_IF:
			flags = O_CREAT | O_TRUNC;
			break;
		case FILE_OPEN_IF:
			flags = O_CREAT;
			break;
		case FILE_OVERWRITE:
			flags = O_TRUNC;
			break;
		case FILE_OPEN:
			flags = 0;
			break;
		default:
			ret = STATUS_INVALID_PARAMETER;
			goto cleanup_ctrl_lock;
	}

	switch (DesiredAccess & (GENERIC_READ | GENERIC_WRITE)) {
		case GENERIC_READ:
			flags |= O_RDONLY;
			break;
		case GENERIC_WRITE:
			flags |= O_WRONLY;
			break;
		case GENERIC_READ | GENERIC_WRITE:
			flags |= O_RDWR;
			break;
		default:
			break;
	}

	/* open the Linux file */
	filename = (char *)kmalloc(ControlObjectAttributes.ObjectName->MaximumLength, GFP_KERNEL);
	ret = STATUS_NO_MEMORY;
	if (!filename)
		goto cleanup_ctrl_lock;

	unistr2charstr((PWSTR)ControlObjectAttributes.ObjectName->Buffer, (LPCSTR)filename);

	fd = get_unused_fd();
	if (fd >= 0) {
		f = filp_open(filename, flags, (FileAttributes & FILE_ATTRIBUTE_READONLY) ? 0444 : 0666);
		if (IS_ERR(f)) {
			put_unused_fd(fd);
			Object->wf_control = NULL;
			/*             fd = PTR_ERR(f); */
			goto cleanup_filename;
		} else {
			/*             fsnotify_open(f->f_dentry); */
			fd_install(fd, f);
		}
	}
	else goto cleanup_filename;

	Object->wf_fd = fd;
	Object->wf_file = NULL;


	Object->wf_file = filp_open(filename, flags,
			(FileAttributes & FILE_ATTRIBUTE_READONLY) ? 0444 : 0666);
	if (IS_ERR(Object->wf_file)) {
		ret = PTR_ERR(Object->wf_file);
		Object->wf_file = NULL;
		Object->wf_control = NULL;
		goto cleanup_filename;
	}

	/* don't permit a directory to be opened */
	if (S_ISDIR (f->f_dentry->d_inode->i_mode)) {
		ret = STATUS_FILE_IS_A_DIRECTORY;
		goto cleanup_file;
	}

	list_add(&Object->wf_ctllist, &ControlObject->wfc_accessors);
	spin_unlock(&ControlObject->wfc_lock);

	ret = STATUS_NO_MEMORY;
	if (copy_to_user(FileHandle, &hFile, sizeof(HANDLE)))
		goto cleanup_file;

	ret = STATUS_SUCCESS;

	kfree(filename);
	goto cleanup_ctrl_obj;

	/* clean up on error */
cleanup_file:
	fput(Object->wf_file);

cleanup_filename:
	kfree(filename);

cleanup_ctrl_lock:
	spin_unlock(&ControlObject->wfc_lock);
	NtClose(hFile);

cleanup_ctrl_obj:
	deref_object(ControlObject);

cleanup_object_attr:
	if (obj_attr) {
        if (ControlObjectAttributes.ObjectName && ControlObjectAttributes.ObjectName->Buffer)
            kfree(ControlObjectAttributes.ObjectName->Buffer);
		kfree(obj_attr);
	}

	return ret;
} /* end NtCreateFile() */
EXPORT_SYMBOL(NtCreateFile);

/*
 * open a file object, failing if non-existent
 * TODO: not implemented, used NtCreateFile instead
 */
NTSTATUS
SERVICECALL
NtOpenFile(
		OUT PHANDLE FileHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes,
		OUT PIO_STATUS_BLOCK IoStatusBlock,
		IN ULONG ShareAccess,
		IN ULONG OpenOptions
	  )
{
	return NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
			IoStatusBlock, NULL, 0, ShareAccess, FILE_OPEN, OpenOptions, NULL, 0);
} /* end NtOpenFile() */
EXPORT_SYMBOL(NtOpenFile);

/*
 * read from a file
 */
NTSTATUS
SERVICECALL
NtReadFile(
		IN HANDLE FileHandle,
		IN HANDLE Event OPTIONAL,
		IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
		IN PVOID ApcContext OPTIONAL,
		OUT PIO_STATUS_BLOCK IoStatusBlock,
		OUT PVOID Buffer,
		IN ULONG Length,
		IN PLARGE_INTEGER ByteOffset OPTIONAL, /* NOT optional for asynch. operations! */
		IN PULONG Key OPTIONAL
	  )
{
	struct win32_file *wf;
	struct file *file;
	loff_t	pos;
	struct ethread	*thread;
	IO_STATUS_BLOCK		io_status;
	NTSTATUS	status = STATUS_UNSUCCESSFUL;

	ktrace("NtReadFile(%p)\n", FileHandle);

	thread = get_current_ethread();
	if (!thread)
		goto cleanup_nobj;

	if (!IoStatusBlock)
		return STATUS_INVALID_PARAMETER;

	status = ref_object_by_handle(FileHandle,
			STANDARD_RIGHTS_REQUIRED,
			NULL,
			KernelMode,
			(PVOID *)&wf,
			NULL);
	if (!NT_SUCCESS(status))
		return status;

	file = wf->wf_file;

	/* check the file can actually be read */
	if (!(wf->wf_access & GENERIC_READ))
		goto cleanup;

	status = STATUS_ACCESS_VIOLATION;
	if (!(file->f_mode & FMODE_READ))
		goto cleanup;

	/* read from file */
	pos = file->f_pos;
	if ((unsigned long)Buffer < TASK_SIZE) { /* FIXME */
		status = vfs_read(file, Buffer, Length, &pos);
		file->f_pos = pos;
	}
	else
		status = kernel_read(file, pos, Buffer, Length);
	if (status >= 0) {
		/* write _ReadBytes_ to user space */
		io_status.Information = (ULONG_PTR)status;
		if ((unsigned long)Buffer < TASK_SIZE) /* FIXME */
			status = copy_to_user(IoStatusBlock, &io_status, sizeof(io_status))
				? STATUS_NO_MEMORY: STATUS_SUCCESS; 
	}

cleanup:
	deref_object((PVOID)wf);

cleanup_nobj:
	ktrace("*** NtReadFile = %d\n", status);
	return status;
} /* end NtReadFile() */
EXPORT_SYMBOL(NtReadFile);

/*
 * write to a file
 */
NTSTATUS
SERVICECALL
NtWriteFile (
		IN HANDLE FileHandle,
		IN HANDLE Event OPTIONAL,
		IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
		IN PVOID ApcContext OPTIONAL,
		OUT PIO_STATUS_BLOCK IoStatusBlock,
		IN PVOID Buffer,
		IN ULONG Length,
		IN PLARGE_INTEGER ByteOffset OPTIONAL, /* NOT optional for asynch. operations! */
		IN PULONG Key OPTIONAL
	    )
{
	struct file	*file;
	struct win32_file	*wf;
	struct ethread	*thread;
	loff_t	pos;
	IO_STATUS_BLOCK	io_status;
	NTSTATUS	status = STATUS_UNSUCCESSFUL;

	ktrace("NtWriteFile(%p)\n", FileHandle);

	thread = get_current_ethread();
	if (!thread)
		goto cleanup_nobj;

	if (!IoStatusBlock)
		return STATUS_INVALID_PARAMETER;

	status = ref_object_by_handle(FileHandle,
			STANDARD_RIGHTS_REQUIRED,
			NULL,
			KernelMode,
			(PVOID *)&wf,
			NULL);
	if (!NT_SUCCESS(status))
		return status;

	file = wf->wf_file;

	/* check the file can actually be written */
	if (!(wf->wf_access & GENERIC_WRITE))
		goto cleanup;

	status = STATUS_ACCESS_VIOLATION;
	if (!(file->f_mode & FMODE_WRITE))
		goto cleanup;

	/* write to file */
	pos = file->f_pos;
	status = vfs_write(file, Buffer, Length, &pos);
	file->f_pos = pos;
	if (status >= 0) {
		/* copy _WRITEDBYTES_ to user space */
		io_status.Information = (ULONG_PTR)status;
		if(copy_to_user(IoStatusBlock, &io_status, sizeof(io_status)))
			status = STATUS_NO_MEMORY;
		else
			status = STATUS_SUCCESS; 
	}

cleanup:
	deref_object((PVOID)wf);

cleanup_nobj:
	ktrace("*** NtWriteFile = %d\n", status);
	return status;
} /* end NtWriteFile() */
EXPORT_SYMBOL(NtWriteFile);

/*
 * set a file information
 */
NTSTATUS
SERVICECALL
NtSetInformationFile(
		HANDLE FileHandle,
		PIO_STATUS_BLOCK IoStatusBlock,
		PVOID FileInformation,
		ULONG Length,
		FILE_INFORMATION_CLASS FileInformationClass
		)
{
	struct file	*file;
	struct win32_file	*wf;
	struct ethread	*thread;
	loff_t	(*fn)(struct file *, loff_t, int);
	loff_t	offset;
	NTSTATUS	status = 0;

	ktrace("*** NtSetInformationFile (%p)\n", FileHandle);

	thread = get_current_ethread();
	if (!thread)
		return STATUS_UNSUCCESSFUL;

	status = ref_object_by_handle(FileHandle,
			STANDARD_RIGHTS_REQUIRED,
			NULL,
			KernelMode,
			(PVOID *)&wf,
			NULL);
	if (!NT_SUCCESS(status))
		return status;

	file = wf->wf_file;

	switch (FileInformationClass) {
		case FilePositionInformation:
			{
				FILE_POSITION_INFORMATION	PosInfo;

				if (Length < sizeof(PosInfo))
					status = STATUS_INVALID_PARAMETER;

				status = copy_from_user(&PosInfo, FileInformation, sizeof(PosInfo));

				/* set the seek function pointer */
				fn = default_llseek;
				if (file->f_op && file->f_op->llseek)
					fn = file->f_op->llseek;

				lock_kernel();
				/* do the seek operation */
				offset = fn(file, PosInfo.CurrentByteOffset.LowPart, 0);
				unlock_kernel();
				if (offset < 0) {
					status = offset;
					goto cleanup;
				}

				status = STATUS_SUCCESS;

				break;
			}
		default:
			break;
	}

cleanup:
	deref_object((PVOID)wf);
	ktrace("*** NtSetInformationFile = %d\n", status);
	return status;
} /* end NtSetInformationFile() */
EXPORT_SYMBOL(NtSetInformationFile);

/*
 * Query File Information
 */
NTSTATUS
SERVICECALL
NtQueryInformationFile(
		HANDLE FileHandle,
		PIO_STATUS_BLOCK IoStatusBlock,
		PVOID FileInformation,
		ULONG Length,
		FILE_INFORMATION_CLASS FileInformationClass
		)
{
	struct file	*file;
	struct win32_file	*wf;
	struct ethread	*thread;
	loff_t	(*fn)(struct file *, loff_t, int);
	NTSTATUS	status = 0;

	ktrace("NtQueryInformationFile (%p)\n", FileHandle);

	thread = get_current_ethread();
	if (!thread)
		return STATUS_UNSUCCESSFUL;

	status = ref_object_by_handle(FileHandle,
			STANDARD_RIGHTS_REQUIRED,
			NULL,
			KernelMode,
			(PVOID *)&wf,
			NULL);
	if (!NT_SUCCESS(status))
		return status;

	file = wf->wf_file;

	switch (FileInformationClass) {
		case FilePositionInformation:
			{
				FILE_POSITION_INFORMATION	PosInfo;

				if (Length < sizeof(PosInfo))
					status = STATUS_INVALID_PARAMETER;

				/* set the seek function pointer */
				fn = default_llseek;
				if (file->f_op && file->f_op->llseek)
					fn = file->f_op->llseek;

				lock_kernel();
				/* get current file position */
				PosInfo.CurrentByteOffset.LowPart = fn(file, 0, 1);
				unlock_kernel();
				if (PosInfo.CurrentByteOffset.LowPart < 0) {
					status = PosInfo.CurrentByteOffset.LowPart;
					goto cleanup;
				}

				/* copy the information to user space */
				if(copy_to_user(FileInformation, &PosInfo, sizeof(PosInfo)))
					status = STATUS_NO_MEMORY;
				else
					status = STATUS_SUCCESS; 
				break;
			}
		default:
			break;
	}

cleanup:
	deref_object((PVOID)wf);
	ktrace("*** NtQueryInformationFile = %d\n", status);
	return status;
} /* end NtQueryInformationFile() */
EXPORT_SYMBOL(NtQueryInformationFile);

/*
 * flush the buffers of a file
 */
NTSTATUS
SERVICECALL
NtFlushBuffersFile(
		IN HANDLE FileHandle,
		OUT PIO_STATUS_BLOCK IoStatusBlock
		)
{
	/* FIXME */
	return STATUS_INVALID_SYSTEM_SERVICE;
} /* end NtFlushBuffersFile() */
EXPORT_SYMBOL(NtFlushBuffersFile);


/*
 * check if the desired access is possible without violating the sharing mode
 * of other opens of the same file
 * - must call with a lock held on the file control struct
 */
static int file_check_sharing(struct win32_file *wf, struct win32_file_ctrl *wfc)
{
	struct list_head	*flist;
	__u32	extant_sharing = FILE_SHARE_READ | FILE_SHARE_WRITE;
	__u32	extant_access = 0;

	/* scan the file access points */
	list_for_each(flist, &wfc->wfc_accessors) {
		struct win32_file	*wf =
			list_entry(flist, struct win32_file, wf_ctllist);

		/* build up a picture of current sharing and access modes */
		extant_sharing &= wf->wf_sharing;
		extant_access |= wf->wf_access;
	}

	if ((wf->wf_access & GENERIC_READ) &&
			!(extant_sharing & FILE_SHARE_READ))
		goto sharing_violation;

	if ((wf->wf_access & GENERIC_WRITE) &&
			!(extant_sharing & FILE_SHARE_WRITE))
		goto sharing_violation;

	if ((extant_access & GENERIC_READ) &&
			!(wf->wf_sharing & FILE_SHARE_READ))
		goto sharing_violation;

	if ((extant_access & GENERIC_WRITE) &&
			!(wf->wf_sharing & FILE_SHARE_WRITE))
		goto sharing_violation;

	return 0;

sharing_violation:
	return STATUS_ACCESS_VIOLATION;

} /* end file_check_sharing() */

VOID
io_delete_file(PVOID ObjectBody)
{
	struct win32_file	*wf = ObjectBody;

	/* discard my association with the Linux file */
	if (wf->wf_file)
		fput(wf->wf_file);

	if (wf->wf_control) {
		/* unlink from the controlling object */
		list_del(&wf->wf_ctllist);
		deref_object((PVOID)wf->wf_control);
	}

	return;
}
#endif
