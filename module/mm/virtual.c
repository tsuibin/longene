/*
 * virtual.c
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
 * virtual.c: virtual memory handling
 * Refered to ReactOS code
 */
#include <linux/mman.h>
#include <linux/syscalls.h>
#include "virtual.h"
#include "attach.h"
#include "section.h"
#include "area.h"

#ifdef CONFIG_UNIFIED_KERNEL

#define	IS_COW(prot)	(((prot) == _PAGE_WRITECOPY) || ((prot) == _PAGE_EXECUTE_WRITECOPY))

static unsigned long prot_table_wtol[] = {
	PROT_NONE,				/* _PAGE_NOACCESS */
	PROT_READ,				/* _PAGE_READONLY */
	PROT_READ | PROT_WRITE,			/* _PAGE_READWRITE */
	PROT_READ | PROT_WRITE,			/* _PAGE_WRITECOPY */
	PROT_EXEC,				/* _PAGE_EXECUTE */
	PROT_EXEC | PROT_READ,			/* _PAGE_EXECUTE_READ */
	PROT_EXEC | PROT_READ | PROT_WRITE,	/* _PAGE_EXECUTE_READWRITE */
	PROT_EXEC | PROT_READ | PROT_WRITE,	/* _PAGE_EXECUTE_WRITECOPY */
};

static unsigned long prot_table_ltow[] = {
	_PAGE_NOACCESS,			/* MAP_PRIVATE, PROT_NONE */
	_PAGE_READONLY,			/* MAP_PRIVATE, PROT_READ */
	_PAGE_WRITECOPY,		/* MAP_PRIVATE, PROT_WRITE */
	_PAGE_WRITECOPY,		/* MAP_PRIVATE, PROT_READ | PROT_WRITE */
	_PAGE_EXECUTE,			/* MAP_PRIVATE, PROT_EXEC */
	_PAGE_EXECUTE_READ,		/* MAP_PRIVATE, PROT_READ | PROT_EXEC */
	_PAGE_EXECUTE_WRITECOPY,	/* MAP_PRIVATE, PROT_WRITE | PROT_EXEC */
	_PAGE_EXECUTE_WRITECOPY,	/* MAP_PRIVATE, PROT_READ | PROT_WRITE | PROT_EXEC */
	_PAGE_NOACCESS,			/* MAP_SHARED, PROT_NONE */
	_PAGE_READONLY,			/* MAP_SHARED, PROT_READ */
	_PAGE_READWRITE,		/* MAP_SHARED, PROT_WRITE */
	_PAGE_READWRITE,		/* MAP_SHARED, PROT_READ | PROT_WRITE */
	_PAGE_EXECUTE,			/* MAP_SHARED, PROT_EXEC */
	_PAGE_EXECUTE_READ,		/* MAP_SHARED, PROT_READ | PROT_EXEC */
	_PAGE_EXECUTE_READWRITE,	/* MAP_SHARED, PROT_WRITE | PROT_EXEC */
	_PAGE_EXECUTE_READWRITE		/* MAP_SHARED, PROT_READ | PROT_WRITE | PROT_EXEC */
};

unsigned long prot_to_linux(unsigned long win)
{
	return prot_table_wtol[ffs(win & 0xff) - 1];
}

unsigned long prot_to_win(struct vm_area_struct *vma)
{
	unsigned long vmflags;

	vmflags = vma->vm_file ? (vma->vm_flags & 0xf) : ((vma->vm_flags & 0x7) | 0x8);
	return prot_table_ltow[vmflags];
}

static inline long uk_mprotect(struct mm_struct *mm,
		unsigned long addr, size_t size, unsigned long prot)
{
	struct mm_struct	*cur_mm;
	long	ret;

	cur_mm = current->mm;
	current->mm = mm;
	ret = sys_mprotect(addr, size, prot);
	current->mm = cur_mm;

	return ret;
}

static inline long uk_msync(struct mm_struct *mm,
		unsigned long addr, size_t size, int flags)
{
	struct mm_struct	*cur_mm;
	long	ret;

	cur_mm = current->mm;
	current->mm = mm;
	ret = sys_msync(addr, size, flags);
	current->mm = cur_mm;

	return ret;
}

/*
 * NtQueryVirtualMemory
 * Get the information of the virtual memory 
 */
NTSTATUS SERVICECALL
NtQueryVirtualMemory (IN HANDLE ProcessHandle,
		IN PVOID Address,
		IN CINT VirtualMemoryInformationClass,
		OUT PVOID VirtualMemoryInformation,
		IN ULONG Length,
		OUT PULONG UnsafeResultLength)
{
	NTSTATUS	status;
	ULONG		result_len, addr;
	struct ethread		*first_thread;
	struct eprocess		*process;
	struct mm_struct	*mm;
	struct vm_area_struct 	*vma;
	struct win32_area_struct	*ra, *ma;
	MEMORY_BASIC_INFORMATION	info;
	MODE		previous_mode;

	ktrace("%p:%p:%d:%p:%x:%p\n",
			ProcessHandle, Address, VirtualMemoryInformationClass,
			VirtualMemoryInformation, Length, UnsafeResultLength);

	previous_mode = (unsigned long)VirtualMemoryInformation > TASK_SIZE ? KernelMode : UserMode;

	status = ref_object_by_handle(ProcessHandle,
			PROCESS_QUERY_INFORMATION,
			NULL,
			UserMode,
			(PVOID *)(&process),
			NULL);
	if (!NT_SUCCESS(status))
		return status;

	first_thread = get_first_thread(process);
	mm = first_thread->et_task->mm;

	addr = (ULONG)Address & PAGE_MASK;

	switch (VirtualMemoryInformationClass) {
		case MemoryBasicInformation:
			if (Length != sizeof(MEMORY_BASIC_INFORMATION)) {
				status = STATUS_INFO_LENGTH_MISMATCH;
				goto out;
			}

			result_len = sizeof(MEMORY_BASIC_INFORMATION);

			if ((ra = find_reserved_area(process, addr, addr))) {
				info.Type = MEM_PRIVATE;
				info.AllocationProtect = ra->prot;
				info.BaseAddress = (PVOID)addr;
				info.AllocationBase = (PVOID)ra->start;
				info.RegionSize = ra->end - ra->start;

				vma = find_vma(mm, addr);
				if (!vma) {
					info.State = MEM_RESERVE;
					info.Protect = 0;
				} else {
					info.Protect = prot_to_win(vma);
					info.State = info.Protect == _PAGE_NOACCESS ? MEM_RESERVE : MEM_COMMIT;
				}
			} else if ((ma = find_mapped_area(process, addr, addr))) {
				struct win32_section	*ws = ma->section_object;

				info.Type = (ws && !ws->ws_sections) ? MEM_MAPPED : MEM_IMAGE;
				info.AllocationProtect = ma->prot;
				info.BaseAddress = (PVOID)addr;
				info.AllocationBase = (PVOID)ma->start;
				info.RegionSize = ma->end - ma->start;

				vma = find_vma(mm, addr);
				if (!vma || vma->vm_start > addr) {
					info.State = MEM_RESERVE;
					info.Protect = 0;
				} else {
					info.Protect = prot_to_win(vma);
					info.State = info.Protect == _PAGE_NOACCESS ? MEM_RESERVE : MEM_COMMIT;
					info.RegionSize = vma->vm_end - addr;
				}
			} else {
				info.Type = MEM_FREE;
				info.RegionSize = get_free_area_size(process, addr);
				info.BaseAddress = (PVOID)addr;
			}

			break;
		default:
			status = STATUS_INVALID_INFO_CLASS;
			goto out;
	}

	status = STATUS_INVALID_ADDRESS;;
	if (previous_mode == UserMode) {
		if (copy_to_user(VirtualMemoryInformation, &info, sizeof(MEMORY_BASIC_INFORMATION)))
			goto out;
		if (UnsafeResultLength && copy_to_user(UnsafeResultLength, &result_len, sizeof(ULONG)))
			goto out;
	}
	else {
		*(PMEMORY_BASIC_INFORMATION)VirtualMemoryInformation = info;
		if (UnsafeResultLength)
			*UnsafeResultLength = result_len;
	}

	status = STATUS_SUCCESS;

out:
	deref_object(process);
	return status;
} /* end NtQueryVirtualMemory */
EXPORT_SYMBOL(NtQueryVirtualMemory);

/*
 * win32_do_mmap_pgoff
 */
unsigned long win32_do_mmap_pgoff(struct task_struct *task, struct file *filp,
		unsigned long addr0, unsigned long size, unsigned long prot,
		unsigned long flags, unsigned long pgoff)
{
	struct mm_struct	*current_mm = current->mm;
	unsigned long	address;

	if (task != current)
		current->mm = task->mm;

	down_write(&current->mm->mmap_sem);
	address = do_mmap_pgoff(filp, addr0, size, prot, flags, pgoff);
	up_write(&current->mm->mmap_sem);

	if (task != current)
		current->mm = current_mm;

	return address;
} /* end win32_do_mmap_pgoff */
EXPORT_SYMBOL(win32_do_mmap_pgoff);

/*
 * NtAllocateVirtualMemory
 * Allocate a block of virtual memory in the process address space
 */
NTSTATUS SERVICECALL
NtAllocateVirtualMemory(IN HANDLE ProcessHandle,
		IN OUT PVOID *BaseAddress,
		IN ULONG ZeroBits,
		IN OUT PULONG RegionSize,
		IN ULONG AllocationType,
		IN ULONG Protect)
{
	struct ethread		*first_thread;
	struct eprocess		*process;
	struct win32_area_struct	*ra, *ma = NULL;
	struct vm_area_struct	*vma;
	unsigned long	prot, flags;
	ULONG		address;
	ULONG		size;
	NTSTATUS 	status = STATUS_SUCCESS;
	MODE	previous_mode;

	ktrace("ProcessHandle %p, BaseAddress %p, Size %x, Type %x, Protect %x\n",
			ProcessHandle, *BaseAddress, *RegionSize, AllocationType, Protect);

	/* Check the validity of the parameters */
	if ((Protect & PAGE_PROT_MASK) != Protect
			|| !(Protect & PAGE_PROT_MASK)) {
		kdebug("FIXME: some protect not implemention! Protect %x\n", Protect);
		return STATUS_INVALID_PAGE_PROTECTION;
	}

	if (!(AllocationType & (MEM_COMMIT | MEM_RESERVE)) && !(AllocationType & MEM_SYSTEM))
		return STATUS_INVALID_PARAMETER;

	previous_mode = (unsigned long)BaseAddress > TASK_SIZE ? KernelMode : UserMode;
	if (previous_mode == UserMode) {
		if (copy_from_user(&address, BaseAddress, sizeof(PVOID)))
			return STATUS_INVALID_ADDRESS;
		if (copy_from_user(&size, RegionSize,sizeof(ULONG)))
			return STATUS_INVALID_ADDRESS;
	}
	else {
		address = (ULONG)*BaseAddress;
		size = *RegionSize;
	}

	if (address > WIN32_TASK_SIZE)
		return STATUS_INVALID_ADDRESS;
	if (size > WIN32_TASK_SIZE || !size)
		return STATUS_INVALID_PARAMETER;
	size = (size + PAGE_SIZE - 1) & PAGE_MASK;

	if (!address && ((AllocationType & (MEM_RESERVE | MEM_COMMIT)) == MEM_COMMIT))
		AllocationType |= MEM_RESERVE;	/* need allocate virtual memory */

	status = ref_object_by_handle(ProcessHandle,
			PROCESS_VM_OPERATION,
			NULL,
			UserMode,
			(PVOID *)(&process),
			NULL);
	if (!NT_SUCCESS(status))
		return status;

	first_thread = get_first_thread(process);

	if (AllocationType & MEM_SYSTEM) {
		struct vm_area_struct *prev;

		if (!(AllocationType & MEM_IMAGE)) {
			insert_mapped_area(process, address, address + size, Protect, NULL);
			deref_object(process);
			return STATUS_SUCCESS;
		}

		prev = find_vma(first_thread->et_task->mm, address - PAGE_SIZE);
		vma = prev ? prev->vm_next : NULL;
		if (prev && vma)
			insert_mapped_area(process, prev->vm_start,
					vma->vm_start + size, Protect, NULL);
		kdebug("address %x, prev: start %lx, flags %lx, vma: start %lx, flags %lx\n",
				address, prev ? prev->vm_start : 0, prev ? prev->vm_flags : 0,
				vma ? vma->vm_start : 0, vma ? vma->vm_flags : 0);
		status = STATUS_SUCCESS;
		goto out;
	}

	switch (AllocationType & (MEM_RESERVE | MEM_COMMIT)) {
		case MEM_COMMIT:	/* commit some reserved memory */
			status = STATUS_INVALID_ADDRESS;
			address &= PAGE_MASK;
			if (!(ra = find_reserved_area(process, address, address + size))
					&& (!(ma = find_mapped_area(process, address, address + size))))
				goto out;
			if (IS_COW(Protect)) {
				status = STATUS_INVALID_PAGE_PROTECTION;
				if (ra && ra->prot != Protect)
					goto out;
				if (ma && ma->prot != Protect)
					goto out;
			}
			prot = prot_to_linux(Protect);
			uk_mprotect(first_thread->et_task->mm, address, size, prot);
			goto allocated;
		case MEM_RESERVE:
			address &= RESERVE_PAGE_MASK;
			prot = PROT_NONE;
			flags = MAP_PRIVATE | MAP_RESERVE;
			break;
		case MEM_RESERVE | MEM_COMMIT:
		default:
			address &= RESERVE_PAGE_MASK;
			prot = prot_table_wtol[ffs(Protect & 0xff) - 1];
			flags = MAP_PRIVATE | MAP_RESERVE;
			break;
	}

	if (address) {
		vma = find_vma(first_thread->et_task->mm, address);
		if (vma && vma->vm_start < address + ((size + RESERVE_PAGE_SIZE - 1) & RESERVE_PAGE_MASK)) {
			status = STATUS_INVALID_ADDRESS;
			goto out;
		}
		flags |= MAP_FIXED;
	}

	address = win32_do_mmap_pgoff(first_thread->et_task, NULL,
			address, size, prot, flags, 0);
	if (IS_ERR((void *)address)) {
		status = (NTSTATUS)address;
		goto out;
	}

	insert_reserved_area(process, address, address + size, Protect);

allocated:
	status = STATUS_INVALID_ADDRESS;
	if (previous_mode == UserMode) {
		if (copy_to_user(BaseAddress, &address, sizeof(PVOID)))
			goto out;
		if (copy_to_user(RegionSize, &size, sizeof(ULONG)))
			goto out;
	}
	else {
		*BaseAddress = (PVOID)address;
		*RegionSize = size;
	}

	status = STATUS_SUCCESS;
out:
	deref_object(process);
	ktrace("done, status=%x\n", status);
	return status;
} /* end NtAllocateVirtualMemory */
EXPORT_SYMBOL(NtAllocateVirtualMemory);

/*
 * NtWriteVirtualMemory
 * Write to  memory
 */
NTSTATUS SERVICECALL
NtWriteVirtualMemory(IN HANDLE ProcessHandle,
		IN PVOID BaseAddress,
		IN PVOID Buffer,
		IN ULONG NumberOfBytesToWrite,
		OUT PULONG NumberOfBytesWritten OPTIONAL)
{
	struct ethread 	*first_thread;
	struct eprocess	*process;
	struct mm_struct	*mm = NULL;
	struct mm_struct	*cur_mm = NULL;
	struct vm_area_struct	*vma;
	PVOID		kbuf;
	MODE		previous_mode;
	NTSTATUS 	status;

	ktrace("ProcessHandle %p, BaseAddress %p, Buffer %p, NumberOfBytesToWrite %d\n",
			ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite);

	previous_mode = (unsigned long)Buffer > TASK_SIZE ? KernelMode : UserMode;

	if (previous_mode == KernelMode) {
		/* TODO */
	}

	if (NumberOfBytesToWrite > WIN32_TASK_SIZE)
		return STATUS_INVALID_PARAMETER;
	if ((ULONG)BaseAddress > WIN32_TASK_SIZE || (ULONG)Buffer > WIN32_TASK_SIZE)
		return STATUS_INVALID_ADDRESS;

	status = ref_object_by_handle(ProcessHandle,
			PROCESS_VM_WRITE,
			NULL,
			UserMode,
			(PVOID *)(&process),
			NULL);
	if (!NT_SUCCESS(status))
		return status;

	first_thread = get_first_thread(process);
	mm = first_thread->et_task->mm;

	vma = find_vma(mm, (ULONG)BaseAddress);
	if (!vma || vma->vm_start > (ULONG)BaseAddress
			|| vma->vm_end < (ULONG)BaseAddress + NumberOfBytesToWrite) {
		status = STATUS_INVALID_ADDRESS;
		goto out;
	}

	if (!(vma->vm_flags & VM_WRITE)) {
		status = STATUS_ACCESS_VIOLATION;
		goto out;
	}

	kbuf = kmalloc(NumberOfBytesToWrite, GFP_KERNEL);
	if (!kbuf) {
		status = STATUS_NO_MEMORY;
		goto out;
	}

	status = STATUS_INVALID_ADDRESS;
	if (copy_from_user(kbuf, Buffer, NumberOfBytesToWrite))
		goto out_free_kbuf;

	/* Write memory */
	if (process == get_current_eprocess()) {
		if (copy_to_user(BaseAddress, kbuf, NumberOfBytesToWrite))
			goto out_free_kbuf;
	}
	else {
		cur_mm = attach_process(&process->pcb);
		if (copy_to_user(BaseAddress, kbuf, NumberOfBytesToWrite)) {
			detach_process(cur_mm);
			goto out_free_kbuf;
		}
		detach_process(cur_mm);
	}

	if (previous_mode == UserMode && NumberOfBytesWritten) {
		if (copy_to_user(NumberOfBytesWritten, &NumberOfBytesToWrite, sizeof(ULONG)))
			goto out_free_kbuf;
	}
	/* TODO
	   else *NumberOfBytesWritten = NumberOfBytesToWrite;
	   */
	status = STATUS_SUCCESS;

out_free_kbuf:
	kfree(kbuf);

out:
	deref_object(process);
	return status;

} /* end NtWriteVirtualMemory */
EXPORT_SYMBOL(NtWriteVirtualMemory);

/*
 * NtReadVirtualMemory
 * Read from memory
 */
NTSTATUS SERVICECALL
NtReadVirtualMemory(IN HANDLE ProcessHandle,
		IN PVOID BaseAddress,
		OUT PVOID Buffer,
		IN ULONG NumberOfBytesToRead,
		OUT PULONG NumberOfBytesRead OPTIONAL)
{
	struct eprocess	*process;
	struct ethread	*first_thread;
	PVOID	kbuf;
	struct mm_struct	*mm, *cur_mm;
	struct vm_area_struct	*vma;
	MODE	previous_mode;
	NTSTATUS status = STATUS_SUCCESS;

	ktrace("ProcessHandle %p, BaseAddress %p, Buffer %p, NumberOfBytesToRead %d\n",
			ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead);

	previous_mode = (unsigned long)Buffer > TASK_SIZE ? KernelMode : UserMode;

	if (previous_mode == KernelMode) {
		/* TODO */
	}

	if (NumberOfBytesToRead > WIN32_TASK_SIZE)
		return STATUS_INVALID_PARAMETER;
	if ((ULONG)BaseAddress > WIN32_TASK_SIZE || (ULONG)Buffer > WIN32_TASK_SIZE)
		return STATUS_INVALID_ADDRESS;

	status = ref_object_by_handle(ProcessHandle,
			PROCESS_VM_READ,
			NULL,
			UserMode,
			(PVOID *)(&process),
			NULL);
	if (!NT_SUCCESS(status))
		return status;

	first_thread = get_first_thread(process);
	mm = first_thread->et_task->mm;

	vma = find_vma(mm, (ULONG)BaseAddress);
	if (!vma || vma->vm_start > (ULONG)BaseAddress
			|| vma->vm_end < (ULONG)BaseAddress + NumberOfBytesToRead) {
		status = STATUS_INVALID_ADDRESS;
		goto out;
	}

	if (!(vma->vm_flags & VM_READ)) {
		status = STATUS_ACCESS_VIOLATION;
		goto out;
	}

	kbuf = kmalloc(NumberOfBytesToRead, GFP_KERNEL);
	if (!kbuf) {
		status = STATUS_NO_MEMORY;
		goto out;
	}

	status = STATUS_INVALID_ADDRESS;

	/* Read memory */
	if (process == get_current_eprocess()) {
		if (copy_from_user(kbuf, BaseAddress, NumberOfBytesToRead))
			goto out_free_kbuf;
	}
	else {
		cur_mm = attach_process(&process->pcb);
		if(copy_from_user(kbuf, BaseAddress, NumberOfBytesToRead)) {
			detach_process(cur_mm);
			goto out_free_kbuf;
		}
		detach_process(cur_mm);
	}

	if (copy_to_user(Buffer, kbuf, NumberOfBytesToRead))
		goto out_free_kbuf;

	if (previous_mode == UserMode && NumberOfBytesRead) {
		if (copy_to_user(NumberOfBytesRead, &NumberOfBytesToRead, sizeof(ULONG))) {
			goto out_free_kbuf;
		}
	}
	/* TODO
	   else *NumberOfBytesRead = NumberOfBytesToRead;
	   */
	status = STATUS_SUCCESS;

out_free_kbuf:
	kfree(kbuf);

out:
	deref_object(process);
	return status;
} /* end NtReadVirtualMemory */
EXPORT_SYMBOL(NtReadVirtualMemory);

/*
 * NtFreeVirtualMemory
 * Free a range of virtual memory
 */
NTSTATUS SERVICECALL
NtFreeVirtualMemory(IN HANDLE ProcessHandle,
		IN PVOID *BaseAddress,
		IN PULONG RegionSize,
		IN ULONG FreeType)
{
	struct ethread  *first_thread;
	struct eprocess *process;
	struct mm_struct        *mm;
	struct win32_area_struct *ra;
	struct win32_area_struct *ma = NULL;
	ULONG   address;
	ULONG   size;
	MODE	previous_mode;
	NTSTATUS status = STATUS_SUCCESS;

	ktrace("ProcessHandle %p, BaseAddress %p, Size %x, FreeType %x\n",
			ProcessHandle, *BaseAddress, *RegionSize, FreeType);

	if (((FreeType & (MEM_RELEASE | MEM_DECOMMIT)) == (MEM_RELEASE | MEM_DECOMMIT))
			|| (!(FreeType & (MEM_RELEASE | MEM_DECOMMIT | MEM_SYSTEM))))
		return STATUS_INVALID_PARAMETER;

	previous_mode = (unsigned long)BaseAddress > TASK_SIZE ? KernelMode : UserMode;
	if (previous_mode == UserMode) {
		if (copy_from_user(&address, BaseAddress, sizeof(PVOID)))
			return STATUS_INVALID_ADDRESS;
		if (copy_from_user(&size, RegionSize, sizeof(ULONG)))
			return STATUS_INVALID_ADDRESS;
	}
	else {
		address = (ULONG)*BaseAddress;
		size = *RegionSize;
	}

	if (size && (FreeType & MEM_RELEASE))
		return STATUS_INVALID_PARAMETER;

	if (size > WIN32_TASK_SIZE)
		return STATUS_INVALID_PARAMETER;

	status = ref_object_by_handle(ProcessHandle,
			PROCESS_VM_OPERATION,
			NULL,
			UserMode,
			(PVOID *)(&process),
			NULL);
	if (!NT_SUCCESS(status))
		return status;

	first_thread = get_first_thread(process);
	mm = first_thread->et_task->mm;

	if (FreeType & MEM_SYSTEM) {
		ma = find_mapped_area(process, address, address + size);
		if (!ma) {
			status = STATUS_INVALID_ADDRESS;
			goto out;
		}
		remove_win32_area(ma);
		status = STATUS_SUCCESS;
		goto out;
	}

	ra = find_reserved_area(process, address, address + size);
	if (!ra) {
		ma = find_mapped_area(process, address, address + size);
		if ((FreeType & MEM_RELEASE) || !ma) {
			status = STATUS_INVALID_ADDRESS;
			goto out;
		}
	}

	if (FreeType & MEM_DECOMMIT) {
		uk_mprotect(mm, address, size, PROT_NONE);
	} else {
		if (address != ra->start) {
			status = STATUS_INVALID_ADDRESS;
			goto out;
		}

		size = ra->end - ra->start;
		remove_win32_area(ra);

		down_write(&mm->mmap_sem);
		if (do_munmap(mm, (ULONG)address, size)) {
			up_write(&mm->mmap_sem);
			status = STATUS_NO_MEMORY;
			goto out;
		}
		up_write(&mm->mmap_sem);
	}

	status = STATUS_INVALID_ADDRESS;
	if (previous_mode == UserMode) {
		if (copy_to_user(BaseAddress, &address, sizeof(PVOID)))
			goto out;
		if (copy_to_user(RegionSize, &size, sizeof(ULONG)))
			goto out;
	}
	else {
		*BaseAddress = (PVOID)address;
		*RegionSize = size;
	}

	status = STATUS_SUCCESS;

out:
	deref_object(process);
	return status;
} /* end NtFreeVirtualMemory */
EXPORT_SYMBOL(NtFreeVirtualMemory);

/*
 * NtProtectVirtualMemory
 * Change the protection
 */
NTSTATUS SERVICECALL
NtProtectVirtualMemory(IN HANDLE ProcessHandle,
		IN OUT PVOID *UnsafeBaseAddress,
		IN OUT ULONG *UnsafeNumberOfBytesToProtect,
		IN ULONG NewProtection,
		OUT PULONG UnsafeOldProtection)
{
	struct eprocess *process;
	struct ethread *first_thread;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	ULONG address, addr_no_aligned;
	ULONG size;
	ULONG new_prot, old_prot;
	MODE previous_mode;
	NTSTATUS status;

	ktrace("ProcessHandle %p, BaseAddress %p, BytesToProtect %x, NewProtection %x\n", 
			ProcessHandle, *UnsafeBaseAddress, *UnsafeNumberOfBytesToProtect, NewProtection);

	if ((NewProtection & PAGE_PROT_MASK) != NewProtection
			|| !(NewProtection & PAGE_PROT_MASK)) {
		kdebug("FIXME: some protect not implemention! Protect %x\n", NewProtection);
		return STATUS_INVALID_PAGE_PROTECTION;
	}

	previous_mode = (unsigned long)UnsafeBaseAddress > TASK_SIZE ? KernelMode : UserMode;
	if (previous_mode == UserMode) {
		if (copy_from_user(&address, UnsafeBaseAddress, sizeof(PVOID)))
			return STATUS_INVALID_ADDRESS;
		if (copy_from_user(&size, UnsafeNumberOfBytesToProtect, sizeof(ULONG)))
			return STATUS_INVALID_ADDRESS;
	}
	else {
		address = (ULONG)*UnsafeBaseAddress;
		size = *UnsafeNumberOfBytesToProtect;
	}

	if (size > WIN32_TASK_SIZE)
		return STATUS_INVALID_ADDRESS;

	status = ref_object_by_handle(ProcessHandle,
			PROCESS_VM_OPERATION,
			NULL,
			UserMode,
			(PVOID *)(&process),
			NULL);
	if (!NT_SUCCESS(status))
		return status;

	first_thread = get_first_thread(process);
	mm = first_thread->et_task->mm;

	addr_no_aligned = address;
	address &= PAGE_MASK;
	size = PAGE_ALIGN(addr_no_aligned + size) - address;

	vma = find_vma(mm, address);
	if (!vma || vma->vm_start > address) {
		status = STATUS_INVALID_ADDRESS;
		goto out;
	}

	if (UnsafeOldProtection) {
		old_prot = prot_to_win(vma);
		if (previous_mode == KernelMode)
			*UnsafeOldProtection = old_prot;
		else if (copy_to_user(UnsafeOldProtection, &old_prot, sizeof(ULONG))) {
			status = STATUS_INVALID_ADDRESS;
			goto out;
		}
	}

	new_prot = prot_to_linux(NewProtection);
	if (IS_COW(NewProtection) && (vma->vm_flags & VM_SHARED)) {
		status = STATUS_INVALID_PAGE_PROTECTION;
		goto out;
	}

	status = uk_mprotect(mm, address, size, new_prot);
	if (!NT_SUCCESS(status)) {
		goto out;
	}

	status = STATUS_INVALID_ADDRESS;
	if (previous_mode == UserMode) {
		if (copy_to_user(UnsafeBaseAddress, &address, sizeof(PVOID)))
			goto out;
		if (copy_to_user(UnsafeNumberOfBytesToProtect, &size, sizeof(ULONG)))
			goto out;
	} else {
		*UnsafeBaseAddress = (PVOID)address;
		*UnsafeNumberOfBytesToProtect = size;
	}

	status = STATUS_SUCCESS;

out:
	deref_object(process);
	return status;
} /*end NtProtectVirtualMemory */
EXPORT_SYMBOL(NtProtectVirtualMemory);

/*
 * NtFlushVirtualMemory
 * Flush a range of virtual memory
 */
NTSTATUS SERVICECALL
NtFlushVirtualMemory(IN HANDLE ProcessHandle,
		IN OUT PVOID *BaseAddress,
		IN OUT PSIZE_T RegionSize,
		OUT PIO_STATUS_BLOCK IoStatus)
{
	struct eprocess *process;
	struct ethread *first_thread;
	struct mm_struct *mm;
	struct win32_area_struct *ma;
	ULONG address, addr_no_aligned;
	SIZE_T size;
	MODE previous_mode;
	NTSTATUS status;

	ktrace("ProcessHandle %p, BaseAddress %p, RegionSize %lx\n",
			ProcessHandle, *BaseAddress, *RegionSize);

	previous_mode = (unsigned long)BaseAddress > TASK_SIZE ? KernelMode : UserMode;
	if (previous_mode == UserMode) {
		if (copy_from_user(&address, BaseAddress, sizeof(PVOID)))
			return STATUS_INVALID_ADDRESS;
		if (copy_from_user(&size, RegionSize, sizeof(SIZE_T)))
			return STATUS_INVALID_ADDRESS;
	} else {
		address = (ULONG)*BaseAddress;
		size = *RegionSize;
	}

	if (size > WIN32_TASK_SIZE)
		return STATUS_INVALID_PARAMETER;

	status = ref_object_by_handle(ProcessHandle,
			PROCESS_VM_OPERATION,
			NULL,
			UserMode,
			(PVOID *)&process,
			NULL);
	if (!NT_SUCCESS(status))
		return status;

	first_thread = get_first_thread(process);
	mm = first_thread->et_task->mm;

	addr_no_aligned = address;
	address &= PAGE_MASK;
	size = PAGE_ALIGN(addr_no_aligned + size) - address;

	ma = find_mapped_area(process, address, address + size);
	if (!ma) {
		status = STATUS_NOT_MAPPED_VIEW;
		goto out;
	}

	if (!size)
		size = ma->end - address;

	status = uk_msync(mm, address, size, MS_SYNC);
	if (!NT_SUCCESS(status))
		goto out;

	status = STATUS_INVALID_ADDRESS;
	if (previous_mode == UserMode) {
		if (copy_to_user(BaseAddress, &address, sizeof(PVOID)))
			goto out;
		if (copy_to_user(RegionSize, &size, sizeof(SIZE_T)))
			goto out;
	} else {
		*BaseAddress = (PVOID)address;
		*RegionSize = size;
	}

	status = STATUS_SUCCESS;

out:
	deref_object(process);
	return status;
} /* end NtFlushVirtualMemory */
EXPORT_SYMBOL(NtFlushVirtualMemory);

NTSTATUS SERVICECALL
NtLockVirtualMemory(IN HANDLE ProcessHandle,
		IN OUT PVOID *BaseAddress,
		IN OUT PSIZE_T RegionSize,
		IN ULONG MapType)
{
	/*
	 * Just cheat it.
	 * FIXME: XueFeng C.
	 */
	return STATUS_SUCCESS;
}
EXPORT_SYMBOL(NtLockVirtualMemory);

NTSTATUS SERVICECALL
NtUnlockVirtualMemory(IN HANDLE ProcessHandle,
		IN OUT PVOID *BaseAddress,
		IN OUT PSIZE_T RegionSize,
		IN ULONG MapType)
{
	/*
	 * Just cheat it.
	 * FIXME: XueFeng C.
	 */
	return STATUS_SUCCESS;
}
EXPORT_SYMBOL(NtUnlockVirtualMemory);
#endif /* CONFIG_UNIFIED_KERNEL */
