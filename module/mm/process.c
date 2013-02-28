/*
 * process.c
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
 * process.c:
 * Refered to Reactos Kernel code
 */
#include <linux/mman.h>
#include "section.h"
#include "area.h"
#include "pefile.h"
#include "virtual.h"
#include "attach.h"

#ifdef CONFIG_UNIFIED_KERNEL

extern unsigned long MmUserProbeAddress;
static unsigned long extra_page = 0;

extern int unistr2charstr(PWSTR unistr, LPCSTR chstr);

#define USER_SHARED_DATA (0x7FFE0000)
#define	MIN(a, b) ((a) > (b) ? (b) : (a))

/*
* alloc_peb_or_teb
* called for alloc peb or teb 
*/ 
PVOID
STDCALL
alloc_peb_or_teb(struct eprocess* Process,
		PVOID BaseAddress)  /* peb or teb base */
{
	unsigned long	addr;
	unsigned long	ret;
	size_t	size = PAGE_SIZE;
	struct ethread	*first_thread = get_first_thread(Process);
	struct task_struct	*tsk = first_thread ? first_thread->et_task : current;
	struct vm_area_struct	*vma;

	addr = (unsigned long)BaseAddress;
	if (PEB_BASE != (unsigned long )BaseAddress) {
		size = RESERVE_PAGE_SIZE;
		addr &= RESERVE_PAGE_MASK;
		do {
			vma = find_vma(tsk->mm, addr);
			if (!vma || vma->vm_start >= addr + size)
				break;
			addr -= size;
		} while (addr > 0);
	}

	ret = win32_do_mmap_pgoff(tsk, NULL, addr, size,
			PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, 0);

	if (IS_ERR((void *)ret))
		return NULL;

	insert_reserved_area(Process, ret, ret + size, _PAGE_READWRITE);

	return (PVOID)ret;
} /* end alloc_peb_or_teb */

/*
 * create_peb
 * called for create peb
 */
NTSTATUS STDCALL
create_peb(struct eprocess *Process)
{
	struct eprocess	*curr_eprocess = get_current_eprocess();
	BOOL attached = false;
	PPEB peb = NULL;
	PPEB kpeb;
	NTSTATUS ret = STATUS_SUCCESS;
	struct mm_struct *mm = NULL;

	ktrace("\n");
	if (curr_eprocess && curr_eprocess != Process) {
		mm = attach_process(&Process->pcb);
		attached = true;
	}

	kpeb = kmalloc(sizeof(PEB), GFP_KERNEL);
	if (!kpeb) {
		ret = STATUS_NO_MEMORY;
		goto out_detach;
	}
	memset(kpeb, 0, sizeof(PEB));

	kpeb->ImageBaseAddress = Process->section_base_address;
	kpeb->OSMajorVersion = 5;
	kpeb->OSMinorVersion = 0;
	kpeb->OSBuildNumber = 13;
	kpeb->OSPlatformId = 2; 		/* VER_PLATFORM_WIN32_NT */
	kpeb->OSCSDVersion = 0;			/* NtOSCSDVersion */
	kpeb->AnsiCodePageData = 0;		/* FIXME */
	kpeb->OemCodePageData = 0;		/* FIXME */
	kpeb->UnicodeCaseTableData = 0;		/* FIXME */
	kpeb->NumberOfProcessors = 1;		/* FIXME */
	kpeb->BeingDebugged = (BOOLEAN)(Process->debug_port ? TRUE : FALSE);

	/* Allocate the PEB */
	peb = alloc_peb_or_teb(Process, (PVOID)PEB_BASE);
	if (!peb) {
		ret = STATUS_NO_MEMORY;
		goto out_free_kpeb;
	}

	/* Initialize the PEB */
	memset(peb, 0, sizeof(PEB));

	/* Set up data */
	if ((copy_to_user(peb, kpeb, sizeof(PEB)))) {
		ret = STATUS_NO_MEMORY;
		goto out_free_kpeb;
	}

	Process->peb = peb;

	ret = STATUS_SUCCESS;

out_free_kpeb:
	kfree(kpeb);

out_detach:
	if (attached)
		detach_process(mm);

	ktrace("end: Peb created at %p\n", peb);
	return ret;
} /* end create_peb */

/* 
 * create_teb
 * called for create teb
 */
PTEB
STDCALL
create_teb(struct eprocess* Process,
		PCLIENT_ID ClientId,
		PINITIAL_TEB InitialTeb)
{
	struct eprocess	*curr_eprocess = get_current_eprocess();
	BOOL attached = false;
	PTEB teb;	
	PTEB kteb;
	struct mm_struct *mm = NULL;

	kteb = kmalloc(sizeof(TEB), GFP_KERNEL);
	if (!kteb)
		return ERR_PTR(STATUS_NO_MEMORY);

	/* Allocate the TEB */
	if (!(teb = alloc_peb_or_teb(Process, (void *)TEB_BASE))){
		goto out_free_kteb;
	}

	memset(kteb, 0, sizeof(TEB));

	/* Set TIB Data */
	kteb->Tib.ExceptionList = (PVOID)0xFFFFFFFF;
	kteb->Tib.DUMMYUNIONNAME.Version = 0;
	kteb->Tib.Self = (PNT_TIB)teb;

	/* Set TEB Data */
	if (ClientId) {
		kteb->RealClientId = *ClientId;
		kteb->Cid = *ClientId;
	}
	else {
		memset(&kteb->RealClientId, 0, sizeof(CLIENT_ID));
		memset(&kteb->Cid, 0, sizeof(CLIENT_ID));
	}
	
	kteb->Peb = Process->peb;
	kteb->CurrentLocale = 0;    /* FIXME: PsDefaultThreadLocaleId; */

	kteb->Tib.StackBase = (PVOID)InitialTeb->StackBase;
	kteb->Tib.StackLimit = (PVOID)InitialTeb->StackLimit;
	kteb->DeallocationStack = kteb->Tib.StackLimit - PAGE_SIZE;

	if (curr_eprocess && curr_eprocess != Process) {
		mm = attach_process(&Process->pcb);
		attached = true;
	}

	if (copy_to_user(teb, kteb, sizeof(TEB))) {
		teb = ERR_PTR(STATUS_NO_MEMORY);
	}

	if (attached)
		detach_process(mm);

out_free_kteb:
	kfree(kteb);

	ktrace("end: Teb created at %p\n", teb);
	return teb; 
} /* end create_teb */

void set_task_name(struct task_struct *tsk,
		struct eprocess *process, struct win32_section *section)
{
	POBJECT_HEADER_NAME_INFO	name_info;
	UCHAR	*name, *p;
	int	len;

	/* Determine the image file name and save it to EPROCESS */
	name_info = HEADER_TO_OBJECT_NAME(BODY_TO_HEADER(section->ws_wfile->wf_control));
	if (!name_info)
		return;

	name = (UCHAR *)kmalloc(name_info->Name.MaximumLength, GFP_KERNEL);
	unistr2charstr((PWSTR)name_info->Name.Buffer, (LPCSTR)name);

	p = strrchr(name, '\\');
	if (!p)
		p = strrchr(name, '/');

	if (p)
		p++;
	else
		p = name;
	len = strlen(p);
	len = MIN(len, sizeof(process->image_file_name));

	memcpy(process->image_file_name, p, len);
	task_lock(tsk);
	strlcpy(tsk->comm, p, sizeof(tsk->comm));
	task_unlock(tsk);

	kfree(name);
}

/*
 * create_process_space
 */
NTSTATUS
STDCALL
create_process_space(struct eprocess *process,
		struct win32_section *section)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG ViewSize = 0;
	PVOID ImageBase = NULL;
	unsigned long	start_code = 0, start_data = 0, end_code = 0, end_data = 0;
	unsigned long	pe_brk = 0;
	struct win32_image_section	*wis;
	struct mm_struct	*mm;
	struct task_struct	*tsk, *parent;
	struct ethread	*thread = get_first_thread(process);
	int idx;

	tsk = thread ? thread->et_task : current;
	mm = tsk->mm;

	if (!section)
		goto out_set_tls;

	/* Check if there's a Section Object */
	status = map_section_view(section,
			process,
			(PVOID*)&ImageBase,
			0,
			0,
			NULL,
			(PSIZE_T)&ViewSize,
			0,
			MEM_COMMIT,
			_PAGE_READWRITE);
	if (!NT_SUCCESS(status))
		return status;

	for (wis = section->ws_sections; wis < section->ws_sections + section->ws_nsecs; wis++) {
		unsigned long k;

		if (wis->wis_character & IMAGE_SCN_TYPE_NOLOAD)
			continue;

		k = section->ws_realbase + wis->wis_rva;

		/*
		 * Check to see if the section's size will overflow the
		 * allowed task size. Note that p_filesz must always be
		 * <= p_memsz so it is only necessary to check p_memsz.
		 */
		status = STATUS_INVALID_IMAGE_WIN_32;
		if (k > TASK_SIZE || TASK_SIZE - wis->wis_size < k) /* Avoid overflows.  */
			goto out_unmap_section;

		if (wis->wis_character & IMAGE_SCN_MEM_EXECUTE) {
			start_code = k;
			end_code = k + wis->wis_rawsize;
		}
		else {
			if (!start_data)
				start_data = k;
			end_data = k + wis->wis_rawsize;
		}

		k += wis->wis_size;
		if (pe_brk < k)	/* pe_brk used set mm->brk */
			pe_brk = k;

		/* TODO: start_data and end_data, diff to ELF */
	}

	mm->brk = pe_brk;
	mm->start_code = start_code;
	mm->start_data = start_data;
	mm->end_code = end_code;
	mm->end_data = end_data;

	/* extra page, used for interpreter ld-linux.so */
	extra_page = win32_do_mmap_pgoff(tsk, NULL, pe_brk, PAGE_SIZE, 
			PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0);
	if (extra_page != pe_brk)
		goto out_unmap_section;
	mm->brk = pe_brk + PAGE_SIZE;
	process->spare0[0] = (void *)extra_page;

	section->ws_entrypoint += section->ws_realbase;
	process->section_base_address = ImageBase;

	/* reserve first 0x100000 */
	win32_do_mmap_pgoff(tsk, NULL, 0, WIN32_LOWEST_ADDR, PROT_NONE,
			MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, 0);
	/* reserve first 0x7fff0000 - 0x80000000 */
	win32_do_mmap_pgoff(tsk, NULL, WIN32_TASK_SIZE - 0x10000, 0x10000,
			PROT_NONE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, 0);
	/* reserve first 0x81000000 - 0xc0000000
	 * 0x80000000 - 0x81000000 used for wine SYSTEM_HEAP */
	win32_do_mmap_pgoff(tsk, NULL, WIN32_TASK_SIZE + WIN32_SYSTEM_HEAP_SIZE,
			TASK_SIZE - WIN32_TASK_SIZE - WIN32_SYSTEM_HEAP_SIZE,
			PROT_NONE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, 0);

	set_task_name(tsk, process, section);

out_set_tls:
	memset(&tsk->thread.tls_array, 0, sizeof(tsk->thread.tls_array));
	/* FIXME: use parent's tls instead temporarily */
	/* use parent's TLS */
	parent = tsk->parent;
	idx = (parent->thread.gs >> 3) - GDT_ENTRY_TLS_MIN;

	memcpy(&tsk->thread.tls_array[idx], &parent->thread.tls_array[idx], 
			sizeof(struct desc_struct));

	return STATUS_SUCCESS;

out_unmap_section:
	unmap_section_view(process, mm, (unsigned long)ImageBase);
	return status;
} /* end create_process_space */

#endif /* CONFIG_UNIFIED_KERNEL */
