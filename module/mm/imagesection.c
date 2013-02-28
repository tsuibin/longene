/*
 * imagesection.c
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
 * imagesection.c:
 * Refered to Linux Kernel code
 */

#include <linux/mman.h>
#include <linux/syscalls.h>
#include <asm/pgalloc.h>
#include "virtual.h"
#include "section.h"
#include "pefile.h"
#include "attach.h"

#ifdef CONFIG_UNIFIED_KERNEL

static int image_section_map(struct task_struct *tsk, struct win32_section *ws,
		unsigned long *addr, unsigned long len, unsigned long flags, unsigned long offset);

static int image_section_munmap(struct win32_section *ws);

static unsigned long character2prot[] = {
	PROT_NONE,
	PROT_EXEC,			/* IMAGE_SCN_MEM_EXECUTE */
	PROT_READ,			/* IMAGE_SCN_MEM_READ */
	PROT_READ | PROT_EXEC,
	PROT_WRITE,			/* IMAGE_SCN_MEM_WRITE */
	PROT_WRITE | PROT_EXEC,
	PROT_WRITE | PROT_READ,
	PROT_WRITE | PROT_READ | PROT_WRITE
};

#ifdef UNALIGNED_MMAP
static struct page *filemap_pe_nopage(struct vm_area_struct *area,
				unsigned long address, int *type);

static struct vm_operations_struct file_pe_shared_mmap = {
	.nopage = filemap_pe_nopage,
};

static struct vm_operations_struct file_pe_private_mmap = {
	.nopage = filemap_pe_nopage,
};
#endif

/* origin in kernel-win32 */
static inline int is_power_of2(unsigned long addr)
{
	if (!addr)
		return 0;

	return !(addr & (addr - 1));
} /* end is_power_of2 */

/*
 * parse a PE image and build a set of VM areas and a relocation table index
 * - performs a cursory check of the image's validity
 * - ignores the fact that file sections may _not_ be page aligned!
 */
#define	ALIGN_UP(addr, align)	(((addr) + (align) - 1) & ~((align) - 1))
int image_section_setup(struct win32_section *ws)
{
	IMAGE_DOS_HEADER	*dos_hdr;
	IMAGE_NT_HEADERS	*nt_hdr;
	IMAGE_OPTIONAL_HEADER	*opt_hdr;
	IMAGE_SECTION_HEADER	*sec_hdr, *ps;
	struct win32_image_section	*wis;
	struct file	*file;
	size_t	hdr_len, nt_hdr_size, sec_hdr_size, total_hdr_size;
	void	*hdr_buf;
	DWORD	rva;
	int	sec_align, file_align, sec_mask, file_mask;
	int	tmp, err;

	ws->ws_mmap = image_section_map;
	ws->ws_munmap = image_section_munmap ;

	/* check that we can map the file into the VM */
	if (!ws->ws_file && ws->ws_wfile)
		ws->ws_file = ws->ws_wfile->wf_file;
	file = ws->ws_file;
	if (!file->f_op || !file->f_op->mmap)
		return STATUS_NOT_MAPPED_VIEW;

	/* check we can read the file */
	if (!(file->f_mode & FMODE_READ))
		return STATUS_ACCESS_DENIED;

	/* get the image header and find the offset of the extended header */
	/* alloc 2 pages to store file header */
	hdr_buf = (void *)__get_free_pages(GFP_KERNEL, 1);
	if (!hdr_buf)
		return STATUS_NO_MEMORY;

	/* read 2 pages to hdr_buf */
	hdr_len = kernel_read(file, 0, hdr_buf, PAGE_SIZE << 1);
	if (hdr_len < 0) {
		err = hdr_len;
		goto free_hdr;
	}

	err = STATUS_UNSUCCESSFUL;
	if (hdr_len < sizeof(IMAGE_DOS_HEADER))
		goto free_hdr;

	/* check the DOS header */
	dos_hdr = (IMAGE_DOS_HEADER *)hdr_buf;
	if (dos_hdr->e_magic != IMAGE_DOS_SIGNATURE || dos_hdr->e_lfanew <= 0)
		goto free_hdr;

	/* get the NT header and OPTIONAL header */
	nt_hdr = (IMAGE_NT_HEADERS *)(hdr_buf + dos_hdr->e_lfanew);
	opt_hdr = (IMAGE_OPTIONAL_HEADER *)&nt_hdr->OptionalHeader;

	if (hdr_len < dos_hdr->e_lfanew + sizeof(IMAGE_NT_HEADERS)
			|| nt_hdr->Signature != IMAGE_NT_SIGNATURE
			|| nt_hdr->FileHeader.Machine != IMAGE_FILE_MACHINE_I386
			|| !(nt_hdr->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
			|| opt_hdr->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC
			|| opt_hdr->ImageBase & 0xffff	/* ImageBase need aligned to 64KB */
			|| !is_power_of2(opt_hdr->SectionAlignment)
			|| !is_power_of2(opt_hdr->FileAlignment)
			|| opt_hdr->SectionAlignment < opt_hdr->FileAlignment
			|| opt_hdr->SectionAlignment < PAGE_SIZE)
		goto free_hdr;

	/* section alignment and file alignment */
	sec_align = opt_hdr->SectionAlignment;
	sec_mask = sec_align - 1;
	file_align = opt_hdr->FileAlignment;
	file_mask = file_align - 1;

	/* fill section for global */
	ws->ws_imagebase = opt_hdr->ImageBase;
	ws->ws_nsecs = nt_hdr->FileHeader.NumberOfSections + 1;
	ws->ws_stackresv = opt_hdr->SizeOfStackReserve;
	ws->ws_stackcommit = opt_hdr->SizeOfStackCommit;
	ws->ws_subsystem = opt_hdr->Subsystem;
	ws->ws_majorver = opt_hdr->MajorSubsystemVersion;
	ws->ws_minorver = opt_hdr->MinorSubsystemVersion;
	ws->ws_entrypoint = opt_hdr->AddressOfEntryPoint;
	ws->ws_executable = opt_hdr->SizeOfCode != 0;
	ws->ws_imagecharacter = nt_hdr->FileHeader.Characteristics;
	ws->ws_machine = nt_hdr->FileHeader.Machine;

	/* locate section header */
	nt_hdr_size = sizeof(*nt_hdr) - sizeof(*opt_hdr) + nt_hdr->FileHeader.SizeOfOptionalHeader;
	sec_hdr = (IMAGE_SECTION_HEADER *)((char *)nt_hdr + nt_hdr_size);
	sec_hdr_size = nt_hdr->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
	total_hdr_size = dos_hdr->e_lfanew + nt_hdr_size + sec_hdr_size;
	if (total_hdr_size > hdr_len)
		goto free_hdr;

	ws->ws_secoff = (char *)sec_hdr - (char *)hdr_buf;

	/* allocate my section table (with a dummy section on the end) */
	err = STATUS_NO_MEMORY;
	tmp = sizeof(struct win32_image_section) * ws->ws_nsecs;
	ws->ws_sections = (struct win32_image_section *)kmalloc(tmp, GFP_KERNEL);
	if (!ws->ws_sections)
		goto free_hdr;

	/* create a virtual section to map the image header */
	wis = ws->ws_sections;
	ps = sec_hdr;

	wis->wis_rva	= 0;
	wis->wis_fpos	= 0;
	wis->wis_size	= ALIGN_UP(total_hdr_size, sec_align);
	wis->wis_rawsize = ALIGN_UP(total_hdr_size, file_align);
	wis->wis_flags = MAP_DENYWRITE | MAP_PRIVATE;
	wis->wis_protect = PROT_READ;
	wis->wis_character = 0;

	/* validate the section table */
	err = STATUS_UNSUCCESSFUL;
	rva = wis->wis_size;
	for (wis++; wis < ws->ws_sections + ws->ws_nsecs; ps++, wis++) {
		unsigned long	characteristics;

		/* not alignment */
		if (ps->VirtualAddress & sec_mask)
			goto free_section;

		wis->wis_rva = ps->VirtualAddress;	/* relate virtual address */
		if (wis->wis_rva < rva)		/* rva = relate virtual address of previous section end */
			goto free_section;

		characteristics = ps->Characteristics;
		/* check the IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE */
		if (!(characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE))) {
			/* no explicit protection */
			if (characteristics & IMAGE_SCN_CNT_CODE)
				characteristics |= IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

			if (characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
				characteristics |= IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

			if (characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
				characteristics |= IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
		}
		if ((ws->ws_entrypoint >= ws->ws_imagebase + wis->wis_rva) 
				&& (ws->ws_entrypoint < ws->ws_imagebase + wis->wis_rva + wis->wis_size)) {
			characteristics |= IMAGE_SCN_MEM_EXECUTE;
		}
		wis->wis_character = characteristics;

		/* get segement size, aligned to SectionAlignment */
		if (!ps->Misc.VirtualSize || ps->Misc.VirtualSize < ps->SizeOfRawData)
			wis->wis_size = ALIGN_UP(ps->SizeOfRawData, sec_align);
		else
			wis->wis_size = ALIGN_UP(ps->Misc.VirtualSize, sec_align);
		if (wis->wis_size > TASK_SIZE)
			goto free_section;

		wis->wis_fpos = ps->PointerToRawData;	/* file postion */
		wis->wis_rawsize = ALIGN_UP(ps->SizeOfRawData, file_align);

		if (wis->wis_size < wis->wis_rawsize)
			goto free_section;

		/* calc this section end */
		rva = wis->wis_rva + wis->wis_size;

		/* determine the specific VM flags for this section */
		wis->wis_flags = MAP_DENYWRITE | MAP_EXECUTABLE;
		if (characteristics & IMAGE_SCN_MEM_SHARED)
			wis->wis_flags |= MAP_SHARED;
		else
			wis->wis_flags |= MAP_PRIVATE;

		/* section protect, get highest 3 bits */
		wis->wis_protect = character2prot[characteristics >> 29];

		if ((wis->wis_flags & MAP_SHARED)
				&& (wis->wis_protect & (PROT_WRITE | PROT_EXEC)))
			goto free_section;
	}

	/* total segements len */
	ws->ws_len = rva;
	ws->ws_pagelen = PAGE_ALIGN(rva);
	err = 0;
	goto free_hdr;

free_section:
	ws->ws_nsecs = 0;
	kfree(ws->ws_sections);
	ws->ws_sections = NULL;

free_hdr:
	free_pages((unsigned long)hdr_buf, 1);
	return err;
} /* end image_section_setup */
EXPORT_SYMBOL(image_section_setup);

/*
 * map the PE image into the process's VM space
 */
static int image_section_map(struct task_struct *tsk, struct win32_section *ws,
		unsigned long *addr, unsigned long len, unsigned long flags, unsigned long offset)
{
	int			load_addr_set = 0;
	unsigned long		ret, base;
	struct file		*file = ws->ws_file;
	struct win32_image_section	*wis;
#ifndef UNALIGNED_MMAP
	loff_t pos;
	ssize_t readed;
	struct mm_struct *current_mm = current->mm;
#else
	struct vm_area_struct	*vma;
	struct vm_operations_struct	*vmops;
#endif

	base = *addr;
	if (!base)
		base = ws->ws_imagebase;

	/* iterate through all the chunks */
	for (wis = ws->ws_sections; wis < ws->ws_sections + ws->ws_nsecs; wis++) {
		if (wis->wis_character & IMAGE_SCN_TYPE_NOLOAD)
			continue;

		/* set vmops */
		flags = 0;
		if (ws->ws_imagecharacter & IMAGE_FILE_EXECUTABLE_IMAGE || load_addr_set)
			flags = MAP_FIXED;

#ifndef UNALIGNED_MMAP
		ret = win32_do_mmap_pgoff(tsk, NULL, base + wis->wis_rva, wis->wis_size,
				PROT_READ | PROT_WRITE, wis->wis_flags | flags, 0);
#else
		if ((wis->wis_flags & MAP_SHARED) && (wis->wis_protect & PROT_WRITE))
			vmops = &file_pe_shared_mmap;
		else
			vmops = &file_pe_private_mmap;

		/* map a section */
		ret = win32_do_mmap_pgoff(tsk, file, base + wis->wis_rva, wis->wis_size,
				wis->wis_protect, wis->wis_flags | flags, wis->wis_rva >> PAGE_SHIFT);

		/* fixup vma */
		vma = find_vma(tsk->mm, ret);
		if (vma) {
			vma->vm_private_data = (void *)ws;
			vma->vm_ops = vmops;
		}
#endif

		if (IS_ERR((void *)ret))
			goto failed;

#ifndef UNALIGNED_MMAP
        if (tsk != current)
            current_mm = attach_process((struct kprocess *)tsk->ethread->threads_process);

        pos = (loff_t)wis->wis_fpos;
        readed = vfs_read(file, (char *)ret, wis->wis_rawsize, &pos);
        sys_mprotect(ret, wis->wis_size, wis->wis_protect);

        if (tsk != current)
            detach_process(current_mm);
#endif

		if (!load_addr_set) {
			load_addr_set = 1;
			if (ws->ws_imagecharacter & IMAGE_FILE_DLL)
				ws->ws_realbase = ret - wis->wis_rva;
			else
				ws->ws_realbase = base;

			base = ws->ws_realbase;
		}
	}

	*addr = base;
	return 0;

	/* clean up on error */
failed:
	return PTR_ERR((void *)ret);
} /* end image_section_map () */


static int image_section_munmap(struct win32_section *ws)
{
	int	err, ret = 0;
	struct win32_image_section	*wis;
	struct mm_struct	*mm = current->mm;

	/* grab the process's memory mapping semaphore */
	down_write(&mm->mmap_sem);

	for (wis = ws->ws_sections; wis < ws->ws_sections + ws->ws_nsecs; wis++) {
		if (wis->wis_character & IMAGE_SCN_TYPE_NOLOAD)
			continue;

		err = do_munmap(mm, ws->ws_realbase + wis->wis_rva, wis->wis_size);

		if (err) {
			ret = err;
		}
	}

	/* release the process's memory mapping semaphore */
	up_write(&mm->mmap_sem);

	kfree(ws);

	return ret;
} /* image_section_munmap */

#ifdef UNALIGNED_MMAP
static struct page *filemap_pe_nopage(struct vm_area_struct *area,
				unsigned long address, int *type)
{
	int	error;
	void	*pgbuf;
	unsigned long	pgoff, floff, voff, size;
	struct page	*page;
	struct file	*file = area->vm_file;
	struct win32_section	*ws;
	struct win32_image_section	*wis;

	if (!(ws = (struct win32_section *)area->vm_private_data))
		return NULL;
	for (wis = ws->ws_sections; wis < ws->ws_sections + ws->ws_nsecs; wis++)
		if ((address < ws->ws_realbase + wis->wis_rva + wis->wis_size)
				&& (address >= ws->ws_realbase + wis->wis_rva))
			break;

	/* get page offset and virtual offset */
	voff = address - area->vm_start;
	pgoff = (voff >> PAGE_CACHE_SHIFT) + area->vm_pgoff;
	voff += area->vm_start - ws->ws_realbase - wis->wis_rva;

	if (pgoff >= ((wis->wis_rva + wis->wis_size) >> PAGE_CACHE_SHIFT))
		if (area->vm_mm == current->mm)
			return NULL;

	page = alloc_pages(GFP_ATOMIC, 0);
	if (!page)
		return NOPAGE_OOM;

	pgbuf = kmap(page);
	if (pgbuf) {
		if (voff > wis->wis_rawsize)
			memset(pgbuf, 0, PAGE_SIZE);
		else {
			floff = voff + wis->wis_fpos;
			size = wis->wis_rawsize - voff;
			size = size < PAGE_SIZE ? size : PAGE_SIZE;
			error = kernel_read(file, floff, pgbuf, size);
			if (size < PAGE_SIZE)
				memset(pgbuf + size, 0, PAGE_SIZE - size);

			if (error < 0)
				goto cleanup;

			grab_swap_token();
		}

		kunmap(page);
		return page;
	}

cleanup:
	kunmap(page);
	__free_pages(page, 0);
	return NULL;
} /* end filemap_pe_nopage */
#endif /* UNALIGNED_MMAP */

#endif /* CONFIG_UNIFIED_KERNEL */
