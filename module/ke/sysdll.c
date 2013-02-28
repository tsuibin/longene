/*
 * sysdll.c
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
 * sysdll.c:
 * Refered to Reactos Kernel code
 */
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <asm/mman.h>
#include "attach.h"
#include "virtual.h"

#ifdef CONFIG_UNIFIED_KERNEL

#define RTL_CONSTANT_STRING(s) { sizeof(s) - sizeof((s)[0]), sizeof(s), (s) }
#define INIT_OBJECT_ATTR(p,n,a,r,s) { \
	(p)->Length = sizeof(OBJECT_ATTRIBUTES); \
	(p)->RootDirectory = (r); \
	(p)->Attributes = (a); \
	(p)->ObjectName = (n); \
	(p)->SecurityDescriptor = (s); \
	(p)->SecurityQualityOfService = NULL; \
}

#if ELF_CLASS == ELFCLASS32
#define elf_sym			elf32_sym
#define	elf_off_t		Elf32_Off
#define	elf_half_t		Elf32_Half
#else
#define elf_sym			elf64_sym
#define	elf_off_t		Elf64_Off
#define	elf_half_t		Elf64_Half
#endif

elf_off_t ntdll_phoff;
elf_half_t ntdll_phnum;

#define ELF_EXEC_PAGESIZE	4096

#if ELF_EXEC_PAGESIZE > PAGE_SIZE
# define ELF_MIN_ALIGN	ELF_EXEC_PAGESIZE
#else
# define ELF_MIN_ALIGN	PAGE_SIZE
#endif

#define ELF_PAGESTART(_v) ((_v) & ~(unsigned long)(ELF_MIN_ALIGN-1))
#define ELF_PAGEOFFSET(_v) ((_v) & (ELF_MIN_ALIGN-1))
#define ELF_PAGEALIGN(_v) (((_v) + ELF_MIN_ALIGN - 1) & ~(ELF_MIN_ALIGN - 1))

static int sym_count = 0;

static unsigned long ntdll_entry;
static unsigned long interp_entry;
static unsigned long pe_entry;
static unsigned long start_thunk;
static unsigned long apc_dispatcher;
static unsigned long thread_entry;
#ifdef EXE_SO
static unsigned long ntdll_start_thunk;
static unsigned long exeso_start_thunk;
#endif

static int padzero(struct task_struct *tsk, unsigned long bss)
{
	int ret = 0;
	unsigned long nbyte;
	struct mm_struct *mm = NULL;

	nbyte = ELF_PAGEOFFSET(bss);
	if (nbyte) {
		nbyte = ELF_MIN_ALIGN - nbyte;
		if (tsk == current) {
			if (clear_user((void __user *) bss, nbyte))
				ret = -EFAULT;
		}
		else {
			struct eprocess *process = tsk->ethread->threads_process;
			mm = attach_process(&process->pcb);
			if (clear_user((void __user *) bss, nbyte))
				ret = -EFAULT;
			detach_process(mm);
		}
	}

	return ret;
}

static inline unsigned long win32_do_mmap(struct task_struct *tsk,
		struct file *file, unsigned long addr, unsigned long len,
		unsigned long prot, unsigned long flag, unsigned long offset)
{
	unsigned long ret = -EINVAL;

	if ((offset + PAGE_ALIGN(len)) < offset)
		goto out;
	if (!(offset & ~PAGE_MASK))
		ret = win32_do_mmap_pgoff(tsk, file, addr, len, prot, flag, offset >> PAGE_SHIFT);

out:
	return ret;
} /* end win32_do_mmap */

static inline unsigned long elf_map(struct task_struct *tsk, struct file *filep,
		unsigned long addr, struct elf_phdr *eppnt, int prot, int type)
{
	return win32_do_mmap(tsk, filep, ELF_PAGESTART(addr),
			eppnt->p_filesz + ELF_PAGEOFFSET(eppnt->p_vaddr), prot, type,
			eppnt->p_offset - ELF_PAGEOFFSET(eppnt->p_vaddr));
} /* end elf_map */

static unsigned long load_elf_interp(struct task_struct *tsk,
		struct elfhdr * interp_elf_ex,
		struct file * interpreter,
		unsigned long *interp_load_addr,
		char *ld_name)
{
	struct elf_phdr *elf_phdata;
	struct elf_phdr *eppnt;
	unsigned long load_addr = 0;
	int load_addr_set = 0;
	unsigned long last_bss = 0, elf_bss = 0;
	unsigned long error = ~0UL;
	int retval, i, size;

	/* First of all, some simple consistency checks */
	if (interp_elf_ex->e_type != ET_EXEC &&
			interp_elf_ex->e_type != ET_DYN)
		goto out;
	if (!elf_check_arch(interp_elf_ex))
		goto out;
	if (!interpreter->f_op || !interpreter->f_op->mmap)
		goto out;

	/*
	 * If the size of this structure has changed, then punt, since
	 * we will be doing the wrong thing.
	 */
	if (interp_elf_ex->e_phentsize != sizeof(struct elf_phdr))
		goto out;
	if (interp_elf_ex->e_phnum < 1 ||
			interp_elf_ex->e_phnum > 65536U / sizeof(struct elf_phdr))
		goto out;

	/* Now read in all of the header information */

	size = sizeof(struct elf_phdr) * interp_elf_ex->e_phnum;
	if (size > ELF_MIN_ALIGN)
		goto out;
	elf_phdata = (struct elf_phdr *) kmalloc(size, GFP_KERNEL);
	if (!elf_phdata)
		goto out;

	retval = kernel_read(interpreter,interp_elf_ex->e_phoff,(char *)elf_phdata,size);
	error = -EIO;
	if (retval != size) {
		if (retval < 0)
			error = retval;	
		goto out_close;
	}

	eppnt = elf_phdata;
	for (i=0; i<interp_elf_ex->e_phnum; i++, eppnt++) {
		if (eppnt->p_type == PT_INTERP && ld_name)
			kernel_read(interpreter, eppnt->p_offset, ld_name, eppnt->p_filesz);

		if (eppnt->p_type == PT_LOAD) {
			int elf_type = MAP_PRIVATE | MAP_DENYWRITE;
			int elf_prot = 0;
			unsigned long vaddr = 0;
			unsigned long k, map_addr;

			if (eppnt->p_flags & PF_R) elf_prot =  PROT_READ | PROT_WRITE;
			if (eppnt->p_flags & PF_W) elf_prot |= PROT_WRITE;
			if (eppnt->p_flags & PF_X) elf_prot |= PROT_EXEC;
			vaddr = eppnt->p_vaddr;
			if (interp_elf_ex->e_type == ET_EXEC || load_addr_set)
				elf_type |= MAP_FIXED;

			map_addr = elf_map(tsk, interpreter, load_addr + vaddr, eppnt, elf_prot, elf_type);
			error = map_addr;
			if (map_addr > (unsigned long)TASK_SIZE)
				goto out_close;

			if (!load_addr_set && interp_elf_ex->e_type == ET_DYN) {
				load_addr = map_addr - ELF_PAGESTART(vaddr);
				*interp_load_addr = map_addr - eppnt->p_offset;
				load_addr_set = 1;
			}

			/*
			 * Check to see if the section's size will overflow the
			 * allowed task size. Note that p_filesz must always be
			 * <= p_memsize so it is only necessary to check p_memsz.
			 */
			k = load_addr + eppnt->p_vaddr;
			if (k > TASK_SIZE || eppnt->p_filesz > eppnt->p_memsz ||
					eppnt->p_memsz > TASK_SIZE || TASK_SIZE - eppnt->p_memsz < k) {
				error = -ENOMEM;
				goto out_close;
			}

			/*
			 * Find the end of the file mapping for this phdr, and keep
			 * track of the largest address we see for this.
			 */
			k = load_addr + eppnt->p_vaddr + eppnt->p_filesz;
			if (k > elf_bss)
				elf_bss = k;

			/*
			 * Do the same thing for the memory mapping - between
			 * elf_bss and last_bss is the bss section.
			 */
			k = load_addr + eppnt->p_memsz + eppnt->p_vaddr;
			if (k > last_bss)
				last_bss = k;
		}
	}

	/*
	 * Now fill out the bss section.  First pad the last page up
	 * to the page boundary, and then perform a mmap to make sure
	 * that there are zero-mapped pages up to and including the 
	 * last bss page.
	 */
	if (padzero(tsk, elf_bss)) {
		error = -EFAULT;
		goto out_close;
	}

	elf_bss = ELF_PAGESTART(elf_bss + ELF_MIN_ALIGN - 1);	/* What we have mapped so far */

	/* Map the last of the bss segment */
	if (last_bss > elf_bss) {
		error = win32_do_mmap_pgoff(tsk, NULL, elf_bss, last_bss - elf_bss,
				PROT_READ | PROT_WRITE, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, 0);
		if (error > (unsigned long)TASK_SIZE)
			goto out_close;
	}

	error = ((unsigned long) interp_elf_ex->e_entry) + load_addr;

out_close:
	kfree(elf_phdata);
out:
	return error;
} /* end load_elf_interp */

unsigned long uk_find_symbol(struct elf_shdr *elf_shdata, int shnum, char *sym)
{
	int		link = -1;
	int		str_tab_size = 0;
	char	*str_tab = NULL;
	struct elf_shdr	*elf_spnt;
	struct elf_sym	*sympnt, *sym_tab = NULL;
	unsigned long	sym_addr = -EINVAL;

	for (elf_spnt = elf_shdata; elf_spnt < elf_shdata + shnum; elf_spnt++) {
		if (elf_spnt->sh_type == SHT_DYNSYM) {
			sym_tab = (struct elf_sym *)(elf_spnt->sh_addr);
			link = elf_spnt->sh_link;
			sym_count = elf_spnt->sh_size / sizeof(struct elf_sym);
		}
	}

	if (link >= 0) {
		elf_spnt = elf_shdata + link;
		if (elf_spnt->sh_type != SHT_STRTAB)
			return -ENOEXEC;

		str_tab = (char *)(elf_spnt->sh_addr);
		str_tab_size = elf_spnt->sh_size;
	}

	if (sym_tab && str_tab) {
		for (sympnt = sym_tab; sympnt < sym_tab + sym_count; sympnt++) {
			if (sympnt->st_name > str_tab_size)
				break;
			if (!strcmp(sympnt->st_name + str_tab, sym)) {
				sym_addr = sympnt->st_value;
				break;
			}
		}
	}

	return sym_addr;
} /* end uk_find_symbol */
EXPORT_SYMBOL(uk_find_symbol);

unsigned long get_ntdll_entry(void)
{
	return ntdll_entry;
}
EXPORT_SYMBOL(get_ntdll_entry);

unsigned long get_thread_entry(void)
{
        return thread_entry;
} 
EXPORT_SYMBOL(get_thread_entry);

unsigned long get_apc_dispatcher(void)
{
	return apc_dispatcher;
}
EXPORT_SYMBOL(get_apc_dispatcher);

unsigned long get_pe_entry(void)
{
	return pe_entry;
}
EXPORT_SYMBOL(get_pe_entry);

unsigned long get_interp_entry(void)
{
	return interp_entry;
}
EXPORT_SYMBOL(get_interp_entry);

unsigned long get_start_thunk(void)
{
	return start_thunk;
}
EXPORT_SYMBOL(get_start_thunk);

#ifdef EXE_SO
unsigned long get_ntdll_start_thunk(void)
{
	return ntdll_start_thunk;
}

unsigned long get_exeso_start_thunk(void)
{
	return exeso_start_thunk;
}
#endif

LONG STDCALL map_system_dll(struct task_struct *tsk, char *name,
		unsigned long *ntdll_load_addr, unsigned long *interp_load_addr)
{
	NTSTATUS retval;
	struct file *interpreter = NULL, *ntdll = NULL;
	struct elfhdr	ntdll_elf_ex, interp_elf_ex;
	char buf[BINPRM_BUF_SIZE];
	char ld_name[32];

	ntdll = open_exec(name);
	retval = PTR_ERR(ntdll);
	if (IS_ERR(ntdll))
		goto out;

	/* read 128 Byte ELF header */
	retval = kernel_read(ntdll, 0, buf, BINPRM_BUF_SIZE);
	if (retval != BINPRM_BUF_SIZE) {
		if (retval >= 0)
			retval = -EIO;
		goto out_free_ntdll;
	}

	/* Get the exec headers */
	ntdll_elf_ex = *((struct elfhdr *)buf);
	ntdll_phoff = ntdll_elf_ex.e_phoff;
	ntdll_phnum = ntdll_elf_ex.e_phnum;

	load_elf_interp(tsk, &ntdll_elf_ex, ntdll, ntdll_load_addr, ld_name);

	if (tsk == current) {
		int elf_shnum;
		int elf_shsize;
		struct elf_shdr *elf_shdata = NULL;

		/* section header is not mapped to memory, need read it */
		/* load section header list for ntdll */
		elf_shnum = ntdll_elf_ex.e_shnum;
		elf_shsize = elf_shnum * ntdll_elf_ex.e_shentsize;
		elf_shdata = (struct elf_shdr *)kmalloc(elf_shsize, GFP_KERNEL);
		if (!elf_shdata) {
			retval = -ENOMEM;
			goto out_free_ntdll;
		}

		retval = kernel_read(ntdll, ntdll_elf_ex.e_shoff, (void *)elf_shdata, elf_shsize);
		if (retval != elf_shsize) {
			if (retval >= 0)
				retval = -EIO;
			kfree(elf_shdata);
			goto out_free_ntdll;
		}

		/* LdrInitializeThunk is used to load dll for PE exe file */
		ntdll_entry = uk_find_symbol(elf_shdata, elf_shnum, "LdrInitializeThunk");
		/* when interpreter done, jump to StartThunk */
		start_thunk = uk_find_symbol(elf_shdata, elf_shnum, "StartThunk");
		/* KiUserApcDispatcher is APC Dispatcher */
		apc_dispatcher = uk_find_symbol(elf_shdata, elf_shnum, "KiUserApcDispatcher");
		/* a forward function , will call BaseProcessStart in kernel32.dll.so */
		pe_entry = uk_find_symbol(elf_shdata, elf_shnum, "ProcessStartForward");
		thread_entry = uk_find_symbol(elf_shdata, elf_shnum, "start_thread");
#ifdef EXE_SO
		ntdll_start_thunk = uk_find_symbol(elf_shdata, elf_shnum, "ntdll_start_thunk");
		exeso_start_thunk = uk_find_symbol(elf_shdata, elf_shnum, "exeso_start_thunk");
#endif

		kfree(elf_shdata);
	}

	allow_write_access(ntdll);
	fput(ntdll);

	interpreter = open_exec(ld_name);
	retval = PTR_ERR(interpreter);
	if (IS_ERR(interpreter))
		goto out;

	retval = kernel_read(interpreter, 0, buf, BINPRM_BUF_SIZE);
	if (retval != BINPRM_BUF_SIZE) {
		if (retval >= 0)
			retval = -EIO;
		goto out_free_interp;
	}

	/* Get the exec headers */
	interp_elf_ex = *((struct elfhdr *)buf);
	interp_entry = load_elf_interp(tsk, &interp_elf_ex, interpreter, interp_load_addr, NULL);

	allow_write_access(interpreter);
	fput(interpreter);

	retval = 0;

out:
	return retval;

out_free_ntdll:
	allow_write_access(ntdll);
	if (ntdll)
		fput(ntdll);
	goto out;

out_free_interp:
	allow_write_access(interpreter);
	if (interpreter)
		fput(interpreter);
	goto out;
} /* end map_system_dll */
EXPORT_SYMBOL(map_system_dll);

#endif
