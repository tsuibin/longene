/*
 * binfmt_exeso.c
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
 * binfmt_exeso.c:
 * 	support running built-in exe for Wine application
 */
#include <linux/mman.h>
#include <linux/ptrace.h>
#include <linux/security.h>
#include <linux/utsname.h>

#include <linux/semaphore.h>
#include "handle.h"

#include "win32.h"
#include "pefile.h"
#include "event.h"
#include "virtual.h"

#ifdef CONFIG_UNIFIED_KERNEL
#ifdef EXE_SO

extern char builtin_dll_path[MAX_PATH];
extern char ntdll_name[MAX_PATH + 16];

extern asmlinkage void w32syscall_exit(void);

extern POBJECT_TYPE	process_object_type;
extern POBJECT_TYPE	thread_object_type;

#define	NTDLL_SO

#define ELF_HWCAP	(boot_cpu_data.x86_capability[0])
#define ELF_EXEC_PAGESIZE	4096

#ifdef NTDLL_SO

#ifndef elf_addr_t
#define elf_addr_t unsigned long
#endif

#if ELF_EXEC_PAGESIZE > PAGE_SIZE
# define ELF_MIN_ALIGN	ELF_EXEC_PAGESIZE
#else
# define ELF_MIN_ALIGN	PAGE_SIZE
#endif

#ifndef ELF_CORE_EFLAGS
#define ELF_CORE_EFLAGS	0
#endif

#define ELF_PAGESTART(_v) ((_v) & ~(unsigned long)(ELF_MIN_ALIGN-1))
#define ELF_PAGEOFFSET(_v) ((_v) & (ELF_MIN_ALIGN-1))
#define ELF_PAGEALIGN(_v) (((_v) + ELF_MIN_ALIGN - 1) & ~(ELF_MIN_ALIGN - 1))

#ifdef CONFIG_STACK_GROWSUP
#define STACK_ADD(sp, items) ((elf_addr_t __user *)(sp) + (items))
#define STACK_ROUND(sp, items) \
	((15 + (unsigned long) ((sp) + (items))) &~ 15UL)
#define STACK_ALLOC(sp, len) ({ elf_addr_t __user *old_sp = (elf_addr_t __user *)sp; sp += len; old_sp; })
#else
#define STACK_ADD(sp, items) ((elf_addr_t __user *)(sp) - (items))
#define STACK_ROUND(sp, items) \
	(((unsigned long) (sp - items)) &~ 15UL)
#define STACK_ALLOC(sp, len) ({ sp -= len ; sp; })
#endif

#if ELF_CLASS == ELFCLASS32
#define elf_sym			elf32_sym
#define	elf_off_t		Elf32_Off
#define	elf_half_t		Elf32_Half
#else
#define elf_sym			elf64_sym
#define	elf_off_t		Elf64_Off
#define	elf_half_t		Elf64_Half
#endif

#endif

extern unsigned long get_ntdll_entry(void);
extern unsigned long get_apc_dispatcher(void);
extern unsigned long get_pe_entry(void);
extern unsigned long get_interp_entry(void);
extern unsigned long get_start_thunk(void);
extern unsigned long get_ntdll_start_thunk(void);
extern unsigned long get_exeso_start_thunk(void);
extern NTSTATUS STDCALL map_system_dll(struct task_struct *tsk, char *name,
		unsigned long *ntdll_load_addr, unsigned long *interp_load_addr);
extern char *search_ntdll(void);
extern int unshare_files(struct files_struct **displaced);
extern void put_files_struct(struct files_struct *files);

static int load_exeso_binary(struct linux_binprm * bprm, struct pt_regs * regs);

static struct linux_binfmt exeso_format = {
		.module		= THIS_MODULE,
		.load_binary	= load_exeso_binary,
		.load_shlib	= NULL,
		.core_dump	= NULL,
		.min_coredump	= ELF_EXEC_PAGESIZE
};


#define BAD_ADDR(x)	((unsigned long)(x) > TASK_SIZE)

static unsigned long find_symbol_in_file(struct elf_phdr *elf_phdata, int phnum, 
	struct elf_shdr *elf_shdata, int shnum, char *sym, unsigned long base_addr)
{
	int sym_count = 0;
	int		link = -1;
	int		str_tab_size = 0;
	char	*str_tab = NULL;
	struct elf_shdr	*elf_spnt;
	struct elf_sym	*sympnt, *sym_tab = NULL;
	unsigned long	sym_addr = -EINVAL;
	struct elf_phdr * elf_ppnt;

	for (elf_spnt = elf_shdata; elf_spnt < elf_shdata + shnum; elf_spnt++) {
		if (elf_spnt->sh_type == SHT_SYMTAB) {
			sym_tab = (struct elf_sym *)((unsigned long)elf_spnt->sh_offset + base_addr);
			link = elf_spnt->sh_link;
			sym_count = elf_spnt->sh_size / sizeof(struct elf_sym);
		}
	}

	if (link >= 0) {
		elf_spnt = elf_shdata + link;
		if (elf_spnt->sh_type != SHT_STRTAB)
			return -ENOEXEC;

		str_tab = (char *)(elf_spnt->sh_offset) + base_addr;
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

	if (sym_addr != -EINVAL) {
		for (elf_ppnt = elf_phdata; elf_ppnt < elf_phdata + phnum; elf_ppnt++) {
			if (sym_addr >= elf_ppnt->p_vaddr && sym_addr < elf_ppnt->p_vaddr + elf_ppnt->p_filesz) {
				sym_addr -= elf_ppnt->p_vaddr - elf_ppnt->p_offset;
				sym_addr += base_addr;
				break;
			}
		}
	}

	return sym_addr;
} /* end find_symbol_in_file */

int check_exeso(struct linux_binprm * bprm)
{
	struct elfhdr *elf_ex;
	struct elf_phdr *elf_phdata = NULL;
	struct elf_shdr *elf_shdata = NULL;
	int retval = 1;
	unsigned long map_addr;
	size_t len;
	unsigned long sym;
	IMAGE_NT_HEADERS *nt;

	elf_ex = (struct elfhdr *)bprm->buf;

	if(!bprm->file->f_dentry || !bprm->file->f_dentry->d_inode)
		return 0;

	if(!current->mm)
		return 0;

	len = bprm->file->f_dentry->d_inode->i_size;
	down_write(&current->mm->mmap_sem);
	map_addr = do_mmap(bprm->file,
			0,
			len,
			PROT_READ,
			MAP_PRIVATE | MAP_DENYWRITE,
			0);
	up_write(&current->mm->mmap_sem);
	if(map_addr >= (unsigned long)TASK_SIZE)
		return 0;

	elf_phdata = (struct elf_phdr *)(map_addr + elf_ex->e_phoff);
	elf_shdata = (struct elf_shdr *)(map_addr + elf_ex->e_shoff);

	sym = find_symbol_in_file(elf_phdata, elf_ex->e_phnum, elf_shdata, elf_ex->e_shnum, 
		"__wine_spec_nt_header", map_addr);

	if(sym >= (unsigned long)TASK_SIZE) {
		down_write(&current->mm->mmap_sem);
		do_munmap(current->mm, map_addr, len);
		up_write(&current->mm->mmap_sem);
		return 0;
	}

	nt = (IMAGE_NT_HEADERS *)sym;
	if(nt->Signature != 0x4550 || (nt->OptionalHeader.Magic != 0x10b && nt->OptionalHeader.Magic != 0x107))
		retval = 0;
	else
		retval = 1;

	down_write(&current->mm->mmap_sem);
	do_munmap(current->mm, map_addr, len);
	up_write(&current->mm->mmap_sem);

	return retval;
}

#ifdef NTDLL_SO

extern elf_off_t ntdll_phoff;
extern elf_half_t ntdll_phnum;

/* 
 * create_elf_tables
 */
static int
create_elf_tables_aux(struct linux_binprm *bprm, 
		unsigned long ntdll_load_addr, elf_off_t ntdll_phoff, elf_half_t ntdll_phnum, unsigned long ntdll_start_thunk,
		unsigned long exeso_load_addr, elf_off_t exeso_phoff, elf_half_t exeso_phnum, unsigned long exeso_start_thunk, 
		unsigned long interp_load_addr, unsigned long interp_entry, unsigned long init_entry)
{
	unsigned long p = bprm->p;
	int argc = bprm->argc;
	int envc = bprm->envc;
	elf_addr_t __user *argv;
	elf_addr_t __user *envp;
	elf_addr_t __user *sp;
	elf_addr_t __user *u_platform;
	const char *k_platform = ELF_PLATFORM;
	int items;
	elf_addr_t *elf_info;
	elf_addr_t *elf_info2;
	int ei_index = 0;
	const struct cred *cred = current_cred();

	/*
	 * If this architecture has a platform capability string, copy it
	 * to userspace.  In some cases (Sparc), this info is impossible
	 * for userspace to get any other way, in others (i386) it is
	 * merely difficult.
	 */

	u_platform = NULL;
	if (k_platform) {
		size_t len = strlen(k_platform) + 1;

		/*
		 * In some cases (e.g. Hyper-Threading), we want to avoid L1
		 * evictions by the processes running on the same package. One
		 * thing we can do is to shuffle the initial stack for them.
		 */
	 
		p = arch_align_stack(p);

		u_platform = (elf_addr_t __user *)STACK_ALLOC(p, len);
		if (__copy_to_user(u_platform, k_platform, len))
			return -EFAULT;
	}

	/* Create the ELF interpreter info */
	elf_info = (elf_addr_t *) current->mm->saved_auxv;
#define NEW_AUX_ENT(id, val) \
	do { elf_info[ei_index++] = id; elf_info[ei_index++] = val; } while (0)

#ifdef ARCH_DLINFO11
	/* 
	 * ARCH_DLINFO must come first so PPC can do its special alignment of
	 * AUXV.
	 */
	ARCH_DLINFO;
#endif
	NEW_AUX_ENT(AT_HWCAP, ELF_HWCAP);
	NEW_AUX_ENT(AT_PAGESZ, ELF_EXEC_PAGESIZE);
	NEW_AUX_ENT(AT_CLKTCK, CLOCKS_PER_SEC);
	NEW_AUX_ENT(AT_PHDR, ntdll_load_addr + ntdll_phoff);
	NEW_AUX_ENT(AT_PHENT, sizeof(struct elf_phdr));
	NEW_AUX_ENT(AT_PHNUM, ntdll_phnum);
	NEW_AUX_ENT(AT_BASE, interp_load_addr);
	NEW_AUX_ENT(AT_FLAGS, 0);
	NEW_AUX_ENT(AT_ENTRY, ntdll_start_thunk);
	NEW_AUX_ENT(AT_UID, cred->uid);
	NEW_AUX_ENT(AT_EUID, cred->euid);
	NEW_AUX_ENT(AT_GID, cred->gid);
	NEW_AUX_ENT(AT_EGID, cred->egid);
 	NEW_AUX_ENT(AT_SECURE, (elf_addr_t) security_bprm_secureexec(bprm));
#if 0
	if (k_platform) {
		/* FIXME */
		NEW_AUX_ENT(AT_PLATFORM, (elf_addr_t)(unsigned long)u_platform);
	}
#endif
	if (bprm->interp_flags & BINPRM_FLAGS_EXECFD) {
		NEW_AUX_ENT(AT_EXECFD, (elf_addr_t) bprm->interp_data);
	}
#undef NEW_AUX_ENT
	/* AT_NULL is zero; clear the rest too */
	memset(&elf_info[ei_index], 0,
	       sizeof current->mm->saved_auxv - ei_index * sizeof elf_info[0]);

	/* And advance past the AT_NULL entry.  */
	ei_index += 2;

	sp = STACK_ADD(p, ei_index * 2);

	items = (argc + 1) + (envc + 1);
	items += 1; /* ELF interpreters only put argc on the stack */
	items += 3; /* interp entry address & _init address & load_base */
	bprm->p = STACK_ROUND(sp, items);

	/* Point sp at the lowest address on the stack */
#ifdef CONFIG_STACK_GROWSUP
	sp = (elf_addr_t __user *)bprm->p - items - ei_index;
	bprm->exec = (unsigned long) sp; /* XXX: PARISC HACK */
#else
	sp = (elf_addr_t __user *)bprm->p;
#endif

	/* Now, let's put argc (and argv, envp if appropriate) on the stack */
	if (__put_user(argc, sp))
		return -EFAULT;
	++sp;
	argv = sp;
	envp = argv + argc + 1;

	/* Populate argv and envp */
	p = current->mm->arg_end = current->mm->arg_start;
	while (argc-- > 0) {
		size_t len;
		__put_user((elf_addr_t)p, argv);
		++argv;
		len = strnlen_user((void __user *)p, MAX_ARG_STRLEN);
		if (!len || len > MAX_ARG_STRLEN)
			return 0;
		p += len;
	}
	if (__put_user(0, argv))
		return -EFAULT;
	current->mm->arg_end = current->mm->env_start = p;
	while (envc-- > 0) {
		size_t len;
		__put_user((elf_addr_t)p, envp);
		++envp;
		len = strnlen_user((void __user *)p, MAX_ARG_STRLEN);
		if (!len || len > MAX_ARG_STRLEN)
			return 0;
		p += len;
	}
	if (__put_user(0, envp))
		return -EFAULT;
	current->mm->env_end = p;

	/* Put the elf_info on the stack in the right place.  */
	sp = (elf_addr_t __user *)envp + 1;
	if (copy_to_user(sp, elf_info, ei_index * sizeof(elf_addr_t)))
		return -EFAULT;
	sp += ei_index;


	elf_info2 = (elf_addr_t *)kmalloc(sizeof(current->mm->saved_auxv), GFP_KERNEL);
	if(!elf_info2)
		return -ENOMEM;

	ei_index = 0;
#define NEW_AUX_ENT(id, val) \
	do { elf_info2[ei_index++] = id; elf_info2[ei_index++] = val; } while (0)

#ifdef ARCH_DLINFO11
	/* 
	 * ARCH_DLINFO must come first so PPC can do its special alignment of
	 * AUXV.
	 */
	ARCH_DLINFO;
#endif
	NEW_AUX_ENT(AT_HWCAP, ELF_HWCAP);
	NEW_AUX_ENT(AT_PAGESZ, ELF_EXEC_PAGESIZE);
	NEW_AUX_ENT(AT_CLKTCK, CLOCKS_PER_SEC);
	NEW_AUX_ENT(AT_PHDR, exeso_load_addr + exeso_phoff);
	NEW_AUX_ENT(AT_PHENT, sizeof(struct elf_phdr));
	NEW_AUX_ENT(AT_PHNUM, exeso_phnum);
	NEW_AUX_ENT(AT_BASE, interp_load_addr);
	NEW_AUX_ENT(AT_FLAGS, 0);
	NEW_AUX_ENT(AT_ENTRY, exeso_start_thunk);
	NEW_AUX_ENT(AT_UID, cred->uid);
	NEW_AUX_ENT(AT_EUID, cred->euid);
	NEW_AUX_ENT(AT_GID, cred->gid);
	NEW_AUX_ENT(AT_EGID, cred->egid);
 	NEW_AUX_ENT(AT_SECURE, (elf_addr_t) security_bprm_secureexec(bprm));
#if 0
	if (k_platform) {
		/* FIXME */
		NEW_AUX_ENT(AT_PLATFORM, (elf_addr_t)(unsigned long)u_platform);
	}
#endif
	if (bprm->interp_flags & BINPRM_FLAGS_EXECFD) {
		NEW_AUX_ENT(AT_EXECFD, (elf_addr_t) bprm->interp_data);
	}
#undef NEW_AUX_ENT
	/* AT_NULL is zero; clear the rest too */
	memset(&elf_info2[ei_index], 0,
	       sizeof(current->mm->saved_auxv) - ei_index * sizeof elf_info2[0]);
	ei_index += 2;
	if (copy_to_user(sp, elf_info2, ei_index * sizeof(elf_addr_t))) {
		kfree(elf_info2);
		return -EFAULT;
	}
	kfree(elf_info2);
	sp += ei_index;

	__put_user(interp_entry, sp);
	++sp;
	__put_user(init_entry, sp);
	++sp;
	__put_user(exeso_load_addr, sp);

	memset(current->mm->saved_auxv, 0, sizeof(current->mm->saved_auxv));

	return 0;
} /* end create_elf_tables */

#else /* NTDLL_SO */

#endif

static int load_exeso_binary(struct linux_binprm *bprm, struct pt_regs *regs)
{
	struct elfhdr *elf_ex;
	struct elf_phdr *elf_phdata = NULL;
	struct mm_struct *mm;
	unsigned long load_addr = 0;
	unsigned long error;
	int retval = 0;
	unsigned long pe_entry, ntdll_load_addr = 0;
	unsigned long start_code, end_code, start_data, end_data;
	unsigned long ntdll_entry;
	int executable_stack = EXSTACK_DEFAULT;
	unsigned long def_flags = 0;
	unsigned long stack_top;
#ifdef NTDLL_SO
	unsigned long	interp_load_addr;
	unsigned long	interp_entry;
#endif
	struct eprocess	*process;
	struct ethread	*thread;
	PRTL_USER_PROCESS_PARAMETERS	ppb;
	OBJECT_ATTRIBUTES	ObjectAttributes;
	INITIAL_TEB	init_teb;

	BOOLEAN is_win32=FALSE;
    	struct startup_info *info=NULL;
    	struct eprocess	*parent_eprocess=NULL;
    	struct ethread	*parent_ethread=NULL;
	struct w32process* child_w32process =NULL;
	struct w32process* parent_w32process =NULL;

	elf_ex = (struct elfhdr *)bprm->buf;
	retval = -ENOEXEC;
	/* First of all, some simple consistency checks */
	if (memcmp(elf_ex->e_ident, ELFMAG, SELFMAG) != 0)
		goto out;
	if (elf_ex->e_type != ET_EXEC && elf_ex->e_type != ET_DYN)
		goto out;
	if (!elf_check_arch(elf_ex))
		goto out;
	if (!bprm->file->f_op||!bprm->file->f_op->mmap)
		goto out;

	if (elf_ex->e_phentsize != sizeof(struct elf_phdr))
		goto out;
	if (elf_ex->e_phnum < 1 ||
	 	elf_ex->e_phnum > 65536U / sizeof(struct elf_phdr))
		goto out;

	if(!check_exeso(bprm))
		goto out;

	start_code = ~0UL;
	end_code = 0;
	start_data = 0;
	end_data = 0;

    if(current->parent->ethread)
    {
		is_win32 = TRUE;
		parent_ethread = current->parent->ethread;
		parent_eprocess = parent_ethread->threads_process;
    }

	/* Flush all traces of the currently running executable */
	retval = flush_old_exec(bprm);
	if (retval) {
		goto out;
	}

	/* OK, This is the point of no return */
	mm = current->mm;
	current->flags &= ~PF_FORKNOEXEC;
	mm->def_flags = def_flags;

	current->signal->rlim[RLIMIT_STACK].rlim_cur = WIN32_STACK_LIMIT;
	current->signal->rlim[RLIMIT_STACK].rlim_max = WIN32_STACK_LIMIT;
	current->personality |= ADDR_COMPAT_LAYOUT;
	arch_pick_mmap_layout(mm);

	/* Do this so that we can load the ntdll, if need be.  We will
	   change some of these later */
	mm->free_area_cache = mm->mmap_base = WIN32_UNMAPPED_BASE;
	mm->cached_hole_size = 0;
	stack_top = WIN32_STACK_LIMIT + WIN32_LOWEST_ADDR;
	retval = setup_arg_pages(bprm, stack_top, executable_stack);
	if (retval < 0)
		goto out_free_file;

	down_write(&mm->mmap_sem);
	/* reserve first 0x100000 */
	do_mmap_pgoff(NULL, 0, WIN32_LOWEST_ADDR, PROT_NONE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, 0);
	/* reserve first 0x7fff0000 - 0x80000000 */
	do_mmap_pgoff(NULL, WIN32_TASK_SIZE - 0x10000, 0x10000,
			PROT_NONE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, 0);
	/* reserve first 0x81000000 - 0xc0000000
	 * 0x80000000 - 0x81000000 used for wine SYSTEM_HEAP */
	do_mmap_pgoff(NULL, WIN32_TASK_SIZE + WIN32_SYSTEM_HEAP_SIZE,
			TASK_SIZE - WIN32_TASK_SIZE - WIN32_SYSTEM_HEAP_SIZE,
			PROT_NONE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, 0);
	up_write(&mm->mmap_sem);

#ifdef NTDLL_SO
	/* search ntdll.dll.so in $PATH, default is /usr/local/lib/wine/ntdll.dll.so */
	if (!*ntdll_name)
		search_ntdll();

	/* map ntdll.dll.so */
	map_system_dll(current, ntdll_name, &ntdll_load_addr, &interp_load_addr);

	pe_entry = get_pe_entry();
	ntdll_entry = get_ntdll_entry();
	interp_entry = get_interp_entry();
#endif

	set_binfmt(&exeso_format);

#ifdef ARCH_HAS_SETUP_ADDITIONAL_PAGES
	retval = arch_setup_additional_pages(bprm, executable_stack);
	if (retval < 0) {
		goto out_free_file;
	}
#endif /* ARCH_HAS_SETUP_ADDITIONAL_PAGES */

	install_exec_creds(bprm);
	current->flags &= ~PF_FORKNOEXEC;

#ifdef NTDLL_SO
	/* copy argv, env, and auxvec to stack, all for interpreter */
	create_elf_tables_aux(bprm, 
		ntdll_load_addr, ntdll_phoff, ntdll_phnum, get_ntdll_start_thunk(),
		load_addr, elf_ex->e_phoff, elf_ex->e_phnum, 0, 
		interp_load_addr, interp_entry, 0);
#endif

	mm->end_code = end_code;
	mm->start_code = start_code;
	mm->start_data = start_data;
	mm->end_data = end_data;
	mm->start_stack = bprm->p;

	if (current->personality & MMAP_PAGE_ZERO) {
		/* Why this, you ask???  Well SVr4 maps page 0 as read-only,
		   and some applications "depend" upon this behavior.
		   Since we do not have the power to recompile these, we
		   emulate the SVr4 behavior.  Sigh.  */
		down_write(&mm->mmap_sem);
		error = do_mmap(NULL, 0, PAGE_SIZE, PROT_READ | PROT_EXEC,
				MAP_FIXED | MAP_PRIVATE, 0);
		up_write(&mm->mmap_sem);
	}


	/* create win-related structure */
	INIT_OBJECT_ATTR(&ObjectAttributes, NULL, 0, NULL, NULL);

	/* Create EPROCESS */
	retval = create_object(KernelMode,
			process_object_type,
			&ObjectAttributes,
			KernelMode,
			NULL,
			sizeof(struct eprocess),
			0,
			0,
			(PVOID *)&process);
	if (retval != STATUS_SUCCESS) {
		goto out_free_file;
	}

	/* init eprocess */
	eprocess_init(NULL, FALSE, process);
	process->unique_processid = create_cid_handle(process, process_object_type);
	if (!process->unique_processid)
		goto out_free_eproc;

	/* initialize EProcess and KProcess */
	process->section_base_address = (void *)load_addr;

	/* FIXME: PsCreateCidHandle */

	/* Create PEB */
	if ((retval = create_peb(process)))
		goto out_free_process_cid;

	/* Create PPB */
	if(is_win32 == FALSE)
	{
		create_ppb(&ppb, process, bprm, bprm->filename, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
		((PEB *)process->peb)->ProcessParameters = ppb;
	}
	/* allocate a Win32 thread object */
	retval = create_object(KernelMode,
			thread_object_type,
			&ObjectAttributes,
			KernelMode,
			NULL,
			sizeof(struct ethread),
			0,
			0,
			(PVOID *)&thread);
	if (retval) {
		goto out_free_process_cid;
	}

	thread->cid.unique_thread = create_cid_handle(thread, thread_object_type);
	thread->cid.unique_process = process->unique_processid;
	if (!thread->cid.unique_thread)
		goto out_free_ethread;

	/* set the teb */
	init_teb.StackBase = (PVOID)(bprm->p);
	init_teb.StackLimit = (PVOID)WIN32_LOWEST_ADDR + PAGE_SIZE;
	thread->tcb.teb = create_teb(process, (PCLIENT_ID)&thread->cid, &init_teb);
	if (IS_ERR(thread->tcb.teb)) {
		retval = PTR_ERR(thread->tcb.teb);
		goto out_free_thread_cid;
	}

	/* Init KThreaad */
	ethread_init(thread, process, current);

	sema_init(&thread->exec_semaphore,0);
	if (is_win32 == TRUE) //parent is a windows process
	{
		down(&thread->exec_semaphore);  //wait for the parent

		child_w32process = process->win32process;
		parent_w32process = parent_eprocess->win32process;
		info = child_w32process->startup_info;

		//now parent has finished its work
		if(thread->inherit_all)
		{
			create_handle_table(parent_eprocess, TRUE, process);
			child_w32process = create_w32process(parent_w32process, TRUE, process);
		}
	}

	deref_object(process);
	deref_object(thread);

	set_teb_selector(current, (long)thread->tcb.teb);

	thread->start_address = (void *)pe_entry;	/* FIXME */

	/* save current trap frame */
	thread->tcb.trap_frame = (struct ktrap_frame *)regs;

	/* init apc, to call LdrInitializeThunk */
#if 0
	thread_apc = kmalloc(sizeof(KAPC), GFP_KERNEL);
	if (!thread_apc) {
		retval = -ENOMEM;
		goto out_free_thread_cid;
	}
	apc_init(thread_apc,
			&thread->tcb,
			OriginalApcEnvironment,
			thread_special_apc,
			NULL,
			(PKNORMAL_ROUTINE)ntdll_entry,
			UserMode,
			(void *)(bprm->p + 12));
	insert_queue_apc(thread_apc, (void *)interp_entry, (void *)extra_page, IO_NO_INCREMENT);
#ifndef TIF_APC
#define	TIF_APC	13
#endif
	set_tsk_thread_flag(current, TIF_APC);
#endif

#ifdef ELF_PLAT_INIT
	/*
	 * The ABI may specify that certain registers be set up in special
	 * ways (on i386 %edx is the address of a DT_FINI function, for
	 * example.  In addition, it may also specify (eg, PowerPC64 ELF)
	 * that the e_entry field is the address of the function descriptor
	 * for the startup routine, rather than the address of the startup
	 * routine itself.  This macro performs whatever initialization to
	 * the regs structure is required as well as any relocations to the
	 * function descriptor entries when executing dynamically links apps.
	 */
	ELF_PLAT_INIT(regs, reloc_func_desc);
#endif

	start_thread(regs, interp_entry, bprm->p);
	if (unlikely(current->ptrace & PT_PTRACED)) {
		if (current->ptrace & PT_TRACE_EXEC)
			ptrace_notify ((PTRACE_EVENT_EXEC << 8) | SIGTRAP);
		else
			send_sig(SIGTRAP, current, 0);
	}

	retval = 0;

	try_module_get(THIS_MODULE); 

	/* return from w32syscall_exit, not syscall_exit */
	((unsigned long *)regs)[-1] = (unsigned long)w32syscall_exit;
	regs->fs = TEB_SELECTOR;

out:
	if(elf_phdata)
		kfree(elf_phdata);
	return retval;

	/* error cleanup */
out_free_thread_cid:
	delete_cid_handle(thread->cid.unique_thread, thread_object_type);
out_free_ethread:
	deref_object(thread);
out_free_process_cid:
	delete_cid_handle(process->unique_processid, process_object_type);
out_free_eproc:
	deref_object(process);
out_free_file:
	send_sig(SIGKILL, current, 0);
	goto out;
}

int init_exeso_binfmt(void)
{
	return insert_binfmt(&exeso_format);
}

void exit_exeso_binfmt(void)
{
	unregister_binfmt(&exeso_format);
}

#endif /* EXE_SO */
#endif /* CONFIG_UNIFIED_KERNEL */
