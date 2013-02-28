/*
 * binfmt_pe.c
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
 * binfmt_pe.c:
 * Refered to Linux Kernel code
 */
#include <linux/mman.h>
#include <linux/ptrace.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/random.h>
#include <linux/utsname.h>

#include <linux/semaphore.h>
#include "handle.h"

#include "win32.h"
#include "pefile.h"
#include "section.h"
#include "apc.h"
#include "area.h"
#include "virtual.h"

#ifdef CONFIG_UNIFIED_KERNEL

char builtin_dll_path[MAX_PATH] = {0x0};
char ntdll_name[MAX_PATH + 16] = {0x0};

unsigned long	extra_page = 0;
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
#define	elf_off_t		Elf32_Off
#define	elf_half_t		Elf32_Half
#else
#define	elf_off_t		Elf64_Off
#define	elf_half_t		Elf64_Half
#endif

#endif

extern unsigned long get_ntdll_entry(void);
extern unsigned long get_apc_dispatcher(void);
extern unsigned long get_pe_entry(void);
extern unsigned long get_interp_entry(void);
extern unsigned long get_start_thunk(void);
extern LONG STDCALL map_system_dll(struct task_struct *tsk, char *name,
		unsigned long *ntdll_load_addr, unsigned long *interp_load_addr);
extern int unshare_files(struct files_struct **displaced);
extern void put_files_struct(struct files_struct *files);

void
STDCALL
thread_special_apc(PKAPC Apc,
		PKNORMAL_ROUTINE* NormalRoutine,
		PVOID* NormalContext,
		PVOID* SystemArgument1,
		PVOID* SystemArgument2);

static int load_pe_binary(struct linux_binprm * bprm, struct pt_regs * regs);

static struct linux_binfmt pe_format = {
		.module		= THIS_MODULE,
		.load_binary	= load_pe_binary,
		.load_shlib	= NULL,
		.core_dump	= NULL,
		.min_coredump	= ELF_EXEC_PAGESIZE
};

#define BAD_ADDR(x)	((unsigned long)(x) > TASK_SIZE)


#ifdef NTDLL_SO

extern elf_off_t ntdll_phoff;
extern elf_half_t ntdll_phnum;
#ifndef ELF_BASE_PLATFORM
#define ELF_BASE_PLATFORM NULL
#endif

/* 
 * create_elf_tables
 */
static int
create_elf_tables(struct linux_binprm *bprm, unsigned long load_addr,
		elf_off_t phoff, elf_half_t phnum, unsigned long entry)
{
	unsigned long p = bprm->p;
	int argc = bprm->argc;
	int envc = bprm->envc;
	elf_addr_t __user *argv;
	elf_addr_t __user *envp;
	elf_addr_t __user *sp;
	elf_addr_t __user *u_platform;
	elf_addr_t __user *u_base_platform;
	elf_addr_t __user *u_rand_bytes;
	const char *k_platform = ELF_PLATFORM;
	const char *k_base_platform = ELF_BASE_PLATFORM;
	unsigned char k_rand_bytes[16];
	int items;
	elf_addr_t *elf_info;
	int ei_index = 0;
	const struct cred *cred = current_cred();
	struct vm_area_struct *vma;

	/*
	 * In some cases (e.g. Hyper-Threading), we want to avoid L1
	 * evictions by the processes running on the same package. One
	 * thing we can do is to shuffle the initial stack for them.
	 */

	p = arch_align_stack(p);

	/*
	 * If this architecture has a platform capability string, copy it
	 * to userspace.  In some cases (Sparc), this info is impossible
	 * for userspace to get any other way, in others (i386) it is
	 * merely difficult.
	 */
	u_platform = NULL;
	if (k_platform) {
		size_t len = strlen(k_platform) + 1;

		u_platform = (elf_addr_t __user *)STACK_ALLOC(p, len);
		if (__copy_to_user(u_platform, k_platform, len))
			return -EFAULT;
	}

	/*
	 * If this architecture has a "base" platform capability
	 * string, copy it to userspace.
	 */
	u_base_platform = NULL;
	if (k_base_platform) {
		size_t len = strlen(k_base_platform) + 1;

		u_base_platform = (elf_addr_t __user *)STACK_ALLOC(p, len);
		if (__copy_to_user(u_base_platform, k_base_platform, len))
			return -EFAULT;
	}

	/*
	 * Generate 16 random bytes for userspace PRNG seeding.
	 */
	get_random_bytes(k_rand_bytes, sizeof(k_rand_bytes));
	u_rand_bytes = (elf_addr_t __user *)
			STACK_ALLOC(p, sizeof(k_rand_bytes));
	if (__copy_to_user(u_rand_bytes, k_rand_bytes, sizeof(k_rand_bytes)))
		return -EFAULT;

	/* Create the ELF interpreter info */
	elf_info = (elf_addr_t *) current->mm->saved_auxv;
	/* update AT_VECTOR_SIZE_BASE if the number of NEW_AUX_ENT() changes */
#define NEW_AUX_ENT(id, val) \
	do { \
		elf_info[ei_index++] = id; \
		elf_info[ei_index++] = val; \
	} while (0)

#ifdef ARCH_DLINFO11
	/* 
	 * ARCH_DLINFO must come first so PPC can do its special alignment of
	 * AUXV.
	 * update AT_VECTOR_SIZE_ARCH if the number of NEW_AUX_ENT() in
	 * ARCH_DLINFO changes
	 */
	ARCH_DLINFO;
#endif
	NEW_AUX_ENT(AT_HWCAP, ELF_HWCAP);
	NEW_AUX_ENT(AT_PAGESZ, ELF_EXEC_PAGESIZE);
	NEW_AUX_ENT(AT_CLKTCK, CLOCKS_PER_SEC);
	NEW_AUX_ENT(AT_PHDR, load_addr + phoff);
	NEW_AUX_ENT(AT_PHENT, sizeof(struct elf_phdr));
	NEW_AUX_ENT(AT_PHNUM, phnum);
	NEW_AUX_ENT(AT_BASE, 0);
	NEW_AUX_ENT(AT_FLAGS, 0);
	NEW_AUX_ENT(AT_ENTRY, entry);
	NEW_AUX_ENT(AT_UID, cred->uid);
	NEW_AUX_ENT(AT_EUID, cred->euid);
	NEW_AUX_ENT(AT_GID, cred->gid);
	NEW_AUX_ENT(AT_EGID, cred->egid);
 	NEW_AUX_ENT(AT_SECURE, (elf_addr_t) security_bprm_secureexec(bprm));
	NEW_AUX_ENT(AT_RANDOM, (elf_addr_t)(unsigned long)u_rand_bytes);
	NEW_AUX_ENT(AT_EXECFN, bprm->exec);
#if 0
	if (k_platform) {
		NEW_AUX_ENT(AT_PLATFORM, (elf_addr_t)(unsigned long)u_platform);
	}
	if (k_base_platform) {
		NEW_AUX_ENT(AT_BASE_PLATFORM, (elf_addr_t)(unsigned long)u_base_platform);
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

	sp = STACK_ADD(p, ei_index);

	items = (argc + 1) + (envc + 1) + 1;
	bprm->p = STACK_ROUND(sp, items);

	/* Point sp at the lowest address on the stack */
#ifdef CONFIG_STACK_GROWSUP
	sp = (elf_addr_t __user *)bprm->p - items - ei_index;
	bprm->exec = (unsigned long) sp; /* XXX: PARISC HACK */
#else
	sp = (elf_addr_t __user *)bprm->p;
#endif

	/*
	 * Grow the stack manually; some architectures have a limit on how
	 * far ahead a user-space access may be in order to grow the stack.
	 */
	vma = find_extend_vma(current->mm, bprm->p);
	if (!vma)
		return -EFAULT;

	/* Now, let's put argc (and argv, envp if appropriate) on the stack */
	if (__put_user(argc, sp++))
		return -EFAULT;
	argv = sp;
	envp = argv + argc + 1;

	/* Populate argv and envp */
	p = current->mm->arg_end = current->mm->arg_start;
	while (argc-- > 0) {
		size_t len;
		if (__put_user((elf_addr_t)p, argv++))
			return -EFAULT;
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
		if (__put_user((elf_addr_t)p, envp++))
			return -EFAULT;
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
	return 0;
} /* end create_elf_tables */

/*
 * search_ntdll
 */
char *search_ntdll(void)
{
	int	len;

	if (!*builtin_dll_path) {
		len = strlen("/usr/local/lib/wine/");
		memcpy(builtin_dll_path, "/usr/local/lib/wine/", len + 1);
	} else
		len = strlen(builtin_dll_path);
	memcpy(ntdll_name, builtin_dll_path, len);
	strcpy(ntdll_name + len, "ntdll.dll.so");

	return ntdll_name;
} /* end search_ntdll */

#else /* NTDLL_SO */

/*
 * create_pe_tables
 */
int
create_pe_tables(struct linux_binprm *bprm, struct win32_section *ws,
		unsigned long load_addr, unsigned long interp_load_addr)
{
	return 0;
} /* end create_pe_tables */
EXPORT_SYMBOL(create_pe_tables);

/*
 * load_pe_interp
 */
static unsigned long load_pe_interp(void *interp_hdr,
		struct file *interpreter,
		unsigned long *interp_load_addr)
{
	return 0;
} /* end load_pe_interp */

#endif

static void adjust_stack(unsigned long start_stack)
{
	struct vm_area_struct *vma = find_vma(current->mm, start_stack);

	if (!vma)
		return;

	if (WIN32_STACK_LIMIT > vma->vm_end - vma->vm_start)
		vma->vm_start =  WIN32_LOWEST_ADDR;

	sys_mprotect(vma->vm_start, PAGE_SIZE, PROT_NONE);
}

/*
 * load_pe_binary
 */
static int load_pe_binary(struct linux_binprm *bprm, struct pt_regs *regs)
{
	IMAGE_DOS_HEADER	*dos_hdr;
	struct win32_section	*ws = NULL;
	struct win32_image_section	*wis;
	unsigned long error;
	unsigned long pe_addr = 0;
	int retval = 0;
	unsigned long pe_entry, ntdll_load_addr = 0;
	unsigned long start_code, end_code, start_data, end_data;
	unsigned long reloc_func_desc = 0;
	unsigned long ntdll_entry;
	struct mm_struct    *mm;
	int executable_stack = EXSTACK_DEFAULT;
	unsigned long def_flags = 0;
	unsigned long stack_top;
	unsigned long ret_addr = 0xdeadbeef;
	unsigned long start_address;
	unsigned long pe_brk = 0;
#ifdef NTDLL_SO
	unsigned long	interp_load_addr;
	unsigned long	interp_entry;
#endif
	int		maped = 0;
	struct eprocess	*process;
	struct ethread	*thread;
	PRTL_USER_PROCESS_PARAMETERS	ppb;
	PKAPC	thread_apc;
	OBJECT_ATTRIBUTES	ObjectAttributes;
	INITIAL_TEB	init_teb;

	BOOLEAN is_win32=FALSE;
    struct startup_info *info=NULL;
    struct eprocess	*parent_eprocess=NULL;
    struct ethread	*parent_ethread=NULL;
	struct w32process* child_w32process =NULL;
	struct w32process* parent_w32process =NULL;

	/* check the DOS header */
	retval = -ENOEXEC;
	dos_hdr = (IMAGE_DOS_HEADER *)bprm->buf;
	if (dos_hdr->e_magic != IMAGE_DOS_SIGNATURE || dos_hdr->e_lfanew <= 0)
		goto out;

	ktrace("bprm=%p\n", bprm);
	retval = -ENOMEM;
	ws = (struct win32_section *)kmalloc(sizeof(struct win32_section), GFP_KERNEL);
	if (!ws)
		goto out;
	memset(ws, 0, sizeof(*ws));

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
		kfree(ws);
		goto out;
	}

	/* OK, This is the point of no return */
	mm = current->mm;
	current->flags &= ~PF_FORKNOEXEC;
	mm->def_flags = def_flags;

	current->signal->rlim[RLIMIT_STACK].rlim_cur = WIN32_STACK_LIMIT;
	current->signal->rlim[RLIMIT_STACK].rlim_max = WIN32_STACK_LIMIT;
	current->personality |= ADDR_COMPAT_LAYOUT;
	setup_new_exec(bprm);

	mm->free_area_cache = mm->mmap_base = WIN32_UNMAPPED_BASE;
	mm->cached_hole_size = 0;
	stack_top = WIN32_STACK_LIMIT + WIN32_LOWEST_ADDR;
	retval = setup_arg_pages(bprm, stack_top, executable_stack);
	if (retval < 0)
		goto out_free_file;

	/* map PE image */
	ws->ws_file = bprm->file;
	image_section_setup(ws);
	ws->ws_mmap(current, ws, &pe_addr, 0, 0, 0);
	maped = 1;

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

	/* adjust stack in 0x100000 - 0x300000
	 * 0x100000 - 0x101000 is not access */
	adjust_stack(bprm->p);

	/* Now we do a little grungy work by mmaping the PE image into
	   the correct location in memory.  At this point, we assume that
	   the image should be loaded at fixed address, not at a variable
	   address. */
	for (wis = ws->ws_sections; wis < ws->ws_sections + ws->ws_nsecs; wis++) {
		unsigned long k;

		if (wis->wis_character & IMAGE_SCN_TYPE_NOLOAD)
			continue;

		k = ws->ws_realbase + wis->wis_rva;

		/*
		 * Check to see if the section's size will overflow the
		 * allowed task size. Note that p_filesz must always be
		 * <= p_memsz so it is only necessary to check p_memsz.
		 */
		if (k > TASK_SIZE || TASK_SIZE - wis->wis_size < k) /* Avoid overflows.  */
			goto out_free_file;

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

	/* extra page, used for interpreter ld-linux.so */
	down_write(&mm->mmap_sem);
	if ((extra_page = do_brk(pe_brk, PAGE_SIZE)) != pe_brk) {
		up_write(&mm->mmap_sem);
		goto out_free_file;
	}
	up_write(&mm->mmap_sem);
	mm->brk = pe_brk + PAGE_SIZE;

	ws->ws_entrypoint += ws->ws_realbase;

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
	reloc_func_desc = 0;

	set_binfmt(&pe_format);

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

	insert_reserved_area(process, WIN32_LOWEST_ADDR,
			WIN32_LOWEST_ADDR + WIN32_STACK_LIMIT, _PAGE_READWRITE);

	/* initialize EProcess and KProcess */
	process->section_base_address = (void *)ws->ws_realbase;
	insert_mapped_area(process, ws->ws_realbase, ws->ws_realbase + ws->ws_pagelen, _PAGE_READONLY, NULL);

	/* Create PEB */
	if ((retval = create_peb(process)))
		goto out_free_process_cid;

	/* Create PPB */
	if(is_win32 == FALSE)
	{
		create_ppb(&ppb, process, bprm, bprm->filename, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
		((PEB *)process->peb)->ProcessParameters = ppb;
	}
#ifdef ARCH_HAS_SETUP_ADDITIONAL_PAGES
	retval = arch_setup_additional_pages(bprm, executable_stack);
	if (retval < 0) {
		send_sig(SIGKILL, current, 0);
		goto out_free_process_cid;
	}
#endif /* ARCH_HAS_SETUP_ADDITIONAL_PAGES */

	install_exec_creds(bprm);
	current->flags &= ~PF_FORKNOEXEC;
#ifdef NTDLL_SO
	/* copy argv, env, and auxvec to stack, all for interpreter */
	create_elf_tables(bprm, ntdll_load_addr, ntdll_phoff, ntdll_phnum, get_start_thunk());
#endif

	/* Set the Esp */
#ifdef CONFIG_STACK_GROWSUP
	/* FIXME */
#else
	/* setup user stack */
	/* -------------    -----------
	   param            PEB_BASE
	   -------------    -----------
	   start_address    entry point
	   -------------    -----------
	   ret_addr         0xdeadbeef
	   -------------    -----------
	   */
	bprm->p = bprm->p			/* stack_top */
		- sizeof(ret_addr)			/* return address, BAD address */
		- sizeof(start_address)		/* image entry point */
		- sizeof(unsigned long);	/* paramters for entry point */
	start_address = ws->ws_entrypoint;
	*(unsigned long *)bprm->p = ret_addr;
	*(unsigned long *)(bprm->p + sizeof(ret_addr)) = start_address;
	*(unsigned long *)(bprm->p + sizeof(ret_addr) + sizeof(start_address)) = PEB_BASE;
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
		   emulate the SVr4 behavior. Sigh. */
		down_write(&mm->mmap_sem);
		error = do_mmap(NULL, 0, PAGE_SIZE, PROT_READ | PROT_EXEC,
				MAP_FIXED | MAP_PRIVATE, 0);
		up_write(&mm->mmap_sem);
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

	/* init apc, to call LdrInitializeThunk */
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
	set_tsk_thread_flag(current, TIF_APC);

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

	start_thread(regs, pe_entry, bprm->p);
	if (unlikely(current->ptrace & PT_PTRACED)) {
		if (current->ptrace & PT_TRACE_EXEC)
			ptrace_notify ((PTRACE_EVENT_EXEC << 8) | SIGTRAP);
		else
			send_sig(SIGTRAP, current, 0);
	}

	/* save current trap frame */
	thread->tcb.trap_frame = (struct ktrap_frame *)regs;
	retval = 0;

	try_module_get(THIS_MODULE); 
	/* return from w32syscall_exit, not syscall_exit */
	((unsigned long *)regs)[-1] = (unsigned long)w32syscall_exit;
	regs->fs = TEB_SELECTOR;

out:
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
	/* free win32_section, if not mapped */
	if (!maped && ws) {
		if (ws->ws_sections)
			kfree(ws->ws_sections);
		kfree(ws);
	}
	send_sig(SIGKILL, current, 0);
	goto out;
} /* end load_pe_binary */


int init_pe_binfmt(void)
{
	return insert_binfmt(&pe_format);
}

void exit_pe_binfmt(void)
{
	/* Remove the COFF and ELF loaders. */
	unregister_binfmt(&pe_format);
}
#endif /* CONFIG_UNIFIED_KERNEL */
