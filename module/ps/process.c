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
 * Refered to ReactOS code
 */
#include <linux/sched.h>
#include "unistr.h"
#include "process.h"
#include "section.h"
#include "handle.h"
#include "wineserver/security.h"

#ifdef CONFIG_UNIFIED_KERNEL

POBJECT_TYPE process_object_type = NULL;
EXPORT_SYMBOL(process_object_type);

struct list_head  process_list = LIST_INIT(process_list);
int user_processes;
struct timeout_user *shutdown_timeout;  /* timeout for server shutdown */
struct w32process *create_w32process(struct w32process *parent, int inherit_all, struct eprocess *eprocess);

extern HANDLE base_dir_handle;
extern char ntdll_name[];
extern void create_dummy_file(struct w32process *process);

extern long do_fork_from_task(struct task_struct *ptsk,
		unsigned long process_flags,
		unsigned long clone_flags,
		unsigned long stack_start,
		struct pt_regs *regs,
		unsigned long stack_size,
		int __user *parent_tidptr,
		int __user *child_tidptr);
extern void do_exit_task(struct task_struct *tsk, long code);
extern void do_group_exit(int exit_code);
extern NTSTATUS STDCALL map_system_dll(struct task_struct *tsk, char *name,
		unsigned long *ntdll_load_addr, unsigned long *interp_load_addr);

extern NTSTATUS STDCALL create_process_space(struct eprocess *, struct win32_section *);

extern void *mem_alloc(size_t size);

/* process operations */

static int process_signaled(struct object *obj, struct w32thread *thread);
static unsigned int process_map_access(struct object *obj, unsigned int access);
extern void process_destroy(struct object *obj);

static const struct object_ops process_ops =
{
	sizeof(struct w32process),   /* size */
	NULL,                        /* dump */
	NULL,                        /* get_type */
	no_get_fd,                   /* get_fd */
	process_map_access,          /* map_access */
	no_lookup_name,              /* lookup_name */
	no_open_file,                /* open_file */
	no_close_handle,             /* close_handle */
	process_destroy,             /* destroy */
	process_signaled,            /* signaled */
	no_satisfied,                /* satisfied */
	no_signal,                   /* signal */
	default_get_sd,              /* get_sd */
	default_set_sd               /* set_sd */
};

void startup_info_dump(struct object *obj, int verbose);
static int startup_info_signaled(struct object *obj, struct w32thread *thread);
extern void startup_info_destroy(struct object *obj);

static const struct object_ops startup_info_ops =
{
	sizeof(struct startup_info),   /* size */
	NULL,			               /* dump */
	NULL,                          /* get_type */
	no_get_fd,                     /* get_fd */
	no_map_access,                 /* map_access */
	no_lookup_name,                /* lookup_name */
	no_open_file,                  /* open_file */
	no_close_handle,               /* close_handle */
	startup_info_destroy,          /* destroy */
	startup_info_signaled,         /* signaled */
	no_satisfied,                  /* satisfied */
	no_signal,                     /* signal */
	default_get_sd,                /* get_sd */
	default_set_sd                 /* set_sd */
};

static WCHAR w32process_type_name[] = {'W', '3', '2', 'P', 'r', 'o', 'c', 'e', 's', 's', 0};
static WCHAR startup_info_type_name[] = {'S', 't', 'a', 'r', 't', 'u', 'p', '_', 'I', 'n', 'f', 'o', 0};

POBJECT_TYPE w32process_object_type = NULL;
EXPORT_SYMBOL(w32process_object_type);

POBJECT_TYPE startup_info_object_type = NULL;
EXPORT_SYMBOL(startup_info_object_type);

static GENERIC_MAPPING w32process_mapping =
{
	STANDARD_RIGHTS_READ | SYNCHRONIZE | 0x1 /* QUERY_STATE */,
	STANDARD_RIGHTS_WRITE | SYNCHRONIZE | 0x2 /* MODIFY_STATE */,
	STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE | 0x1 /* QUERY_STATE */,
	STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3
};

static GENERIC_MAPPING startup_info_mapping =
{
	STANDARD_RIGHTS_READ | SYNCHRONIZE | 0x1 /* QUERY_STATE */,
	STANDARD_RIGHTS_WRITE | SYNCHRONIZE | 0x2 /* MODIFY_STATE */,
	STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE | 0x1 /* QUERY_STATE */,
	STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3
};

/*
 * poll the state of a process for WaitFor*() functions
 * - if signalled, sets to non-signalled before returning
 */
int poll_process(struct wait_table_entry *wte)
{
	struct eprocess * process = (struct eprocess *)(wte->wte_obj);

	return (process->pcb.state == PROCESS_STATE_ACTIVE) ? POLL_NOTSIG : POLL_SIG;
} /* end poll_process() */

VOID delete_process(PVOID Object)
{
	struct eprocess *process = Object;

	ktrace("\n");

	if (process->unique_processid)
		delete_cid_handle(process->unique_processid, process_object_type);

	if (process->ep_nls)
		unload_nls(process->ep_nls);
}

/* initialize kprocess */
void kprocess_init(struct kprocess *process, char prio,
		unsigned long affinity, physical_address_t dir_table_base)
{
	ktrace("\n");

	INIT_DISP_HEADER(&process->header, ProcessObject, sizeof(struct kprocess), false);

	/* Initialize Scheduler Data, Disable Alignment Faults and Set the PDE */
	process->affinity = affinity;
	process->base_priority = prio;
	process->quantum_reset = 6;
	process->directory_table_base = dir_table_base;
	process->auto_alignment = true;
	process->state = PROCESS_STATE_ACTIVE;

	/* Initialize the Thread List */
	INIT_LIST_HEAD(&process->thread_list_head);
} /* end kprocess_init */

/* initialize eprocess */
void eprocess_init(struct eprocess *parent, BOOLEAN inherit, struct eprocess *process)
{
	physical_address_t      dir_table_base = { .quad = 0LL };

	ktrace("\n");

	process->ep_nls = load_nls("utf8");

	INIT_LIST_HEAD(&process->thread_list_head);
	rwlock_init(&process->ep_lock);

	process->debug_port = NULL;             /* FIXME */
	process->exception_port = NULL;         /* FIXME */
	process->section_base_address = 0;      /* FIXME */
	/* FIXME: event_init(&Process->LockEvent, SynchronizationEvent, FALSE); */
	/* FIXME: process->object_table = process->default_object_table; */
	/* FIXME: Status = PspInitializeProcessSecurity(Process, pParentProcess); */

	/* 
	 * FIXME:
	 * affinity == active processors, used 1 here
	 * directory_table_base, used 0 here 
	 */
	kprocess_init(&process->pcb, PROCESS_PRIO_NORMAL, 1, dir_table_base);

	INIT_LIST_HEAD(&process->ep_reserved_head);
	INIT_LIST_HEAD(&process->ep_mapped_head);
	
	process->watch_fd = -1;
	process->watch_thread = 0;

	process->ep_handle_info_table = alloc_handle_info_table();

	process->epoll_fd = -1;

	/* alloc handle table */
	if (parent) {
		create_handle_table(parent, inherit, process);
		process->win32process = create_w32process(parent->win32process, inherit, process);
	} else {
		create_handle_table(NULL, FALSE, process);
		process->win32process = create_w32process(NULL, FALSE, process);
	}
}

/*
 * create_process
 */
NTSTATUS STDCALL create_process(OUT PHANDLE ProcessHandle,
                 IN ACCESS_MASK DesiredAccess,
                 IN POBJECT_ATTRIBUTES ObjectAttributes  OPTIONAL,
                 IN HANDLE ParentProcessHandle  OPTIONAL,
                 IN BOOLEAN InheritObjectTable,
                 IN HANDLE SectionHandle  OPTIONAL,
                 IN HANDLE DebugPort  OPTIONAL,
                 IN HANDLE ExceptionPort  OPTIONAL)
{
	HANDLE hProcess = NULL;
	struct eprocess *child_eprocess;
	struct eprocess *parent_eprocess = NULL;
	NTSTATUS Status = STATUS_SUCCESS;
	char *system_dll_name = ntdll_name;
	long	cpid;
	struct task_struct	*child_task = NULL, *parent_task = NULL;
	struct ethread *current_ethread = get_current_ethread();
	struct ethread *parent_ethread = NULL;
	struct ethread *child_ethread = NULL;
	struct ktrap_frame	*trap_frame = NULL;
	struct win32_section	*section = NULL;
	unsigned long system_dll_load_addr, interp_load_addr;

	ktrace("\n");
	if (!ProcessHandle)
		return STATUS_INVALID_PARAMETER;

	if (!current_ethread)
		return STATUS_INVALID_PARAMETER;

    	/* Reference the Parent if there is one */
	if (ParentProcessHandle == NtCurrentProcess()) {
		parent_eprocess = current_ethread->threads_process;
		parent_ethread = current_ethread;
		ref_object((PVOID)parent_eprocess);
	}
	else {
		Status = ref_object_by_handle(ParentProcessHandle,
				PROCESS_ALL_ACCESS,
				process_object_type,
				KernelMode,
				(PVOID *)&parent_eprocess,
				NULL);
		if (!NT_SUCCESS(Status)) {
			return Status;
		}
		parent_ethread = get_first_thread(parent_eprocess);
	}

	trap_frame = parent_ethread->tcb.trap_frame;
	parent_task = parent_ethread->et_task;

	cpid = do_fork_from_task(parent_task, CREATE_PROCESS,
			SIGCHLD | CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND,	/* SIGCHLD ????? */
			trap_frame->esp, (struct pt_regs *)trap_frame, 0, NULL, NULL);

	if (parent_eprocess)
		deref_object((PVOID)parent_eprocess);

	if (cpid < 0) {
		Status = STATUS_INVALID_PARAMETER;
		goto out;
	}

	child_task = find_task_by_vpid(cpid);

	/* Create EPROCESS */
	Status = create_object(KernelMode,
			process_object_type,
			ObjectAttributes,
			KernelMode,
			NULL,
			sizeof(struct eprocess),
			0,
			0,
			(PVOID *)&child_eprocess);
	if (!NT_SUCCESS(Status))
		goto cleanup_child_task;

	eprocess_init(parent_eprocess, InheritObjectTable, child_eprocess);

	/* Insert Process into Handle Table */
	Status = insert_object(child_eprocess,
			NULL,
			DesiredAccess,
			0,
			NULL,
			&hProcess);
	if (!NT_SUCCESS(Status))
		goto cleanup_child_eprocess;

	/* allocate a Win32 thread object */
	Status = create_object(KernelMode,
			thread_object_type,
			ObjectAttributes,
			KernelMode,
			NULL,
			sizeof(struct ethread),
			0,
			0,
			(PVOID *)&child_ethread);
	if (!NT_SUCCESS(Status))
		goto cleanup_proc_handle;

	ethread_init(child_ethread, child_eprocess, child_task);

	child_eprocess->fork_in_progress = child_ethread;

	/* Inherit stuff from the Parent since we now have the object created */
	if (parent_eprocess) {
		child_eprocess->inherited_from_unique_pid = parent_eprocess->unique_processid;
		child_eprocess->session = parent_eprocess->session;
	}

	/* FIXME: Set up the Quota Block from the Parent
	 *	 PspInheritQuota(Parent, child_eprocess); 
	 */

	/* FIXME: Set up Dos Device Map from the Parent
	 *  ObInheritDeviceMap(Parent, child_eprocess) 
	 */

	/* Set the Process' LPC Ports */

	/* Setup the Lock Event */
	event_init(&child_eprocess->lock_event, synchronization_event, FALSE);

	/* Add the Section */
	if (SectionHandle) {
		Status = ref_object_by_handle(SectionHandle,
				0,
				section_object_type,
				KernelMode,
				(PVOID *)&section,
				NULL);
		if (!NT_SUCCESS(Status))
			goto cleanup_child_ethread;
	}

	/* Create the Process' Address Space */
	Status = create_process_space(child_eprocess, section);
	if (!NT_SUCCESS(Status))
		goto cleanup_section;

	/* Do what exec should do */
	flush_old_exec_from_task(child_task);

	if (section) {
		/* Map the System Dll */
		map_system_dll(child_task, system_dll_name,
				&system_dll_load_addr, &interp_load_addr);
	}

	child_eprocess->unique_processid = create_cid_handle(child_eprocess, process_object_type);
	if (!(child_eprocess->unique_processid))
		goto cleanup_section;

	/* Create PEB only for User-Mode Processes */
	if (parent_eprocess) {
		Status = create_peb(child_eprocess);
		if (!NT_SUCCESS(Status))
			goto cleanup_section;
	}

	/* Let's take advantage of this time to kill the reference too */
	parent_eprocess = NULL;

    	/* Set the Creation Time */
	if (copy_to_user(ProcessHandle, &hProcess, sizeof(hProcess))) {
		Status = STATUS_UNSUCCESSFUL;
		goto cleanup_section;
	}

	deref_object(child_eprocess);
	deref_object(child_ethread);

    	return STATUS_SUCCESS;

cleanup_section:
	deref_object((PVOID)section);

cleanup_child_ethread:
	deref_object((PVOID)child_ethread);

cleanup_proc_handle:
	if (hProcess)
		NtClose(hProcess);

cleanup_child_eprocess:
	deref_object(child_eprocess);

cleanup_child_task:
	do_exit_task(child_task, 0);

out:
    	return Status;
} /* end create_process */

NTSTATUS SERVICECALL
NtCreateProcess(OUT PHANDLE ProcessHandle,
			IN ACCESS_MASK DesiredAccess,
			IN POBJECT_ATTRIBUTES ObjectAttributes  OPTIONAL,
			IN HANDLE ParentProcessHandle,
			IN BOOLEAN InheritObjectTable,
			IN HANDLE SectionHandle  OPTIONAL,
			IN HANDLE DebugPort  OPTIONAL,
			IN HANDLE ExceptionPort  OPTIONAL)
{
	ktrace("\n");
	return ParentProcessHandle
		? create_process(ProcessHandle,
				DesiredAccess,
				ObjectAttributes,
				ParentProcessHandle,
				InheritObjectTable,
				SectionHandle,
				DebugPort,
				ExceptionPort)
		: STATUS_INVALID_PARAMETER;
} /* end NtCreateProcess */
EXPORT_SYMBOL(NtCreateProcess);

NTSTATUS SERVICECALL
NtOpenProcess(OUT PHANDLE ProcessHandle, 
	      IN ACCESS_MASK DesiredAccess, 
	      IN POBJECT_ATTRIBUTES ObjectAttributes, 
	      IN PCLIENT_ID ClientId)
{
	/* FIXME: combine Ke and Ex into the one */
	KPROCESSOR_MODE pre_mode = (KPROCESSOR_MODE)get_pre_mode();
	struct eprocess *process = NULL;
	struct ethread *thread = NULL;
	NTSTATUS status = STATUS_INVALID_PARAMETER;
	CLIENT_ID cid;
	
	ktrace("\n");

	if (ObjectAttributes->ObjectName) {
		return open_object_by_name(ObjectAttributes, 
				process_object_type, 
				NULL, 
				pre_mode, 
				DesiredAccess, 
				NULL, 
				ProcessHandle);
	} else if (ClientId) {
		if (copy_from_user(&cid, ClientId, sizeof(cid)))
			return STATUS_INVALID_ADDRESS;
		if (cid.UniqueProcess) {
			if (lookup_process_by_pid(cid.UniqueProcess, &process))
				return status;
		} else if (cid.UniqueThread) {
			if (lookup_process_thread_by_cid(&cid, &process, &thread))
				return status;
		} else
			return status;
		
		status = open_object_by_pointer(process, 
				ObjectAttributes->Attributes, 
				NULL, 
				DesiredAccess, 
				process_object_type, 
				pre_mode, 
				ProcessHandle);

		if (thread)
			deref_object(thread);
		
		deref_object(process);
	}
	return status;
}
EXPORT_SYMBOL(NtOpenProcess);

/* copy unicode string to PPB */
static inline int
copy_param_str(void *ptr, PUNICODE_STRING dst, PUNICODE_STRING src)
{
	int		ret = 0;

	dst->Length = src->Length;
	dst->MaximumLength = src->MaximumLength;
	dst->Buffer = (PWSTR)ptr;
	if (src->Length)
		ret = copy_to_user(dst->Buffer, src->Buffer, src->Length + sizeof(wchar_t));

	return ret ? -EFAULT : ALIGN_TO_LONG(dst->MaximumLength);
}

static int copy_env(struct nls_table *nls, PWSTR *pwcs, char *src, int len)
{
	char		*ksrc;
	PWSTR	wcs = *pwcs;
	wchar_t	*wc;
	int		ret = -ENOMEM;
	int		n = 0;

	if (wcs)
		return -EINVAL;

	ksrc = kmalloc(len + 1, GFP_KERNEL);
	if (!ksrc)
		return ret;

	ret = -EFAULT;
	if (copy_from_user(ksrc, src, len))
		goto out_free_src;
	ksrc[len++] = 0;

	wcs = kmalloc(len * sizeof(wchar_t), GFP_KERNEL);
	ret = -ENOMEM;
	if (!wcs)
		goto out_free_src;

	wc = wcs;
	n = char2wchar(nls, wc, ksrc, len);
	if (n < 0) {
		ret = -EINVAL;
		goto out_free_wcs;
	}

	ret = n;
	*pwcs = wcs;
	goto out_free_src;

out_free_wcs:
	kfree(wcs);
out_free_src:
	kfree(ksrc);

	return ret;
}

long wcslen_user(const wchar_t *s)
{
	long res = 0;
	wchar_t c = 0;

	for (;;) {
		if (get_user(c, s))
			return 0;
		if (!c)
			return res + sizeof(wchar_t);
		
		res += sizeof(wchar_t);
		s++;
	}
}
EXPORT_SYMBOL(wcslen_user);

static int copy_cmdline(struct nls_table *nls, PUNICODE_STRING dst, int argc, char **argv, int total_len)
{
	int	i, n, len;
	char	*p, *kargv;
	int	ret = -ENOMEM;
	wchar_t	*wc;
	int	j;
	if (!(kargv = kmalloc(total_len, GFP_KERNEL)))
		return ret;

	dst->Length = 0;
	dst->MaximumLength = total_len * sizeof(wchar_t) + argc * 2 * sizeof(wchar_t);  
	
	dst->Buffer = kmalloc(dst->MaximumLength, GFP_KERNEL);
	if (!dst->Buffer)
		goto out_free_src;

	wc = dst->Buffer;

	for (i = 0; i < argc; i++) {
		len = (i == argc - 1) ? strlen_user(argv[i]) : argv[i + 1] - argv[i];
		ret = -EFAULT;
		if (copy_from_user(kargv, argv[i], len))
			goto out_free_src;
		p = kargv;
		
		if (*p != '"') {
			dst->Length += sizeof(wchar_t);
			*wc++ = L'"';
		}
		
		while(p < kargv + len - 1)
		{
		    unsigned char tmp = *(p + j);
		    while(j < 6  &&  ((tmp << j)& 0xff) >> 7 &&  (((tmp << (j+1)) & 0xff) >> 7))
		    //while(j < 6  &&  ((tmp << j) & 0x80)  &&  ((tmp << (j+1)) & 0x80))
		    {
			j++;
		    }
		    j++;
		    n = nls->char2uni(p, j, wc++);
		    if (n < 0)
		    {
			ret = -EINVAL;
			goto out_free_dst;
		    }
		    p += j;
		    j = 0;
		    dst->Length += sizeof(wchar_t);
		}

		if (*kargv != '"') {
			dst->Length += sizeof(wchar_t);
			*wc++ = L'"';
		}
		if (i == argc - 1) {
			*wc++ = L'\0';
			dst->Length += sizeof(wchar_t);
			
		} else {
			*wc++ = L' ';
			dst->Length += sizeof(wchar_t);
		}
	}
	ret = 0;
	ktrace("copy_cmdline SUCCESS\n");
	goto out_free_src;

out_free_dst:
	kfree(dst->Buffer);
	memset(dst, 0, sizeof(UNICODE_STRING));
out_free_src:
	kfree(kargv);
	return ret;
}

/* create ppb */
NTSTATUS
create_ppb(PRTL_USER_PROCESS_PARAMETERS *ppb_res,
		struct eprocess *process,
		struct linux_binprm *bprm,
		char *image_name,
		char *dll_path,
		char *current_dir,
		PWSTR environ,
		char *window_title,
		char *desktop_info,
		char *shell_info,
		char *rt_info)
{
	PRTL_USER_PROCESS_PARAMETERS ppb = NULL;
	HANDLE current_dir_handle;
	HANDLE console_handle;
	int		i, env_size, len, brk_size;
	int		ret = -EINVAL;
	unsigned long	console_flags;
	unsigned long	addr;
#ifndef EXE_SO
	unsigned long	pos = bprm->p;
#else
	unsigned long	pos = current->mm->arg_start;
#endif
	unsigned long	argv_start, envp_start;
	unsigned long	brk_res;
	char	**argv, **envp;
	char	*p, *cdir, *cwd;
	char	*native_app = NULL, *native_cmdline = NULL;
	char	*desktop = NULL;
	int	cdir_len, size;
	void	*ptr;
	UNICODE_STRING	dll_path_uni = {0, 2, NULL};
	UNICODE_STRING	current_dir_uni;
	UNICODE_STRING	current_work_dir;
	UNICODE_STRING	window_title_uni = {0, 2, NULL};
	UNICODE_STRING	desktop_info_uni = {0, 2, NULL};
	UNICODE_STRING	shell_info_uni = {0, 2, NULL};
	UNICODE_STRING	rt_info_uni = {0, 2, NULL};
	UNICODE_STRING	image_name_uni;
	UNICODE_STRING	cmd_line_uni;
	PWSTR	kenv = NULL;
	struct nls_table	*nls = process->ep_nls;
	mm_segment_t old_fs;

	size = 1024;
	cdir = (char *)kmalloc(0x400, GFP_KERNEL);
	cwd = (char *)kmalloc(0x400, GFP_KERNEL);
	argv = (char **)kmalloc(bprm->argc * sizeof(char *), GFP_KERNEL);
	envp = (char **)kmalloc(bprm->envc * sizeof(char *), GFP_KERNEL);

	argv_start = pos;
	for (i = 0; i < bprm->argc; i++) {
		argv[i] = (char *)pos;
		pos += strlen_user(argv[i]);
	}

	envp_start = pos;
	for (i = 0; i < bprm->envc; i++) {
		envp[i] = (char *)pos;
		pos += strlen_user(envp[i]);
	}

	for (i = 0; i < bprm->envc; i++) {
		if (!native_app && !strncmp(envp[i], "NATIVEAPP=", strlen("NATIVEAPP="))) {
			len = strlen_user(envp[i]);
			native_app = (char *)kmalloc(len, GFP_KERNEL);
			if (!native_app) {
				ret = -ENOMEM;
				if (native_cmdline)
					kfree(native_cmdline);
				goto out_free_envp;
			}
			if (copy_from_user(native_app, envp[i] + strlen("NATIVEAPP="), 
				len - strlen("NATIVEAPP="))) {
				ret = -EFAULT;
				kfree(native_app);
				if (native_cmdline)
					kfree(native_cmdline);
				goto out_free_envp;
			}
			continue;
		}

		if (!native_cmdline && !strncmp(envp[i], "NATIVECMDLINE=", 
			strlen("NATIVECMDLINE="))) {
			len = strlen_user(envp[i]);
			native_cmdline = (char *)kmalloc(len, GFP_KERNEL);
			if (!native_cmdline) {
				ret = -ENOMEM;
				if (native_app)
					kfree(native_app);
				goto out_free_envp;
			}
			if (copy_from_user(native_cmdline, envp[i] + strlen("NATIVECMDLINE="), 
				len - strlen("NATIVECMDLINE="))) {
				ret = -EFAULT;
				kfree(native_cmdline);
				if (native_app)
					kfree(native_app);
				goto out_free_envp;
			}
			continue;
		}

		if (!desktop && !strncmp(envp[i], "DESKTOP=", strlen("DESKTOP="))) {
			len = strlen_user(envp[i]);
			desktop = (char *)kmalloc(len, GFP_KERNEL);
			if (!desktop) {
				ret = -ENOMEM;
				goto out_free_envp;
			}
			if (copy_from_user(desktop, envp[i] + strlen("DESKTOP="), 
				len - strlen("DESKTOP="))) {
				ret = -EFAULT;
				kfree(desktop);
				goto out_free_envp;
			}
			continue;
		}
	}

	if ((ret = copy_cmdline(nls, &cmd_line_uni, bprm->argc, argv, pos - argv_start)))
		goto out_free_envp;

	if (native_cmdline) {
		str2unistr(nls, &cmd_line_uni, native_cmdline);
		kfree(native_cmdline);
	}

	/* copy environment from user to kernel */
	env_size = copy_env(nls, &kenv, (char *)envp_start, pos - envp_start);
	if ((ret = env_size) < 0)
		goto out_free_cmd;

	/* get current working directory */
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	sys_getcwd(cwd, size);
	set_fs(old_fs);
	ktrace("cdir=%s, image_name=%s, cwd=%s\n", cdir, image_name, cwd);

	if (*image_name == '/')
		strcpy(cdir, image_name);
	else {
		for (i = 0; i < bprm->envc; i++) {
			if (strncmp(envp[i], "PWD", strlen("PWD")))
				continue;

			p = envp[i] + strlen("PWD");
			while (*p && *p != '=')
				p++;

			if (*p)
				current_dir = p + 1;

			cdir_len = strlen_user(current_dir) - 1;
			ret = -EFAULT;
			if (copy_from_user(cdir, current_dir, cdir_len))
				goto out_free_kenv;
			if (cdir[cdir_len - 1] != '/')
				cdir[cdir_len++] = '/';

			if (*image_name == '.' && image_name[1] == '/')
				strcpy(cdir + cdir_len, image_name + 2);
			else
				strcpy(cdir + cdir_len, image_name);
			strcpy(image_name, cdir);
		}
	}

	p = strrchr(cdir, '/');
	if (!p)
		goto out_free_kenv;
	*++p = '\0';

	len = p - cdir;
	current_dir = (char *)((bprm->p - len - 1) & ~3);
	ret = -EFAULT;
	if (copy_to_user(current_dir, cdir, len))
		goto out_free_kenv;

	if ((ret = sys_chdir(current_dir))) {
		goto out_free_kenv;
	}

	ret = -EINVAL;
	if (str2unistr(nls, &current_work_dir, cwd))
		goto out_free_kenv;

	if (str2unistr(nls, &current_dir_uni, current_dir))
		goto out_free_kenv;

	if (str2unistr(nls, &image_name_uni, image_name))
		goto out_free_cwd;

	if (native_app) {
		str2unistr(nls, &image_name_uni, native_app);
		kfree(native_app);
	}

	if (desktop && !desktop_info) {
		str2unistr(nls, &desktop_info_uni, desktop);
		kfree(desktop);
	}

	current_dir_handle = NULL;
	console_handle = NULL;
	console_flags = 0;

	len = sizeof(RTL_USER_PROCESS_PARAMETERS)	/* size of process parameter block */
		+ MAX_PATH * sizeof(wchar_t)	/* size of current directory buffer */
		+ ALIGN_TO_LONG(dll_path_uni.MaximumLength)
		+ ALIGN_TO_LONG(image_name_uni.MaximumLength)
		+ ALIGN_TO_LONG(cmd_line_uni.MaximumLength)
		+ ALIGN_TO_LONG(window_title_uni.MaximumLength)
		+ ALIGN_TO_LONG(desktop_info_uni.MaximumLength)
		+ ALIGN_TO_LONG(shell_info_uni.MaximumLength)
		+ ALIGN_TO_LONG(rt_info_uni.MaximumLength)
		+ ALIGN_TO_LONG(env_size);
	/* FIXME: just for pass the socket fd, may be unused in the future */
	len += sizeof(int);

	/* Calculate the required block size */
	brk_size = ALIGN(len, PAGE_SIZE);

	addr = 0x20000000UL - brk_size;
	down_write(&current->mm->mmap_sem);
	brk_res = do_brk(addr, brk_size);
	up_write(&current->mm->mmap_sem);
	if (brk_res != addr)
		goto out_free_image;

	ppb = (PRTL_USER_PROCESS_PARAMETERS)addr;
	memset(ppb, 0, sizeof(*ppb));
	ppb->AllocationSize = brk_size;
	ppb->Size = len;
	ppb->Flags = PPF_NORMALIZED;
	ppb->CurrentDirectoryHandle = current_dir_handle;
	ppb->hConsole = console_handle;
	ppb->ProcessGroup = console_flags;

	ptr = (void *)(ppb + 1);

	/* FIXME: just for pass the socket fd, may be unused in the future */
	memset(ppb + 1, 0, sizeof(int));
	ptr += 4;

	/* copy current directory */
	ret = copy_param_str(ptr, &ppb->CurrentDirectoryName, &current_work_dir);
	if (ret < 0)
		goto out_free_image;

	/* copy dll path */
	ptr += ret;
	ret = copy_param_str(ptr, &ppb->DllPath, &dll_path_uni);
	if (ret < 0)
		goto out_free_image;

	/* copy image path name */
	ptr += ret;
	ret = copy_param_str(ptr, &ppb->ImagePathName, &image_name_uni);
	if (ret < 0)
		goto out_free_image;

	/* copy command line */
	ptr += ret;
	ret = copy_param_str(ptr, &ppb->CommandLine, &cmd_line_uni);
	if (ret < 0)
		goto out_free_image;

	/* copy title */
	ptr += ret;
	ret = copy_param_str(ptr, &ppb->WindowTitle, &window_title_uni);
	if (ret < 0)
		goto out_free_image;

	/* copy desktop */
	ptr += ret;
	ret = copy_param_str(ptr, &ppb->DesktopInfo, &desktop_info_uni);
	if (ret < 0)
		goto out_free_image;

	/* copy shell info */
	ptr += ret;
	ret = copy_param_str(ptr, &ppb->ShellInfo, &shell_info_uni);
	if (ret < 0)
		goto out_free_image;

	/* copy runtime info */
	ptr += ret;
	ret = copy_param_str(ptr, &ppb->RuntimeInfo, &rt_info_uni);
	if (ret < 0)
		goto out_free_image;

	/* copy Environment */
	ptr += ret;
	ret = copy_to_user(ppb->Environment = ptr, kenv, env_size);
	if (ret)
		goto out_free_image;

	*ppb_res = ppb;
	ret = STATUS_SUCCESS;

out_free_image:
	FREE_UNI(image_name_uni);
out_free_cwd:
	FREE_UNI(current_dir_uni);
out_free_kenv:
	kfree(kenv);
out_free_cmd:
	FREE_UNI(cmd_line_uni);
out_free_envp:
	kfree(envp);
	kfree(argv);
	kfree(cdir);
	kfree(cwd);

	return ret;
}

VOID
init_w32process_implement(VOID)
{
	OBJECT_TYPE_INITIALIZER ObjectTypeInitializer;
	UNICODE_STRING Name;

	memset(&ObjectTypeInitializer, 0, sizeof(ObjectTypeInitializer));
	init_unistr(&Name, w32process_type_name);
	ObjectTypeInitializer.Length = sizeof(ObjectTypeInitializer);
	ObjectTypeInitializer.DefaultNonPagedPoolCharge = sizeof(struct w32process);
	ObjectTypeInitializer.GenericMapping = w32process_mapping;
	ObjectTypeInitializer.PoolType = NonPagedPool;
	ObjectTypeInitializer.ValidAccessMask = EVENT_ALL_ACCESS;
	ObjectTypeInitializer.UseDefaultObject = TRUE;
	create_type_object(&ObjectTypeInitializer, &Name, &w32process_object_type);
}

VOID
init_startup_info_implement(VOID)
{
	OBJECT_TYPE_INITIALIZER ObjectTypeInitializer;
	UNICODE_STRING Name;

	memset(&ObjectTypeInitializer, 0, sizeof(ObjectTypeInitializer));
	init_unistr(&Name, startup_info_type_name);
	ObjectTypeInitializer.Length = sizeof(ObjectTypeInitializer);
	ObjectTypeInitializer.DefaultNonPagedPoolCharge = sizeof(struct startup_info);
	ObjectTypeInitializer.GenericMapping = startup_info_mapping;
	ObjectTypeInitializer.PoolType = NonPagedPool;
	ObjectTypeInitializer.ValidAccessMask = EVENT_ALL_ACCESS;
	ObjectTypeInitializer.UseDefaultObject = TRUE;
	create_type_object(&ObjectTypeInitializer, &Name, &startup_info_object_type);
}

/* return the main thread of the process */
struct w32thread *get_process_first_thread(struct w32process *process)
{
	struct list_head *ptr = list_head(&process->thread_list);
	if (!ptr)
		return NULL;
	return LIST_ENTRY(ptr, struct w32thread, proc_entry);
}

/* set the state of the process startup info */
void set_process_startup_state(struct w32process *process, enum startup_state state)
{
	if (process->startup_state == STARTUP_IN_PROGRESS)
		process->startup_state = state;
	if (process->startup_info) {
		uk_wake_up(&process->startup_info->obj, 0);
		release_object(process->startup_info);
		process->startup_info = NULL;
	}
}

/* create a new process and its main thread */
/* if the function fails the fd is closed */
struct w32process *create_w32process(struct w32process *parent, int inherit_all, struct eprocess *eprocess)
{
	struct w32process *process;

	ktrace("\n");
	if(eprocess->win32process)
	{
		process = eprocess->win32process;
		if(parent)
		{
			process->parent = (struct w32process *)grab_object(parent);
			process->token = token_duplicate(parent->token, TRUE, 0);
		}

		process->start_time = current_time;
		process->end_time = 0;

		return process;
	}
	else
	{
		if (!(process = alloc_wine_object(&process_ops)))
			goto error;
	}

	INIT_DISP_HEADER(&process->obj.header, PROCESS, sizeof(struct w32process), 0);
	process->parent          = NULL;
	process->debugger        = NULL;
	process->sigkill_timeout = NULL;
	process->exit_code       = 0; /* STILL_ACTIVE */
	process->running_threads = 0;
	process->priority        = 0; /* PROCESS_PRIOCLASS_NORMAL */
	process->affinity        = ~0;
	process->suspend         = 0;
	process->is_system       = 0;
	process->create_flags    = 0;
	process->console         = NULL;
	process->startup_state   = STARTUP_IN_PROGRESS;
	process->startup_info    = NULL;
	process->idle_event      = NULL;
	process->queue           = NULL;
	process->winstation      = 0;
	process->desktop         = 0;
	process->token           = NULL;
	process->trace_data      = 0;
	process->dummyfd         = -1;
	INIT_LIST_HEAD(&process->thread_list);
	INIT_LIST_HEAD(&process->locks);
	INIT_LIST_HEAD(&process->classes);
	INIT_LIST_HEAD(&process->dlls);

	process->start_time = current_time;
	process->end_time = 0;
	list_add_before(&process_list, &process->entry);

	process->eprocess = eprocess;

	if (!parent) {
		create_dummy_file(process);
		process->token = token_create_admin();
	}
	else {
		/* can not call create_dummy_file here, because in parent space,
		 * create_dummy_file is called in user_thread_startup */
		process->parent = (struct w32process *)grab_object(parent);
		/* Note: for security reasons, starting a new process does not attempt
		 * to use the current impersonation token for the new process */
		process->token = token_duplicate(parent->token, TRUE, 0);
	}
	return process;

error:
	if (process)
		release_object(process);
	return NULL;
}

/* initialize the current process and fill in the request */
data_size_t init_process(struct w32thread *thread)
{
	struct w32process *process = thread->process;
	struct startup_info *info = process->startup_info;

	if (!info)
		return 0;
	return info->data_size;
}

static int process_signaled(struct object *obj, struct w32thread *thread)
{
	struct w32process *process = (struct w32process *)obj;
	return !process->running_threads;
}

static unsigned int process_map_access(struct object *obj, unsigned int access)
{
	if (access & GENERIC_READ)
		access |= STANDARD_RIGHTS_READ | SYNCHRONIZE;
	if (access & GENERIC_WRITE)
			access |= STANDARD_RIGHTS_WRITE | SYNCHRONIZE;
	if (access & GENERIC_EXECUTE)
		access |= STANDARD_RIGHTS_EXECUTE;
	if (access & GENERIC_ALL)
		access |= PROCESS_ALL_ACCESS;
	return access & ~(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);
}

static int startup_info_signaled(struct object *obj, struct w32thread *thread)
{
	struct startup_info *info = (struct startup_info *)obj;
	return info->process && info->process->startup_state != STARTUP_IN_PROGRESS;
}

/* get a process from a handle (and increment the refcount) */
struct w32process *get_process_from_handle(obj_handle_t handle, unsigned int access)
{
	struct eprocess *process = (struct eprocess *)get_handle_obj(handle, access);
	deref_object(process);
	return grab_object(process ? process->win32process : NULL);
}

struct w32process *get_process_from_id(unsigned int id)
{
	struct eprocess *eproc;

	if (lookup_process_by_pid((HANDLE)id, &eproc))
		return NULL;
	deref_object(eproc);
	return grab_object(eproc->win32process);
}

/* add a thread to a process running threads list */
void add_process_thread(struct w32process *process, struct w32thread *thread)
{
	ktrace("\n");

	list_add_before(&process->thread_list, &thread->proc_entry);
	if (!process->running_threads++) {
#if 0
		if (!process->is_system) {
			if (!user_processes++ && shutdown_timeout) {
				remove_timeout_user(shutdown_timeout);
				shutdown_timeout = NULL;
			}
		}
#endif
	}
	grab_object(thread);
}

void enum_processes(int (*cb)(struct w32process*, void*), void *user)
{
	struct list_head *ptr, *next;

	LIST_FOR_EACH_SAFE(ptr, next, &process_list) {
		struct w32process *process = LIST_ENTRY(ptr, struct w32process, entry);
		if ((cb)(process, user))
			break;
	}
}

/* create a new process */
extern int msleep(int);
extern void inherit_console(struct w32thread *parent_thread, struct w32process *process, obj_handle_t hconin);
 DECL_HANDLER(new_process)
 {
    struct startup_info *info = NULL;
    struct task_struct  *child_task = NULL;
    struct eprocess *child_eprocess=NULL;
    struct ethread *child_ethread = NULL;
    struct w32process *parent_w32process = get_current_w32process();
    struct w32thread  *parent_w32thread = get_current_w32thread();
    struct w32process *child_w32process=NULL;

    ktrace("parent_pid %x child_pid %x\n",current->pid,req->child_pid);

    child_task = find_task_by_vpid(req->child_pid);

    if (child_task)
    {
		if (child_task->state == TASK_DEAD || child_task->flags & PF_EXITING)
		{
			set_error(STATUS_ACCESS_DENIED);
			return;
		}
	
		if (req->operation == 0)
		{
			//this is the first time this function is called
			while ( !child_task->ethread &&
				(child_task->state != TASK_DEAD) &&
				!(child_task->flags & PF_EXITING) )
			{
				msleep(20);  //wait for 20mS

				if (child_task->state == TASK_DEAD ||
					child_task->flags & PF_EXITING)
				{
					printk("error:TASK_DEAD\n");
					set_error(STATUS_ACCESS_DENIED);
					return;
				}
			}
		}
		else  //this is the 2nd time
		{
			child_ethread  = child_task->ethread;

			up(&child_ethread->exec_semaphore);	 //let the child go
			return;
		}
   }
    else
    {
		printk("error:child_task is null\n");
		set_error(STATUS_INVALID_PARAMETER);
		goto done;
    }

    child_ethread  = child_task->ethread;
    child_eprocess = child_ethread->threads_process;
    child_w32process = child_eprocess->win32process;

    child_eprocess->fork_in_progress = NULL;

   /* build a startup info for the child process */
    if (!(info = alloc_wine_object( &startup_info_ops ))) return;
    info->hstdin       = req->hstdin;
    info->hstdout      = req->hstdout;
    info->hstderr      = req->hstderr;
    info->exe_file     = NULL;
    info->process      = (struct w32process*)grab_object(  child_w32process );
    info->data_size    = get_req_data_size();
    info->data         = NULL;

    if (!(info->data = memdup( get_req_data(), info->data_size ))) goto done;

    ref_object_by_pointer(info, 0, NULL, 0);
//     child_w32process->startup_info = info;

	if(req->create_flags & 0x00000004)//CREATE_SUSPENDED = 0x04
		child_ethread->suspend_on_create = 1;  //1 if suspend
	else
		child_ethread->suspend_on_create = 0;
	
	if(req->inherit_all)
		child_ethread->inherit_all = 1;
	else
		child_ethread->inherit_all = 0;

    reply->info = alloc_handle( parent_w32process, info, SYNCHRONIZE, 0 );
    reply->pid = (unsigned int)child_eprocess->unique_processid;
    reply->tid = (unsigned int)child_ethread->cid.unique_thread;
    reply->phandle = alloc_handle( parent_w32process, child_eprocess, req->process_access, req->process_attr );
    reply->thandle = alloc_handle( parent_w32process, child_ethread, req->thread_access, req->thread_attr );

	if(req->hstdin != (HANDLE)EX_INVALID_HANDLE)
	{
		inherit_console(parent_w32thread, child_w32process, req->inherit_all?req->hstdin:0);
	}

	/* Setup the Lock Event */
	event_init(&child_eprocess->lock_event, synchronization_event, FALSE);

done:
    release_object( info );
    return;
 }

/* Retrieve information about a newly started process */
DECL_HANDLER(get_new_process_info)
{
	struct startup_info *info;

	ktrace("\n");
	if ((info = (struct startup_info *)get_handle_obj(req->info, 0))) {
		reply->success = is_process_init_done(info->process);
		reply->exit_code = info->process->exit_code;
		release_object(info);
	}
}

/* Retrieve the new process startup info */
DECL_HANDLER(get_startup_info)
{
#if 0
	struct w32process *process = current_thread->process;
	struct startup_info *info = process->startup_info;
	data_size_t size;

	ktrace("\n");
	if (!info)
		return;

	if (info->exe_file &&
			!(reply->exe_file = alloc_handle(process, info->exe_file, GENERIC_READ, 0)))
		return;

	reply->hstdin  = info->hstdin;
	reply->hstdout = info->hstdout;
	reply->hstderr = info->hstderr;

	/* we return the data directly without making a copy so this can only be called once */
	size = info->data_size;
	if (size > get_reply_max_size())
		size = get_reply_max_size();
	set_reply_data_ptr(info->data, size);
	info->data = NULL;
	info->data_size = 0;
#endif
}

/* signal the end of the process initialization */
DECL_HANDLER(init_process_done)
{
	struct w32process *process = current_thread->process;
	set_process_startup_state(process, STARTUP_DONE);

	if (req->gui) {
		OBJECT_ATTRIBUTES attr;
		HANDLE handle;
		struct kevent *event;

		INIT_OBJECT_ATTR(&attr, NULL, 0, NULL, NULL);
		NtCreateEvent(&handle, 0, &attr, 1, 0);
		ref_object_by_handle(handle, EVENT_ALL_ACCESS, event_object_type, KernelMode, (PVOID *)&event, NULL);
		process->idle_event = event;
		NtClose(handle);
	}
}

/* retrieve the process idle event */
DECL_HANDLER(get_process_idle_event)
{
	struct w32process *process;

	ktrace("\n");
	reply->event = 0;
	if ((process = get_process_from_handle(req->handle, PROCESS_QUERY_INFORMATION))) {
		if (process->idle_event && process != current_thread->process)
			reply->event = alloc_handle(process, process->idle_event,
					EVENT_ALL_ACCESS, 0);
		release_object(process);
	}
}

/* make the current process a system process */
DECL_HANDLER(make_process_system)
{
	struct w32process *process = current_thread->process;
	OBJECT_ATTRIBUTES attr;
	WCHAR process_system[] = {'_','_','p','r','o','c','e','s','s','_','s','y','s','t','e','m',0};
	UNICODE_STRING name;
	NTSTATUS status;
	HANDLE handle = NULL;

	ktrace("\n");

	init_unistr(&name, (PWSTR)process_system);
	INIT_OBJECT_ATTR(&attr, &name, 0, base_dir_handle, NULL);
	status = NtCreateEvent(&handle, 0, &attr, 1, 0);
	if (status && status != STATUS_OBJECT_NAME_EXISTS)
		return;
	NtMakePermanentObject(handle);

	reply->event = handle;

	if (!process->is_system) {
		process->is_system = 1;
		ktrace("DECL_HANDLER(make_process_system) 1\n");
		close_process_desktop(process);
#if 0
		if (!--user_processes && !shutdown_stage && master_socket_timeout != TIMEOUT_INFINITE)
		    shutdown_timeout = add_timeout_user(master_socket_timeout, server_shutdown_timeout, NULL);
#endif
	}
}

/* notify the server that a dll has been loaded */
DECL_HANDLER(load_dll)
{
	return;
}

/* notify the server that a dll is being unloaded */
DECL_HANDLER(unload_dll)
{
	return;
}

struct security_descriptor *default_get_sd(struct object *obj)
{
	return NULL;
}

int default_set_sd(struct object *obj, const struct security_descriptor *sd, unsigned int set_info)
{
	return 0;
}
#endif /* CONFIG_UNIFIED_KERNEL */
