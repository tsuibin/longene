/*
 * thread.c
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
 * thread.c: thread implementation
 * Refered to ReactOS code
 */
#include "mutex.h"
#include "unistr.h"
#include "attach.h"
#include "semaphore.h"
#include "thread.h"
#include "wineserver/lib.h"

#ifdef CONFIG_UNIFIED_KERNEL

POBJECT_TYPE thread_object_type = NULL;
EXPORT_SYMBOL(thread_object_type);

struct list_head  thread_list = LIST_INIT(thread_list);

static void thread_close(struct ethread *);
static int  thread_signal(struct ethread *, int);
static void thread_exit(struct ethread *, int);
static void thread_execve(struct ethread *);
static void thread_fork(struct ethread *,
		struct task_struct *,
		struct task_struct *,
		unsigned long);

extern void do_exit_task(struct task_struct *tsk, long code);
extern long do_fork_from_task(struct task_struct *ptsk,
		unsigned long process_flags,
		unsigned long clone_flags,
		unsigned long stack_start,
		struct pt_regs *regs,
		unsigned long stack_size,
		int __user *parent_tidptr,
		int __user *child_tidptr);

extern asmlinkage void thread_startup(void);

extern unsigned long get_ntdll_entry(void);
extern unsigned long get_interp_entry(void);
extern unsigned long get_thread_entry(void);

extern void create_dummy_file(struct w32process *process);
extern void add_process_thread(struct w32process *process, struct w32thread *thread);

extern int ptrace_set_breakpoint_addr(struct task_struct *tsk, int nr, unsigned long addr);
extern int ptrace_write_dr7(struct task_struct *tsk, unsigned long data);

struct w32thread *get_thread_from_handle(obj_handle_t handle, unsigned int access);
struct w32thread *create_w32thread(struct w32process *process, struct ethread *ethread);

#define arch_init_thread        i386_init_thread
#define i386_init_thread(th, ctx)       do { } while (0)

static const struct ethread_operations ethread_ops = {
		name:           "ethread",
		owner:          THIS_MODULE,
		close:          thread_close,
		exit:           thread_exit,
		signal:         thread_signal,
		execve:         thread_execve,
		fork:           thread_fork
};

/* thread operations */
static int thread_signaled(struct object *obj, struct w32thread *thread);
static unsigned int thread_map_access(struct object *obj, unsigned int access);
extern void destroy_thread(struct object *obj);

static const struct object_ops thread_ops =
{
	sizeof(struct w32thread),   /* size */
	NULL,		                /* dump */
	NULL,                       /* get_type */
	no_get_fd,                  /* get_fd */
	thread_map_access,          /* map_access */
	no_lookup_name,             /* lookup_name */
	no_open_file,               /* open_file */
	no_close_handle,            /* close_handle */
	destroy_thread,             /* destroy */
	thread_signaled,            /* signaled */
	no_satisfied,               /* satisfied */
	no_signal,                  /* signal */
	default_get_sd,             /* get_sd */
	default_set_sd              /* set_sd */
};

static WCHAR w32thread_type_name[] = {'W', '3', '2', 'T', 'h', 'r', 'e', 'a', 'd', 0};

POBJECT_TYPE w32thread_object_type = NULL;
EXPORT_SYMBOL(w32thread_object_type);

static GENERIC_MAPPING w32thread_mapping =
{
	STANDARD_RIGHTS_READ | SYNCHRONIZE | 0x1 /* QUERY_STATE */,
	STANDARD_RIGHTS_WRITE | SYNCHRONIZE | 0x2 /* MODIFY_STATE */,
	STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE | 0x1 /* QUERY_STATE */,
	STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3
};

void __attribute__((regparm(3)))
set_trap_frame(unsigned long esp, struct task_struct *tsk)
{
	if (tsk->ethread)
		tsk->ethread->tcb.trap_frame = (struct ktrap_frame *)esp;
}

int set_tls_array(struct thread_struct *t, int idx, unsigned long addr, unsigned int limit)
{
	struct user_desc info;
	struct desc_struct *desc;

	if (idx < GDT_ENTRY_TLS_MIN || idx > GDT_ENTRY_TLS_MAX)
		return -EINVAL;

	desc = t->tls_array + idx - GDT_ENTRY_TLS_MIN;

	info.entry_number = idx;
	info.base_addr = addr;
	info.limit = limit;
	info.contents = 0;
	info.read_exec_only = 0;
	info.seg_not_present = 0;
	info.seg_32bit = 1;
	info.limit_in_pages = 1;
	info.useable = 0;

/* FIXME */
	fill_ldt(desc, &info);
#if 0
	desc->a = LDT_entry_a(&info);
	desc->b = LDT_entry_b(&info);
#endif

	return 0;
}

/* copy a context structure according to the flags */
void copy_context(CONTEXT *to, const CONTEXT *from, unsigned int flags)
{
    flags &= ~CONTEXT_i386;  /* get rid of CPU id */
    if (flags & CONTEXT_CONTROL) {
        to->Ebp    = from->Ebp;
        to->Eip    = from->Eip;
        to->Esp    = from->Esp;
        to->SegCs  = from->SegCs;
        to->SegSs  = from->SegSs;
        to->EFlags = from->EFlags;
    }
    if (flags & CONTEXT_INTEGER) {
        to->Eax = from->Eax;
        to->Ebx = from->Ebx;
        to->Ecx = from->Ecx;
        to->Edx = from->Edx;
        to->Esi = from->Esi;
        to->Edi = from->Edi;
    }
    if (flags & CONTEXT_SEGMENTS) {
        to->SegDs = from->SegDs;
        to->SegEs = from->SegEs;
        to->SegFs = from->SegFs;
        to->SegGs = from->SegGs;
    }
    if (flags & CONTEXT_FLOATING_POINT) {
        to->FloatSave = from->FloatSave;
    }
    if (flags & CONTEXT_EXTENDED_REGISTERS) {
        memcpy(to->ExtendedRegisters, from->ExtendedRegisters, sizeof(to->ExtendedRegisters));
    }
    if (flags & CONTEXT_DEBUG_REGISTERS) {
        to->Dr0 = from->Dr0;
        to->Dr1 = from->Dr1;
        to->Dr2 = from->Dr2;
        to->Dr3 = from->Dr3;
        to->Dr6 = from->Dr6;
        to->Dr7 = from->Dr7;
    }
    to->ContextFlags |= flags;
}

void set_thread_context(struct w32thread *thread, const CONTEXT *context, unsigned int flags)
{
}

void get_thread_context(struct w32thread *thread, CONTEXT *context, unsigned int flags)
{
}

/*
 * thread object destructor
 */     
static void thread_close(struct ethread *thread)
{       
	struct eprocess *process;

	process = thread->threads_process;
	thread->threads_process = NULL;

	/* detach the thread record from the Linux task */
	ktrace("obj %p\n", thread);
	thread->et_task = NULL;
	thread->tcb.state = Terminated;

	deref_object((PVOID)thread);

	/* detach from the containing process */
	deref_object(process);
} /* end thread_close() */

void rundown_thread(void)
{
	struct kthread * thread = (struct kthread *) get_current_ethread();
	struct kmutant * mutant;
	struct list_head * cur_entry;

	ktrace("\n");

	local_irq_disable();
	while (!list_empty(&thread->mutant_list_head)) {
		/* Get the Mutant */
		cur_entry = thread->mutant_list_head.next;
		mutant = list_entry(cur_entry, struct kmutant, mutant_list_entry);

		/* check apc disable */

		mutant->header.signal_state = 1;
		mutant->abandoned = 1;
		mutant->owner_thread = NULL;
		list_del(&mutant->mutant_list_entry);

		if(!list_empty(&mutant->header.wait_list_head)) {
			wait_test(&mutant->header, MUTANT_INCREMENT);
		}
	}
	local_irq_enable();
}

/*
 * notification of exit
 * - the exit_status is as sys_wait() would return
 * - notification includes fatal signals
 */
static void thread_exit(struct ethread *thread, int exit_status)
{
	struct eprocess	*process = thread->threads_process;
	BOOLEAN last;

	/* if Terminated, do nothing */
	ktrace("thread %p, exit_status %ld\n", thread, thread->exit_status);

	thread->terminated = 1;

	/* Can't terminate a thread if it attached another process */
	if (thread->tcb.apc_state_index) {
		return;
	}

	/* TODO: Lower to Passive Level */
	
	/* Lock the Process before we modify its thread entries */
	lock_process(process);

	list_del(&thread->thread_list_entry);

	/* TODO: close port */
	
	/* TODO: Rundown Win32 Structures */

    	/* Set the last Thread Exit Status */
	process->last_thread_exit_status = thread->exit_status;
	
	/* The last Thread shuts down the Process */
	if ((last = list_empty(&process->thread_list_head))) {
		/* Save the Exit Time if not already done by NtTerminateProcess. This 
		   happens when the last thread just terminates without explicitly 
		   terminating the process. TODO */
#if 0
		process->exit_time = thread->exit_time;
#endif
		__exit_process(process);
	}

#if 0
	if (thread->tcb.win32thread) {
		kfree(thread->tcb.win32thread);
		thread->tcb.win32thread = NULL;
	}
#endif

	/* Free the TEB, if last thread, teb is freed by exit() */
	if (thread->tcb.teb && !last) {
		delete_teb(thread->tcb.teb);
		thread->tcb.teb = NULL;
	}

	list_del(&thread->tcb.thread_list_entry);

	/* Unlock the Process */		
	unlock_process(process);

	/* Rundown Mutexes */
	rundown_thread();

	/* Satisfy waits */
	local_irq_disable();
	thread->tcb.header.signal_state = true;
	if (!list_empty(&thread->tcb.header.wait_list_head))
		wait_test((struct dispatcher_header *)&thread->tcb, IO_NO_INCREMENT);
	local_irq_enable();
} /* end thread_exit() */

/*
 * notification of signal
 */
static int thread_signal(struct ethread *thread, int signal)
{
	return WIN32_THREAD_SIGNAL_OKAY;
} /* end thread_signal() */

/*
 * notification of execve
 * - if this is NULL, a thread object will be destroyed on execve
 */
static void thread_execve(struct ethread *thread)
{       
	/* TODO */
} /* end thread_execve() */

/*
 * notification that fork/clone has set up the new process and
 * is just about to dispatch it
 * - no threads will have been copied by default
 */
static void thread_fork(struct ethread *thread,
		struct task_struct *parent,
		struct task_struct *child,
		unsigned long clone_flags)
{       
	/* TODO */
} /* end thread_fork() */

VOID delete_thread(PVOID Object)
{
	struct ethread * thread = Object;

	ktrace("obj %p\n", Object);

	if (thread->cid.unique_thread)
		delete_cid_handle(thread->cid.unique_thread, thread_object_type);

	/* TODO: release stack mem */
}

/* FIXME */
int poll_thread(struct wait_table_entry *wte)
{
	struct ethread * thread = (struct ethread *)wte->wte_obj;
	int ret;

	ret = (thread->tcb.state == Running) ? POLL_NOTSIG : POLL_SIG;

	return ret;
}

/*      
 * set teb on fs
 */     
int set_teb_selector(struct task_struct *tsk, long teb)
{
	int	cpu;

	set_tls_array(&tsk->thread, TEB_SELECTOR >> 3, teb, 1);
	cpu = get_cpu();
	load_TLS(&tsk->thread, cpu);
	put_cpu();

	return 0;
} /* end set_teb_selector */

/* initialize kthread */
void kthread_init(struct kthread *thread, struct eprocess *process)
{
	ktrace("\n");

	INIT_DISP_HEADER(&thread->header, ThreadObject, sizeof(struct ethread), false);

	/* initialize the mutant list */
	INIT_LIST_HEAD(&thread->mutant_list_head);

	/* setup apc fields */
	INIT_LIST_HEAD(&thread->apc_state.apc_list_head[0]);
	INIT_LIST_HEAD(&thread->apc_state.apc_list_head[1]);
	INIT_LIST_HEAD(&thread->saved_apc_state.apc_list_head[0]);
	INIT_LIST_HEAD(&thread->saved_apc_state.apc_list_head[1]);
	thread->apc_state.process = (struct kprocess *)process;
	thread->apc_state_pointer[OriginalApcEnvironment] = &thread->apc_state;
	thread->apc_state_pointer[AttachedApcEnvironment] = &thread->saved_apc_state;
	thread->apc_state_index = OriginalApcEnvironment;
	thread->apc_queue_lock = SPIN_LOCK_UNLOCKED;
	thread->apc_queueable = true;

	/*NOW FIXME Initialize the Suspend APC */
	apc_init(&thread->suspend_apc, 
			thread, 
			OriginalApcEnvironment, 
			suspend_thread_kernel_routine, 
			NULL, 
			suspend_thread_normal_routine, 
			KernelMode, 
			NULL);


	/* Initialize the Suspend Semaphore */
	semaphore_init(&thread->suspend_semaphore, 0, 128);

	/* initialize the suspend semaphore */
	/* FIXME: sema_init(&thread->suspend_semaphore, 0); */
	/* FIXME: keinitializetimer(&thread->timer); */

	arch_init_thread(thread, context);

	thread->base_priority = process->pcb.base_priority;
	thread->quantum = process->pcb.quantum_reset;
	thread->quantum_reset = process->pcb.quantum_reset;
	thread->affinity = process->pcb.affinity;
	thread->priority = process->pcb.base_priority;
	thread->user_affinity = process->pcb.affinity;
	thread->disable_boost = process->pcb.disable_boost;
	thread->auto_alignment = process->pcb.auto_alignment;

	/* set the thread to initalized */
	thread->state = Initialized;

	lock_process(process);
	list_add_tail(&thread->thread_list_entry, &process->pcb.thread_list_head);
	unlock_process(process);
	if (!thread->win32thread)
		thread->win32thread = create_w32thread(process->win32process, (struct ethread *)thread);
} /* end kthread_init */

/* initialize ethread */
void ethread_init(struct ethread *thread, struct eprocess *process, struct task_struct *tsk)
{
	ktrace("\n");

	/* attach to the containing process */
	ref_object((PVOID)process);
	write_lock(&process->ep_lock);
	thread->threads_process = process;
	write_unlock(&process->ep_lock);

	/* FIXME create a thread object and hook in to the Linux task */
	thread->et_task = tsk;

	atomic_set(&thread->et_count, 0);

	/* FIXME */
	thread->et_ops = (struct ethread_operations *)&ethread_ops;

	INIT_LIST_HEAD(&thread->lpc_reply_chain);
	INIT_LIST_HEAD(&thread->irp_list);
	INIT_LIST_HEAD(&thread->active_timer_list_head);
	thread->active_timer_list_lock = SPIN_LOCK_UNLOCKED;
	thread->thread_lock = SPIN_LOCK_UNLOCKED;

	/* FIXME: semaphore_init */

	thread->cid.unique_process = process->unique_processid;

	thread->win32_start_address = 0;        /* context->Eax, default is 0 */
	lock_process(process);
	list_add_tail(&thread->thread_list_entry, &process->thread_list_head);
	unlock_process(process);

	add_ethread(thread->et_task, thread);
	if (atomic_read(&thread->et_count) == 1)	/* FIXME: add this to win32_thread.c */
		ref_object(thread);

	kthread_init(&thread->tcb, process);
} /* end ethread_init */

/*
 * user_thread_startup
 * prepare for jumping to userspace to execute after new thread waken
 */
VOID
STDCALL
user_thread_startup(PKSTART_ROUTINE StartRoutine,
		PVOID StartContext)
{
	struct ethread  *thread;
	PKAPC   thread_apc;
	void * start_stack;

	ktrace("pid %x, tgid %x\n",current->pid, current->tgid);

	if (!(thread = get_current_ethread())) {
		return;
	}

	/* create dummy file */
	create_dummy_file(thread->threads_process->win32process);

	if (!(thread_apc = kmalloc(sizeof(struct kapc),GFP_KERNEL))) {
		return;
	}

	start_stack = (void *)thread->tcb.stack_base; /* user stack base */

	if (thread->threads_process->fork_in_progress) {
		apc_init(thread_apc,
				&thread->tcb,
				OriginalApcEnvironment,
				thread_special_apc,
				NULL,
				(PKNORMAL_ROUTINE)get_ntdll_entry(),
				UserMode,
				start_stack);
		insert_queue_apc(thread_apc, 
				(void *)get_interp_entry(), 
				thread->threads_process->spare0[0], 
				IO_NO_INCREMENT);

		thread->threads_process->fork_in_progress = NULL;
	} else {
		apc_init(thread_apc,
				&thread->tcb,
				OriginalApcEnvironment,
				thread_special_apc,
				NULL,
				(PKNORMAL_ROUTINE)get_thread_entry(),
				UserMode,
				start_stack);
		insert_queue_apc(thread_apc, NULL,NULL, IO_NO_INCREMENT);
	}
	thread->tcb.apc_state.uapc_pending = 1;
	set_tsk_thread_flag(current, TIF_APC);

	try_module_get(THIS_MODULE);

	return;
} /* end user_thread_startup */

/*
 * init_thread_with_context
 * init context for thread
 */
VOID
STDCALL
init_thread_with_context(struct kthread* Thread,
		PKSYSTEM_ROUTINE SystemRoutine,
		PKSTART_ROUTINE StartRoutine, /* FIXME */
		PVOID StartContext,           /* FIXME */
		PCONTEXT Context)
{
	struct thread_info *info;
	struct task_struct *p;
	unsigned long * trapframe;
	struct pt_regs * regs;
	PCONTEXT context;

	if (!(context = kmalloc(sizeof(*context),GFP_KERNEL))) {
		return;
	}

	if (copy_from_user(context, Context, sizeof(*context))) {
		kfree(context);
		return;
	}

	info = (struct thread_info *)((unsigned long)Thread->kernel_stack- THREAD_SIZE);
	p = info->task;
	set_tls_array(&p->thread, TEB_SELECTOR >> 3, (unsigned long)Thread->teb, 1);

	/* set for switch */
	trapframe = (unsigned long *)((unsigned long)Thread->kernel_stack - 8 - sizeof(struct pt_regs) - 12);
	regs = (struct pt_regs *)(trapframe + 3);

	Thread->trap_frame = (struct ktrap_frame *)regs;
	
	trapframe[0] = (unsigned long)SystemRoutine;
	trapframe[1] = (unsigned long)StartRoutine;
	trapframe[2] = (unsigned long)StartContext;

	p->thread.ip = (unsigned long)thread_startup;
	p->thread.sp = (unsigned long)trapframe;
	p->thread.sp0 = (unsigned long)(regs + 1);
#if 0
	/* FIXME: 'struct thread_struct' has no member named 'fs' in linux-2.6.34 */
	p->thread.fs = TEB_SELECTOR;
#endif 

	/* set for userspace */
	regs->sp = context->Esp;
	regs->ip = context->Eip;

	kfree(context);
	return;
} /* end init_thread_with_context */

/*
 * initialize_thread
 * initialize kthread
 */
VOID
STDCALL
initialize_thread(struct kprocess* Process,
		struct kthread* Thread,
		PKSYSTEM_ROUTINE SystemRoutine,
		PKSTART_ROUTINE StartRoutine,  /* FIXME */
		PVOID StartContext,            /* FIXME */
		PCONTEXT Context,
		PVOID Teb,
		PVOID KernelStack)
{
	ktrace("kprocess %p, kthread %p, systemroutine %p, context %p, teb %p, kernelstack %p\n", 
			Process, Thread, SystemRoutine, Context, Teb, KernelStack);

	/* Set the TEB */
	Thread->teb = Teb;

	/* Allocate Stack use linux task stack and init
	 * Set the Thread Stacks
	 */
	Thread->kernel_stack = (PCHAR)KernelStack + THREAD_SIZE;

	/* FIXME
	 * Establish the pde's for the new stack and the thread structure within the
	 * address space of the new process. They are accessed while taskswitching or
	 * while handling page faults. At this point it isn't possible to call the
	 * page fault handler for the missing pde's.
	 */
	update_page_dir(((struct ethread *)Thread)->et_task->mm, (void *)Thread->stack_limit, THREAD_SIZE);
	update_page_dir(((struct ethread *)Thread)->et_task->mm, Thread, sizeof(struct ethread));

	init_thread_with_context(Thread,
			SystemRoutine,
			StartRoutine,
			StartContext,
			Context);
} /* end initialize_thread */

NTSTATUS
STDCALL
create_thread(OUT PHANDLE ThreadHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes  OPTIONAL,
		IN HANDLE ProcessHandle,
		IN struct eprocess* TargetProcess,   			/* FIXME */
		OUT PCLIENT_ID ClientId,
		IN PCONTEXT ThreadContext,
		IN PINITIAL_TEB InitialTeb,
		IN BOOLEAN CreateSuspended,
		IN PKSTART_ROUTINE StartRoutine OPTIONAL,   	/* FIXME */
		IN PVOID StartContext OPTIONAL)            	/* FIXME */
{
	struct eprocess * process;
	struct ethread * thread, *first_thread, *cur_thread;
	struct task_struct *new_tsk = NULL;
	unsigned clone_flags = 0;
	PTEB teb_base;
	long   cpid;
	HANDLE hthread;
	NTSTATUS status = STATUS_SUCCESS;

	ktrace("\n");

	if (!(cur_thread = get_current_ethread())) {
		return STATUS_INVALID_PARAMETER;
	}

	/* current still be regarded */
	if (ProcessHandle && ProcessHandle != NtCurrentProcess()) {
		status = ref_object_by_handle(ProcessHandle,
				PROCESS_ALL_ACCESS,
				process_object_type,
				KernelMode,
				(PVOID *)&process,
				NULL);
		if (!NT_SUCCESS(status))
			return status;
	} else {
		if (TargetProcess)
			process = (struct eprocess *)TargetProcess;
		else
			process = cur_thread->threads_process;
		ref_object(process);
	}

	if (!process->fork_in_progress) {
		/* second and after */
		if (!ProcessHandle || ProcessHandle == NtCurrentProcess())
			first_thread = cur_thread;
		else
			first_thread = get_first_thread(process);
		if (!first_thread) {
			status = STATUS_INVALID_PARAMETER;
			goto cleanup_process;
		}
		
		clone_flags = SIGCHLD | CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_PARENT | CLONE_THREAD;

		cpid = do_fork_from_task(first_thread->et_task, CREATE_THREAD, clone_flags,
				first_thread->tcb.trap_frame->esp, (struct pt_regs *)first_thread->tcb.trap_frame,
			       	0, NULL, NULL);
		if (cpid < 0) {
			status = STATUS_INVALID_PARAMETER;
			goto cleanup_process;
		}

		new_tsk = find_task_by_vpid(cpid);
		
		memset(&new_tsk->thread.tls_array, 0, sizeof(new_tsk->thread.tls_array));
		set_tls_array(&new_tsk->thread, first_thread->et_task->thread.gs >> 3, 
				(unsigned long)InitialTeb->StackBase + 0x800, 0xfffff);

		/* allocate a Win32 thread object */
		status = create_object(KernelMode,
				thread_object_type,
				ObjectAttributes,
				KernelMode,
				NULL,
				sizeof(struct ethread),
				0,
				0,
				(PVOID *)&thread);
		if (!NT_SUCCESS(status))
			goto cleanup_tsk;

		ethread_init(thread, process, new_tsk);
		deref_object(thread);

	} else {
		/* for first thread */
		thread = process->fork_in_progress;
		new_tsk = thread->et_task;
	}

	thread->cid.unique_thread = create_cid_handle(thread, thread_object_type);
	thread->cid.unique_process = process->unique_processid;
	if (!thread->cid.unique_thread) {
		goto cleanup_tsk;
	}

	if (ClientId) {
		if (copy_to_user(&ClientId->UniqueThread, &thread->cid.unique_thread, sizeof(HANDLE)))
			goto cleanup_tsk;
		if (copy_to_user(&ClientId->UniqueProcess, &thread->cid.unique_process, sizeof(HANDLE)))
			goto cleanup_tsk;
	}

	/* set user stack base */
	thread->tcb.stack_base = InitialTeb->StackBase;

	if (ThreadContext) {
		/* Create Teb */
		teb_base = create_teb(process, (PCLIENT_ID)&thread->cid, InitialTeb);

		/* Set the Start Addresses */
		thread->start_address = (PVOID)ThreadContext->Eip;
		thread->win32_start_address = (PVOID)ThreadContext->Eax; /*FIXME */

		/* intialize kthread */
		initialize_thread(&process->pcb,
				&thread->tcb,
				user_thread_startup,
				NULL,
				NULL,
				ThreadContext,
				teb_base,
				task_thread_info(new_tsk));
	} else {
		/* FIXME PsCreateSystemThread */
	}

	/* Insert Thread into Handle Table */
	status = insert_object(thread,
			NULL,
			DesiredAccess,
			0,
			NULL,
			&hthread);
	if (!NT_SUCCESS(status))
		goto cleanup_tsk;

	if (copy_to_user(ThreadHandle, &hthread, sizeof(hthread))) {
		status = STATUS_UNSUCCESSFUL;
		goto cleanup_thread;
	}

	clear_tsk_need_resched(new_tsk);
	sched_fork(new_tsk, clone_flags);
	wake_up_new_task(new_tsk, CLONE_VM | CLONE_FS | CLONE_FILES| CLONE_SIGHAND);

	/* FIXME Notify Thread Creation */

	/* NOW FIXME Suspend the Thread if we have to */
	if (CreateSuspended)
		suspend_thread(&thread->tcb);

	/* FIXME: SECURITY */

	/* FIXME Dispatch thread */
	status = STATUS_SUCCESS;
	goto cleanup_process;

cleanup_thread:
	deref_object(thread);

cleanup_tsk:
	if (new_tsk)
		do_exit_task(new_tsk,0);

cleanup_process:
	deref_object(process);

	return status;
} /* end create_thread */

/*
 * NtCreateThread
 */
NTSTATUS 
SERVICECALL
NtCreateThread(OUT PHANDLE              ThreadHandle,
		IN  ACCESS_MASK          DesiredAccess,
		IN  POBJECT_ATTRIBUTES   ObjectAttributes  OPTIONAL,
		IN  HANDLE               ProcessHandle,
		OUT PCLIENT_ID           ClientId,
		IN  PCONTEXT             ThreadContext,
		IN  PINITIAL_TEB         InitialTeb,
		IN  BOOLEAN              CreateSuspended)
{
	PINITIAL_TEB safe_initial_teb;
	NTSTATUS	status;

	ktrace("\n");

	if (!(safe_initial_teb = kmalloc(sizeof(INITIAL_TEB), GFP_KERNEL))) {
		return STATUS_NO_MEMORY;
	}

	status = STATUS_UNSUCCESSFUL;
	if (copy_from_user(safe_initial_teb, InitialTeb, sizeof(INITIAL_TEB)))
		goto out;

	/* Call the shared function */
	status = create_thread(ThreadHandle,
			DesiredAccess,
			ObjectAttributes,
			ProcessHandle,
			NULL,
			ClientId,
			ThreadContext,
			safe_initial_teb,
			CreateSuspended,
			NULL,
			NULL);
	ktrace("done, handle=%p\n", *ThreadHandle);

out:
	kfree(safe_initial_teb);	
	return status;
} /* end NtCreateThread */
EXPORT_SYMBOL(NtCreateThread);

NTSTATUS
SERVICECALL
NtOpenThread(OUT PHANDLE ThreadHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes  OPTIONAL,
		IN PCLIENT_ID ClientId  OPTIONAL)
{
	KPROCESSOR_MODE pre_mode = (KPROCESSOR_MODE)get_pre_mode();
	struct ethread *thread = NULL;
	NTSTATUS status = STATUS_INVALID_PARAMETER;

	ktrace("\n");
	if (ObjectAttributes->ObjectName) {
		return open_object_by_name(ObjectAttributes, 
				thread_object_type, 
				NULL, 
				pre_mode, 
				DesiredAccess, 
				NULL, 
				ThreadHandle);
	} else if (ClientId && ClientId->UniqueThread) {
		if ((status = lookup_thread_by_tid(ClientId->UniqueThread, &thread)))
			return status;

		status = open_object_by_pointer(thread, 
				ObjectAttributes->Attributes, 
				NULL, 
				DesiredAccess, 
				thread_object_type, 
				pre_mode,
				ThreadHandle);

		deref_object(thread);
	}

	return status;
}
EXPORT_SYMBOL(NtOpenThread);

void trapframe_to_context(struct ethread * thread, PCONTEXT context)
{
	struct pt_regs * trap_frame =  (struct pt_regs *)thread->tcb.trap_frame; 

	if ((context->ContextFlags & CONTEXT_CONTROL) == CONTEXT_CONTROL) {
		context->Esp = trap_frame->sp;
		context->SegSs = trap_frame->ss;
		context->SegCs = trap_frame->cs;
		context->Eip = trap_frame->ip;
		context->EFlags = trap_frame->flags;
		context->Ebp = trap_frame->bp;
	} 


	if ((context->ContextFlags & CONTEXT_INTEGER) == CONTEXT_INTEGER) {
		context->Eax = trap_frame->ax;
		context->Ebx = trap_frame->bx;
		context->Ecx = trap_frame->cx;
		context->Edx = trap_frame->dx;
		context->Esi = trap_frame->si;
		context->Edi = trap_frame->di;
	}

	if ((context->ContextFlags & CONTEXT_SEGMENTS) == CONTEXT_SEGMENTS) {
		context->SegDs = trap_frame->ds;
		context->SegEs = trap_frame->es;
		context->SegFs = trap_frame->fs; /* FIXME */
		context->SegGs = thread->et_task->thread.gs;
	}

	if ((context->ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS) {
		/* FIXME:  'struct thread_struct' has no member named 'debugreg[0-3]' in linux-2.6.34*/
		context->Dr0 = thread->et_task->thread.ptrace_bps[0]->hw.info.address;
		context->Dr1 = thread->et_task->thread.ptrace_bps[1]->hw.info.address;
		context->Dr2 = thread->et_task->thread.ptrace_bps[2]->hw.info.address;
		context->Dr3 = thread->et_task->thread.ptrace_bps[3]->hw.info.address;
		context->Dr6 = thread->et_task->thread.debugreg6;
		context->Dr7 = thread->et_task->thread.ptrace_dr7;
	}
}

void context_to_trapframe(PCONTEXT context , struct ethread * thread)
{
	struct pt_regs * trap_frame =  (struct pt_regs *)thread->tcb.trap_frame; 

	if ((context->ContextFlags & CONTEXT_CONTROL) == CONTEXT_CONTROL) {
		trap_frame->sp = context->Esp;
		trap_frame->ss = context->SegSs;
		trap_frame->cs = context->SegCs;
		trap_frame->ip = context->Eip;
		trap_frame->flags = context->EFlags;
		trap_frame->bp = context->Ebp;
	} 

	if ((context->ContextFlags & CONTEXT_INTEGER) == CONTEXT_INTEGER) {
		trap_frame->ax = context->Eax;
		trap_frame->bx = context->Ebx;
		trap_frame->cx = context->Ecx;
		trap_frame->dx = context->Edx;
		trap_frame->si = context->Esi;
		trap_frame->di = context->Edi;
	}

	if ((context->ContextFlags & CONTEXT_SEGMENTS) == CONTEXT_SEGMENTS) {
		trap_frame->ds = context->SegDs;
		trap_frame->es = context->SegEs;
		trap_frame->fs = context->SegFs; /* FIXME */
		thread->et_task->thread.gs = context->SegGs;
	}	

	if ((context->ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS) {
		/* FIXME:  'struct thread_struct' has no member named 'debugreg[0-3]' in linux-2.6.34*/
		ptrace_set_breakpoint_addr(thread->et_task, 0, context->Dr0);
		ptrace_set_breakpoint_addr(thread->et_task, 1, context->Dr1);
		ptrace_set_breakpoint_addr(thread->et_task, 2, context->Dr2);
		ptrace_set_breakpoint_addr(thread->et_task, 3, context->Dr3);
		thread->et_task->thread.debugreg6 = context->Dr6;
		ptrace_write_dr7(thread->et_task, context->Dr7);
	}

	/* TODO: float register */
}

VOID
STDCALL
get_set_kernel_context_routine(PKAPC Apc,
			PKNORMAL_ROUTINE* NormalRoutine,
			PVOID* NormalContext,
			PVOID* SystemArgument1,
			PVOID* SystemArgument2)
{
	PGET_SET_CTX_CONTEXT get_set_context;
	struct kevent * event;
	PCONTEXT context;

	get_set_context = (PGET_SET_CTX_CONTEXT) Apc;
	event = &get_set_context->event;
	context = &get_set_context->context;

	if (*SystemArgument1)
		trapframe_to_context(get_current_ethread(), context);
	else
		context_to_trapframe(context, get_current_ethread());

	set_event(event, EVENT_INCREMENT, FALSE);
	suspend_thread(&current->ethread->tcb);
}

NTSTATUS SERVICECALL
NtGetContextThread(IN  HANDLE   ThreadHandle,
                   OUT PCONTEXT ThreadContext)
{
	struct ethread * thread;
	GET_SET_CTX_CONTEXT	ctx_context;
	NTSTATUS status = STATUS_SUCCESS;

	ktrace("%p, %p\n",ThreadHandle, ThreadContext);

	status = ref_object_by_handle(ThreadHandle,
			THREAD_ALL_ACCESS,
			thread_object_type,
			KernelMode,
			(PVOID *)&thread,
			NULL);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	if (thread == get_current_ethread()) {
		trapframe_to_context(thread, &ctx_context.context);
	} else {
		event_init(&ctx_context.event, notification_event, 0);

		apc_init(&ctx_context.apc, 
				&thread->tcb, 
				OriginalApcEnvironment, 
				get_set_kernel_context_routine, 
				NULL, 
				NULL, 
				KernelMode, 
				NULL);
		insert_queue_apc(&ctx_context.apc, (PVOID)1, NULL, IO_NO_INCREMENT);

		resume_thread(&thread->tcb);
		status = wait_for_single_object(&ctx_context.event,
				0,
				KernelMode,
				FALSE,
				NULL);
	}
	deref_object(thread);

	if (copy_to_user(ThreadContext, &ctx_context.context, sizeof(CONTEXT)))
		status = STATUS_UNSUCCESSFUL;

	ktrace("return %x\n", status);
	return status;
}
EXPORT_SYMBOL(NtGetContextThread);

NTSTATUS SERVICECALL
NtSetContextThread(IN HANDLE   ThreadHandle,
		IN PCONTEXT ThreadContext)
{
	struct ethread * thread;
	GET_SET_CTX_CONTEXT	ctx_context;
	NTSTATUS status = STATUS_SUCCESS;

	ktrace("%p, %p\n",ThreadHandle, ThreadContext);

	if (copy_from_user(&ctx_context.context, ThreadContext, sizeof(CONTEXT)))
		return STATUS_UNSUCCESSFUL;

	status = ref_object_by_handle(ThreadHandle,
			THREAD_ALL_ACCESS,
			thread_object_type,
			KernelMode,
			(PVOID *)&thread,
			NULL);
	if (!NT_SUCCESS(status)) {
		return status;
	}


	if (thread == get_current_ethread()) {
		context_to_trapframe(&ctx_context.context, thread);
	} else {
		event_init(&ctx_context.event, notification_event, 0);

		apc_init(&ctx_context.apc, 
				&thread->tcb, 
				OriginalApcEnvironment, 
				get_set_kernel_context_routine, 
				NULL, 
				NULL, 
				KernelMode, 
				NULL);
		insert_queue_apc(&ctx_context.apc, (PVOID)0, NULL, IO_NO_INCREMENT);

		resume_thread(&thread->tcb);
		wait_for_single_object(&ctx_context.event,
				0,
				KernelMode,
				FALSE,
				NULL);
	}

	deref_object(thread);

	ktrace("return %x\n", status);
	return status;
}
EXPORT_SYMBOL(NtSetContextThread);

VOID
init_w32thread_implement(VOID)
{
	OBJECT_TYPE_INITIALIZER ObjectTypeInitializer;
	UNICODE_STRING Name;

	memset(&ObjectTypeInitializer, 0, sizeof(ObjectTypeInitializer));
	init_unistr(&Name, w32thread_type_name);
	ObjectTypeInitializer.Length = sizeof(ObjectTypeInitializer);
	ObjectTypeInitializer.DefaultNonPagedPoolCharge = sizeof(struct w32thread);
	ObjectTypeInitializer.GenericMapping = w32thread_mapping;
	ObjectTypeInitializer.PoolType = NonPagedPool;
	ObjectTypeInitializer.ValidAccessMask = EVENT_ALL_ACCESS;
	ObjectTypeInitializer.UseDefaultObject = TRUE;
	create_type_object(&ObjectTypeInitializer, &Name, &w32thread_object_type);
}

/* initialize the structure for a newly allocated thread */
static inline void init_thread_structure(struct w32thread *thread)
{
	thread->state           = RUNNING;
	thread->affinity        = ~0;
}

/* create a new thread */
struct w32thread *create_w32thread(struct w32process *process, struct ethread *ethread)
{
	struct w32thread *thread;

	ktrace("\n");
	if (!(thread = alloc_wine_object(&thread_ops))) return NULL;
	INIT_DISP_HEADER(&thread->obj.header, THREAD, sizeof(struct w32thread), 0);

	init_thread_structure(thread);

	thread->process = (struct w32process *)grab_object(process);
	thread->desktop = process->desktop;
	thread->ethread = ethread;

	list_add_before(&thread_list, &thread->entry);
	add_process_thread(thread->process, thread);
	return thread;
}

static int thread_signaled(struct object *obj, struct w32thread *thread)
{
	struct w32thread *mythread = (struct w32thread *)obj;
	return (mythread->state == TERMINATED);
}

static unsigned int thread_map_access(struct object *obj, unsigned int access)
{
	if (access & GENERIC_READ)
		access |= STANDARD_RIGHTS_READ | SYNCHRONIZE;
	if (access & GENERIC_WRITE)
		access |= STANDARD_RIGHTS_WRITE | SYNCHRONIZE;
	if (access & GENERIC_EXECUTE)
		access |= STANDARD_RIGHTS_EXECUTE;
	if (access & GENERIC_ALL)
		access |= THREAD_ALL_ACCESS;
	return access & ~(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);
}

/* queue an async procedure call */
int thread_queue_apc(struct w32thread *thread, struct object *owner, const apc_call_t *call_data)
{
	ktrace("WHA!! please use NtQueueApcThread\n");
	return 0;
}

void thread_cancel_apc(struct w32thread *thread, struct object *owner, enum apc_type type)
{
	ktrace("WHA!! please use function in ke/apc.c\n");
	return;
}

/* gets the current impersonation token */
struct token *thread_get_impersonation_token(struct w32thread *thread)
{
	if (thread->token)
		return thread->token;
	else
		return thread->process->token;
}

DECL_HANDLER(new_thread)
{
	struct ethread *thread = get_current_ethread();

	if (thread->suspend_on_create){
		suspend_thread(&thread->tcb);
		set_tsk_thread_flag(thread->et_task, TIF_APC);
	}

	return;
}

/* initialize a new thread */
DECL_HANDLER(init_thread)
{
	reply->info_size  = init_process(current_thread);
	reply->version = SERVER_PROTOCOL_VERSION;
	return;
}

/* queue an APC for a thread or process */
DECL_HANDLER(queue_apc)
{
	return;
}

/* Get the result of an APC call */
DECL_HANDLER(get_apc_result)
{
	return;
}

/* retrieve the current context of a thread */
DECL_HANDLER(get_thread_context)
{
	struct w32thread *thread;
	CONTEXT *context;

	ktrace("\n");
	if (get_reply_max_size() < sizeof(CONTEXT)) {
		set_error(STATUS_INVALID_PARAMETER);
		return;
	}
	if (!(thread = get_thread_from_handle(req->handle, THREAD_GET_CONTEXT)))
		return;

	if (req->suspend) {
		if (thread != current_thread || !thread->suspend_context) {
			/* not suspended, shouldn't happen */
			set_error(STATUS_INVALID_PARAMETER);
		}
		else {
			if (thread->context == thread->suspend_context)
				thread->context = NULL;
			set_reply_data_ptr(thread->suspend_context, sizeof(CONTEXT));
			thread->suspend_context = NULL;
		}
	}
	else if (thread != current_thread && !thread->context) {
		/* thread is not suspended, retry (if it's still running) */
		if (thread->state != RUNNING)
			set_error(STATUS_ACCESS_DENIED);
		else 
			set_error(STATUS_PENDING);
	}
	else if ((context = set_reply_data_size(sizeof(CONTEXT)))) {
		unsigned int flags = get_context_system_regs(req->flags);

		memset(context, 0, sizeof(CONTEXT));
		context->ContextFlags = get_context_cpu_flag();
		if (thread->context)
			copy_context(context, thread->context, req->flags & ~flags);
		if (flags)
			get_thread_context(thread, context, flags);
	}
	reply->self = (thread == current_thread);
	release_object(thread);
}

/* set the current context of a thread */
DECL_HANDLER(set_thread_context)
{
	struct w32thread *thread;

	ktrace("\n");
	if (get_req_data_size() < sizeof(CONTEXT)) {
		set_error(STATUS_INVALID_PARAMETER);
		return;
	}
	if (!(thread = get_thread_from_handle(req->handle, THREAD_SET_CONTEXT)))
		return;

	if (req->suspend) {
		if (thread != current_thread || thread->context) {
			/* nested suspend or exception, shouldn't happen */
			set_error(STATUS_INVALID_PARAMETER);
		}
		else if ((thread->suspend_context = mem_alloc(sizeof(CONTEXT)))) {
			memcpy(thread->suspend_context, get_req_data(), sizeof(CONTEXT));
			thread->context = thread->suspend_context;
		}
	}
	else if (thread != current_thread && !thread->context) {
		/* thread is not suspended, retry (if it's still running) */
		if (thread->state != RUNNING)
			set_error(STATUS_ACCESS_DENIED);
		else
			set_error(STATUS_PENDING);
	}
	else {
		const CONTEXT *context = get_req_data();
		unsigned int flags = get_context_system_regs(req->flags);

		if (flags)
			set_thread_context(thread, context, flags);
		if (thread->context && !get_error())
			copy_context(thread->context, context, req->flags & ~flags);
	}
	reply->self = (thread == current_thread);
	release_object(thread);
}

/* get a thread from a handle (and increment the refcount) */
struct w32thread *get_thread_from_handle(obj_handle_t handle, unsigned int access)
{
	NTSTATUS status;
	PVOID obj;

	ktrace("\n");
	status = ref_object_by_handle(handle,
			access,
			NULL,
			KernelMode,
			(PVOID *)&obj,
			NULL);
	if (!NT_SUCCESS(status)) {
		set_error(status);
		return NULL;
	}

	deref_object(obj);
	return grab_object(((struct ethread *)obj)->tcb.win32thread);
}

struct w32thread *get_thread_from_id(thread_id_t id)
{
	int status;
	struct ethread *ethread;

	ktrace("id=%d\n", id);
	if (!NT_SUCCESS(status = lookup_thread_by_tid((HANDLE)id, &ethread))) {
		set_error(status);
		return NULL;
	}

	deref_object(ethread);
	return grab_object(ethread->tcb.win32thread);
}

/* add a ethread to a task */
void add_ethread(struct task_struct *tsk, struct ethread *thread)
{
	etget(thread);

	write_lock(&tsk->alloc_lock);
	tsk->ethread = thread;
	write_unlock(&tsk->alloc_lock);
} /* end add_ethread() */

/* remove a ethread from a task */
void remove_ethread(struct task_struct *tsk, struct ethread *thread)
{
	write_lock(&tsk->alloc_lock);
	if (tsk->ethread == thread)
		tsk->ethread = NULL;
	else
		thread = NULL;
	write_unlock(&tsk->alloc_lock);

	if (thread)
		etput(thread);
} /* end remove_ethread() */

/* clean up all task ethread for exit() */
void exit_ethread(struct task_struct *tsk)
{
	struct ethread	*thread;
	ktrace("tsk %p\n", tsk);

	write_lock(&tsk->alloc_lock);
	thread = tsk->ethread;
	tsk->ethread = NULL;
	write_unlock(&tsk->alloc_lock);

	if (thread)
		etput(thread);
} /* end exit_ethread() */

/*
 * notify a ethread of a process that is exiting
 * - this'll be called from notify_parent() in kernel/signal.c
 */
void __ethread_notify_exit(struct task_struct *tsk, int exit_code)
{
	struct ethread	*thread;
	ktrace("tsk %p\n", tsk);

	read_lock(&tsk->alloc_lock);
	thread = tsk->ethread;
	read_unlock(&tsk->alloc_lock);

	etget(thread);
	thread->et_exit_called = 1;
	if (thread->et_ops->exit)
		thread->et_ops->exit(thread, exit_code);		/* call the operation */
	etput(thread);
} /* end __ethread_notify_exit() */

/*
 * notify a ethread of a signal being delivered to a process that would cause
 * the parent process to get SIGCHLD
 * - this'll be called from notify_parent() in kernel/signal.c
 * - return WIN32_THREAD_SIGNAL_OKAY to keep the signal
 * - return WIN32_THREAD_CANCEL_SIGNAL to cancel the signal immediately
 */
int __ethread_notify_signal(struct task_struct *tsk, int signal)
{
	struct ethread	*thread;

	read_lock(&tsk->alloc_lock);
	thread = tsk->ethread;
	read_unlock(&tsk->alloc_lock);

	etget(thread);
	if (thread->et_ops->signal)
		thread->et_ops->signal(thread, signal);		/* call the operation */
	etput(thread);

	return WIN32_THREAD_SIGNAL_OKAY;
} /* end __ethread_notify_signal() */

/*
 * notify a ethread of a process execve'ing itself
 * - this'll be called from flush_old_exec() in kernel/exec.c
 */
void __ethread_notify_execve(struct task_struct *tsk)
{
	struct ethread	*thread;

	read_lock(&tsk->alloc_lock);
	thread = tsk->ethread;
	read_unlock(&tsk->alloc_lock);

	etget(thread);
	if (thread->et_ops->execve)
		thread->et_ops->execve(thread);		/* call the operation */
	etput(thread);
} /* end __ethread_notify_execve() */

/*
 * notify a ethread of a process forking/cloning itself
 * - this'll be called from do_fork() in kernel/fork.c
 */
void __ethread_notify_fork(struct task_struct *tsk,
				 struct task_struct *child,
				 unsigned long clone_flags)
{
	struct ethread	*thread;

	read_lock(&tsk->alloc_lock);
	thread = tsk->ethread;
	read_unlock(&tsk->alloc_lock);

	etget(thread);
	if (thread->et_ops->fork)
		thread->et_ops->fork(thread, tsk, child, clone_flags);	/* call the operation */
	etput(thread);
} /* end __ethread_notify_fork() */
#endif /* CONFIG_UNIFIED_KERNEL */
