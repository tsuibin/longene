/*
 * kill.c
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
 * kill.c:
 * Refered to ReactOS code
 */
#include "virtual.h"
#include "handle.h"
#include "area.h"
#include "unistr.h"

#ifdef CONFIG_UNIFIED_KERNEL

extern struct list_head process_list;
extern HANDLE base_dir_handle;

extern VOID STDCALL
delete_handle_callback(struct handle_table *HandleTable,
		PVOID Object,
		ULONG GrantedAccess,
		PVOID Context);
extern struct w32thread *console_get_renderer(struct console_input *console);
extern int free_console(struct w32process *process);

static void process_killed(struct w32process *process);

VOID STDCALL
delete_teb(PTEB Teb)
{
	unsigned long len = PAGE_SIZE;

	ktrace("%p\n", Teb);
	NtFreeVirtualMemory((HANDLE)-1, (PVOID *)&Teb, (PULONG)&len, MEM_RELEASE);
}

void __exit_process(struct eprocess * process)
{
	unsigned long old_state;

	ktrace("()\n");
	/* close all handles associated with our process, this needs to be done 
	 * when the last thread still runs */
	__destroy_handle_table(process->object_table, delete_handle_callback, process);

	/* remove all reserved area and mapped area */
	remove_all_win32_area(&process->ep_reserved_head);
	remove_all_win32_area(&process->ep_mapped_head);

	/* FIXME: spin_lock_irq(&t); */
	local_irq_disable();

#if 0
	if (process->win32process)
		kfree(process->win32process);
#endif

	if (process->ep_handle_info_table) {
		free_handle_info_table(process->ep_handle_info_table);
		kfree(process->ep_handle_info_table);
		process->ep_handle_info_table = NULL;
	}

	old_state = process->pcb.header.signal_state;
	process->pcb.header.signal_state = true;
	if ((!old_state) && !list_empty(&process->pcb.header.wait_list_head)) {
		/* Satisfy waits */
		wait_test((struct dispatcher_header *)&process->pcb,IO_NO_INCREMENT);
	}

	local_irq_enable();
	/* FIXME: spin_unlock_irq(&t); */
}
EXPORT_SYMBOL(__exit_process);

static inline void terminate_thread_by_pointer(struct ethread *thread, NTSTATUS exit_code)
{
	thread->exit_status = exit_code;
	send_sig_info(SIGINT, SEND_SIG_FORCED, thread->et_task);
}

void exit_process_threads(struct eprocess *process, NTSTATUS ExitStatus)
{
	struct list_head *cur_entry;
	struct ethread *thread;

	/* process is locked by caller */
	cur_entry = process->thread_list_head.next;
	while (cur_entry != &process->thread_list_head) {
		thread = list_entry(cur_entry, struct ethread, thread_list_entry);
		cur_entry = cur_entry->next;
		if (thread != get_current_ethread())
			terminate_thread_by_pointer(thread, ExitStatus);
	}
}
EXPORT_SYMBOL(exit_process_threads);

/* terminate a process with the given exit code */
void terminate_process(struct w32process *process, int exit_code)
{
	struct list_head *ptr;

	grab_object(process);  /* make sure it doesn't get freed when threads die */
	while ((ptr = list_head(&process->thread_list))) {
		struct w32thread *thread = LIST_ENTRY(ptr, struct w32thread, proc_entry);

		remove_process_thread(process, thread);
		release_object(thread);
	}
	if (process->dummyfd != -1) {
		close(process->dummyfd);
		process->dummyfd = -1;
	}
	release_object(process);
}

NTSTATUS SERVICECALL
NtTerminateProcess(IN HANDLE ProcessHandle,
		IN NTSTATUS ExitStatus)
{
	struct eprocess *process;
	struct ethread *cur_thread;
	NTSTATUS status;

	ktrace("\n");

	if ((status = ref_object_by_handle(ProcessHandle ? ProcessHandle : NtCurrentProcess(),
				PROCESS_TERMINATE, 
				process_object_type, 
				get_pre_mode(), 
				(PVOID *) &process, 
				NULL)))
		return status;

	cur_thread = (struct ethread *) get_current_ethread();

	terminate_process(process->win32process, ExitStatus);
	release_object(process->win32process);

	lock_process(process);

	if (process->exit_time.quad) {
		unlock_process(process);
		deref_object(process);
		return STATUS_PROCESS_IS_TERMINATING;
	}

	query_sys_time(&process->exit_time);
	process->exit_status = (unsigned long)ExitStatus;

	unlock_process(process);
	deref_object(process);

	if (process == get_current_eprocess()) {
		cur_thread->exit_status = ExitStatus;
		do_group_exit((ExitStatus & 0xff) << 8);
	} else {
		struct ethread *first_thread = get_first_thread(process);

		first_thread->exit_status = ExitStatus;
		send_sig_info(SIGKILL, SEND_SIG_FORCED, first_thread->et_task->group_leader);
	}

	return STATUS_SUCCESS;
}
EXPORT_SYMBOL(NtTerminateProcess);

NTSTATUS 
SERVICECALL
NtTerminateThread(IN HANDLE   ThreadHandle,
		IN NTSTATUS ExitStatus)
{
	struct ethread * thread;
	struct w32thread *w32thread;
	NTSTATUS status;

	ktrace("%p\n", ThreadHandle);

	status = ref_object_by_handle(ThreadHandle,
			THREAD_TERMINATE,
			thread_object_type,
			get_pre_mode(),
			(PVOID *)&thread,
			NULL);

	if (!NT_SUCCESS(status))
		return status;

	if (!thread->et_task){
		deref_object(thread);
		return STATUS_THREAD_IS_TERMINATING; 
	}

	w32thread = thread->tcb.win32thread;
	remove_process_thread(w32thread->process, w32thread);
	thread->tcb.win32thread = NULL;
	release_object(w32thread);

	/* FIXME Make sure this is not a system thread */

	if (thread != get_current_ethread()) {
		terminate_thread_by_pointer(thread, ExitStatus); 
		deref_object(thread);
	} else {
		deref_object(thread);
		thread->exit_status = ExitStatus;
		do_exit((ExitStatus & 0xff) << 8); 
	}

	return STATUS_SUCCESS;		
}
EXPORT_SYMBOL(NtTerminateThread);

/* destroy a process when its refcount is 0 */
void process_destroy(struct object *obj)
{
	struct w32process *process = (struct w32process *)obj;

	ktrace("obj %p\n", obj);

	set_process_startup_state(process, STARTUP_ABORTED);
	if (process->console)
		release_object(process->console);
	if (process->parent)
		release_object(process->parent);
#if 0
	if (process->msg_fd)
		release_object(process->msg_fd);
#endif
	list_remove(&process->entry);

	/* to terminate the services.exe.so */
	if (is_last_list(&process_list)) {
		OBJECT_ATTRIBUTES attr;
		WCHAR process_system[] = {'_','_','p','r','o','c','e','s','s','_','s','y','s','t','e','m',0};
		UNICODE_STRING name;
		NTSTATUS status;
		HANDLE handle = NULL;

		init_unistr(&name, (PWSTR)process_system);
		INIT_OBJECT_ATTR(&attr, &name, 0, base_dir_handle, NULL);
		status = NtCreateEvent(&handle, 0, &attr, 1, 0);
		if (status && status != STATUS_OBJECT_NAME_EXISTS)
			return;
		NtSetEvent(handle, NULL);
		NtClose(handle);
	}
	if (process->idle_event)
		release_object(process->idle_event);
	if (process->queue)
		release_object(process->queue);
	if (process->token)
		release_object(process->token);
}

void startup_info_destroy(struct object *obj)
{
	struct startup_info *info = (struct startup_info *)obj;
	free(info->data);
	if (info->exe_file)
		release_object(info->exe_file);
	if (info->process)
		release_object(info->process);
}

/* remove a thread from a process running threads list */
void remove_process_thread(struct w32process *process, struct w32thread *thread)
{
	list_remove(&thread->proc_entry);

	if (!--process->running_threads) {
		/* we have removed the last running thread, exit the process */
		process->exit_code = thread->exit_code;
		close(process->dummyfd);
		process->dummyfd = -1;
		process_killed(process);
	}
	release_object(thread);
}

/* kill all processes being attached to a console renderer */
void kill_console_processes(struct w32thread *renderer, int exit_code)
{
	for (;;) { /* restart from the beginning of the list every time */
		struct w32process *process;

		/* find the first process being attached to 'renderer' and still running */
		LIST_FOR_EACH_ENTRY(process, &process_list, struct w32process, entry) {
			if (process == renderer->process)
				continue;
			if (!process->running_threads)
				continue;
			if (process->console && console_get_renderer(process->console) == renderer)
				break;
		}
		if (&process->entry == &process_list)
			break;  /* no process found */
		terminate_process(process, exit_code);
	}
}

/* a process has been killed (i.e. its last thread died) */
static void process_killed(struct w32process *process)
{
	struct list_head *ptr;
	ktrace("process %p\n", process);

	if (!process->is_system)
		close_process_desktop(process);

	/* close the console attached to this process, if any */
	free_console(process);

	while ((ptr = list_head(&process->dlls))) {
		struct process_dll *dll = LIST_ENTRY(ptr, struct process_dll, entry);
		if (dll->file)
			release_object(dll->file);
		free(dll->filename);
		list_remove(&dll->entry);
		free(dll);
	}
	destroy_process_classes(process);
	remove_process_locks(process);
	set_process_startup_state(process, STARTUP_ABORTED);
}

/* cleanup everything that is no longer needed by a dead thread */
static void cleanup_thread(struct w32thread *thread)
{
	ktrace("cleanup_thread()\n");
	free(thread->req_data);
	free(thread->reply_data);
	free(thread->suspend_context);
	free_msg_queue(thread);
	cleanup_clipboard_thread(thread);
	destroy_thread_windows(thread);
	close_thread_desktop(thread);
	thread->req_data = NULL;
	thread->reply_data = NULL;
	thread->context = NULL;
	thread->suspend_context = NULL;
	thread->desktop = 0;
}

/* destroy a thread when its refcount is 0 */
void destroy_thread(struct object *obj)
{
	struct w32thread *thread = (struct w32thread *)obj;

	ktrace("%p\n", obj);
    list_remove( &thread->entry );
	cleanup_thread(thread);
	release_object(thread->process);
	if (thread->token)
		release_object(thread->token);
}
#endif /* CONFIG_UNIFIED_KERNEL */
