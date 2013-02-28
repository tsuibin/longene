/*
 * w32init.c
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
 * w32init.c: initiliase w32systemcall and some object classes
 */
#include "mutex.h"
#include "event.h"
#include "semaphore.h"
#include "handle.h"

#ifdef CONFIG_UNIFIED_KERNEL

void open_dummy_file(void);
void close_dummy_file(void);

char *rootdir;

extern timeout_t start_time;
extern SSDT_ENTRY KeServiceDescriptorTable[];
asmlinkage int w32system_call(void);
int set_w32system_gate(unsigned int, void *);
int backup_idt_entry(unsigned int n, unsigned long *a, unsigned long *b);
int restore_idt_entry(unsigned int n, unsigned long a, unsigned long b);
unsigned long orig_idt_2e_a, orig_idt_2e_b;
int init_pe_binfmt(void);
void exit_pe_binfmt(void);
#ifdef EXE_SO
int init_exeso_binfmt(void);
void exit_exeso_binfmt(void);
#endif

struct proc_dir_entry *unifiedkernel_proc;
struct list_head object_class_list;

extern int proc_uk_init(void);
extern void proc_uk_exit(void);

extern void init_rootdir(void);
extern void free_rootdir(void);  /*rootdir*/

extern void kernel_init_registry(void);
extern void init_process_manager(void);
extern void init_section_implement(void);
extern void display_object_dir(POBJECT_DIRECTORY DirectoryObject, LONG Depth);
extern void display_name_info(void);
extern void exit_object(void);
extern void init_named_pipe(void);
extern void init_directories(void);
extern struct task_struct* save_kernel_task;
extern int kthread_stop(struct task_struct*);
extern void init_tet_ops(struct task_ethread_operations* ops);
struct task_struct* timer_kernel_task = NULL;

struct task_ethread_operations tet_ops = {
    .add_ethread            = add_ethread,
    .remove_ethread         = remove_ethread,
    .exit_ethread           = exit_ethread,
    .ethread_notify_exit    = ethread_notify_exit,
    .ethread_notify_signal  = ethread_notify_signal,
    .ethread_notify_execve  = ethread_notify_execve,
    .ethread_notify_fork    = ethread_notify_fork,
};

/* move to h --xuefengc */
extern void init_msg_queue_implement(void);
extern void init_thread_input_implement(void);
extern void init_sock_implement(void);
extern void init_desktop_implement(void);
extern void init_winstation_implement(void);
extern void init_hook_table_implement(void);
extern void init_atom_table_implement(void);
extern void init_async_implement(void);
extern void init_async_queue_implement(void);
extern void init_completion_implement(void);
extern void init_w32thread_implement(void);
extern void init_w32process_implement(void);
extern void init_startup_info_implement(void);

extern void init_clipboard_implement(void);

extern void init_console_input_implement(void);
extern void init_console_input_events_implement(void);
extern void init_screen_buffer_implement(void);

extern void init_ioctl_call_implement(void);
extern void init_device_manager_implement(void);
extern void init_device_implement(void);

extern void init_mailslot_implement(void);
extern void init_mailslot_writer_implement(void);
extern void init_mailslot_device_implement(void);

extern void init_named_pipe_implement(void);
extern void init_pipe_server_implement(void);
extern void init_pipe_client_implement(void);
extern void init_named_pipe_device_implement(void);

extern void init_serial_implement(void);
extern void init_snapshot_implement(void);
extern void init_timer_implement(void);

extern int kthread_should_stop(void);
extern struct task_struct* kthread_create(int (*fn)(void* data),void* data,
		const char namefmt[],...);

void timer_loop(void)
{
	unsigned int msecs, timeout, next;
	msecs = 10000;
	timeout = msecs_to_jiffies(msecs) + 1;
	while (1) {
		next = get_next_timeout();
		if (kthread_should_stop()) {
			return;
		}

		local_irq_enable();
		set_current_state(TASK_INTERRUPTIBLE);
		if (next == -1)
			schedule_timeout(timeout);
		else {
			next = msecs_to_jiffies(next) + 1;
			schedule_timeout(next);
		}
		local_irq_disable();
	}
}

void init_wineobj_implement(void)
{
	ktrace("\n");

	init_msg_queue_implement();
	init_thread_input_implement();
	init_sock_implement();
	init_desktop_implement();
	init_winstation_implement();
	init_hook_table_implement();
	init_atom_table_implement();
	init_async_implement();
	init_async_queue_implement();
	init_completion_implement();
	init_w32thread_implement();
	init_w32process_implement();
	init_startup_info_implement();

	/*
	 * under device directory
	 */
	init_clipboard_implement();
	init_console_input_implement();
	init_console_input_events_implement();
	init_screen_buffer_implement();

	init_ioctl_call_implement();
	init_device_manager_implement();
	init_device_implement();

	init_mailslot_implement();
	init_mailslot_writer_implement();
	init_mailslot_device_implement();

	init_named_pipe_implement();
	init_pipe_server_implement();
	init_pipe_client_implement();
	init_named_pipe_device_implement();

	init_serial_implement();

	init_snapshot_implement();

	init_timer_implement();
}

/* w32_init */
static int w32_init(void)
{
	ktrace("Unifiedkernel loading...\n");
	/* store the original address that the 0x2E points */ 
	if (backup_idt_entry(0x2E, &orig_idt_2e_a, &orig_idt_2e_b) == -1) {
		kdebug("Module not loaded. backup_idt_entry error: bad idt entry\n");
		return -1;
	}
	
	/* initialize 0x2E */
	if (set_w32system_gate(0x2E, &w32system_call) == -1) {
		kdebug("Module not loaded. set_w32system_gate error: bad idt entry\n");
		return -1;
	}
	
	proc_uk_init();
	init_rootdir();

	/* initialise the internal bits */
	INIT_LIST_HEAD(&object_class_list);
	init_pe_binfmt();
#ifdef EXE_SO
	init_exeso_binfmt();
#endif
	init_handle_tables();
	init_object();
	init_symbol_link();
	init_io();
	init_directories();
	init_named_pipe();
	init_cid_table();
	init_process_manager();
	init_section_implement();
	init_semaphore_implement();
	init_event_implement();
	init_mutant_implement();
	kernel_init_registry();
	init_tet_ops(&tet_ops);

	open_dummy_file();

	init_wineobj_implement();
	display_object_dir(name_space_root, 1);

	register_binfmt(NULL);
	start_time = get_current_time();

	timer_kernel_task = kthread_create((void*)timer_loop, NULL, "timer_thread");
	if(!IS_ERR(timer_kernel_task))
		wake_up_process(timer_kernel_task);

	ktrace("done\n");
	return 0;
} /* end w32_exit */
/* w32_exit */
static void w32_exit(void)
{
	int ret;

	close_dummy_file();

	destroy_cid_table();
	exit_object();
#ifdef EXE_SO
	exit_exeso_binfmt();
#endif
	exit_pe_binfmt();
	proc_uk_exit();
	free_rootdir();
	ret = wake_up_process(save_kernel_task);
	kthread_stop(save_kernel_task);

	ret = wake_up_process(timer_kernel_task);
	kthread_stop(timer_kernel_task);

	/* restore 0x2E */
	restore_idt_entry(0x2E, orig_idt_2e_a, orig_idt_2e_b);

	ktrace("Module w32 Off!\n");
} /*end w32_exit */

module_init(w32_init);
module_exit(w32_exit);
module_param(rootdir, charp, S_IRUGO);
MODULE_LICENSE("GPL");
#endif
