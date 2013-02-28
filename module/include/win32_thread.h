/*
 * win32_thread.h
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
 * win32_thread.h:
 */
#ifndef _WIN32_THREAD_H_
#define _WIN32_THREAD_H_

#include <linux/module.h>
#include <linux/list.h>
#include <linux/semaphore.h>
#include <linux/sched.h>
#include <asm/atomic.h>
#include "winternl.h"

#define WIN32_THREAD_SIGNAL_OKAY	0
#define WIN32_THREAD_CANCEL_SIGNAL	1

enum kthread_state {
	Initialized,
    	Ready,
    	Running,
    	Standby,
    	Terminated,
    	Waiting,
    	Transition,
    	DeferredReady,
};

struct ethread_operations {
	const char	*name;		/* ethread name */
	struct module	*owner;		/* responsible module */

	void (*close)(struct ethread *thread);	/* request to destruct */
	void (*exit)(struct ethread *thread, int status);	/* notification of exit */
	int (*signal)(struct ethread *thread, int signal);	/* notification of signal (can cancel) */
	void (*execve)(struct ethread *thread);	/* notification of execve */
	/* notification that fork/clone has set up the new process and */
	void (*fork)(struct ethread *thread, struct task_struct *parent,
		     struct task_struct *child, unsigned long clone_flags);
};

struct task_ethread_operations {
    void (*add_ethread)(struct task_struct *tsk, struct ethread *thread);
    void (*remove_ethread)(struct task_struct *tsk, struct ethread *thread);
    void (*exit_ethread)(struct task_struct *tsk);
    void (*ethread_notify_exit)(struct task_struct *tsk, int exit_code);
    int (*ethread_notify_signal)(struct task_struct *tsk, int signal);
    void (*ethread_notify_execve)(struct task_struct *tsk);
    void (*ethread_notify_fork)(struct task_struct *tsk,
                         struct task_struct *child,
                         unsigned long clone_flags);
};

struct kthread
{
	struct dispatcher_header 	header;    
	struct list_head        	mutant_list_head;      
	void*				initial_stack;        
	unsigned long         		stack_limit;          
	void*			teb;                
	void*				tls_array;            
	void*				kernel_stack;         
	unsigned char             	debug_active;         
	unsigned char             	state;               
	unsigned char           	alerted[2];          
	unsigned char             	iopl;                
	unsigned char             	npx_state;            
	char              		saturation;          
	char              		priority;            
	unsigned long             	context_switches;     
	long              		wait_status;          
	kirql_t             		wait_irql;            
	kprocessor_mode_t              	wait_mode;            
	unsigned char             	wait_next;            
	unsigned char             	wait_reason;          
	union                                  
	{
		struct kwait_block*	wait_block_list;       
		struct kgate*		gate_object;          
	};                                     
	struct list_head        	wait_list_entry;       
	unsigned long             	wait_time;            
	char              		base_priority;        
	unsigned char             	decrement_count;      
	unsigned char             	priority_decrement;   
	char              		quantum;             
	struct kwait_block       	wait_block[4];        
	void*				lego_data;            

	kaffinity_t         		user_affinity;        
	kaffinity_t         		affinity;            
	unsigned char             	system_affinity_active;

	unsigned char             	power_state;          
	unsigned char             	npx_irql;             
	unsigned char             	pad[1];              

	struct kqueue*			queue;              
	struct ktimer            	timer;               
	struct list_head        	queue_list_entry;      

	unsigned char             	preempted;           
	unsigned char             	process_ready_queue;   
	unsigned char             	next_processor;       
	unsigned char             	kstack_resident; 

	void*				callback_stack;       

	struct w32thread*		win32thread;        
	struct ktrap_frame*		trap_frame;        

	/* APC */
	union
	{
		struct
		{
			unsigned short 	kernel_apc_disable;
			unsigned short  special_apc_disable;
		};
		unsigned long         	combined_apc_disable;  
	};
	spinlock_t        		apc_queue_lock;        
	struct kapc_state*		apc_state_pointer[2];  
	struct kapc_state        	apc_state;            
	struct kapc_state        	saved_apc_state;       
	struct kapc              	suspend_apc;          
	unsigned char             	apc_queueable;        
	unsigned char             	apc_state_index;       

	unsigned char             	enable_stack_swap;     
	unsigned char             	large_stack;          
	unsigned char             	resource_index;       
	unsigned char             	previous_mode;        
	unsigned char             	alertable;           
	unsigned char             	auto_alignment;       
	void*				stack_base;           
	struct ksemaphore        	suspend_semaphore;    
	struct list_head        	thread_list_entry;     
	char              		freeze_count;         
	unsigned char            	suspend_count;        
	unsigned char             	ideal_processor;      
	unsigned char             	disable_boost;        
	unsigned char             	quantum_reset;        
};

struct ethread
{
	struct kthread			tcb;
	union
	{
		ntstatus_t              exit_status;                  
		void*			ofs_chain;                    
	};
	struct list_head                post_block_list;               
	union
	{
		struct termination_port* termination_port;            
		struct ethread*		reaper_link;                 
		void*			keyed_wait_value;              
	};
	spinlock_t                     	active_timer_list_lock;         
	struct list_head               	active_timer_list_head;         
	struct client_id               	cid;                         

	union
	{
		struct semaphore        lpc_reply_semaphore;           
		struct semaphore        keyed_reply_semaphore;
		struct semaphore        exec_semaphore;
	};
	union
	{
		void*			lpc_reply_message;             
		void*			lpc_waiting_on_port;            
	};
	union
	{
		struct list_head	lpc_reply_chain;               
		struct list_head	keyed_wait_chain;              
	};
	unsigned long               	lpc_reply_messageid;           

	struct ps_impersonation_information*	impersonation_info;           

	struct list_head 		irp_list;                     
	unsigned long                	top_level_irp;                 
	struct device_object*		device_to_verify;              
	struct eprocess*		threads_process;             
	void*				start_address;                
	union
	{
		void*			win32_start_address;           
		unsigned long           lpc_received_messageid;        
	};
	struct list_head		thread_list_entry;
	ex_rundown_ref_t 		rundown_protect;              
	spinlock_t                   	thread_lock;                  
	unsigned long      		read_cluster_size;             
	access_mask_t 			granted_access;               
	union
	{
		struct
		{
			unsigned long  	terminated:1;
			unsigned long  	dead_thread:1;
			unsigned long  	hide_from_debugger:1;
			unsigned long   active_impersonation_info:1;
			unsigned long   system_thread:1;
			unsigned long   hard_errors_are_disabled:1;
			unsigned long   break_on_termination:1;
			unsigned long   skip_creation_msg:1;
			unsigned long   skip_termination_msg:1;
			unsigned long   suspend_on_create: 1;
			unsigned long   inherit_all: 1;
		};
		unsigned long           cross_thread_flags;            
	};
	union
	{
		struct
		{
			unsigned long   active_exworker:1;
			unsigned long   exworker_can_wait_user:1;
			unsigned long   memory_maker:1;
			unsigned long   keyed_event_inuse:1;
		};
		unsigned long           same_thread_passive_flags;      
	};
	union
	{
		struct
		{
			unsigned long   lpc_received_msgid_valid:1;
			unsigned long   lpc_exit_thread_called:1;
			unsigned long   address_space_owner:1;
			unsigned long   owns_process_workingsete_xclusive:1;
			unsigned long   owns_process_workingset_shared:1;
			unsigned long   owns_system_workingset_exclusive:1;
			unsigned long   owns_system_workingset_shared:1;
			unsigned long   owns_session_workingset_exclusive:1;
			unsigned long   owns_session_workingset_shared:1;
			unsigned long   apc_needed:1;
		};
		unsigned long           same_thread_apc_flags;          
	};
	unsigned char                   forward_cluster_only;          
	unsigned char                   disable_page_fault_clustering;  
	unsigned char                   active_fault_count;            

	/* for unified kernel */
	atomic_t			et_count;	/* ref count */         
	int				et_exit_called;	/* exit is called? */
	struct task_struct*		et_task;	/* Linux task */
	struct ethread_operations*	et_ops;
	void*				tsb;
#if 0
	void*				et_extend;
#endif
};

typedef struct ethread ETHREAD, *PETHREAD;

static __inline__ void etget(struct ethread *thread)
{
	atomic_inc(&thread->et_count);
} /* end etget() */

static __inline__ void etput(struct ethread *thread)
{
	if (atomic_dec_and_test(&thread->et_count)){
		struct module *owner = thread->et_ops->owner;
		thread->et_ops->close(thread);	/* will destroy this ethread */
		if(owner)
			module_put(owner);
	}
} /* end etput()*/

/* add a win32 thread to a task */
extern void add_ethread(struct task_struct *tsk, struct ethread *thread);

/* remove a win32 thread from a task */
extern void remove_ethread(struct task_struct *tsk, struct ethread *thread);

/* a win32 thread exit */
extern void exit_ethread(struct task_struct *tsk);


/* notification of exit/fatal signal */
extern void __ethread_notify_exit(struct task_struct *tsk, int exit_code);

static __inline__ void ethread_notify_exit(struct task_struct *tsk, int exit_code)
{
	if (tsk->ethread)
		__ethread_notify_exit(tsk, exit_code);
} /* end __ethread_notify_exit() */

/* notification of signal */
extern int __ethread_notify_signal(struct task_struct *tsk, int signal);

static __inline__ int ethread_notify_signal(struct task_struct *tsk, int signal)
{
	return tsk->ethread
		? __ethread_notify_signal(tsk, signal)
		: WIN32_THREAD_SIGNAL_OKAY;
} /* end __ethread_notify_signal() */

/* notification of signal execve */
extern void __ethread_notify_execve(struct task_struct *tsk);

static __inline__ void ethread_notify_execve(struct task_struct *tsk)
{
	if (tsk->ethread)
		__ethread_notify_execve(tsk);
} /* end __ethread_notify_execve() */

/* notification of fork */
extern void __ethread_notify_fork(struct task_struct *tsk,
					struct task_struct *child,
					unsigned long clone_flags);

static __inline__ void ethread_notify_fork(struct task_struct *tsk,
						 struct task_struct *child,
						 unsigned long clone_flags)
{
	if (tsk->ethread)
		__ethread_notify_fork(tsk, child, clone_flags);
} /* end __ethread_notify_fork() */
#endif /* _WIN32_THREAD_H_ */
