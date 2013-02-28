/*
 * apc.c
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
 * apc.c: apc implementation
 * Refered to ReactOS code
 */
#include "apc.h"
#include <linux/syscalls.h>

#ifdef CONFIG_UNIFIED_KERNEL
unsigned long get_apc_dispatcher(void);

/* 
 * free_apc_routine
 * Free apc
 */
VOID
STDCALL
free_apc_routine(PKAPC Apc,
		PKNORMAL_ROUTINE* NormalRoutine,
		PVOID* NormalContext,
		PVOID* SystemArgument1,
		PVOID* SystemArgument2)
{
	/* Free the APC */
	kfree(Apc);
} /* end free_apc_routine */
EXPORT_SYMBOL(free_apc_routine);

/* exit_special_apc*/
VOID
STDCALL
exit_special_apc(PKAPC Apc,    
		PKNORMAL_ROUTINE* NormalRoutine,
		PVOID* NormalContext,
		PVOID* SystemArgument1,
		PVOID* SystemArguemnt2)
{
	int exit_status = (int) Apc->normal_routine;

	ktrace("called to exit thread: 0x%p\n",get_current_ethread());
	/* Free the APC */
	kfree(Apc);

	/* Terminate the Thread */
	do_exit(exit_status);  
} /* end exit_special_apc */
EXPORT_SYMBOL(exit_special_apc);

/*
 * FUNCTION: Tests whether there are any pending APCs for the current thread
 * and if so the APCs will be delivered on exit from kernel mode
 */
BOOLEAN
STDCALL
test_alert_thread(IN KPROCESSOR_MODE AlertMode)
{
	/* FIXME */
	return 0;
}
EXPORT_SYMBOL(test_alert_thread);

/* 
 * apc_init
 * Initialize Apc
 */
VOID
STDCALL
apc_init(IN PKAPC Apc,
		IN struct kthread* Thread,
		IN KAPC_ENVIRONMENT TargetEnvironment,
		IN PKKERNEL_ROUTINE KernelRoutine,
		IN PKRUNDOWN_ROUTINE RundownRoutine OPTIONAL,
		IN PKNORMAL_ROUTINE NormalRoutine,
		IN KPROCESSOR_MODE Mode,
		IN PVOID Context)
{
	ktrace("(Apc %p, Thread %p, Environment %d, KernelRoutine %p, \
			RundownRoutine %p, NormalRoutine %p, Mode %d, Context %p)\n", 
			Apc, &Thread, TargetEnvironment, KernelRoutine, 
			RundownRoutine, NormalRoutine, Mode, Context);

	Apc->type = ApcObject;
	Apc->size = sizeof(struct kapc);
	if (TargetEnvironment == CurrentApcEnvironment) 
		Apc->apc_state_index = Thread->apc_state_index;
	else Apc->apc_state_index = TargetEnvironment;

	/* Set the Thread and Routines */
	Apc->thread = Thread;
	Apc->kernel_routine = KernelRoutine;
	Apc->rundown_routine = NULL;   /*rundown routine hasn't been implemented*/
	Apc->normal_routine = NormalRoutine;

	/* Check if this is a Special APC, in which case we use KernelMode and no Context */
	if (NormalRoutine!=NULL) {
		Apc->apc_mode = Mode;
		Apc->normal_context = Context;
	} else 	Apc->apc_mode = KernelMode;

	Apc->inserted = 0;
	return;
} /* end apc_init */
EXPORT_SYMBOL(apc_init);

/* 
 * __insert_queue_apc
 * Insert apc to apc queue
 */
BOOLEAN
STDCALL
__insert_queue_apc(PKAPC Apc, KPRIORITY PriorityBoost)
{
	struct kthread *thread = Apc->thread; 
	struct list_head *head, *apc_listentry;
	struct kapc *queued_apc;
	struct kapc_state *apc_state;

	ktrace("\n");
	/* Don't do anything if the APC is already inserted */
	if (Apc->inserted)
		return 0;

	/*
	 * Three scenarios:
	 * 1) Kernel APC with Normal Routine or User APC = Put it at the end of the List
	 * 2) User APC which is exit_special_apc = Put it at the front of the List
	 * 3) Kernel APC without Normal Routine = Put it at the end of the No-Normal Routine 
	 *    Kernel APC list
	 */
	apc_state = thread->apc_state_pointer[(int)Apc->apc_state_index];
	head = &apc_state->apc_list_head[(int)(Apc->apc_mode)];
	if ((Apc->apc_mode != KernelMode) && 
			(Apc->kernel_routine == (PKKERNEL_ROUTINE)exit_special_apc)) { /* 2) */
		list_add(&Apc->apc_list_entry, head);
	} else if (!Apc->normal_routine) {                                             /* 3) */
		for (apc_listentry = head->next;
				apc_listentry != head;
				apc_listentry = apc_listentry->next) {
			queued_apc = list_entry(apc_listentry, struct kapc, apc_list_entry);
			if (queued_apc->normal_routine != NULL) break;
		}
		/* We found the first "Normal" APC, so write right before it */
		apc_listentry = apc_listentry->prev;
		list_add(&Apc->apc_list_entry, apc_listentry);
	} else {                                                                       /* 1) */
		list_add_tail(&Apc->apc_list_entry, head);
	}

	/* FIXME
	 * Three possibilites here again:
	 *  1) Kernel APC, The thread is Running: Request an Interrupt
	 *  2) Kernel APC, The Thread is Waiting at PASSIVE_LEVEL and APCs are enabled 
	 *     and not in progress: Unwait the Thread
	 *  3) User APC, Unwait the Thread if it is alertable
	 */

	/* Confirm Insertion */
	Apc->inserted = 1;
	if (Apc->apc_mode == KernelMode)
		thread->apc_state.kapc_pending = 1;
	else
		thread->apc_state.uapc_pending = 1;

	return 1;
} /* end __insert_queue_apc */
EXPORT_SYMBOL(__insert_queue_apc);

/*
 * insert_queue_apc
 */
BOOLEAN
STDCALL
insert_queue_apc(PKAPC Apc,
		PVOID SystemArgument1,
		PVOID SystemArgument2,
		KPRIORITY PriorityBoost)
{
	BOOL inserted;
	struct kthread *thread;

	ktrace("(Apc %p, SystemArgument1 %p, SystemArgument2 %p)\n", 
			Apc, SystemArgument1, SystemArgument2);
	/* Get the Thread specified in the APC */
	thread = Apc->thread;	

	/* Disable interrupt and lock shared resource */
	spin_lock_irq(&thread->apc_queue_lock);

	if (!thread->apc_queueable) {                       
		spin_unlock_irq(&thread->apc_queue_lock);
		return 0;
	}

	Apc->system_argument1 = SystemArgument1;
	Apc->system_argument2 = SystemArgument2;
	inserted = __insert_queue_apc(Apc, PriorityBoost);

	/* Enable interrupt and unlock shared resource */
	spin_unlock_irq(&thread->apc_queue_lock);

	return inserted;
} /* end insert_queue_apc */
EXPORT_SYMBOL(insert_queue_apc);

/*
 * NtQueueApcThread  
 * system call NtQueueApcThread
 * which called from user  
 */
NTSTATUS SERVICECALL
NtQueueApcThread(HANDLE ThreadHandle,
		PKNORMAL_ROUTINE ApcRoutine,
		PVOID NormalContext,
		PVOID SystemArgument1,
		PVOID SystemArgument2)
{
	struct kapc *apc;
	struct ethread *thread;
	NTSTATUS status;

	ktrace("\n");
	status = ref_object_by_handle(ThreadHandle,
			THREAD_ALL_ACCESS,
			thread_object_type,
			KernelMode,
			(PVOID *)&thread,
			NULL);
	if (!(thread)) {
		return STATUS_UNSUCCESSFUL;
	}

	/* Set thread_info's flag */ 	
	set_tsk_thread_flag(thread->et_task, TIF_APC);
	if (!(apc = kmalloc(sizeof(struct kapc),GFP_KERNEL))) {
		return STATUS_NO_MEMORY;
	}

	apc_init(apc,
			&thread->tcb,
			OriginalApcEnvironment,
			free_apc_routine,
			NULL,
			ApcRoutine,
			UserMode,
			NormalContext);
	if (!insert_queue_apc(apc, SystemArgument1, SystemArgument2, IO_NO_INCREMENT)) {
		kfree(apc);
		status = STATUS_UNSUCCESSFUL;
	} else	status = STATUS_SUCCESS;

	sys_kill(thread->et_task->pid, SIGUSR2);
	deref_object(thread);
	return status;
} /* end NtQueueApcThread */
EXPORT_SYMBOL(NtQueueApcThread);

/* 
 * deliver_apc
 * Dequeue the apc queue , and call apc function one by one
 */
VOID 
STDCALL
deliver_apc(KPROCESSOR_MODE DeliveryMode,
		PVOID Reserved,
		struct pt_regs * TrapFrame)
{
	struct ethread *thread;
	struct list_head * apc_listentry; 
	struct kapc *apc = NULL;
	kernel_routine_t kernel_routine;
	void * normal_context;
	normal_routine_t normal_routine;
	void *system_argument1;
	void *system_argument2;

	ktrace("(DeliverMode 0x%x, Reserved 0x%p, TrapFrame 0x%p)\n", 
			DeliveryMode, Reserved, TrapFrame);
	if (!(thread = get_current_ethread())) {	
		clear_tsk_thread_flag(current, TIF_APC);
		return;
	}

	/* Disable interrupt and lock shared resource */
	spin_lock_irq(&thread->tcb.apc_queue_lock);

	/* Clear APC Pending */
	thread->tcb.apc_state.kapc_pending = 0;

	/* Do the Kernel APCs first */
	while (!list_empty(&thread->tcb.apc_state.apc_list_head[KernelMode])) {
		/* Clear APC Pending */
		thread->tcb.apc_state.kapc_pending = 0;

		/* Get the next Entry */
		apc_listentry = thread->tcb.apc_state.apc_list_head[KernelMode].next;
		apc = list_entry(apc_listentry, struct kapc, apc_list_entry);

		/* Save Parameters so that it's safe to free the Object in Kernel Routine*/
		normal_routine = apc->normal_routine;
		kernel_routine = apc->kernel_routine;
		normal_context = apc->normal_context;
		system_argument1 = apc->system_argument1;
		system_argument2 = apc->system_argument2;

		if (!normal_routine) {
			/* Remove the APC from the list */
			apc->inserted= 0;
			list_del(apc_listentry);

			/* Enable interrupt and unlock shared resource */
			spin_unlock_irq(&thread->tcb.apc_queue_lock);

			/* Call the Special APC */
			kernel_routine(apc,
					&normal_routine,
					&normal_context,
					&system_argument1,
					&system_argument2);

			/* Disable interrupt and lock shared resource again */
			spin_lock_irq(&thread->tcb.apc_queue_lock);
		} else {

			/* FIXME
			 * DeliveryMode must be KernelMode in this case, since one may not
			 * return to umode while being inside a critical section or while 
			 * a regular kmode apc is running (the latter should be impossible btw).
			 */

			/* Dequeue the APC */
			list_del(apc_listentry);
			apc->inserted = 0;

			/* Enable interrupt and unlock shared resource */
			spin_unlock_irq(&thread->tcb.apc_queue_lock);

			/* Call the Kernel APC */
			kernel_routine(apc,
					&normal_routine,
					&normal_context,
					&system_argument1,
					&system_argument2);

			/* If There still is a Normal Routine, then we need to call it */
			if (normal_routine) {
				/* which is unplemented for premting by special apc */  
				thread->tcb.apc_state.kapc_inprogress = 1; 

				normal_routine(&normal_context, &system_argument1, &system_argument2);
			}

			/* Disable interrupt and lock shared resource again */
			spin_lock_irq(&thread->tcb.apc_queue_lock);

			thread->tcb.apc_state.kapc_inprogress = 0;
		}
	}

	/* Now we do the User APCs */
	if ((!list_empty(&thread->tcb.apc_state.apc_list_head[UserMode])) &&
			(thread->tcb.apc_state.uapc_pending)) {		/* && (DeliveryMode == UserMode) */ 

		/* Get the APC Object */
		apc_listentry = thread->tcb.apc_state.apc_list_head[UserMode].next;
		apc = list_entry(apc_listentry, struct kapc, apc_list_entry);

		/* Save Parameters so that it's safe to free the Object in Kernel Routine*/
		normal_routine = apc->normal_routine;
		kernel_routine = apc->kernel_routine;
		normal_context = apc->normal_context;
		system_argument1 = apc->system_argument1;
		system_argument2 = apc->system_argument2; 

		/* Remove the APC from Queue, call the APC */
		list_del(apc_listentry);
		apc->inserted = 0;

		/* Enable interrupt and unlock shared resource */
		spin_unlock_irq(&thread->tcb.apc_queue_lock);

		kernel_routine(apc,
				&normal_routine,
				&normal_context,
				&system_argument1,
				&system_argument2);

		if (!normal_routine) {	
			test_alert_thread(UserMode);   /* Unimplemented */
		} else {
			/* Set up the Trap Frame and prepare for Execution in NTDLL.DLL */
			init_user_apc(Reserved, 
					TrapFrame,
					normal_routine,
					normal_context,
					system_argument1,
					system_argument2); 
		}
	} else {
		/* It's not pending anymore */
		thread->tcb.apc_state.uapc_pending = 0;

		/* Enable interrupt and unlock shared resource */
		spin_unlock_irq(&thread->tcb.apc_queue_lock);

		/* Clear thread_info's flag */
		clear_tsk_thread_flag(thread->et_task,TIF_APC);
	}
	return;
} /* end deliver_apc */
EXPORT_SYMBOL(deliver_apc);

/*
 * init_user_apc
 * Save the trapframe and set the esp for returning to user space to call apc function
 */
VOID
STDCALL
init_user_apc(IN PVOID Reserved,
		IN PKTRAP_FRAME TrapFrame,
		IN PKNORMAL_ROUTINE NormalRoutine,
		IN PVOID NormalContext,
		IN PVOID SystemArgument1,
		IN PVOID SystemArgument2)  
{
	PContext context;
	PULONG esp;

	ktrace("ESP 0x%lx\n", TrapFrame->sp);
	/*
	 * Save the thread's current context (in other words the registers
	 * that will be restored when it returns to user mode) so the
	 * APC dispatcher can restore them later
	 */
	context = (PContext)(((PUCHAR)TrapFrame->sp) - sizeof(*context));
	memcpy(context, TrapFrame, sizeof(*context));

	/*
	 * Setup the trap frame so the thread will start executing at the
	 * APC Dispatcher when it returns to user-mode
	 */
	esp = (PULONG)(((PUCHAR)TrapFrame->sp) - (sizeof(CONTEXT) + (6 * sizeof(ULONG))));
	esp[0] = 0xdeadbeef;
	esp[1] = (ULONG)NormalRoutine;
	esp[2] = (ULONG)NormalContext;
	esp[3] = (ULONG)SystemArgument1;
	esp[4] = (ULONG)SystemArgument2;
	esp[5] = (ULONG)context;
	TrapFrame->ip = get_apc_dispatcher();
	TrapFrame->sp = (ULONG)esp;
} /* end init_user_apc */

/*
 * thread_special_apc
 */
void
STDCALL
thread_special_apc(PKAPC Apc,
		PKNORMAL_ROUTINE* NormalRoutine,
		PVOID* NormalContext,
		PVOID* SystemArgument1,
		PVOID* SystemArgument2)
{
	ktrace("\n");
	kfree(Apc);
} /* end thread_special_apc */
EXPORT_SYMBOL(thread_special_apc);

/*
 * NtContinue
 * Go back to kernel space
 */
NTSTATUS 
SERVICECALL
NtContinue(IN PContext Context,
		IN BOOLEAN TestAlert)
{
	PKTRAP_FRAME trap_frame = (PKTRAP_FRAME)current->ethread->tcb.trap_frame;

	ktrace("\n");
	/*
	 * Copy the supplied context over the register information that was saved
	 * on entry to kernel mode, it will then be restored on exit
	 * FIXME: Validate the context
	 */
	memcpy(trap_frame, Context, sizeof(*trap_frame));

	/* FIXME
	 * Copy floating point context into the thread's FX_SAVE_AREA
	 */

	__asm__(
			"andl %%esp, %%ecx;\n\t"
			"movl %%ecx, %%ebp;\n\t"
			"movl %%ebx, %%esp;\n\t"
			"jmp w32syscall_exit\n\t"
			:
			: "b" (trap_frame), "c" (-THREAD_SIZE));

	/* This doesn't actually happen b/c KeRosTrapReturn() won't return */
	return STATUS_SUCCESS;
} /* NtContinue */
EXPORT_SYMBOL(NtContinue);

NTSTATUS 
SERVICECALL
NtCatchApc(int param)
{
	set_tsk_thread_flag(current, TIF_APC);
	return STATUS_SUCCESS;
}

/* do_apc */
__attribute__((regparm(3)))
void do_apc(struct pt_regs *regs, sigset_t *oldset,
		      __u32 thread_info_flags)
{
	struct ethread *thread;
	ktrace("Do Apc\n");
	
	/* Get the Current Thread */
	if (!(thread = get_current_ethread())) {
		clear_tsk_thread_flag(thread->et_task, TIF_APC);
		return;
	}
	deliver_apc(0, 0, regs); /* first parament is kernelMode or UserMode or 0 for both*/
}/* end do_apc */
#endif
