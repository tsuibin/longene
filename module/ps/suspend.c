/*
 * suspend.c
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
 * suspend.c:
 * Refered to ReactOS code
 */
#include "apc.h"
#include "objwait.h"

#ifdef CONFIG_UNIFIED_KERNEL

#define THREAD_ALERT_INCREMENT 2

VOID STDCALL
suspend_thread_kernel_routine(PKAPC Apc,
		PKNORMAL_ROUTINE* NormalRoutine,
		PVOID *NormalContext,
		PVOID *SystemArgument1,
		PVOID *SystemArguemnt2)
{
	return;
}

VOID STDCALL
suspend_thread_normal_routine(PVOID NormalContext,
		PVOID SystemArgument1,
		PVOID SystemArgument2)
{
	struct kthread *cur_thread = (struct kthread *)get_current_ethread();

	ktrace("call wait_for_single_object()\n");
	/* Non-alertable kernel-mode suspended wait */
	wait_for_single_object(&cur_thread->suspend_semaphore,
			0,		/* Suspended debuging aid */
			KernelMode,
			FALSE,
			NULL);
}

ULONG STDCALL
resume_thread(PKTHREAD Thread)
{
	unsigned long previous_count; 

	ktrace("(Thread %p called). %x, %x\n", Thread, Thread->suspend_count, Thread->freeze_count); 

	/* Lock the Dispatcher */ 
	spin_lock_irq(&((struct ethread * ) Thread)->thread_lock);

	/* Save the Old Count */ 
	previous_count = Thread->suspend_count; 

	/* Check if it existed */ 
	if (previous_count) { 
		Thread->suspend_count--; 
		/* Decrease the current Suspend Count and Check Freeze Count */ 
		if ((!Thread->suspend_count) && (!Thread->freeze_count)) { 
			/*TODO Signal the Suspend Semaphore */ 
			Thread->suspend_semaphore.header.signal_state++; 
			wait_test(&Thread->suspend_semaphore.header, IO_NO_INCREMENT); 
		} 
	} 

	/* Release Lock and return the Old State */ 
	spin_unlock_irq(&((struct ethread * ) Thread)->thread_lock);

	return previous_count;
}
EXPORT_SYMBOL(resume_thread);

ULONG STDCALL
suspend_thread(PKTHREAD Thread)
{
	unsigned long previous_count; 
	/* FIXME: KIRQL old_irql; */

	spin_lock_irq(&((struct ethread * ) Thread)->thread_lock);

	/* Save the Old Count */
	previous_count = Thread->suspend_count;

	/* Increment it */
	Thread->suspend_count++;

	/* Check if we should suspend it */
	if (!previous_count && !Thread->freeze_count) {

		/* Insert the APC */
		if (!__insert_queue_apc(&Thread->suspend_apc, IO_NO_INCREMENT)) {
			/* FIXME Unsignal the Semaphore, the APC already got inserted */
			Thread->suspend_semaphore.header.signal_state--;
		}
	}

	/* Release Lock and return the Old State */
	spin_unlock_irq(&((struct ethread * ) Thread)->thread_lock);

	return previous_count;
}
EXPORT_SYMBOL(suspend_thread);

BOOLEAN STDCALL
alert_thread(PKTHREAD Thread, KPROCESSOR_MODE AlertMode)
{
	/* KIRQL OldIrql; */
	BOOLEAN previous_state;

	/* Acquire the Dispatcher Database Lock */
	spin_lock_irq(&((struct ethread * ) Thread)->thread_lock);

	/* Save the Previous State */
	previous_state = Thread->alerted[(int)AlertMode];

	/* Return if Thread is already alerted. */
	if (previous_state == false) {
		/* If it's Blocked, unblock if it we should */
		if (Thread->state == Waiting &&
				(AlertMode == KernelMode || Thread->wait_mode == AlertMode) && Thread->alertable) {
			abort_wait_thread(Thread, STATUS_ALERTED, THREAD_ALERT_INCREMENT);

		} else {
			/* If not, simply Alert it */
			Thread->alerted[(int)AlertMode] = true;
		}
	}

	/* Release the Dispatcher Lock */
	spin_unlock_irq(&((struct ethread * ) Thread)->thread_lock);

	/* Return the old state */
	return previous_state;
}
EXPORT_SYMBOL(alert_thread);

ULONG STDCALL
alert_resume_thread(IN PKTHREAD Thread)
{
	unsigned long previous_count;

	/* Lock the Dispatcher Database and the APC Queue */
	spin_lock_irq(&((struct ethread * ) Thread)->thread_lock);
	spin_lock(&Thread->apc_queue_lock);/* TODO consider again */

	/* Return if Thread is already alerted. */
	if (Thread->alerted[KernelMode] == false) {
		/* If it's Blocked, unblock if it we should */
		if (Thread->state == Waiting &&  Thread->alertable) {
			abort_wait_thread(Thread, STATUS_ALERTED, THREAD_ALERT_INCREMENT);

		} else {
			/* If not, simply Alert it */
			Thread->alerted[KernelMode] = true;
		}
	}

	/* Save the old Suspend Count */
	previous_count = Thread->suspend_count;

	/* If the thread is suspended, decrease one of the suspend counts */
	if (previous_count) {
		/* Decrease count. If we are now zero, unwait it completely */
		if (--Thread->suspend_count) {
			/* Signal and satisfy */
			Thread->suspend_semaphore.header.signal_state++;
			wait_test(&Thread->suspend_semaphore.header, IO_NO_INCREMENT);
		}
	}

	/* Release Locks and return the Old State */
	spin_unlock(&Thread->apc_queue_lock);/* TODO consider again */
	spin_lock_irq(&((struct ethread * ) Thread)->thread_lock);

	return previous_count;
}
EXPORT_SYMBOL(alert_resume_thread);

NTSTATUS SERVICECALL
NtResumeThread(IN HANDLE ThreadHandle,
		IN PULONG SuspendCount  OPTIONAL)
{
	struct ethread * thread;
	ULONG prev;
	KPROCESSOR_MODE previous_mode = (KPROCESSOR_MODE)get_pre_mode();
	NTSTATUS status = STATUS_SUCCESS;

	ktrace("\n");
	/* Get the Thread Object */
	status = ref_object_by_handle(ThreadHandle,
			THREAD_SUSPEND_RESUME,
			thread_object_type,
			previous_mode,
			(PVOID*)&thread,
			NULL);
	if (status)
		return status;

	/* Call the Kernel Function */
	prev = resume_thread(&thread->tcb);

	/* Return it */
	if (SuspendCount) {
		if (UserMode == previous_mode) {
			if (copy_to_user(SuspendCount, &prev, sizeof(ULONG))) {
				status = STATUS_UNSUCCESSFUL;
				goto out;
			}
		} else
			*SuspendCount = prev;
	}

out:
	/* Dereference and Return */
	deref_object((PVOID)thread);
	return status;	
}
EXPORT_SYMBOL(NtResumeThread);

NTSTATUS SERVICECALL
NtSuspendThread(IN HANDLE ThreadHandle,
		IN PULONG PreviousSuspendCount  OPTIONAL)
{ 
	struct ethread * thread;
	ULONG prev;
	KPROCESSOR_MODE previous_mode = (KPROCESSOR_MODE)get_pre_mode();
	NTSTATUS status = STATUS_SUCCESS;

	ktrace("\n");
	/* Get the Thread Object */
	status = ref_object_by_handle(ThreadHandle,
			THREAD_SUSPEND_RESUME,
			thread_object_type,
			previous_mode,
			(PVOID*)&thread,
			NULL);
	if (status)
		return status;

	/* Call the Kernel Function */
	prev = suspend_thread(&thread->tcb);

	set_tsk_thread_flag(thread->et_task, TIF_APC);

	/* Return it */
	if (PreviousSuspendCount){
		if (UserMode == previous_mode) {
			if (copy_to_user(PreviousSuspendCount, &prev, sizeof(ULONG))) {
				status = STATUS_UNSUCCESSFUL;
				goto out;
			}
		} else
			*PreviousSuspendCount = prev;
	}

out:
	/* Dereference and Return */
	deref_object((PVOID)thread);
	return status;
}
EXPORT_SYMBOL(NtSuspendThread);

NTSTATUS SERVICECALL
NtAlertThread (IN HANDLE ThreadHandle)
{
	KPROCESSOR_MODE previous_mode = (KPROCESSOR_MODE)get_pre_mode();
	struct ethread * thread;
	NTSTATUS status;

	ktrace("\n");
	/* Reference the Object */
	status = ref_object_by_handle(ThreadHandle,
			THREAD_SUSPEND_RESUME,
			thread_object_type,
			previous_mode,
			(PVOID*)&thread,
			NULL);
	if (status)
		return status; 

	/* 
	 * Do an alert depending on the processor mode. If some kmode code wants to 
	 * enforce a umode alert it should call KeAlertThread() directly. If kmode 
	 * code wants to do a kmode alert it's sufficient to call it with Zw or just 
	 * use KeAlertThread() directly 
	 */ 
	alert_thread(&thread->tcb, previous_mode); 

	/* Dereference Object */
	deref_object(thread);

	/* Return status */
	return status;

}
EXPORT_SYMBOL(NtAlertThread);

NTSTATUS SERVICECALL
NtAlertResumeThread(IN  HANDLE ThreadHandle,
		OUT PULONG SuspendCount)
{
	KPROCESSOR_MODE previous_mode = (KPROCESSOR_MODE)get_pre_mode();
	struct ethread * thread;
	NTSTATUS status;
	ULONG previous_state;

	ktrace("\n");
	/* Reference the Object */
	status = ref_object_by_handle(ThreadHandle,
			THREAD_SUSPEND_RESUME,
			thread_object_type,
			previous_mode,
			(PVOID*)&thread,
			NULL);
	if (status)
		return status; 

	/* Call the Kernel Function */ 
	previous_state = alert_resume_thread(&thread->tcb); 

	/* Dereference Object */ 
	deref_object(thread); 

	if (SuspendCount) { 
		if (UserMode == previous_mode) {
			if(copy_to_user(SuspendCount, &previous_state, sizeof(ULONG)))  
				return STATUS_UNSUCCESSFUL;
		} else
			*SuspendCount = previous_state;
	}

	return status;
}
EXPORT_SYMBOL(NtAlertResumeThread);

NTSTATUS SERVICECALL
NtDelayExecution(IN BOOLEAN Alertable,
		IN PLARGE_INTEGER DelayInterval)
{
	/* TODO */
	return 0;
}
EXPORT_SYMBOL(NtDelayExecution);

#endif /* CONFIG_UNIFIED_KERNEL */
