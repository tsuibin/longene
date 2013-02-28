/*
 * wait.c
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
 * wait.c: thread wait on object 
 * Refered to Kernel-win32 code
 */
#include <linux/poll.h>
#include "semaphore.h"
#include "wineserver/lib.h"

#ifdef CONFIG_UNIFIED_KERNEL

/* Tells us if the Timer or Event is a Syncronization or Notification Object */
#define TIMER_OR_EVENT_TYPE 0x7L

/* One of the Reserved Wait Blocks, this one is for the Thread's Timer */
#define TIMER_WAIT_BLOCK 0x3L

#define SynchronizationObject 2
#define NotificationObject 3

void call_kapc(void){
	/* FIXME */
}
EXPORT_SYMBOL(call_kapc);

void msg_queue_remove_queue(struct object *obj, struct w32thread *thread );

extern int is_signaled(struct msg_queue *queue);

void proc_msg_queue(struct object *obj, struct kthread *Thread)
{
	ktrace("obj->header.type=%d\n", obj->header.type);
	if(is_wine_object(obj->header.type) && (obj->header.type == MSG_QUEUE)) {
		msg_queue_remove_queue(obj, Thread->win32thread); 
	}
}

struct poll_param {
	int		poll_count;
	int		*indexs;
	int		timeout;	/* msec */
	struct pollfd	*pfds;
};

VOID
STDCALL
block_thread(PNTSTATUS Status,
		UCHAR Alertable,
		ULONG WaitMode,
		UCHAR WaitReason,
		PULONG_PTR Timeout,
		struct poll_param *poll_param)
{
	struct kthread * thread = (struct kthread *)get_current_ethread();
	struct kwait_block * wait_block;

	ktrace("\n");
	if (thread->apc_state.kapc_pending) {
		/* Remove Waits */
		wait_block = thread->wait_block_list;
		do {
			proc_msg_queue(wait_block->object, thread); /* TBD, D.M. */
			list_del(&wait_block->wait_list_entry);
			wait_block = wait_block->next_wait_block;
		} while (wait_block!= thread->wait_block_list);
		thread->wait_block_list = NULL;

		/* Ready Dispatch it and return status */
		call_kapc();

		if (Status != NULL) *Status = STATUS_KERNEL_APC;

		if (poll_param->poll_count) {
			kfree(poll_param->pfds);
			kfree(poll_param->indexs);
			poll_param->poll_count = 0;
		}
	} else {
		/* Set the Thread Data as Requested */
		thread->alertable = Alertable;
		thread->wait_mode = (UCHAR)WaitMode;
		thread->wait_reason = WaitReason;

		if (poll_param->poll_count) {
			int i, n, index;
			unsigned long long tt;
			asm volatile ("rdtsc\n" : "=A"(tt));

			kdebug("%08llx: poll, n=%d\n", tt, poll_param->poll_count);
			n = poll(poll_param->pfds, poll_param->poll_count, poll_param->timeout);
			if (n < 0) {
				/* TODO */
			} else if (!n)	{ /* timeout */
				kdebug("poll timeout, %d\n", poll_param->timeout);
				*Timeout = 0;
			} else {
				if (poll_param->pfds[0].revents)
					index = ((struct kthread *)current->ethread)->wait_status;
				else
					index = 0x7fffffff;
				for (i = 1; i < poll_param->poll_count; i++) { /* dummy fd not checked */
					kdebug("n %d revents %x\n", n, poll_param->pfds[i].revents);
					if (poll_param->pfds[i].revents && index > poll_param->indexs[i])
						index = poll_param->indexs[i];
					((struct kthread *)current->ethread)->wait_status = index;
					kdebug("fd %d, status %ld\n", poll_param->pfds[i].fd, ((struct kthread*)current->ethread)->wait_status);
				}
			}
			kfree(poll_param->pfds);
			kfree(poll_param->indexs);
			poll_param->poll_count = 0;
		} else {
			BOOL timeout = *Timeout ? TRUE : FALSE;

			local_irq_enable();
			set_current_state(TASK_INTERRUPTIBLE);
			*Timeout = schedule_timeout(*Timeout);
			local_irq_disable();

			if (((struct kthread *)current->ethread)->wait_status == STATUS_USER_APC) {
				set_tsk_thread_flag(current, TIF_APC);
				if (Status)
					*Status = STATUS_USER_APC;
				return;
			}
			if (!timeout) {
				*Status = STATUS_TIMEOUT;
				return;
			}
		}

		/* Dispatch it and return status */
		if (signal_pending(current)) {
			/* thread is signaled
			 * Remove Waits */
			wait_block = thread->wait_block_list;
			do {
				proc_msg_queue(wait_block->object, thread); /* TBD */
				list_del(&wait_block->wait_list_entry);
				wait_block = wait_block->next_wait_block;
			} while (wait_block!= thread->wait_block_list);
			thread->wait_block_list = NULL;
			*Status = -EINTR; /* Linux error code for special check */
			return;
		}

		if(Status) {
			if (!(*Timeout)){ 
				/* thread is signaled
				 * Remove Waits */
				wait_block = thread->wait_block_list;
				do {
					proc_msg_queue(wait_block->object, thread);  /* TBD */
					list_del(&wait_block->wait_list_entry);
					wait_block = wait_block->next_wait_block;
				} while (wait_block!= thread->wait_block_list);
				thread->wait_block_list = NULL;
				*Status = STATUS_TIMEOUT;
			} else *Status = ((struct kthread * )current->ethread)->wait_status;
		}
	}
}
EXPORT_SYMBOL(block_thread);

VOID
inline
check_alert(BOOLEAN Alertable,
		struct kthread *CurrentThread,
		KPROCESSOR_MODE WaitMode,
		PNTSTATUS Status)
{
	/* At this point, we have to do a wait, so make sure we can make the thread Alertable if requested */
	if (Alertable) {

		/* If the Thread is Alerted, set the Wait Status accordingly */
		if (CurrentThread->alerted[(int)WaitMode]) {
			CurrentThread->alerted[(int)WaitMode] = false;
			*Status = STATUS_ALERTED;

			/* If there are User APCs Pending, then we can't really be alertable */
		} else if ((!list_empty(&CurrentThread->apc_state.apc_list_head[UserMode])) &&
				(WaitMode == UserMode)) {
			CurrentThread->apc_state.uapc_pending= true;
			*Status = STATUS_USER_APC;
		}

		/* If there are User APCs Pending and we are waiting in usermode, then we must notify the caller */
	} else if ((CurrentThread->apc_state.uapc_pending) && (WaitMode == UserMode)) {
		*Status = STATUS_USER_APC;
	}

	*Status = STATUS_WAIT_0;
}
EXPORT_SYMBOL(check_alert);

VOID
satisfy_object_wait(struct dispatcher_header * Object,
		struct kthread *Thread)
{
	ktrace("obj %p, type=%d\n", Object, Object->type);
	if (is_wine_object(Object->type)) {
		struct object *obj = (struct object*)Object;
		if (BODY_TO_HEADER(obj)->ops->satisfied)
			BODY_TO_HEADER(obj)->ops->satisfied(obj, Thread->win32thread);
		return;
	}
	/* Special case for Mutants */ 
	if (Object->type == MutantObject) { 
		Object->signal_state--; 

		/* Check if it's now non-signaled */ 
		if (Object->signal_state == 0)  { 
			((struct kmutant *)Object)->owner_thread = Thread; 
			Thread->kernel_apc_disable -= ((struct kmutant *)Object)->apc_disable; 

			/* Check if it's abandoned */ 
			if (((struct kmutant *)Object)->abandoned) { 
				/* Unabandon it */ 
				((struct kmutant *)Object)->abandoned = FALSE; 
				Thread->wait_status = STATUS_ABANDONED; 
			} 

			list_add(&((struct kmutant *)Object)->mutant_list_entry, &Thread->mutant_list_head); 
		} 
	} else if ((Object->type & TIMER_OR_EVENT_TYPE) == SynchronizationObject) { 
		Object->signal_state= 0; 
	} else if (Object->type == SemaphoreObject) {
		Object->signal_state--; 
	}
	ktrace("done\n");
}

void
satisfy_multi_obj_waits(struct kwait_block * WaitBlock)
{ 
	struct kwait_block * first_block = WaitBlock; 
	struct kthread * wait_thread = WaitBlock->thread; 

	/* Loop through all the Wait Blocks, and wake each Object */ 
	do { 
		/* Wake the Object */ 
		satisfy_object_wait(WaitBlock->object, wait_thread); 
		WaitBlock = WaitBlock->next_wait_block; 
	} while (WaitBlock != first_block);
}

NTSTATUS
STDCALL
wait_for_single_object(PVOID Object,
		KWAIT_REASON WaitReason,
		KPROCESSOR_MODE WaitMode,
		BOOLEAN Alertable,
		PLARGE_INTEGER Timeout)
{
	NTSTATUS status;
	struct kwait_block wait_block[MAXIMUM_WAIT_OBJECTS];

	ktrace("\n");
	status = wait_for_multi_objs(1,
				&Object,
				WaitAll,
				UserRequest,
				WaitMode,
				Alertable,
				Timeout,
				wait_block);
	return status;
}
EXPORT_SYMBOL(wait_for_single_object);

BOOL
is_object_waitable(PVOID Object)
{
	return 0;
}


VOID
wait_test(struct dispatcher_header * Object,
		KPRIORITY Increment)
{
	struct list_head * wait_entry; 
	struct list_head * wait_list; 
	struct kwait_block * cur_wait_block; 
	struct kwait_block * next_wait_block; 
	struct kthread * wait_thread; 
	int is_wine_obj = is_wine_object(Object->type);

	wait_list = &Object->wait_list_head; /* TODO kernel */
	wait_entry = wait_list->next; 

	while ((wait_entry != wait_list) && (Object->signal_state > 0)) {
		/* Get the current wait block */ 
		cur_wait_block = list_entry(wait_entry, struct kwait_block, wait_list_entry);
		wait_thread = cur_wait_block->thread;

		if (cur_wait_block->wait_type == WaitAny) {
			wait_entry = wait_entry->prev;   
			/* because this entry will be removed from the queue */
			satisfy_object_wait(Object, wait_thread); 
		} else {
			next_wait_block = cur_wait_block->next_wait_block; 

			/* Loop first to make sure they are valid */ 
			while (next_wait_block != cur_wait_block) {
				if (!is_object_signaled(next_wait_block->object, wait_thread)) { 
					/* It's not, move to the next one */ 
					goto SkipUnwait; 
				} 

				next_wait_block = next_wait_block->next_wait_block;
			} 

			/* All the objects are signaled, we can satisfy */ 
			wait_entry = wait_entry->prev;  
			/* because this entry will be removed from the queue */
			satisfy_multi_obj_waits(cur_wait_block); 
		} /* end Wait_All */

		if (!is_wine_obj) {
			struct w32thread *w32thread = wait_thread->win32thread;

			if (w32thread) w32thread->wake_up = 1;
		} 
		if (Object->type == CONSOLE_INPUT_EVENTS) {
			struct w32thread *w32thread = wait_thread->win32thread;

			if (w32thread) w32thread->wake_up = 1;
		}
		/* All waits satisfied, unwait the thread */
		abort_wait_thread(wait_thread, cur_wait_block->wait_key, Increment); 

SkipUnwait: 
		wait_entry = wait_entry->next; 
	} 

}
EXPORT_SYMBOL(wait_test);

int msg_queue_add_queue(struct object *obj, struct w32thread* thread);

int is_waitible_object(KOBJECTS type)
{
	switch(type)
	{
	case MSG_QUEUE:
	case SOCK:
		return 1;
	default:
    	return 0;
	}
}

extern int extract_unix_fd(struct fd *fdp);

void free_wait_block(struct kwait_block *WaitBlockArray)
{
	struct kwait_block * wait_block = WaitBlockArray;
	struct list_head *entry;
	void *prev, *next;
	do
	{
        entry = &wait_block->wait_list_entry;
		prev = entry->prev;
		next = entry->next;
		if((next!= entry) && (next != LIST_POISON1))
		{
			list_del(entry);
		}
		wait_block = wait_block->next_wait_block;
	} while (wait_block != WaitBlockArray);
}

NTSTATUS 
STDCALL
wait_for_multi_objs(ULONG Count,
		PVOID Object[],
		WAIT_TYPE WaitType,
		KWAIT_REASON WaitReason,
		KPROCESSOR_MODE WaitMode,
		BOOLEAN Alertable,
		PLARGE_INTEGER Timeout,
		struct kwait_block *WaitBlockArray)
{
	struct dispatcher_header * cur_obj;
	struct kwait_block * wait_block;
	struct kthread * cur_thread = (struct kthread *)get_current_ethread();
	unsigned long all_objects_signaled;
	unsigned long wait_index;
	NTSTATUS status, wait_status;
	struct timespec ts;
	long timeout;
	int poll_index = 0;
	struct fd *fdp;
	struct poll_param poll_param = { .poll_count = 0 };

	if (Timeout) {
		s32 rem;
		ts.tv_sec = div_s64_rem(-Timeout->QuadPart * 100, 1000000000, &rem);
		ts.tv_nsec = rem;
		timeout = timespec_to_jiffies(&ts) + (ts.tv_sec || ts.tv_nsec);
	}
	else
		timeout = MAX_SCHEDULE_TIMEOUT;

	/* Check if the lock is already held */
	if (cur_thread->wait_next)  {
		/* Lock is held, disable Wait Next */
		cur_thread->wait_next = false;
	} else {
		local_irq_disable();
		/* FIXME Lock not held, acquire it */
	}

	if (Count == 0) {
		block_thread(&status, Alertable, WaitMode, WaitReason, &timeout, &poll_param);
		local_irq_enable();
		return status;
	}

	/* Make sure the Wait Count is valid for the Thread and Maximum Wait Objects */
	if (!WaitBlockArray) {
		/* FIXME Debug Check in regards to the Thread Object Limit */

		/* Use the Thread's Wait Block */
		WaitBlockArray = &cur_thread->wait_block[0];
	} else {
		/* FIXME Using our own Block Array. Check in regards to System Object Limit */
	}

	/* Start the actual Loop */
	do {
		wait_status = cur_thread->wait_status;
		cur_thread->wait_block_list = wait_block = WaitBlockArray;
		all_objects_signaled = true;

		/* First, we'll try to satisfy the wait directly */
		for (wait_index = 0; wait_index < Count; wait_index++) {
			cur_obj = (struct dispatcher_header * )Object[wait_index];
			if (is_waitible_object(cur_obj->type)
					&& BODY_TO_HEADER(cur_obj)->ops->get_fd
					&& (fdp = BODY_TO_HEADER(cur_obj)->ops->get_fd((struct object *)cur_obj))) {
				release_object(fdp);
				poll_param.poll_count++;
			}

			if (cur_obj->type == IO_TYPE_FILE) {
				cur_obj = (struct dispatcher_header *)(&((PFILE_OBJECT)cur_obj)->Event);
			}

			if (is_object_signaled(cur_obj, cur_thread)) {
				if (WaitType == WaitAny) {
					if (cur_obj->signal_state!= (LONG)MINLONG) {
						/* It has a normal signal state, so unwait it and return */
						satisfy_object_wait(cur_obj, cur_thread);
						if(STATUS_ABANDONED == cur_thread->wait_status)
							status = cur_thread->wait_status = (STATUS_ABANDONED | wait_index);
						else
							status = STATUS_WAIT_0 | wait_index;
						goto WaitDone;

					} else {
						/* Is this a Mutant? */
						if (cur_obj->type == MutantObject) {
							/* FIXME exception*/
						}
					}
				}

			} else {
				/* One of the objects isn't signaled... if this is a WaitAll, we will fail later */
				all_objects_signaled = false;
			}

			/* Set up a Wait Block for this Object */
			wait_block->object = cur_obj;
			wait_block->thread = cur_thread;
			if(WaitAny == WaitType)
				wait_block->wait_key = (USHORT)(STATUS_WAIT_0 + wait_index);
			else  
				wait_block->wait_key = (USHORT)(STATUS_WAIT_0);
			wait_block->wait_type = (USHORT)WaitType;
			wait_block->next_wait_block = wait_block + 1;

			wait_block = wait_block->next_wait_block;
		}

		/* Return to the Root Wait Block */
		wait_block--;
		wait_block->next_wait_block = WaitBlockArray;

		if ((WaitType == WaitAll) && (all_objects_signaled)) {
			wait_block = cur_thread->wait_block_list;

			satisfy_multi_obj_waits(wait_block);
			if(STATUS_ABANDONED == cur_thread->wait_status)
				status = STATUS_ABANDONED_WAIT_0;
			else status = STATUS_WAIT_0;
			goto WaitDone;
		}

		/* Now we have to wait, otherwise we will not be here. */
		current_thread->wake_up = 0;
		if (poll_param.poll_count) {
			poll_param.poll_count++;  /* for dummyfile */
			if (timeout == MAX_SCHEDULE_TIMEOUT)
				poll_param.timeout = -1;
			else
				poll_param.timeout = ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
			poll_param.pfds = kmalloc(poll_param.poll_count * sizeof(struct pollfd), GFP_KERNEL);
			poll_param.pfds[0].fd = current_thread->process->dummyfd;
			poll_param.pfds[0].events = POLLIN | POLLHUP | POLLERR;
			poll_param.pfds[0].revents = 0;
			poll_param.indexs = kmalloc(poll_param.poll_count * sizeof(int), GFP_KERNEL);
		}
		poll_index = 1;
		/* Make sure we can satisfy the Alertable request */
		check_alert(Alertable, cur_thread, WaitMode, &status);

		cur_thread->wait_status = status;
		wait_block = cur_thread->wait_block_list;

		do {
			cur_obj = wait_block->object;
			if (is_wine_object(cur_obj->type)) {
				struct object *obj = (struct object*)cur_obj;
				if (is_waitible_object(cur_obj->type)
						&& BODY_TO_HEADER(obj)->ops->get_fd
						&& (fdp = BODY_TO_HEADER(obj)->ops->get_fd(obj))) { /* like msg_queue, sock, ... */
					poll_param.pfds[poll_index].fd = extract_unix_fd(fdp);
					poll_param.pfds[poll_index].events = POLLIN | POLLHUP | POLLERR;
					poll_param.pfds[poll_index].revents = 0;
					poll_param.indexs[poll_index] = wait_block->wait_key;
					poll_index++;
					release_object(fdp);
				}
				if(cur_obj->type == MSG_QUEUE) {
				}
			}
			INIT_LIST_HEAD(&wait_block->wait_list_entry);
			list_add(&wait_block->wait_list_entry, &cur_obj->wait_list_head);
			wait_block = wait_block->next_wait_block;
		} while (wait_block != WaitBlockArray);

		/* block current thread */
		block_thread(&status, Alertable, WaitMode,
				(UCHAR)WaitReason, &timeout, &poll_param);

		free_wait_block(WaitBlockArray);
		poll_index = 0;

		/* Check if we were executing an APC */
		if (status != STATUS_KERNEL_APC) {
			local_irq_enable();
			return status;
		}
	} while (true);

WaitDone:
	local_irq_enable();
	/* Release the Lock, we are done */
	if (Timeout) {
		jiffies_to_timespec(timeout, &ts);
		Timeout->QuadPart = -(ts.tv_sec * 10000000L + ts.tv_nsec / 100);
	}

	return status;
}
EXPORT_SYMBOL(wait_for_multi_objs);

/* Must be called with the dispatcher lock held */
VOID
abort_wait_thread(struct kthread *Thread,
		NTSTATUS WaitStatus,
		KPRIORITY Increment)
{
	struct kwait_block *  wait_block; 

	/* If we are blocked, we must be waiting on something also */ 
	if(!((((struct ethread *) Thread)->et_task->state & 
					(TASK_STOPPED | TASK_TRACED | TASK_INTERRUPTIBLE | TASK_UNINTERRUPTIBLE)) 
				&& Thread->wait_block_list != NULL))
		return;

	wait_block = Thread->wait_block_list; 
	do {
		proc_msg_queue(wait_block->object, Thread); /* TBD */
		list_del(&wait_block->wait_list_entry); 
		wait_block = wait_block->next_wait_block; 
	} while (wait_block != Thread->wait_block_list); 

	if(STATUS_ABANDONED == Thread->wait_status) Thread->wait_status += WaitStatus - STATUS_WAIT_0;
	else Thread->wait_status = WaitStatus;

	/* FIXME : Check if there's a Thread Timer */ 

	/* Reschedule the Thread */ 
	set_tsk_need_resched(current);
	wake_up_process(((struct ethread *)Thread)->et_task);
}
EXPORT_SYMBOL(abort_wait_thread);

BOOLEAN
is_object_signaled(struct dispatcher_header *Object, struct kthread *Thread)
{
	ktrace("\n");
	if (is_wine_object(Object->type)) {
		struct object *obj = (struct object*)Object;
		if (BODY_TO_HEADER(obj)->ops->signaled)
			return BODY_TO_HEADER(obj)->ops->signaled(obj, Thread->win32thread);
		else
			return FALSE;
	}
	/* Mutants are...well...mutants! */
	if (Object->type == MutantObject) {
		/* Because Cutler hates mutants, they are actually signaled if the Signa
		 * l State is <= 0
		 *          * Well, only if they are recursivly acquired (i.e if we own it right no
		 *          w).
		 *                   * Of course, they are also signaled if their signal state is 1.  */
		if ((Object->signal_state <= 0 && ((struct kmutant *)Object)->owner_thread == Thread)
				|| (Object->signal_state >= 1)) {
			if(Object->signal_state >= 1) Object->signal_state =1;
			/* Signaled Mutant */
			return true;
		} else {
			/* Unsignaled Mutant */
			return false;
		}
	}

	/* Any other object is not a mutated freak, so let's use logic */
	return (!Object->signal_state <= 0);
}

#endif /* CONFIG_UNIFIED_KERNEL */
