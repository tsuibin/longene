/*
 * attach.c
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
 * attach.c: attach to another process
 * Refered to ReactOS code
 */
#include "attach.h"
#include <asm/pgtable.h>

#ifdef CONFIG_UNIFIED_KERNEL

VOID set_page_table_dir(long X)
{
	__asm__ __volatile__(
		"movl %0, %%cr3\n\t"
		:
		:"r"(X));
} /* end set_page_table_dir */
EXPORT_SYMBOL(set_page_table_dir);

/*
 * update_page_dir
 */
VOID
STDCALL
update_page_dir(struct mm_struct *mm, PVOID Address, ULONG Size)
{
	ULONG offset, start_offset, end_offset;
	struct mm_struct *current_mm = current->mm;

	if (Address < (PVOID)TASK_SIZE) {
		return;
	}

	spin_lock(&mm->page_table_lock);

	start_offset = 	pgd_index((ULONG)Address);
	end_offset = pgd_index((ULONG)Address+ Size);

	for (offset = start_offset; offset <= end_offset; offset++) {
		pgd_t *pgd = (pgd_t *)(mm->pgd + offset);
		if (!pgd->pgd)
			pgd->pgd = ((pgd_t *)(current_mm->pgd + offset))->pgd;
	}
	spin_unlock(&mm->page_table_lock);
} /* end update_page_dir */
EXPORT_SYMBOL(update_page_dir);

/*
 * repair_list
 */
VOID repair_list(struct list_head *Original,
		struct list_head *Copy,
		KPROCESSOR_MODE Mode)
{
	/* Copy Source to Desination */
	if (list_empty(&Original[(int)Mode]))
		INIT_LIST_HEAD(&Copy[(int)Mode]);
	else {
		Copy[(int)Mode].next = Original[(int)Mode].next;
		Copy[(int)Mode].prev = Original[(int)Mode].prev;
		Original[(int)Mode].next->prev = &Copy[(int)Mode];
		Original[(int)Mode].prev->next = &Copy[(int)Mode];
	}
} /* end repair_list */
EXPORT_SYMBOL(repair_list);

/*
 * move_apc_state
 */
VOID
STDCALL
move_apc_state(struct  kapc_state *OldState,
		struct  kapc_state *NewState)
{
	/* Restore backup of Original Environment */
	*NewState = *OldState;

	/* Repair Lists */
	repair_list(NewState->apc_list_head, OldState->apc_list_head, KernelMode);
	repair_list(NewState->apc_list_head, OldState->apc_list_head, UserMode);
} /* end move_apc_state */

/* 
 * attach_process
 */
struct mm_struct *
attach_process(struct kprocess *Process)
{
	struct ethread *current_ethread = get_current_ethread();
	struct ethread *thread;
	struct kthread *tcb;
	struct mm_struct *mm, *old_mm;

	thread = get_first_thread((struct eprocess *)Process);
	mm = thread ? thread->et_task->mm : current->mm;

	tcb = &current_ethread->tcb;

	/* Make sure that we are in the right page directory */
	update_page_dir(mm, (PVOID)tcb->stack_limit, MM_STACK_SIZE);
	update_page_dir(mm, (PVOID)thread, sizeof(struct ethread));

	local_irq_disable();

	/* Increase Stack Count */
	Process->stack_count++;

	/* Swap the APC Environment */
	move_apc_state(&tcb->apc_state, &tcb->saved_apc_state);

	/* Reinitialize APC State */
	INIT_LIST_HEAD(&tcb->apc_state.apc_list_head[KernelMode]);
	INIT_LIST_HEAD(&tcb->apc_state.apc_list_head[UserMode]);
	tcb->apc_state.process = Process;
	tcb->apc_state.kapc_inprogress = FALSE;
	tcb->apc_state.kapc_pending = FALSE;
	tcb->apc_state.uapc_pending = FALSE;

	/* Update Environment Pointers */
	tcb->apc_state_pointer[OriginalApcEnvironment] = &tcb->saved_apc_state;
	tcb->apc_state_pointer[AttachedApcEnvironment] = &tcb->apc_state;
	tcb->apc_state_index = AttachedApcEnvironment;
	
	/* Swap the Processes */
	set_page_table_dir(__pa(mm->pgd));

	old_mm = current->mm;
	current->mm = mm;

	local_irq_enable();
	return old_mm;
} /* end attach_process */
EXPORT_SYMBOL(attach_process);

/*
 * detach_process
 */
VOID
STDCALL
detach_process (struct mm_struct *mm)
{
	struct ethread *thread = get_current_ethread();

	local_irq_disable();

	/* Decrease Stack Count */
	thread->threads_process->pcb.stack_count--;

	/* Restrore the APC State */
	move_apc_state(&thread->tcb.saved_apc_state, &thread->tcb.apc_state);
	thread->tcb.saved_apc_state.process = NULL;
	thread->tcb.apc_state_pointer[OriginalApcEnvironment] = &thread->tcb.apc_state;
	thread->tcb.apc_state_pointer[AttachedApcEnvironment] = &thread->tcb.saved_apc_state;
	thread->tcb.apc_state_index = OriginalApcEnvironment;

	/* Swap Processes */
	set_page_table_dir(__pa(mm->pgd));

	current->mm = mm;
	local_irq_enable();
} /* end detach_process */
EXPORT_SYMBOL(detach_process);
#endif /* CONFIG_UNIFIED_KERNEL */
