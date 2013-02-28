/*
 * objwait.h
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
 * objwait.h: win32 wait table definition
 * Refered to Kernel-win32 code
 */

#ifndef _OBJWAIT_H
#define _OBJWAIT_H

#include <linux/module.h>
#include "object.h"
#include "ke.h"
#include "ntstatus.h"

#ifdef CONFIG_UNIFIED_KERNEL

#define MAXIMUM_WAIT_OBJECTS	64

#define WAIT_OBJECT_0		(STATUS_WAIT_0 + 0)
#define WAIT_ABANDONED		(STATUS_ABANDONED_WAIT_0 + 0)
#define WAIT_ABANDONED_0	(STATUS_ABANDONED_WAIT_0 + 0)
#define WAIT_TIMEOUT		STATUS_TIMEOUT

#define DECLARE_SINGLE_WAIT(VAR,OBJ) \
	struct wait_table VAR = { \
		&VAR.wt_entries[1], \
		{{ __WAITQUEUE_INITIALIZER("InternalWait", current), \
			 (OBJ), 0 }} \
	}

struct wait_table_entry {
	/* note wte_wait must always be _first_ */
	wait_queue_t	wte_wait;	/* link in queue waiting on object */
	void		*wte_obj;	/* object being waited upon */
	int		wte_data;	/* object specific data */
};

struct wait_table {
	struct wait_table_entry	*wt_last;
	struct wait_table_entry	wt_entries[1];
};

extern int do_wait_for_objects(struct ethread *, struct wait_table *, long *);

NTSTATUS STDCALL
wait_for_single_object(PVOID Object,
		KWAIT_REASON WaitReason,
		KPROCESSOR_MODE WaitMode,
		BOOLEAN Alertable,
		PLARGE_INTEGER Timeout);

NTSTATUS STDCALL
wait_for_multi_objs(ULONG Count,
		PVOID Object[],
		WAIT_TYPE WaitType,
		KWAIT_REASON WaitReason,
		KPROCESSOR_MODE WaitMode,
		BOOLEAN Alertable,
		PLARGE_INTEGER Timeout,
		struct kwait_block *WaitBlockArray);

NTSTATUS SERVICECALL NtWaitForMultipleObjects(ULONG,PHANDLE,WAIT_TYPE,BOOLEAN,PLARGE_INTEGER);

VOID
wait_test(struct dispatcher_header * Object,
	KPRIORITY Increment);

VOID
abort_wait_thread(struct kthread *Thread,
		NTSTATUS WaitStatus,
		KPRIORITY Increment);

#endif /* CONFIG_UNIFIED_KERNEL */
#endif /* _OBJWAIT_H */
