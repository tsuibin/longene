/*
 * ke.h
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
 * ke.h:
 * Refered to ReactOS code
 */

#ifndef _KE_H
#define _KE_H

#include "win32.h"
#include "win32_thread.h"

#ifdef CONFIG_UNIFIED_KERNEL
/* 
 * get_pre_mode() should be defined like: 
 * #define get_pre_mode() get_current_ethread()->tcb.previous_mode
 *
 * Temporarily, we define it as "UserMode" 
 */
#define	get_pre_mode()	UserMode

typedef enum _KOBJECTS {
	EventSynchronizationObject = 10,
	EventNotificationObject = 11,
	MutantObject = 12,
	ProcessObject = 13,
	QueueObject = 14,
	SemaphoreObject = 15,
	ThreadObject = 16,
	GateObject = 17,
	TimerNotificationObject = 18,
	TimerSynchronizationObject = 19,
	Spare2Object = 20,
	Spare3Object = 21,
	Spare4Object = 22,
	Spare5Object = 23,
	Spare6Object = 24,
	Spare7Object = 25,
	Spare8Object = 26,
	Spare9Object = 27,
	ApcObject = 28,
	DpcObject = 29,
	DeviceQueueObject = 30,
	EventPairObject = 31,
	InterruptObject = 32,
	ProfileObject = 33,
	ThreadedDpcObject = 34,
	MaximumKernelObject = 35,

	CLIPBOARD = 81,
	CONSOLE_INPUT,
	CONSOLE_INPUT_EVENTS,
	SCREEN_BUFFER,
	IOCTL_CALL,
	DEVICE_MANAGER,   /* 86 */
	DEVICE,
	MAILSLOT,
	MAIL_WRITER,
	MAILSLOT_DEVICE,
	NAMED_PIPE,       /* 91 */
	PIPE_SERVER,
	PIPE_CLIENT,
	NAMED_PIPE_DEVICE,
	SERIAL,
	SNAPSHOT,         /* 96 */
	TIMER,
	ASYNC,
	ASYNC_QUEUE,
	_DIR,
	COMPLETION,       /* 101 */
	_OBJECT_TYPE,
	DIRECTORY,
	FD,
	FD_DEVICE,
	INODE,            /* 106 */
	FILE_LOCK,
	_FILE,
	MAPPING,
	SYMLINK,
	_TOKEN,           /* 111 */
	W32EVENT,
	ATOM_TABLE,
	HOOK_TABLE,
	MSG_QUEUE,
	THREAD_INPUT,     /* 116 */
	WINSTATION,
	DESKTOP,
	HANDLE_TABLE,
	PROCESS,
	STARTUP_INFO,     /* 121 */
	THREAD_APC,
	THREAD,
	SOCK
} KOBJECTS;

static inline int is_wine_object(KOBJECTS type)
{
	return (type > 80); 
};

typedef LONG KPRIORITY;

static inline void enter_critical_region(void)
{
	struct ethread	*thread = current->ethread;

	if (thread)
		thread->tcb.kernel_apc_disable--;
}

static inline void leave_critical_region(void)
{
	struct ethread	*thread = current->ethread;

	/* FIXME: kernel apc check */
	if (thread && ++thread->tcb.kernel_apc_disable == 0) {
#if 0 
		if (list_empty(&CurrentThread->apc_state.apc_list_head[KernelMode]))
			KiKernelApcDeliveryCheck();
#endif
	}
}

BOOLEAN is_object_signaled(struct dispatcher_header *, struct kthread *);

extern void query_sys_time(large_integer_t *CurrentTime);

#endif /* CONFIG_UNIFIED_KERNEL */
#endif /* _KE_H */
