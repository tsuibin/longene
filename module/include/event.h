/*
 * event.h
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
 * event.h: win32 event definition
 * Refered to Kernel-win32 code
 */

#ifndef _EVENT_H
#define _EVENT_H

#include <linux/module.h>
#include "win32.h"
#include "thread.h"
#include "process.h"
#include "objwait.h"
#include "apc.h"

#ifdef CONFIG_UNIFIED_KERNEL
/*
 * event object definition
 */
#define EVENT_QUERY_STATE (0x0001)
#define EVENT_MODIFY_STATE (0x0002)
#define EVENT_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3)

#define EVENT_INCREMENT		1

VOID init_event_implement(VOID);

NTSTATUS SERVICECALL NtCreateEvent(OUT PHANDLE EventHandle,
              	IN ACCESS_MASK DesiredAccess,
              	IN POBJECT_ATTRIBUTES ObjectAttributes,
              	IN EVENT_TYPE EventType,
              	IN BOOLEAN InitialState);

NTSTATUS SERVICECALL NtOpenEvent(OUT PHANDLE EventHandle,
            		IN ACCESS_MASK DesiredAccess,
            		IN POBJECT_ATTRIBUTES ObjectAttributes);

LONG STDCALL set_event(struct kevent *Event,
		KPRIORITY Icrement,
		BOOLEAN Wait);

NTSTATUS SERVICECALL NtSetEvent(IN HANDLE EventHandle,
           		OUT PLONG PreviousState);

LONG STDCALL reset_event(struct kevent *Event);

NTSTATUS SERVICECALL NtResetEvent(IN HANDLE EventHandle,
             	OUT PLONG PreviousState);

LONG STDCALL pulse_event(IN struct kevent *Event,
		IN KPRIORITY Increment,
		IN BOOLEAN Wait);

NTSTATUS SERVICECALL NtPulseEvent(IN HANDLE EventHandle,
            		OUT PLONG PreviousState);

VOID STDCALL event_init(struct kevent *event,
		enum event_type type,
		BOOLEAN state);

struct kevent *get_event_obj(struct w32process *process, obj_handle_t handle, 
		unsigned int access);
#endif /* CONFIG_UNIFIED_KERNEL */
#endif /* _EVENT_H */
