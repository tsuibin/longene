/*
 * event.c
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
 * event.c: event syscall functions
 * Refered to Kernel-win32 code
 */

#include "event.h"
#include "unistr.h"
#include "handle.h"

#ifdef CONFIG_UNIFIED_KERNEL

POBJECT_TYPE event_object_type = NULL;
EXPORT_SYMBOL(event_object_type);

static GENERIC_MAPPING event_mapping = {
	STANDARD_RIGHTS_READ | SYNCHRONIZE | EVENT_QUERY_STATE,
	STANDARD_RIGHTS_WRITE | SYNCHRONIZE | EVENT_MODIFY_STATE,
	STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE | EVENT_QUERY_STATE,
	EVENT_ALL_ACCESS};

static WCHAR event_type_name[] = {'E', 'v', 'e', 'n', 't', 0};

extern VOID STDCALL event_init(struct kevent *event, enum event_type type, BOOLEAN state);

extern void display_object_dir(POBJECT_DIRECTORY DirectoryObject, LONG Depth);

extern HANDLE base_dir_handle;

VOID
init_event_implement(VOID)
{
	OBJECT_TYPE_INITIALIZER ObjectTypeInitializer;
	UNICODE_STRING Name;

	memset(&ObjectTypeInitializer, 0, sizeof(ObjectTypeInitializer));
	init_unistr(&Name, (PWSTR)event_type_name);
	ObjectTypeInitializer.Length = sizeof(ObjectTypeInitializer);
	ObjectTypeInitializer.DefaultNonPagedPoolCharge = sizeof(struct kevent);
	ObjectTypeInitializer.GenericMapping = event_mapping;
	ObjectTypeInitializer.PoolType = NonPagedPool;
	ObjectTypeInitializer.ValidAccessMask = EVENT_ALL_ACCESS;
	ObjectTypeInitializer.UseDefaultObject = TRUE;
	create_type_object(&ObjectTypeInitializer, &Name, &event_object_type);
}

VOID
STDCALL
event_init(struct kevent *event,
		enum event_type type,
		BOOLEAN state)
{
	int obj_type = (type == SynchronizationEvent) ? EventSynchronizationObject : EventNotificationObject;
	/* Initialize the Dispatcher Header */
	INIT_DISP_HEADER(&event->header, obj_type, sizeof(event) / sizeof(ULONG), state);
} /* end event_init */
EXPORT_SYMBOL(event_init);

/*
 * open a event object, creating if non-existent
 */
NTSTATUS
SERVICECALL
NtCreateEvent(OUT PHANDLE EventHandle,
              IN ACCESS_MASK DesiredAccess,
              IN POBJECT_ATTRIBUTES ObjectAttributes,
              IN EVENT_TYPE EventType,
              IN BOOLEAN InitialState)

{
	HANDLE Handle;
	struct kevent *Event;
	POBJECT_ATTRIBUTES obj_attr = NULL;
	NTSTATUS status = STATUS_SUCCESS;

	ktrace("\n");
	if (ObjectAttributes) {
		if ((ULONG)ObjectAttributes < TASK_SIZE) {
			if (copy_object_attr_from_user(ObjectAttributes, &obj_attr))
				return STATUS_NO_MEMORY;
		}
		else {
			obj_attr = ObjectAttributes;
		}
	}

	if (obj_attr) {
		if (obj_attr->RootDirectory)
			obj_attr->RootDirectory = base_dir_handle;
	}

	status = create_object(KernelMode,
			event_object_type,
			obj_attr,
			KernelMode,
			NULL,
			sizeof(struct kevent),
			0,
			0,
			(PVOID *)&Event);

	if (ObjectAttributes && (ULONG)ObjectAttributes < TASK_SIZE)
		kfree(obj_attr);

	if (!NT_SUCCESS(status))
		return status;

	event_init(Event, EventType, InitialState);

	status = insert_object((PVOID)Event,
			NULL,
			DesiredAccess,
			0,
			NULL,
			&Handle);

	if (status == STATUS_OBJECT_NAME_EXISTS) {
		goto event_exists;
	}

	if (!NT_SUCCESS(status))
		return status;

event_exists:
	deref_object(Event);

	if (EventHandle) {
		if ((ULONG)EventHandle < TASK_SIZE) {
			if (copy_to_user(EventHandle, &Handle, sizeof(HANDLE)))
			return STATUS_NO_MEMORY;
		}
		else
			*EventHandle = Handle;
	}
	ktrace("return %x, event %p, handle %p\n", status, Event, Handle);
	return status;
} /* end NtCreateEvent() */
EXPORT_SYMBOL(NtCreateEvent);

/*
 * open a event object, failing if non-existent
 */
NTSTATUS
SERVICECALL
NtOpenEvent(OUT PHANDLE EventHandle,
            IN ACCESS_MASK DesiredAccess,
            IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	HANDLE handle;
	POBJECT_ATTRIBUTES obj_attr = NULL;
	NTSTATUS status = STATUS_SUCCESS;

	ktrace("\n");
	if (ObjectAttributes) {
		if ((ULONG)ObjectAttributes < TASK_SIZE) {
			if (copy_object_attr_from_user(ObjectAttributes, &obj_attr))
				return STATUS_NO_MEMORY;
		}
		else {
			obj_attr = ObjectAttributes;
		}
	}

	if (obj_attr) {
		if (obj_attr->RootDirectory)
			obj_attr->RootDirectory = base_dir_handle;
	}

	status = open_object_by_name(obj_attr,
			event_object_type,
			NULL,
			KernelMode,
			DesiredAccess,
			NULL,
			&handle);

	if (ObjectAttributes && (ULONG)ObjectAttributes < TASK_SIZE)
		kfree(obj_attr);

	if (!NT_SUCCESS(status))
		return status;

	if (EventHandle) {
		if ((ULONG)EventHandle < TASK_SIZE) {
			if (copy_to_user(EventHandle, &handle, sizeof(HANDLE)))
				return STATUS_NO_MEMORY;
		}
		else
			*EventHandle = &handle;
	}
	
	return status;
}/* end NtOpenEvent() */
EXPORT_SYMBOL(NtOpenEvent);

LONG
STDCALL
set_event(struct kevent *Event,
	KPRIORITY Increment,
	BOOLEAN Wait)
{
	struct ethread *thread = get_current_ethread();
	LONG prev;
	struct kwait_block *block;

	local_irq_disable();

	prev = Event->header.signal_state;

	if (list_empty(&Event->header.wait_list_head))
		Event->header.signal_state = 1;
	else {
		block = list_entry(Event->header.wait_list_head.next, struct kwait_block, wait_list_entry);

		/* FIXME */
		if (prev == 0) {
			Event->header.signal_state = 1;
			wait_test(&Event->header, Increment);
		}
	}

	if (Wait == FALSE)
		local_irq_enable();
	else
		thread->tcb.wait_next = TRUE;

	return prev;
}
EXPORT_SYMBOL(set_event);

/*
 * set an event
 */
NTSTATUS
SERVICECALL
NtSetEvent(IN HANDLE EventHandle,
           OUT PLONG PreviousState)
{
	struct kevent *event;
	LONG prev;
	NTSTATUS status = STATUS_SUCCESS;

	ktrace("handle %p\n", EventHandle);
	status = ref_object_by_handle(EventHandle,
			EVENT_MODIFY_STATE,
			event_object_type,
			KernelMode,
			(PVOID *)&event,
			NULL);
	
	if (!NT_SUCCESS(status))
		return status;

	prev = set_event(event, EVENT_INCREMENT, FALSE);
	deref_object(event);

	if (PreviousState) {
		if ((ULONG)PreviousState < TASK_SIZE) {
			if (copy_to_user(PreviousState, &prev, sizeof(LONG)))
				return STATUS_NO_MEMORY;
		}
		else
			*PreviousState = prev;
	}

	return status;
}/* end NtSetEvent() */
EXPORT_SYMBOL(NtSetEvent);

LONG
STDCALL
reset_event(struct kevent *Event)
{
	LONG prev;

	local_irq_disable();

	prev = Event->header.signal_state;
	Event->header.signal_state = 0;

	local_irq_enable();

	return prev;
}
EXPORT_SYMBOL(reset_event);

/*
 * reset an event
 */
NTSTATUS
SERVICECALL
NtResetEvent(IN HANDLE EventHandle,
             OUT PLONG PreviousState)
{
	struct kevent *event;
	LONG prev;
	NTSTATUS status = STATUS_SUCCESS;

	ktrace("handle %p \n" ,EventHandle);
	status = ref_object_by_handle(EventHandle,
			EVENT_MODIFY_STATE,
			event_object_type,
			KernelMode,
			(PVOID *)&event,
			NULL);

	if (!NT_SUCCESS(status))
		return status;

	prev = reset_event(event);
	deref_object(event);

	if (PreviousState) {
		if ((ULONG)PreviousState < TASK_SIZE) {
			if (copy_to_user(PreviousState, &prev, sizeof(LONG)))
				return STATUS_NO_MEMORY;
		}
		else
			*PreviousState = prev;
	}

	return STATUS_SUCCESS;
}/* end NtResetEvent() */
EXPORT_SYMBOL(NtResetEvent);

LONG
STDCALL
pulse_event(IN struct kevent *Event,
	IN KPRIORITY Increment,
	IN BOOLEAN Wait)
{
	struct ethread *thread = get_current_ethread();
	LONG prev;

	local_irq_disable();

	prev = Event->header.signal_state;

	if (prev == 0 && !list_empty(&Event->header.wait_list_head)) {
		Event->header.signal_state = 1;
		wait_test(&Event->header, Increment);
	}

	Event->header.signal_state = 0;

	if (Wait == FALSE)
		local_irq_enable();
	else
		thread->tcb.wait_next = TRUE;

	return prev;
}
EXPORT_SYMBOL(pulse_event);

/*
 * pulse an event
 */
NTSTATUS
SERVICECALL
NtPulseEvent(IN HANDLE EventHandle,
             OUT PLONG PreviousState)
{
	struct kevent *event;
	long prev;
	NTSTATUS status = STATUS_SUCCESS;

	ktrace("\n");
	status = ref_object_by_handle(EventHandle,
			EVENT_MODIFY_STATE,
			event_object_type,
			KernelMode,
			(PVOID *)&event,
			NULL);

	if (!NT_SUCCESS(status))
		return status;

	prev = pulse_event(event, EVENT_INCREMENT, FALSE);
	deref_object(event);

	if (PreviousState) {
		if ((ULONG)PreviousState < TASK_SIZE) {
			if (copy_to_user(PreviousState, &prev, sizeof(LONG)))
				return STATUS_NO_MEMORY;
		}
		else
			*PreviousState = prev;
	}

	return status;
}/* end NtPulseEvent() */
EXPORT_SYMBOL(NtPulseEvent);

/* contributed by Welfear */
VOID
STDCALL
clear_event(struct kevent *Event)
{
	Event->header.signal_state = 0;
}
EXPORT_SYMBOL(clear_event);

NTSTATUS
SERVICECALL
NtClearEvent(IN HANDLE EventHandle
	   )
{
	struct kevent *event;
	NTSTATUS status;

	ktrace("\n");

	status = ref_object_by_handle(EventHandle,
			EVENT_MODIFY_STATE,
			event_object_type,
			KernelMode,
			(PVOID *)&event,
			NULL);
	if (NT_SUCCESS(status)) {
		clear_event(event);
		deref_object(event);
	}

	return status;
}
EXPORT_SYMBOL(NtClearEvent);

typedef struct _EVENT_BASIC_INFORMATION
{
    EVENT_TYPE EventType;
    LONG EventState;
} EVENT_BASIC_INFORMATION, *PEVENT_BASIC_INFORMATION;

LONG
STDCALL
query_event(IN struct kevent *Event
		)
{
	return Event->header.signal_state;
}
EXPORT_SYMBOL(query_event);

NTSTATUS
SERVICECALL
NtQueryEvent(IN HANDLE EventHandle,
	IN EVENT_INFORMATION_CLASS EventInformationClass,
	OUT PVOID EventInformation,
	IN ULONG EventInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	struct kevent 		*event;
	NTSTATUS 		status;
	ULONG			return_length;
	EVENT_BASIC_INFORMATION basic_info;


	ktrace("handle %p\n", EventHandle);
	
	if (EventInformationClass != 0 /*EventBasicInformation*/) {
		return STATUS_INVALID_INFO_CLASS;
	}

	if (EventInformationLength != sizeof(EVENT_BASIC_INFORMATION)) {
		return STATUS_INFO_LENGTH_MISMATCH;
	}

	if (EventInformation == NULL) {
		return STATUS_INVALID_PARAMETER; /* may be exception code */
	}

	status = ref_object_by_handle(EventHandle,
			EVENT_QUERY_STATE,
			event_object_type,
			KernelMode,
			(PVOID *)&event,
			NULL);
	if (!NT_SUCCESS(status))
		return status;

	basic_info.EventState 	= query_event(event);
	basic_info.EventType 	= event->header.type;

	return_length = sizeof(EVENT_BASIC_INFORMATION);

	deref_object(event);

	if ((ULONG)EventInformation < TASK_SIZE) {
		if (copy_to_user(EventInformation, &basic_info, sizeof(EVENT_BASIC_INFORMATION)))
			return STATUS_NO_MEMORY;
	} else {
		memcpy(EventInformation, &basic_info, sizeof(EVENT_BASIC_INFORMATION));
	}

	if (ReturnLength != NULL) {
		if ((ULONG)ReturnLength < TASK_SIZE) {
			if (copy_to_user(ReturnLength, &return_length, sizeof(ReturnLength)))
				return STATUS_NO_MEMORY;
		} else {
			*ReturnLength = return_length;
		}
	}

	return status;
}
EXPORT_SYMBOL(NtQueryEvent);
/* contributed by Welfear */

/* stubs from Wine server */
struct kevent *create_event(struct directory *root, const struct unicode_str *name, unsigned int attr,
			int manual_reset, int initial_state, const struct security_descriptor *sd)
{
	struct kevent *Event;
	POBJECT_ATTRIBUTES obj_attr = NULL;
	NTSTATUS status = STATUS_SUCCESS;

	ktrace("\n");

	status = create_object(KernelMode,
			event_object_type,
			obj_attr,
			KernelMode,
			NULL,
			sizeof(struct kevent),
			0,
			0,
			(PVOID *)&Event);

	if (!NT_SUCCESS(status))
		return NULL;

	event_init(Event, NotificationEvent, initial_state);

	return Event;
}

struct kevent *get_event_obj(struct w32process *process, obj_handle_t handle, 
		unsigned int access)
{
	return (struct kevent *)get_handle_obj(handle, access);
}

#endif /* CONFIG_UNIFIED_KERNEL */
