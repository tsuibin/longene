/*
 * objwait.c
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
 * objwait.c:
 * Refered to Kernel-win32 code
 */

#include "objwait.h"
#include "mutex.h"
#include "semaphore.h"
#include "wineserver/lib.h"

#ifdef CONFIG_UNIFIED_KERNEL

NTSTATUS SERVICECALL
NtWaitForSingleObject(IN HANDLE ObjectHandle,
		IN BOOLEAN Alertable,
		IN PLARGE_INTEGER TimeOut OPTIONAL)
{
	PVOID object;
	LARGE_INTEGER _timeout;
	MODE previous_mode;
	NTSTATUS status;

	ktrace("ObjectHandle %p, Alertable %d\n", ObjectHandle, Alertable);
	previous_mode = (unsigned long)TimeOut > TASK_SIZE ? KernelMode : UserMode;
	if(TimeOut){
		if (previous_mode == UserRequest) {
			if (copy_from_user(&_timeout, TimeOut, sizeof(_timeout)))
				return STATUS_NO_MEMORY;
		} else
			_timeout = *TimeOut;
	}

	status = ref_object_by_handle(ObjectHandle,
				SYNCHRONIZE,
				NULL,
				KernelMode,
				&object,
				NULL);
	if (!NT_SUCCESS(status))
		return status;

	if(TimeOut){
		status = wait_for_single_object(object,
				UserRequest,
				KernelMode,
				Alertable,
				&_timeout);
	} else {
		status = wait_for_single_object(object,
				UserRequest,
				KernelMode,
				Alertable,
				NULL);
	}	
	       	
	if (!NT_SUCCESS(status))
		goto out;

	if (previous_mode == UserMode) {
		if (copy_to_user(TimeOut, &_timeout, sizeof(_timeout))) {
			status = STATUS_NO_MEMORY;
			goto out;
		}
	}
	else
		*TimeOut = _timeout;

out:
	deref_object(object);
	return status;
} /* end NtWaitForSingleObject */
EXPORT_SYMBOL(NtWaitForSingleObject);

NTSTATUS SERVICECALL
NtSignalAndWaitForSingleObject(IN HANDLE ObjectHandleToSignal,
		IN HANDLE WaitableObjectHandle,
		IN BOOLEAN Alertable,
		IN PLARGE_INTEGER TimeOut OPTIONAL)
{
	PVOID signal_obj, wait_obj;
	struct dispatcher_header *signal_header;
	LARGE_INTEGER _timeout;
	MODE previous_mode;
	NTSTATUS status;

	ktrace("ObjectHandleToSignal %p, WaitableObjectHandle %p, Alertable %d\n",
			ObjectHandleToSignal, WaitableObjectHandle, Alertable);
	previous_mode = (unsigned long)TimeOut > TASK_SIZE ? KernelMode : UserMode;
	if(TimeOut){
		if (previous_mode == UserMode) {
			if (copy_from_user(&_timeout, TimeOut, sizeof(_timeout)))
				return STATUS_NO_MEMORY;
		} else
			_timeout = *TimeOut;
	}

	status = ref_object_by_handle(ObjectHandleToSignal, 0,
			NULL, KernelMode, &signal_obj, NULL);
	if (!NT_SUCCESS(status))
		return status;

	status = ref_object_by_handle(WaitableObjectHandle, SYNCHRONIZE,
			NULL, KernelMode, &wait_obj, NULL);
	if (!NT_SUCCESS(status)) {
		deref_object(signal_obj);
		return status;
	}

	signal_header = (struct dispatcher_header *)signal_obj;

	if (is_wine_object(signal_header->type)) {
		struct object *obj = (struct object*)signal_obj;
		unsigned int access = get_handle_access(process2eprocess(current_thread->process), WaitableObjectHandle);
		if (BODY_TO_HEADER(obj)->ops->signal)
			BODY_TO_HEADER(obj)->ops->signal(obj, access);
	}
	else
		switch (signal_header->type) {
			case EventNotificationObject:
			case EventSynchronizationObject:
				set_event(signal_obj, EVENT_INCREMENT, TRUE);
				break;

			case MutantObject:
				release_mutant(signal_obj, IO_NO_INCREMENT, FALSE, TRUE);
				break;

			case SemaphoreObject:
				release_semaphore(signal_obj, SEMAPHORE_INCREMENT, 1, TRUE);
				break;

			default:
				deref_object(signal_obj);
				deref_object(wait_obj);
				return STATUS_OBJECT_TYPE_MISMATCH;
		}

	if(TimeOut){
		status = wait_for_single_object(wait_obj,
				UserRequest, KernelMode, Alertable, &_timeout);
	} else {
		status = wait_for_single_object(wait_obj,
				UserRequest, KernelMode, Alertable, NULL);
	}	

	if (!NT_SUCCESS(status))
		goto out;

	if (TimeOut) {
		if (previous_mode == UserMode) {
			if (copy_to_user(TimeOut, &_timeout, sizeof(_timeout))) {
				status = STATUS_NO_MEMORY;
				goto out;
			}
		} else
			*TimeOut = _timeout;
	}

out:
	deref_object(signal_obj);
	deref_object(wait_obj);

	return status;
} /* end NtSignalAndWaitForSingleObject */
EXPORT_SYMBOL(NtSignalAndWaitForSingleObject);

NTSTATUS SERVICECALL
NtWaitForMultipleObjects(IN ULONG ObjectCount,
		IN PHANDLE ObjectsArray,
		IN WAIT_TYPE WaitType,
		IN BOOLEAN Alertable,
		IN PLARGE_INTEGER TimeOut  OPTIONAL)
{
	int i;
	struct kwait_block *wait_block;
	LARGE_INTEGER _timeout;
	NTSTATUS status;
	PVOID object[ObjectCount];
	HANDLE hobj[ObjectCount];
	MODE previous_mode;

	ktrace("%d, %p\n", ObjectCount, *ObjectsArray);
	previous_mode = (unsigned long)ObjectsArray > TASK_SIZE ? KernelMode : UserMode;
	if(TimeOut){
		if (previous_mode == UserMode) {
			if (copy_from_user(&_timeout, TimeOut, sizeof(_timeout)))
				return STATUS_NO_MEMORY;
		} else
			_timeout = *TimeOut;
	}
	if(previous_mode == UserMode) {
		if(copy_from_user(hobj, ObjectsArray, sizeof(HANDLE)*ObjectCount))
			return STATUS_NO_MEMORY;
	} else {
		memcpy(ObjectsArray, hobj, sizeof(HANDLE)*ObjectCount);
	}

	if (ObjectCount == 0) {
		wait_block = (struct kwait_block *)kmalloc(MAXIMUM_WAIT_OBJECTS * sizeof(struct kwait_block), GFP_KERNEL);
		if (!wait_block) {
			status = STATUS_NO_MEMORY;
			goto out;
		}

		status = wait_for_multi_objs(0,
				NULL,
				WaitType,
				UserRequest,
				KernelMode,
				Alertable,
				TimeOut ? &_timeout : NULL,
				wait_block);

		kfree(wait_block);
		return status;
	}

	for (i = 0; i < ObjectCount; i++) {
		status = ref_object_by_handle(hobj[i],
					SYNCHRONIZE,
					NULL,
					KernelMode,
					&object[i],
					NULL);
		if (!NT_SUCCESS(status)) {
			ObjectCount = i;
			goto out;
		}
		if (BODY_TO_HEADER(object[i])->Type == thread_object_type
				&& object[i] == get_current_ethread()) {
			status = STATUS_INVALID_PARAMETER;
			ObjectCount = i + 1;
			goto out;
		}
	}

	wait_block = (struct kwait_block *)kmalloc(MAXIMUM_WAIT_OBJECTS * sizeof(struct kwait_block), GFP_KERNEL);
	if (!wait_block) {
		status = STATUS_NO_MEMORY;
		goto out;
	}

	status = wait_for_multi_objs(ObjectCount,
			object,
			WaitType,
			UserRequest,
			KernelMode,
			Alertable,
			TimeOut ? &_timeout : NULL,
			wait_block);

	kfree(wait_block);

out:
	for (i = 0; i < ObjectCount; i++)
		deref_object(object[i]);

	ktrace("%x\n", status);
	return status;
} /* end NtWaitForMultipleObjects */
EXPORT_SYMBOL(NtWaitForMultipleObjects);
#endif
