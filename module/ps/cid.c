/*
 * cid.c
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
 * cid.c:
 * Refered to ReactOS code
 */

#include "handle.h"

#ifdef CONFIG_UNIFIED_KERNEL

struct handle_table *cid_table = NULL;
EXPORT_SYMBOL(cid_table);

#define CID_FLAG_PROCESS	0x1
#define CID_FLAG_THREAD		0x2
#define CID_FLAG_MASK		(CID_FLAG_PROCESS | CID_FLAG_THREAD)

#define CID_RESERVE_OFFSET	32

long init_cid_table(void)
{
	return (long) (cid_table = __create_handle_table(NULL));
}
EXPORT_SYMBOL(init_cid_table);

void destroy_cid_table(void)
{
	__destroy_handle_table(cid_table, NULL, NULL);
}
EXPORT_SYMBOL(destroy_cid_table);

HANDLE create_cid_handle(PVOID object, POBJECT_TYPE obj_type)
{
	struct handle_table_entry entry;
	long exhandle;

	entry.u1.object = object;

	if (obj_type == process_object_type)
		entry.u2.granted_access = CID_FLAG_PROCESS;
	else if (obj_type == thread_object_type)
		entry.u2.granted_access = CID_FLAG_THREAD;
	else
		goto error;

	exhandle = create_ex_handle(cid_table, &entry);
	if (exhandle != EX_INVALID_HANDLE)
		return EX_HANDLE_TO_HANDLE(exhandle + CID_RESERVE_OFFSET);

error:
	return NULL;
}
EXPORT_SYMBOL(create_cid_handle);

int delete_cid_handle(HANDLE cid_handle, POBJECT_TYPE obj_type)
{
	struct handle_table_entry * entry;
	long ex_handle = HANDLE_TO_EX_HANDLE(cid_handle) - CID_RESERVE_OFFSET;

	enter_critical_region();
	
	if (!(entry = map_handle_to_pointer(cid_table, ex_handle)))
		goto invalid;

	if (((obj_type == thread_object_type) && 
			((entry->u2.granted_access & CID_FLAG_MASK) == CID_FLAG_THREAD)) || 
	    ((obj_type == process_object_type) && 
	     		((entry->u2.granted_access & CID_FLAG_MASK) == CID_FLAG_PROCESS))) {
		destroy_handle_by_entry(cid_table, entry, ex_handle);
		leave_critical_region();
		return 0;
	} else
		unlock_handle_table_entry(cid_table, entry);
	
invalid:
	leave_critical_region();
	return STATUS_INVALID_PARAMETER;
}
EXPORT_SYMBOL(delete_cid_handle);

struct handle_table_entry* lookup_cid_handle(HANDLE cid_handle, POBJECT_TYPE obj_type, PVOID *object)
{
	struct handle_table_entry *entry;

	enter_critical_region();
	if (!(entry = map_handle_to_pointer(cid_table, 
					HANDLE_TO_EX_HANDLE(cid_handle) - CID_RESERVE_OFFSET)))
		goto no_target;

	if (((obj_type == thread_object_type) && 
				((entry->u2.granted_access & CID_FLAG_MASK) == CID_FLAG_THREAD)) || 
			((obj_type == process_object_type) && 
			 ((entry->u2.granted_access & CID_FLAG_MASK) == CID_FLAG_PROCESS))) {
		*object = entry->u1.object;
		leave_critical_region();
		return entry;
	} else
		unlock_handle_table_entry(cid_table, entry); 

no_target:
	leave_critical_region();
	return NULL;
}
EXPORT_SYMBOL(lookup_cid_handle);

int lookup_process_by_pid(HANDLE pid, struct eprocess** process)
{
	struct handle_table_entry* entry;
	struct eprocess* found_process;

	if (!process)
		goto invalid_parameter;
	
	if ((entry = lookup_cid_handle(pid, process_object_type, (PVOID *) &found_process))) {
		ref_object(found_process);
		unlock_handle_table_entry(cid_table, entry);
		*process = found_process;
		return 0;	
	}
		
invalid_parameter:
	return STATUS_INVALID_PARAMETER;
}
EXPORT_SYMBOL(lookup_process_by_pid);

int lookup_thread_by_tid(HANDLE tid, struct ethread** thread)
{
	struct handle_table_entry* entry;
	struct ethread* found_thread;

	if (!thread)
		goto invalid_parameter;
	
	if ((entry = lookup_cid_handle(tid, thread_object_type, (PVOID *) &found_thread))) {
		ref_object(found_thread);
		unlock_handle_table_entry(cid_table, entry);
		*thread = found_thread;
		return 0;	
	}
		
invalid_parameter:
	return STATUS_INVALID_PARAMETER;
}
EXPORT_SYMBOL(lookup_thread_by_tid);

NTSTATUS lookup_process_thread_by_cid(PCLIENT_ID cid, PEPROCESS *process, PETHREAD *thread)
{
	struct handle_table_entry* entry = NULL;
	struct ethread* found_thread = NULL;

	if (!thread)
		return STATUS_INVALID_PARAMETER;

	if ((entry = lookup_cid_handle(cid->UniqueThread, thread_object_type, (PVOID *)&found_thread))) {
		if (found_thread->cid.unique_process == cid->UniqueProcess) {
			ref_object(found_thread);
			*thread = found_thread;

			if (process) {
				*process = found_thread->threads_process;
				ref_object(*process);
			}

			return STATUS_SUCCESS;
		}
	}

	return STATUS_INVALID_CID;

}
#endif /* CONFIG_UNIFIED_KERNEL */
