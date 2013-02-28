/*
 * psmgr.c
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
 * psmgr.c:
 * Refered to ReactOS code
 */
#include "process.h"
#include "thread.h"
#include "unistr.h"

#ifdef CONFIG_UNIFIED_KERNEL

static WCHAR ProcessTypeName[] = {'P', 'r', 'o', 'c', 'e', 's', 's', 0};
static WCHAR ThreadTypeName[] = {'T', 'h', 'r', 'e', 'a', 'd', 0};

static GENERIC_MAPPING PiProcessMapping =
{
	STANDARD_RIGHTS_READ    | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
	STANDARD_RIGHTS_WRITE   | PROCESS_CREATE_PROCESS    | PROCESS_CREATE_THREAD   |
	PROCESS_VM_OPERATION    | PROCESS_VM_WRITE          | PROCESS_DUP_HANDLE      |
	PROCESS_TERMINATE       | PROCESS_SET_QUOTA         | PROCESS_SET_INFORMATION |
	PROCESS_SUSPEND_RESUME,
	STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE,
	PROCESS_ALL_ACCESS
};

static GENERIC_MAPPING PiThreadMapping =
{
	STANDARD_RIGHTS_READ    | THREAD_GET_CONTEXT      | THREAD_QUERY_INFORMATION,
	STANDARD_RIGHTS_WRITE   | THREAD_TERMINATE        | THREAD_SUSPEND_RESUME    |
	THREAD_ALERT            | THREAD_SET_INFORMATION  | THREAD_SET_CONTEXT,
	STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE,
	THREAD_ALL_ACCESS
};

VOID
init_process_mgmt(VOID)
{
	UNICODE_STRING Name;
	OBJECT_TYPE_INITIALIZER ObjectTypeInitializer;

	ktrace("Creating Process Object Type\n");

	/*  Initialize the Thread type  */
	memset(&ObjectTypeInitializer, 0, sizeof(ObjectTypeInitializer));
	init_unistr(&Name, (PWSTR)ProcessTypeName);
	ObjectTypeInitializer.Length = sizeof(ObjectTypeInitializer);
	ObjectTypeInitializer.DefaultNonPagedPoolCharge = sizeof(struct eprocess);
	ObjectTypeInitializer.GenericMapping = PiProcessMapping;
	ObjectTypeInitializer.PoolType = NonPagedPool;
	ObjectTypeInitializer.ValidAccessMask = PROCESS_ALL_ACCESS;
	ObjectTypeInitializer.UseDefaultObject = TRUE;
	ObjectTypeInitializer.DeleteProcedure = delete_process;
	ObjectTypeInitializer.PollProcedure = poll_process;
	create_type_object(&ObjectTypeInitializer, &Name, &process_object_type);
}

VOID
init_thread_mgmt(VOID)
{
	UNICODE_STRING Name;
	OBJECT_TYPE_INITIALIZER ObjectTypeInitializer;

	ktrace("Creating Thread Object Type\n");

	/*  Initialize the Thread type  */
	memset(&ObjectTypeInitializer, 0, sizeof(ObjectTypeInitializer));
	init_unistr(&Name, (PWSTR)ThreadTypeName);
	ObjectTypeInitializer.Length = sizeof(ObjectTypeInitializer);
	ObjectTypeInitializer.DefaultNonPagedPoolCharge = sizeof(struct ethread);
	ObjectTypeInitializer.GenericMapping = PiThreadMapping;
	ObjectTypeInitializer.PoolType = NonPagedPool;
	ObjectTypeInitializer.ValidAccessMask = THREAD_ALL_ACCESS;
	ObjectTypeInitializer.UseDefaultObject = TRUE;
	ObjectTypeInitializer.DeleteProcedure = delete_thread;
	ObjectTypeInitializer.PollProcedure = poll_thread;
	create_type_object(&ObjectTypeInitializer, &Name, &thread_object_type);
}

VOID
init_process_manager(VOID)
{
	init_process_mgmt();
	init_thread_mgmt();
}

#endif /* CONFIG_UNIFIED_KERNEL */
