/*
 * token.c
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
 * token.c: token implementation
 * Refered to ReactOS code
 */
#include "handle.h"

#ifdef CONFIG_UNIFIED_KERNEL

POBJECT_TYPE token_object_type = NULL;
EXPORT_SYMBOL(token_object_type);

NTSTATUS SERVICECALL
NtOpenThreadToken(IN HANDLE ThreadHandle,
		IN ACCESS_MASK DesiredAccess,
		IN BOOLEAN OpenAsSelf,
		OUT PHANDLE TokenHandle)
{
	ktrace("\n");
	return NtOpenThreadTokenEx(ThreadHandle, 
			DesiredAccess, 
			OpenAsSelf, 
			0,
			TokenHandle);
}
EXPORT_SYMBOL(NtOpenThreadToken);

PACCESS_TOKEN
ref_impersonation_token(IN struct ethread *Thread,
		OUT PBOOLEAN CopyOnOpen,
		OUT PBOOLEAN EffectiveOnly,
		OUT PSECURITY_IMPERSONATION_LEVEL ImpersonationLevel)
{

	if (Thread->active_impersonation_info == FALSE) 
		return NULL;

	*ImpersonationLevel = Thread->impersonation_info->impersonation_level;
	*CopyOnOpen = Thread->impersonation_info->copy_on_open;
	*EffectiveOnly = Thread->impersonation_info->effective_only;

	ref_object(Thread->impersonation_info->token);

	return Thread->impersonation_info->token;
}
EXPORT_SYMBOL(ref_impersonation_token);

NTSTATUS SERVICECALL
NtOpenThreadTokenEx(IN HANDLE ThreadHandle,
		IN ACCESS_MASK DesiredAccess,
		IN BOOLEAN OpenAsSelf,
		IN ULONG HandleAttributes,
		OUT PHANDLE TokenHandle)
{
	struct ethread *thread;
	PTOKEN token; /* TODO */
	BOOLEAN copy_on_open, effective_only;
	SECURITY_IMPERSONATION_LEVEL impersonation = 0;
	KPROCESSOR_MODE pre_mode = (KPROCESSOR_MODE)get_pre_mode();
	HANDLE htoken;
	NTSTATUS status;

	ktrace("\n");
	status = ref_object_by_handle(ThreadHandle, 
			THREAD_QUERY_INFORMATION, /* TODO */
			thread_object_type, 
			pre_mode, 
			(PVOID *) &thread,
			NULL);
	if (status)
		return status;

	token = ref_impersonation_token(thread, 
			&copy_on_open, 
			&effective_only, 
			&impersonation);
	deref_object(thread);

	if (!token)
		return STATUS_NO_TOKEN;

	if (impersonation == SecurityAnonymous) {
		deref_object(token);
		return STATUS_CANT_OPEN_ANONYMOUS;
	}

	if (OpenAsSelf) {
		/* TODO: disable impersonation */
	}

	/* FIXME:  copy_on_open is set to be 0 before the following TODO is done*/
	copy_on_open = 0;
	if (copy_on_open) {
		/* TODO */
	} else {
		status = open_object_by_pointer(token, 
				HandleAttributes, 
				NULL, 
				DesiredAccess, 
				token_object_type, 
				pre_mode, 
				&htoken);
	}

	if (OpenAsSelf) {
		/* TODO: restore impersonation */
	}

	if (NT_SUCCESS(status))
		if (copy_to_user(TokenHandle, &htoken, sizeof(htoken)))
			status = STATUS_UNSUCCESSFUL;

	return status;
}
EXPORT_SYMBOL(NtOpenThreadTokenEx);

NTSTATUS
open_process_token(HANDLE ProcessHandle, 
		PACCESS_TOKEN *Token)
{
	struct eprocess *process;
	NTSTATUS status;

	status = ref_object_by_handle(ProcessHandle, 
			PROCESS_QUERY_INFORMATION, /* TODO */
			process_object_type,
			get_pre_mode(), 
			(PVOID *)&process, 
			NULL);

	if (NT_SUCCESS(status)) {
		ref_object(&process->token);
		*Token = process->token.object;
		deref_object(process);
	}
	return status;
}

NTSTATUS SERVICECALL
NtOpenProcessTokenEx(IN  HANDLE 	ProcessHandle,
		IN  ACCESS_MASK 	DesiredAccess,
		IN  ULONG 		HandleAttributes,
		OUT PHANDLE 	TokenHandle)
{
	PACCESS_TOKEN token;
	NTSTATUS status;
	HANDLE htoken;

	ktrace("\n");
	status = open_process_token(ProcessHandle, &token);

	if (NT_SUCCESS(status)) {
		status = create_handle((struct eprocess * )get_current_eprocess(), /* TODO */
				(void *)token,
				DesiredAccess, 
				FALSE, 
				&htoken);
		deref_object(token);
		if (NT_SUCCESS(status))
			if (copy_to_user(TokenHandle, &htoken, sizeof(htoken)))
				status = STATUS_UNSUCCESSFUL;
	}

	return status;
}
EXPORT_SYMBOL(NtOpenProcessTokenEx);

NTSTATUS SERVICECALL
NtOpenProcessToken(IN HANDLE ProcessHandle, 
		IN ACCESS_MASK DesiredAccess, 
		OUT PHANDLE TokenHandle)
{
	ktrace("\n");
	return NtOpenProcessTokenEx(ProcessHandle, 
			DesiredAccess, 
			0, 
			TokenHandle);
}
EXPORT_SYMBOL(NtOpenProcessToken);
#endif /* CONFIG_UNIFIED_KERNEL */
