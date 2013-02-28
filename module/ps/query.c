/*
 * query.c
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
 * queue.c: 
 * Refered to ReactOS code
 */
#include "thread.h"

#ifdef CONFIG_UNIFIED_KERNEL
/*
 * FIXME:
 *   Remove the Implemented value if all functions are implemented.
 */
typedef struct _THREAD_BASIC_INFORMATION
{
	NTSTATUS ExitStatus;
	PVOID TebBaseAddress;
	CLIENT_ID ClientId;
	KAFFINITY AffinityMask;
	KPRIORITY Priority;
	KPRIORITY BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

static const struct
{
	BOOLEAN Implemented;
	ULONG Size;
} QueryInformationData[MaxThreadInfoClass + 1] = {
	{TRUE, sizeof(THREAD_BASIC_INFORMATION)},	/* ThreadBasicInformation */
	{TRUE, sizeof(KERNEL_USER_TIMES)},			/* ThreadTimes */
	{TRUE, sizeof(CHAR)},						/* ThreadPriority */
	{TRUE, sizeof(CHAR)},						/* ThreadBasePriority */
	{TRUE, sizeof(KAFFINITY)},					/* ThreadAffinityMask */
	{TRUE, sizeof(PACCESS_TOKEN)},				/* ThreadImpersonationToken */
	{FALSE, 0},									/* ThreadDescriptorTableEntry */
	{TRUE, 0},									/* ThreadEnableAlignmentFaultFixup */
	{TRUE, 0},									/* ThreadEventPair */
	{TRUE, sizeof(PVOID)},						/* ThreadQuerySetWin32StartAddress */
	{TRUE, 0},									/* ThreadZeroTlsCell */
	{TRUE, sizeof(LARGE_INTEGER)},				/* ThreadPerformanceCount */
	{TRUE, sizeof(BOOLEAN)},					/* ThreadAmILastThread */
	{TRUE, sizeof(UCHAR)},						/* ThreadIdealProcessor */
	{FALSE, 0},									/* ThreadPriorityBoost */
	{TRUE, 0},									/* ThreadSetTlsArrayAddress */
	{FALSE, 0},									/* ThreadIsIoPending */
	{TRUE, 0}									/* ThreadHideFromDebugger */
};

static const struct
{
	BOOLEAN Implemented;
	ULONG Size;
} SetInformationData[MaxThreadInfoClass + 1] = {
	{TRUE, 0},					/* ThreadBasicInformation */
	{TRUE, 0},					/* ThreadTimes */
	{TRUE, sizeof(KPRIORITY)},	/* ThreadPriority */
	{TRUE, sizeof(LONG)},		/* ThreadBasePriority */
	{TRUE, sizeof(KAFFINITY)},	/* ThreadAffinityMask */
	{TRUE, sizeof(HANDLE)},		/* ThreadImpersonationToken */
	{TRUE, 0},					/* ThreadDescriptorTableEntry */
	{FALSE, 0},					/* ThreadEnableAlignmentFaultFixup */
	{FALSE, 0},					/* ThreadEventPair */
	{TRUE, sizeof(PVOID)},		/* ThreadQuerySetWin32StartAddress */
	{FALSE, 0},					/* ThreadZeroTlsCell */
	{TRUE, 0},					/* ThreadPerformanceCount */
	{TRUE, 0},					/* ThreadAmILastThread */
	{FALSE, 0},					/* ThreadIdealProcessor */
	{FALSE, 0},					/* ThreadPriorityBoost */
	{FALSE, 0},					/* ThreadSetTlsArrayAddress */
	{TRUE, 0},					/* ThreadIsIoPending */
	{FALSE, 0}					/* ThreadHideFromDebugger */
};

NTSTATUS SERVICECALL
NtQueryInformationProcess(IN  HANDLE ProcessHandle,
		IN  PROCESSINFOCLASS ProcessInformationClass,
		OUT PVOID ProcessInformation,
		IN  ULONG ProcessInformationLength,
		OUT PULONG ReturnLength  OPTIONAL)
{
	PEPROCESS Process;
	KPROCESSOR_MODE PreviousMode = 
		(ULONG)ProcessInformation < TASK_SIZE ? UserMode : KernelMode;	/* TODO ... */
	union
	{
		PROCESS_BASIC_INFORMATION BasicInformation;
		KERNEL_USER_TIMES Time;
		ULONG HandleCount;
		PROCESS_SESSION_INFORMATION SessionInfo;
		VM_COUNTERS VMCounters;
		ULONG HardErrMode;
		ULONG BoostEnabled;
		USHORT Priority;
	}u;
	ULONG Length = 0;
	NTSTATUS Status = STATUS_SUCCESS;

	ktrace("()\n");
	if (ProcessInformationClass != ProcessCookie) {
		Status = ref_object_by_handle(ProcessHandle,
				PROCESS_QUERY_INFORMATION,
				process_object_type,
				PreviousMode,
				(PVOID*)&Process,
				NULL);
		if (!NT_SUCCESS(Status))
			return Status;
	}
	else if (ProcessHandle != NtCurrentProcess()) {
		/* retreiving the process cookie is only allowed for the calling process
		   itself! XP only allowes NtCurrentProcess() as process handles even if a
		   real handle actually represents the current process. */
		return STATUS_INVALID_PARAMETER;
	}

	switch (ProcessInformationClass) {
		case ProcessBasicInformation:
			if (ProcessInformationLength < sizeof(PROCESS_BASIC_INFORMATION))
				Status = STATUS_INFO_LENGTH_MISMATCH;
			else {
				u.BasicInformation.ExitStatus = Process->exit_status;
				u.BasicInformation.PebBaseAddress = (DWORD)Process->peb;
				u.BasicInformation.AffinityMask = Process->pcb.affinity;
				u.BasicInformation.UniqueProcessId = 
					(ULONG)Process->unique_processid;
				u.BasicInformation.InheritedFromUniqueProcessId = 
					(ULONG)Process->inherited_from_unique_pid;
				u.BasicInformation.BasePriority = 
					Process->pcb.base_priority;
				if (ReturnLength)
					Length = sizeof(PROCESS_BASIC_INFORMATION);
			}
			break;
		case ProcessQuotaLimits:
		case ProcessIoCounters:
			/* TODO : take time from linux task_struct ? */
			Status = STATUS_NOT_IMPLEMENTED;
			break;
		case ProcessTimes:
			if (ProcessInformationLength < sizeof(KERNEL_USER_TIMES))
				Status = STATUS_INFO_LENGTH_MISMATCH;
			else {
				u.Time.CreateTime = Process->create_time;
				u.Time.UserTime.quad = Process->pcb.user_time * 100000LL;
				u.Time.KernelTime.quad = Process->pcb.kernel_time * 100000LL;
				u.Time.ExitTime = Process->exit_time;
				if (ReturnLength)
					Length = sizeof(KERNEL_USER_TIMES);
			}
			break;
		case ProcessDebugPort:
			if (ProcessInformationLength == 4) {
				memset(ProcessInformation, 0, ProcessInformationLength);
				Length = 4;
			} else
				Status = STATUS_INFO_LENGTH_MISMATCH;
			break;
		case ProcessLdtInformation:
		case ProcessWorkingSetWatch:
		case ProcessWx86Information:
			Status = STATUS_NOT_IMPLEMENTED;
			break;
		case ProcessHandleCount:
			if (ProcessInformationLength < sizeof(ULONG))
				Status = STATUS_INFO_LENGTH_MISMATCH;
			else {
				u.HandleCount = Process->object_table->handle_count;
				if (ReturnLength)
					Length = sizeof(ULONG);
			}
			break;
		case ProcessSessionInformation:
			if (ProcessInformationLength < sizeof(PROCESS_SESSION_INFORMATION))
				Status = STATUS_INFO_LENGTH_MISMATCH;
			else {
				u.SessionInfo.SessionId = Process->session;
				if (ReturnLength)
					Length = sizeof(PROCESS_SESSION_INFORMATION);
			}
			break;
		case ProcessWow64Information:
			Status = STATUS_NOT_IMPLEMENTED;
			break;
		case ProcessVmCounters:
			if (ProcessInformationLength < sizeof(VM_COUNTERS))
				Status = STATUS_INFO_LENGTH_MISMATCH;
			else {
				u.VMCounters.PeakVirtualSize            = Process->peak_virtual_size;
				u.VMCounters.VirtualSize                = (ULONG)Process->virtual_size;
				u.VMCounters.PageFaultCount             = Process->vm.page_fault_count;
				u.VMCounters.PeakWorkingSetSize         = Process->vm.peak_working_set_size;
				u.VMCounters.WorkingSetSize             = Process->vm.working_set_size;
				u.VMCounters.QuotaPeakPagedPoolUsage    = Process->quota_peak[0];	/* TODO: Verify! */
				u.VMCounters.QuotaPagedPoolUsage        = Process->quota_usage[0];	/* TODO: Verify! */
				u.VMCounters.QuotaPeakNonPagedPoolUsage = Process->quota_peak[1];	/* TODO: Verify! */
				u.VMCounters.QuotaNonPagedPoolUsage     = Process->quota_usage[1];	/* TODO: Verify! */
				u.VMCounters.PagefileUsage              = Process->quota_usage[2];
				u.VMCounters.PeakPagefileUsage          = Process->quota_peak[2];
				if (ReturnLength)
					Length = sizeof(VM_COUNTERS);
			}
			break;
		case ProcessDefaultHardErrorMode:
			if (ProcessInformationLength < sizeof(ULONG))
				Status = STATUS_INFO_LENGTH_MISMATCH;
			else {
				u.HardErrMode = Process->def_hard_error_processing;
				if (ReturnLength)
					Length = sizeof(ULONG);
			}
			break;
		case ProcessPriorityBoost:
			if (ProcessInformationLength < sizeof(ULONG))
				Status = STATUS_INFO_LENGTH_MISMATCH;
			else {
				u.BoostEnabled = Process->pcb.disable_boost ? FALSE : TRUE;
				if (ReturnLength)
					Length = sizeof(ULONG);
			}
			break;
		case ProcessDeviceMap:
			/* TODO ... */
			Status = STATUS_NOT_IMPLEMENTED;
			break;
		case ProcessPriorityClass:
			if (ProcessInformationLength < sizeof(USHORT))
				Status = STATUS_INFO_LENGTH_MISMATCH;
			else {
				u.Priority = Process->priority_class;

				if (ReturnLength)
					Length = sizeof(USHORT);
			}
			break;
		case ProcessImageFileName:
			/* TODO ... */
		case ProcessCookie:
			/* TODO ... */
			Status = STATUS_NOT_IMPLEMENTED;
			break;

			/*
			 * Note: The following 10 information classes are verified to not be
			 * implemented on NT, and do indeed return STATUS_INVALID_INFO_CLASS;
			 */
		case ProcessBasePriority:
		case ProcessRaisePriority:
		case ProcessExceptionPort:
		case ProcessAccessToken:
		case ProcessLdtSize:
		case ProcessIoPortHandlers:
		case ProcessUserModeIOPL:
		case ProcessEnableAlignmentFaultFixup:
		case ProcessAffinityMask:
		case ProcessForegroundInformation:
		default:
			Status = STATUS_INVALID_INFO_CLASS;
			break;
	}

	if (ProcessInformationClass != ProcessCookie)
		deref_object(Process);

	if (Status != STATUS_SUCCESS)
		return Status;

	if (PreviousMode != KernelMode) {
		if(copy_to_user(ProcessInformation, &u.BasicInformation, Length))
			return STATUS_UNSUCCESSFUL;
		if (ReturnLength != NULL) {
			if(copy_to_user(ReturnLength, &Length, sizeof(ULONG)))
				return STATUS_UNSUCCESSFUL;
		}
	}
	else {
		memcpy(ProcessInformation, &u.BasicInformation, Length);
		*ReturnLength = Length;
	}

	return Status;
}
EXPORT_SYMBOL(NtQueryInformationProcess);

NTSTATUS SERVICECALL
NtSetInformationProcess(IN HANDLE ProcessHandle,
		IN PROCESSINFOCLASS ProcessInformationClass,
		IN PVOID ProcessInformation,
		IN ULONG ProcessInformationLength)
{
	PEPROCESS Process;
	KPROCESSOR_MODE PreviousMode = 
		(ULONG)ProcessInformation < TASK_SIZE ? UserMode : KernelMode;	/* TODO ... */
	ACCESS_MASK Access;
	NTSTATUS Status = STATUS_SUCCESS;

	ktrace("()\n");
	switch (ProcessInformationClass) {
		case ProcessSessionInformation:
			Access = PROCESS_SET_INFORMATION | PROCESS_SET_SESSIONID;
			break;
		case ProcessExceptionPort:
			Access = PROCESS_SET_INFORMATION | PROCESS_SUSPEND_RESUME;
			break;
		default:
			Access = PROCESS_SET_INFORMATION;
			break;
	}

	Status = ref_object_by_handle(ProcessHandle,
			Access,
			process_object_type,
			PreviousMode,
			(PVOID*)&Process,
			NULL);
	if (!NT_SUCCESS(Status))
		return Status;

	switch (ProcessInformationClass) {
		case ProcessPriorityClass:
			if (ProcessInformationLength != sizeof(PROCESS_PRIORITY_CLASS))
				Status = STATUS_INFO_LENGTH_MISMATCH;
			else {
				PROCESS_PRIORITY_CLASS ppc;

				if (PreviousMode != KernelMode) {
					if (copy_from_user(&ppc, ProcessInformation, sizeof(PROCESS_PRIORITY_CLASS)))
						Status = STATUS_UNSUCCESSFUL;
				}
				else
					ppc = *(PPROCESS_PRIORITY_CLASS)ProcessInformation;

				Process->priority_class = ppc.PriorityClass;
			}
			break;
		case ProcessAffinityMask:
			if (ProcessInformationLength != sizeof(DWORD_PTR))
				Status = STATUS_INFO_LENGTH_MISMATCH;
			else {
				DWORD_PTR affinity;

				if (PreviousMode != KernelMode) {
					if (copy_from_user(&affinity, ProcessInformation, sizeof(DWORD_PTR)))
						Status = STATUS_UNSUCCESSFUL;
				}
				else
					affinity = *(PDWORD_PTR)ProcessInformation;

				if (affinity != 1)
					Status = STATUS_UNSUCCESSFUL;
				else
					Process->pcb.affinity = affinity;
			}
			break;
		case ProcessDefaultHardErrorMode:
			if (ProcessInformationLength != sizeof(LONG))
				Status = STATUS_INFO_LENGTH_MISMATCH;
			else {
				LONG error;

				if (PreviousMode != KernelMode) {
					if (copy_from_user(&error, ProcessInformation, sizeof(LONG)))
						Status = STATUS_UNSUCCESSFUL;
				}
				else
					error = *(PLONG)ProcessInformation;

				(void)xchg(&Process->def_hard_error_processing, error);
			}
			break;
		case ProcessSessionInformation:
			if (ProcessInformationLength != sizeof(PROCESS_SESSION_INFORMATION))
				Status = STATUS_INFO_LENGTH_MISMATCH;
			else {
				PROCESS_SESSION_INFORMATION session;

				if (PreviousMode != KernelMode) {
					if (copy_from_user(&session, ProcessInformation,
								sizeof(PROCESS_SESSION_INFORMATION)))
						Status = STATUS_UNSUCCESSFUL;
				}
				else
					session = *(PPROCESS_SESSION_INFORMATION)ProcessInformation;

				Process->session = session.SessionId;
			}
			break;
		case ProcessQuotaLimits:
		case ProcessBasePriority:
		case ProcessRaisePriority:
		case ProcessExceptionPort:
		case ProcessAccessToken:
		case ProcessLdtInformation:
		case ProcessLdtSize:
		case ProcessIoPortHandlers:
		case ProcessWorkingSetWatch:
		case ProcessUserModeIOPL:
		case ProcessEnableAlignmentFaultFixup:
			/* TODO */
			Status = STATUS_NOT_IMPLEMENTED;
			break;
		case ProcessBasicInformation:
		case ProcessIoCounters:
		case ProcessTimes:
		case ProcessPooledUsageAndLimits:
		case ProcessWx86Information:
		case ProcessHandleCount:
		case ProcessWow64Information:
		case ProcessDebugPort:
			/* TODO */
		default:
			Status = STATUS_INVALID_INFO_CLASS;
			break;
	}
	deref_object(Process);

	return Status;
}
EXPORT_SYMBOL(NtSetInformationProcess);

NTSTATUS SERVICECALL
NtQueryInformationThread (IN HANDLE ThreadHandle,
		IN  THREADINFOCLASS ThreadInformationClass,
		OUT PVOID ThreadInformation,
		IN  ULONG ThreadInformationLength,
		OUT PULONG ReturnLength OPTIONAL)
{
	struct ethread	*cur_thread, *thread; 
	struct eprocess *process;
	NTSTATUS status = STATUS_SUCCESS;
	union
	{
		THREAD_BASIC_INFORMATION TBI;
		KERNEL_USER_TIMES TTI;
		PVOID Address;
		LARGE_INTEGER Count;
		BOOLEAN Last;
	} u;
	KPROCESSOR_MODE PreviousMode = 
		(ULONG)ThreadInformation < TASK_SIZE ? UserMode : KernelMode;	/* TODO ... */

	ktrace("hthread %p\n", ThreadHandle);

	if (ThreadInformationClass <= MaxThreadInfoClass &&
			!QueryInformationData[ThreadInformationClass].Implemented)
		return STATUS_NOT_IMPLEMENTED;

	if (ThreadInformationClass > MaxThreadInfoClass ||
			QueryInformationData[ThreadInformationClass].Size == 0)
		return STATUS_INVALID_INFO_CLASS;

	if (ThreadInformationLength != QueryInformationData[ThreadInformationClass].Size)
		return STATUS_INFO_LENGTH_MISMATCH;

	cur_thread = get_current_ethread();
	if (!cur_thread){
		return -EINVAL;
	}

	status = ref_object_by_handle(ThreadHandle,
			THREAD_ALL_ACCESS,
			thread_object_type,
			KernelMode,
			(PVOID *)&thread,
			NULL);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	switch (ThreadInformationClass) {
		case ThreadBasicInformation:
			u.TBI.ExitStatus = thread->et_task ? STATUS_PENDING : 0;
			u.TBI.TebBaseAddress = (PVOID)thread->tcb.teb;
			u.TBI.ClientId.UniqueProcess = (HANDLE)thread->cid.unique_process;
			u.TBI.ClientId.UniqueThread = (HANDLE)thread->cid.unique_thread;
			u.TBI.AffinityMask = (kaffinity_t)thread->tcb.affinity;
			u.TBI.Priority = (KPRIORITY)thread->tcb.priority;
			u.TBI.BasePriority = (KPRIORITY)thread->tcb.priority;
			break;
		case ThreadTimes:
			break;
		case ThreadQuerySetWin32StartAddress:
			u.Address = thread->win32_start_address;
			break;
		case ThreadPerformanceCount:
			/* Nebbett says this class is always zero */
			u.Count.QuadPart = 0;
			break;
		case ThreadAmILastThread:
			process = thread->threads_process;
			u.Last = (process->thread_list_head.next == process->thread_list_head.prev
					&& process->thread_list_head.next == &thread->thread_list_entry)
				? TRUE : FALSE;
			break;
		default:
			status = STATUS_INVALID_INFO_CLASS;
			break;
	}

	deref_object(thread);

	if (PreviousMode == UserMode) {
		if (ThreadInformationLength) {
			if (copy_to_user(ThreadInformation,
						&u.TBI,
						ThreadInformationLength))
				return STATUS_UNSUCCESSFUL;
		}
		if (ReturnLength) {
			if(copy_to_user(ReturnLength,
						&ThreadInformationLength,
						sizeof(ULONG)))
				return STATUS_UNSUCCESSFUL;
		}
	}
	else {
		memcpy(ThreadInformation, &u.TBI, ThreadInformationLength);
		*ReturnLength = ThreadInformationLength;
	}

	return status;	
}
EXPORT_SYMBOL(NtQueryInformationThread);

NTSTATUS SERVICECALL
NtSetInformationThread (IN HANDLE ThreadHandle,
		IN THREADINFOCLASS ThreadInformationClass,
		IN PVOID ThreadInformation,
		IN ULONG ThreadInformationLength)
{
	PETHREAD Thread;
	union
	{
		KPRIORITY Priority;
		LONG Increment;
		KAFFINITY Affinity;
		HANDLE Handle;
		PVOID Address;
	}u;
	KPROCESSOR_MODE PreviousMode =
		(ULONG)ThreadInformation < TASK_SIZE ? UserMode : KernelMode;	/* TODO ... */
	NTSTATUS Status = STATUS_SUCCESS;

	ktrace("\n");
	if (ThreadInformationClass <= MaxThreadInfoClass &&
			!SetInformationData[ThreadInformationClass].Implemented)
		return STATUS_NOT_IMPLEMENTED;
	if (ThreadInformationClass > MaxThreadInfoClass ||
			SetInformationData[ThreadInformationClass].Size == 0)
		return STATUS_INVALID_INFO_CLASS;
	if (ThreadInformationLength != SetInformationData[ThreadInformationClass].Size)
		return STATUS_INFO_LENGTH_MISMATCH;

	if (PreviousMode == UserMode) {
		if (copy_from_user(&u.Priority,
					ThreadInformation,
					ThreadInformationLength))
			return STATUS_UNSUCCESSFUL; 
	} else
		memcpy(&u.Priority, ThreadInformation, ThreadInformationLength); 

	/* FIXME: This is REALLY wrong. Some types don't need THREAD_SET_INFORMATION */
	/* FIXME: We should also check for certain things before doing the reference */
	Status = ref_object_by_handle (ThreadHandle,
			THREAD_SET_INFORMATION,
			thread_object_type,
			PreviousMode,
			(PVOID*)&Thread,
			NULL);
	if (!NT_SUCCESS(Status))
		return Status;

	switch (ThreadInformationClass) {
		case ThreadPriority:
			if (u.Priority < LOW_PRIORITY || u.Priority >= MAXIMUM_PRIORITY) {
				Status = STATUS_INVALID_PARAMETER;
				break;
			}
			/* TODO: KeSetPriorityThread(&Thread->tcb, u.Priority); */
			break;
		case ThreadBasePriority:
			/* TODO: KeSetBasePriorityThread (&Thread->tcb, u.Increment); */
			break;
		case ThreadAffinityMask:
			if ((Thread->threads_process->pcb.affinity & u.Affinity) != u.Affinity) {
				Status = STATUS_INVALID_PARAMETER;
				break;
			}
			/* TODO: Status = KeSetAffinityThread(&Thread->tcb, u.Affinity); */
			break;
		case ThreadImpersonationToken:
			/* TODO: Status = PsAssignImpersonationToken (Thread, u.Handle); */
			break;
		case ThreadQuerySetWin32StartAddress:
			Thread->win32_start_address = u.Address;
			break;
		default:
			Status = STATUS_INVALID_INFO_CLASS;
			break;
	}
	deref_object(Thread);

	return Status;
}
EXPORT_SYMBOL(NtSetInformationThread);

#endif /* CONFIG_UNIFIED_KERNEL */
