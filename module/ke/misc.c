/*
 * misc.c
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
 * misc.c:
 */

#include "object.h"
#include "process.h"
#include "thread.h"

#ifdef CONFIG_UNIFIED_KERNEL
#define WINNT_DAY_BEFORE 134774 /* days from 1601.1.1 to 1970.1.1 */

extern struct list_head  process_list;
extern struct list_head  thread_list;

void query_sys_time(large_integer_t *CurrentTime)
{
	struct timespec unix_time;
	long long temp;
 
	/* need EXPORT_SYMBOL. kernel/posix-timers.c */
	do_posix_clock_monotonic_gettime(&unix_time);

	temp = WINNT_DAY_BEFORE * 24;
	CurrentTime->quad = (temp * 3600 + unix_time.tv_sec) * 10000000;
	CurrentTime->quad += unix_time.tv_nsec / 100;
}
EXPORT_SYMBOL(query_sys_time);

/* stubs from Wine server */
struct process_snapshot *process_snap(int *count)
{
    struct process_snapshot *snapshot, *ptr;
    struct w32process *process;
	int process_count = 0;
	struct list_head *head;

	LIST_FOR_EACH(head, &process_list)
		process_count++;

	if (process_count == 0)
		return NULL;

    if (!(snapshot = (struct process_snapshot *)kmalloc( sizeof(*snapshot) * process_count, GFP_KERNEL )))
        return NULL;
    ptr = snapshot;
    LIST_FOR_EACH_ENTRY( process, &process_list, struct w32process, entry )
    {
        if (!process || !process->eprocess || !process->running_threads 
		|| !process->eprocess->object_table) {
			process_count--;
			continue;
		}
        ptr->process  = process;
        ptr->threads  = process->running_threads;
        ptr->count    = atomic_read(&((BODY_TO_HEADER(process->eprocess))->PointerCount));
        ptr->priority = process->priority;
        ptr->handles  = process->eprocess->object_table->handle_count;
        grab_object( process );
        ptr++;
    }

    if (!(*count = process_count))
    {
        kfree( snapshot );
        snapshot = NULL;
    }
    return snapshot;
}

struct module_snapshot *module_snap(struct w32process *process, int *count)
{
	return NULL;
}

struct thread_snapshot *thread_snap(int *count)
{
    struct thread_snapshot *snapshot, *ptr;
    struct w32thread *thread;
    int total = 0;

    LIST_FOR_EACH_ENTRY( thread, &thread_list, struct w32thread, entry )
        if (thread->state != TERMINATED) total++;
    if (!total || !(snapshot = (struct thread_snapshot *)kmalloc( sizeof(*snapshot) * total, GFP_KERNEL ))) return NULL;
    ptr = snapshot;
    LIST_FOR_EACH_ENTRY( thread, &thread_list, struct w32thread, entry )
    {
        if (thread->state == TERMINATED) continue;
        ptr->thread   = thread;
        ptr->count    = atomic_read(&(BODY_TO_HEADER(thread->ethread))->PointerCount);
        ptr->priority = thread->priority;
        grab_object( thread );
        ptr++;
    }
    *count = total;
    return snapshot;
}

struct object_type *no_get_type(struct object *obj)
{
	/* ERR: gets called! */
	return NULL;
}

void no_destroy(struct object *obj)
{
	/* ERR: gets called! */
}

/* --- Query/Set System Information ---*/
#define QSI_USE(n) QSI##n
#define QSI_DEF(n) \
static NTSTATUS QSI_USE(n) (PVOID Buffer, ULONG Size, PULONG ReqSize)

#define SSI_USE(n) SSI##n
#define SSI_DEF(n) \
static NTSTATUS SSI_USE(n) (PVOID Buffer, ULONG Size);

/* Class 0 - Basic Information */
QSI_DEF(SystemBasicInformation)
{
	/* FIXME: */
	return STATUS_NOT_IMPLEMENTED;
}

/* Class 1 - Processor Information */
QSI_DEF(SystemProcessorInformation)
{
	/* FIXME: */
	return STATUS_NOT_IMPLEMENTED;
}

/* Class 2 - Performance Information */
QSI_DEF(SystemPerformanceInformation)
{
	/* FIXME: */
	return STATUS_NOT_IMPLEMENTED;
}

/* Class 3 - Time Of Day Information */
QSI_DEF(SystemTimeOfDayInformation)
{
	PSYSTEM_TIMEOFDAY_INFORMATION Sti;
	LARGE_INTEGER CurrentTime;
	struct timeval now;

	Sti = (PSYSTEM_TIMEOFDAY_INFORMATION)Buffer;
	if (ReqSize)
		*ReqSize= sizeof(SYSTEM_TIMEOFDAY_INFORMATION);

	/* Check user buffer's size */
	if (Size != sizeof(SYSTEM_TIMEOFDAY_INFORMATION)) {
		return STATUS_INFO_LENGTH_MISMATCH;
	}

	/* FIXME: KeQuerySystemTime should be called */
	do_gettimeofday(&now);
	CurrentTime.QuadPart = now.tv_sec * 10000000; /* FIXME */
	CurrentTime.QuadPart += now.tv_usec * 10;

	Sti->BootTime.QuadPart = 0;
	Sti->CurrentTime = CurrentTime;
	Sti->TimeZoneBias.QuadPart = 0;
	Sti->TimeZoneId = 0;
	Sti->Reserved = 0;

	return STATUS_SUCCESS;
}

/* Class 5 - Process Information */
QSI_DEF(SystemProcessInformation)
{
	/* FIXME: */
	return STATUS_NOT_IMPLEMENTED;
}

/* Class 8 - Processor Performance Information */
QSI_DEF(SystemProcessorPerformanceInformation)
{
	/* FIXME: */
	return STATUS_NOT_IMPLEMENTED;
}

/* Class 11 - Module Information */
QSI_DEF(SystemModuleInformation)
{
	/* FIXME: */
	return STATUS_NOT_IMPLEMENTED;
}

/* Class 16 - Handle Information */
QSI_DEF(SystemHandleInformation)
{
	/* FIXME: */
	return STATUS_NOT_IMPLEMENTED;
}

/* Class 21 - File Cache Information */
QSI_DEF(SystemFileCacheInformation)
{
	/* FIXME: */
	return STATUS_NOT_IMPLEMENTED;
}

/* Class 23 - Interrupt Information for all processors */
QSI_DEF(SystemInterruptInformation)
{
	/* FIXME: */
	return STATUS_NOT_IMPLEMENTED;
}

/* Class 35 - Kernel Debugger Information */
QSI_DEF(SystemKernelDebuggerInformation)
{
	/* FIXME: */
	return STATUS_NOT_IMPLEMENTED;
}

/* Class 37 - Registry Quota Information */
QSI_DEF(SystemRegistryQuotaInformation)
{
	/* FIXME: */
	return STATUS_NOT_IMPLEMENTED;
}

/* Query/Set Calls Table */
typedef struct _QSSI_CALLS
{
	NTSTATUS (*Query)(PVOID, ULONG, PULONG);
	NTSTATUS (*Set)(PVOID, ULONG);
} QSSI_CALLS;

/*
 * QS - Query & Set 
 * QX - Query
 * XS - Set
 * XX - unknown behaviour
 */
#define SI_QS(n) {QSI_USE(n),SSI_USE(n)}
#define SI_QX(n) {QSI_USE(n), NULL}
#define SI_XS(n) {NULL, SSI_USE(n)}
#define SI_XX(n) {NULL, NULL}

static QSSI_CALLS
CallQS[] = 
{
	SI_QX(SystemBasicInformation), 						/* 0 */
	SI_QX(SystemProcessorInformation),
	SI_QX(SystemPerformanceInformation),
	SI_QX(SystemTimeOfDayInformation),
	SI_XX(SystemPathInformation),
	SI_QX(SystemProcessInformation), 					/* 5 */
	SI_XX(SystemCallCountInformation),
	SI_XX(SystemDeviceInformation),
	SI_QX(SystemProcessorPerformanceInformation),
	SI_XX(SystemFlagsInformation),
	SI_XX(SystemCallTimeInformation), 					/* 10 */
	SI_QX(SystemModuleInformation),
	SI_XX(SystemLocksInformation),
	SI_XX(SystemStackTraceInformation),
	SI_XX(SystemPagedPoolInformation),
	SI_XX(SystemNonPagedPoolInformation), 				/* 15 */
	SI_QX(SystemHandleInformation),
	SI_XX(SystemObjectInformation),
	SI_XX(SystemPageFileInformation),
	SI_XX(SystemVdmInstemulInformation),
	SI_XX(SystemVdmBopInformation), 					/* 20 */
	SI_QX(SystemFileCacheInformation),
	SI_XX(SystemPoolTagInformation),
	SI_QX(SystemInterruptInformation),
	SI_XX(SystemDpcBehaviourInformation),
	SI_XX(SystemFullMemoryInformation), 				/* 25 */
	SI_XX(SystemLoadGdiDriverInformation),
	SI_XX(SystemUnloadGdiDriverInformation),
	SI_XX(SystemTimeAdjustmentInformation),
	SI_XX(SystemSummaryMemoryInformation),
	SI_XX(SystemNextEventIdInformation), 				/* 30 */ 
	SI_XX(SystemEventIdsInformation),
	SI_XX(SystemCrashDumpInformation),
	SI_XX(SystemExceptionInformation),
	SI_XX(SystemCrashDumpStateInformation),
	SI_QX(SystemKernelDebuggerInformation), 			/* 35 */
	SI_XX(SystemContextSwitchInformation),
	SI_QX(SystemRegistryQuotaInformation),
	SI_XX(SystemExtendServiceTableInformation),
	SI_XX(SystemPrioritySeperation),
	SI_XX(SystemPlugPlayBusInformation), 				/* 40 */
	SI_XX(SystemDockInformation),
	SI_XX(SystemPowerInformation),
	SI_XX(SystemProcessorSpeedInformation),
	SI_XX(SystemCurrentTimeZoneInformation),
	SI_XX(SystemLookasideInformation), 					/* 45 */
	SI_XX(SystemSetTimeSlipEvent),
	SI_XX(SystemCreateSession),
	SI_XX(SystemDeleteSession),
	SI_XX(SystemInvalidInfoClass4),
	SI_XX(SystemRangeStartInformation), 				/* 50 */
	SI_XX(SystemVerifierInformation),
	SI_XX(SystemAddVerifier),
	SI_XX(SystemSessionProcessesInformation)
};

NTSTATUS SERVICECALL
NtQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
		OUT PVOID SystemInformation, 
		IN ULONG Length, 
		OUT PULONG ResultLength)
{
	NTSTATUS Status = STATUS_NOT_IMPLEMENTED;

	/* Check the request is vaild */
	if (SystemInformationClass >= SystemInformationClassMax) {
		return STATUS_INVALID_INFO_CLASS;
	}

	if (NULL != CallQS[SystemInformationClass].Query) {
		Status = CallQS[SystemInformationClass].Query(SystemInformation, 
							Length,
							ResultLength);
	}

	return Status;
}
EXPORT_SYMBOL(NtQuerySystemInformation);
#endif /* CONFIG_UNIFIED_KERNEL */
