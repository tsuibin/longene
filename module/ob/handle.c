/*
 * handle.c
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
 * handle.c:
 * Refered to ReactOS code
 */
#include "handle.h"
#include "semaphore.h"
#include "mutex.h"

#ifdef CONFIG_UNIFIED_KERNEL
static BOOLEAN initialized = FALSE;
static struct list_head handle_table_head;
static FAST_MUTEX handle_table_lock;
static LARGE_INTEGER handle_short_wait;
struct handle_table *kernel_handle_table = NULL;
EXPORT_SYMBOL(kernel_handle_table);

extern POBJECT_TYPE process_object_type;
extern POBJECT_TYPE thread_object_type;

#define acquire_handle_table_lock() acquire_fmutex_unsafe(&handle_table_lock)
#define release_handle_table_lock() release_fmutex_unsafe(&handle_table_lock)

#define GENERIC_ANY (GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL)

extern VOID STDCALL event_init(struct kevent *event, enum event_type type, BOOLEAN state);

struct file *get_unix_file(struct fd *fd);

VOID
memory_barrier(VOID)
{
	volatile long barrier;
	__asm__ __volatile__ ("xchg %%eax, %0": :"m"(barrier): "%eax");
} /*end memory_barrier */

VOID
STDCALL
map_generic_mask(PACCESS_MASK AccessMask,
		const PGENERIC_MAPPING GenericMapping)
{
	if (*AccessMask & GENERIC_READ)
		*AccessMask |= GenericMapping->GenericRead;

	if (*AccessMask & GENERIC_WRITE)
		*AccessMask |= GenericMapping->GenericWrite;

	if (*AccessMask & GENERIC_EXECUTE)
		*AccessMask |= GenericMapping->GenericExecute;

	if (*AccessMask & GENERIC_ALL)
		*AccessMask |= GenericMapping->GenericAll;

	*AccessMask &= ~(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);
} /* end map_generic_mask */
EXPORT_SYMBOL(map_generic_mask);

NTSTATUS
STDCALL
init_resource(struct eresource *Resource)
{
	memset(Resource, 0, sizeof(struct eresource));
	Resource->number_of_shared_waiters = 0;
	Resource->number_of_exclusive_waiters = 0;
	spin_lock_init(&Resource->spinlock);
	Resource->flag = 0;
	Resource->exclusive_waiters = kmalloc(sizeof(struct kevent), GFP_KERNEL);
	event_init(Resource->exclusive_waiters, SynchronizationEvent, FALSE);
	Resource->shared_waiters = kmalloc(sizeof(struct ksemaphore), GFP_KERNEL);
	semaphore_init(Resource->shared_waiters, 0, 0x7fffffff);
	Resource->active_count = 0;
	return 0;
} /* init_resource */
EXPORT_SYMBOL(init_resource);

NTSTATUS
STDCALL
delete_resource(struct eresource *Resource)
{
	if (Resource->owner_table)
		kfree(Resource->owner_table);

	if (Resource->shared_waiters)
		kfree(Resource->shared_waiters);

	if (Resource->exclusive_waiters)
		kfree(Resource->exclusive_waiters);
	
	return STATUS_SUCCESS;
} /* end delete_resource */
EXPORT_SYMBOL(delete_resource);

VOID
init_handle_tables(VOID)
{
	handle_short_wait.QuadPart = -50000;
	INIT_LIST_HEAD(&handle_table_head);
	init_fast_mutex(&handle_table_lock);
	initialized = TRUE;
} /* init_handle_tables */

static BOOLEAN
lock_entry_no_check(IN struct handle_table *HandleTable,
		IN struct handle_table_entry *Entry)
{
	ULONG_PTR Current, New;

	if (!HandleTable || !Entry)
		return FALSE;

	for (;;) {
		Current = (ULONG_PTR)Entry->u1.object;

		if (!Current)
			break;

		if (!(Current & EX_HANDLE_ENTRY_LOCKED)) {
			New = Current | EX_HANDLE_ENTRY_LOCKED;
			__xchg((void *)New, &Entry->u1.object, sizeof(Entry->u1.object));
			return TRUE;
		}

		wait_for_single_object(&HandleTable->handle_contention_event,
				Executive,
				KernelMode,
				FALSE,
				&handle_short_wait);
	}

	return FALSE;
} /* end lock_entry_no_check */

BOOLEAN
lock_handle_table_entry(IN struct handle_table *HandleTable,
		IN struct handle_table_entry *Entry)
{
	ULONG_PTR Current, New;

	if (!HandleTable || !Entry)
		return FALSE;

	for (;;) {
		Current = (ULONG_PTR)Entry->u1.object;

		if (!Current || (HandleTable->flags & EX_HANDLE_TABLE_CLOSING))
			break;

		if (!(Current & EX_HANDLE_ENTRY_LOCKED)) {
			New = Current | EX_HANDLE_ENTRY_LOCKED;
			__xchg((void *)New, &Entry->u1.object, sizeof(Entry->u1.object));
			return TRUE;
		}

		wait_for_single_object(&HandleTable->handle_contention_event,
				Executive,
				KernelMode,
				FALSE,
				&handle_short_wait);
	}

	return FALSE;
} /* end lock_handle_table_entry */

VOID
unlock_handle_table_entry(IN struct handle_table *HandleTable,
		IN struct handle_table_entry *Entry)
{
	ULONG_PTR Current, New;

	if (!HandleTable || !Entry)
		return;

	Current	= (ULONG_PTR)Entry->u1.object;

	if (Current & EX_HANDLE_ENTRY_LOCKED) {
		New = Current &~EX_HANDLE_ENTRY_LOCKED;
		__xchg((void *)New, &Entry->u1.object, sizeof(Entry->u1.object));

		pulse_event(&HandleTable->handle_contention_event,
			0,
			FALSE);
	}
} /* end unlock_handle_table_entry */
	
struct handle_table *
__create_handle_table(IN struct eprocess *QuotaProcess  OPTIONAL)
{
	struct handle_table *handle_table;

	if (!initialized)
		return NULL;

	handle_table = kmalloc(sizeof(handle_table) + (N_TOPLEVEL_POINTERS * 
			sizeof(struct handle_table_entry **)), GFP_KERNEL);
	if (!handle_table)
		return handle_table;

	/* Initialize the handle table */
	handle_table->flags = 0;
	handle_table->handle_count = 0;
	handle_table->table = (struct handle_table_entry ***)(handle_table + 1);
	handle_table->quota_process = QuotaProcess;
	handle_table->first_free_table_entry = -1;
	handle_table->next_index_needing_pool = 0;
	handle_table->unique_processid = (QuotaProcess ? QuotaProcess->unique_processid : NULL);

	init_resource(&handle_table->handle_table_lock);
	event_init(&handle_table->handle_contention_event, NotificationEvent, FALSE);

	memset(handle_table->table, 0, N_TOPLEVEL_POINTERS * sizeof(struct handle_table_entry **));

	enter_critical_region();
	acquire_handle_table_lock();

	/* Insert it into the global handle table list */
	list_add_tail(&handle_table->handle_table_list, &handle_table_head);

	release_handle_table_lock();
	leave_critical_region();

	return handle_table;
} /* __create_handle_table */
EXPORT_SYMBOL(__create_handle_table);

BOOLEAN STDCALL
dup_handle_callback(struct handle_table *HandleTable,
			struct handle_table_entry *HandleTableEntry,
			PVOID Context)
{
	POBJECT_HEADER object_header;

	if (HandleTableEntry->u1.obattributes & EX_HANDLE_ENTRY_INHERITABLE) {
		object_header = EX_HTE_TO_HDR(HandleTableEntry);
		atomic_inc(&object_header->HandleCount);
		ref_object(&object_header->Body);
		return TRUE;
	}
	else return FALSE;
} /* end dup_handle_callback */

VOID STDCALL
delete_handle_callback(struct handle_table *HandleTable,
                     PVOID Object,
                     ULONG GrantedAccess,
                     PVOID Context)
{
	POBJECT_HEADER object_header;
	PVOID object_body;

	object_header = EX_OBJ_TO_HDR(Object);
	object_body = &object_header->Body;

	if (IS_WINE_OBJECT(object_header))
		release_object(object_body);
	else   /* not a wine object */
		decrement_handle_count(object_body);
} /* end delete_handle_callback */

VOID
__destroy_handle_table(IN struct handle_table *HandleTable,
		IN PEX_DESTROY_HANDLE_CALLBACK DestroyHandleCallback OPTIONAL,
		IN PVOID Context OPTIONAL)
{
	struct handle_table_entry ***tlp, ***lasttlp, **mlp, **lastmlp;

	if (!HandleTable)
		return;

	enter_critical_region();

	spin_lock(&HandleTable->handle_table_lock.spinlock);

	if (HandleTable->flags & EX_HANDLE_TABLE_CLOSING)
		return;
	
	HandleTable->flags |= EX_HANDLE_TABLE_CLOSING;

	pulse_event(&HandleTable->handle_contention_event, 0, FALSE);

	acquire_handle_table_lock();
	list_del(&HandleTable->handle_table_list);
	release_handle_table_lock();

	/* Call the callback function to cleanup the objects */
	lasttlp = HandleTable->table + N_TOPLEVEL_POINTERS;
	if (DestroyHandleCallback) {
		for (tlp = HandleTable->table; tlp != lasttlp; tlp++) {
			if (*tlp) {
				lastmlp = *tlp + N_MIDDLELEVEL_POINTERS;
				for (mlp = *tlp; mlp != lastmlp; mlp++) {
					if (*mlp) {
						struct handle_table_entry *cure, *laste;

						laste = *mlp + N_SUBHANDLE_ENTRIES;
						for(cure = *mlp; cure != laste; cure++) {
							if (cure->u1.object && 
							    lock_entry_no_check(HandleTable, cure)) {
								DestroyHandleCallback(HandleTable,
										cure->u1.object,
										cure->u2.granted_access,
										Context);
								unlock_handle_table_entry(HandleTable, cure);
							}
						}
					}
				}
			}
		}
	}

	/* Free the table if necessary */
	for (tlp = HandleTable->table; tlp != lasttlp; tlp++) {
		if (*tlp) {
			lastmlp = *tlp + N_MIDDLELEVEL_POINTERS;
			for (mlp = *tlp; mlp != lastmlp; mlp++) {
				if (*mlp)
					kfree(*mlp);
			}
			kfree(*tlp);
		}
	}

	spin_unlock(&HandleTable->handle_table_lock.spinlock);

	leave_critical_region();

	delete_resource(&HandleTable->handle_table_lock);
	kfree(HandleTable);
} /* end __destroy_handle_table */
EXPORT_SYMBOL(__destroy_handle_table);

struct handle_table *
dup_handle_table(IN struct eprocess *QuotaProcess OPTIONAL,
		IN PEX_DUPLICATE_HANDLE_CALLBACK dup_handle_callback OPTIONAL,
		IN PVOID Context OPTIONAL,
		IN struct handle_table *SourceHandleTable)
{
	struct handle_table *handle_table;
	struct handle_table_entry ***srctlp, **srcmlp, *srcstbl;
	struct handle_table_entry ***tlp, **mlp, *stbl;
	struct handle_table_entry ***etlp, **emlp, *estbl;
	LONG tli, mli, eli;
	tli = mli = eli = 0;

	if (!SourceHandleTable)
		return NULL;

	/* Create a handle table for the quota process */
	if(QuotaProcess->object_table)
	{
		handle_table = QuotaProcess->object_table;
	}
	else
	{
		handle_table = __create_handle_table(QuotaProcess);
		if (!handle_table)
			return handle_table;
	}


	spin_lock(&SourceHandleTable->handle_table_lock.spinlock);

	/* Duplicate the handles from the parent */
	handle_table->handle_count = SourceHandleTable->handle_count;
	handle_table->first_free_table_entry = SourceHandleTable->first_free_table_entry;
	handle_table->next_index_needing_pool = SourceHandleTable->next_index_needing_pool;

	srctlp = SourceHandleTable->table;
	tlp = handle_table->table;
	etlp = SourceHandleTable->table + N_TOPLEVEL_POINTERS;
	for (; srctlp != etlp; srctlp++, tlp++, tli++) {
		if (*srctlp) {
			/* Allocate a top level entry if the parent has one */
			*tlp = kmalloc(sizeof(struct handle_table_entry *) * N_MIDDLELEVEL_POINTERS, GFP_KERNEL);
			if (!*tlp)
				goto out;

			memset(*tlp, 0, sizeof(struct handle_table_entry *) * N_MIDDLELEVEL_POINTERS);
			memory_barrier();

			emlp = *srctlp + N_MIDDLELEVEL_POINTERS;
			for (srcmlp = *srctlp, mlp = *tlp; srcmlp != emlp; srcmlp++, mlp++, mli++){
				if (*srcmlp) {
					/* Allocate a middle level entry if the parent has one */
					*mlp = kmalloc(sizeof(struct handle_table_entry) *
						N_SUBHANDLE_ENTRIES, GFP_KERNEL);
					if (!*mlp)
						goto out;

					memset(*mlp, 0, sizeof(struct handle_table_entry) * N_SUBHANDLE_ENTRIES);

					/* Walk all handle entries and duplicate them if wanted */
					estbl = *srcmlp + N_SUBHANDLE_ENTRIES;
					for (srcstbl = *srcmlp, stbl = *mlp; srcstbl != estbl;
					    srcstbl++, stbl++, eli++) {
						if (srcstbl->u1.object && 
						    lock_handle_table_entry(SourceHandleTable, srcstbl)) {
							/* Ask the caller if this handle should be duplicated */
							if (dup_handle_callback && 
							    !dup_handle_callback(handle_table, srcstbl, Context)) {
							   	/* The handle is not inheritable, free it */
								handle_table->handle_count--;
								stbl->u1.object = NULL;
								stbl->u2.next_free_table_entry = 
									handle_table->first_free_table_entry;
								handle_table->first_free_table_entry = 
									BUILD_HANDLE(tli, mli, eli);
							}
							else {
								POBJECT_HEADER objhdr;
								stbl->u2.granted_access = srcstbl->u2.granted_access;
								stbl->u1.object = srcstbl->u1.object;
								objhdr = (void*)((unsigned int)stbl->u1.object &
										~(EX_HANDLE_ENTRY_PROTECTFROMCLOSE | EX_HANDLE_ENTRY_INHERITABLE));


								stbl->u1.obattributes &= ~EX_HANDLE_ENTRY_LOCKED;

								set_handle_info(QuotaProcess,
										EX_HANDLE_TO_HANDLE(BUILD_HANDLE(tli, mli, eli)),
										(struct object*)&objhdr->Body);
							}
							unlock_handle_table_entry(SourceHandleTable, srcstbl);
						}
						else *stbl = *srcstbl;
					}
				}
				else *mlp = NULL;
			}
		}
		else *tlp = NULL;
	}
	spin_unlock(&SourceHandleTable->handle_table_lock.spinlock);

	return handle_table;
out:
	spin_unlock(&SourceHandleTable->handle_table_lock.spinlock);

	__destroy_handle_table(handle_table, NULL, NULL);
	return __create_handle_table(QuotaProcess);
} /* end dup_handle_table */

VOID
create_handle_table(struct eprocess *Parent,
		BOOLEAN Inherit,
		struct eprocess *Process)
{
	if (Inherit && Parent)
		/* If it has a parent, duplicate the handle table */
		Process->object_table = dup_handle_table(Process,
						dup_handle_callback,
						NULL,
						Parent->object_table);
	else if (Process)
		Process->object_table = __create_handle_table(Process);

	else
		kernel_handle_table = __create_handle_table(NULL);
} /* end create_handle_table */
EXPORT_SYMBOL(create_handle_table);

struct handle_table_entry *
alloc_handle_table_entry(IN struct handle_table *HandleTable,
			OUT PLONG Handle)
{
	struct handle_table_entry *entry = NULL;
	ULONG tli, mli, eli;
	
	if (!HandleTable || !Handle)
		return NULL;

	if (HandleTable->handle_count >= EX_MAX_HANDLES)
		return NULL;

	if (HandleTable->first_free_table_entry != -1) {
		/* There is a free entry we can use */
		tli = TLI_FROM_HANDLE(HandleTable->first_free_table_entry);
		mli = MLI_FROM_HANDLE(HandleTable->first_free_table_entry);
		eli = ELI_FROM_HANDLE(HandleTable->first_free_table_entry);

		/* Get the entry and the handle */
		entry = &HandleTable->table[tli][mli][eli];
		*Handle = HandleTable->first_free_table_entry;

		/* Set the first free table entry for the next time */
		HandleTable->first_free_table_entry = entry->u2.next_free_table_entry;
		entry->u2.next_free_table_entry = 0;
		entry->u1.object = NULL;

		HandleTable->handle_count++;
	}
	else {
		/* We need to allocate a new subhandle table first */
		struct handle_table_entry **nmtbl, *ntbl, *laste, *cure;
		BOOLEAN allocated = FALSE;
		ULONG i;

		tli = TLI_FROM_HANDLE(HandleTable->next_index_needing_pool);
		mli = MLI_FROM_HANDLE(HandleTable->next_index_needing_pool);

		nmtbl = HandleTable->table[tli];
		if (!nmtbl) {
			/* Allocate a middle level entry */
			if (!(nmtbl = kmalloc(sizeof(struct handle_table_entry *) * 
						N_MIDDLELEVEL_POINTERS, GFP_KERNEL)))
				return NULL;

			memset(nmtbl, 0, sizeof(struct handle_table_entry *) * N_MIDDLELEVEL_POINTERS);
			memory_barrier();

			/* We have allocated a middle level entry */
			allocated = TRUE;
		}

		if (!(ntbl = kmalloc(sizeof(struct handle_table_entry) * N_SUBHANDLE_ENTRIES, GFP_KERNEL))) {
			if (allocated)
				kfree(nmtbl);
			return NULL;
		}

		entry = ntbl;
		entry->u1.obattributes = EX_HANDLE_ENTRY_LOCKED;
		entry->u2.next_free_table_entry = 0;

		/* next_index_needing_pool has been set to 0 in __create_handle_table() */
		*Handle = HandleTable->next_index_needing_pool;
		HandleTable->handle_count++;

		/* Set the first free entry */
		HandleTable->first_free_table_entry = HandleTable->next_index_needing_pool + 1;
		laste = entry + N_SUBHANDLE_ENTRIES;
		i = HandleTable->first_free_table_entry + 1;
		/* Set all of the next_free_table_entry members of the index */
		for (cure = entry + 1; cure != laste; cure++, i++) {
			cure->u1.object = NULL;
			cure->u2.next_free_table_entry = i;
		}
		/* truncate the free entry list */
		(cure - 1)->u2.next_free_table_entry = -1;

		__xchg((void *)ntbl, &nmtbl[mli], sizeof(nmtbl[mli]));
		if (allocated)
			__xchg((void *)nmtbl, &HandleTable->table[tli], sizeof(HandleTable->table[tli]));

		/* Set the next index needing pool to the next index */
		HandleTable->next_index_needing_pool += N_SUBHANDLE_ENTRIES;
	}

	return entry;
} /* end alloc_handle_table_entry */

LONG
create_ex_handle(IN struct handle_table *HandleTable,
	IN struct handle_table_entry *Entry)
{
	struct handle_table_entry *new_entry;
	LONG handle = EX_INVALID_HANDLE;
	
	if (!HandleTable || !Entry)
		return 0;

	if (!((ULONG_PTR)Entry->u1.object & EX_HANDLE_ENTRY_LOCKED))
		return 0;

	enter_critical_region();
	spin_lock(&HandleTable->handle_table_lock.spinlock);

	/* Allocate an entry of the handle table */
	new_entry = alloc_handle_table_entry(HandleTable, &handle);

	if (new_entry) {
		*new_entry = *Entry;
		unlock_handle_table_entry(HandleTable, new_entry);
	}

	spin_unlock(&HandleTable->handle_table_lock.spinlock);
	leave_critical_region();

	return handle;
} /* end create_ex_handle */
EXPORT_SYMBOL(create_ex_handle);

NTSTATUS
create_handle(struct eprocess *Process,
		PVOID ObjectBody,
		ACCESS_MASK GrantedAccess,
		BOOLEAN Inherit,
		PHANDLE HandleReturn)
{
	struct handle_table_entry new_entry;
	struct handle_table *handle_table;
	BOOLEAN kernel_handle = FALSE;
	LONG ex_handle;
	HANDLE new_handle;
	POBJECT_HEADER object_header;

	if (!ObjectBody)
		return STATUS_INVALID_PARAMETER;

	object_header = BODY_TO_HEADER(ObjectBody);
	if (!((ULONG_PTR)object_header & EX_HANDLE_ENTRY_LOCKED))
		return STATUS_WAS_LOCKED;

	if (GrantedAccess & MAXIMUM_ALLOWED) {
		GrantedAccess &= ~MAXIMUM_ALLOWED;
		GrantedAccess |= GENERIC_ALL;
	}

	if ((GrantedAccess & GENERIC_ANY) && object_header->Type)
		map_generic_mask(&GrantedAccess, &object_header->Type->TypeInfo.GenericMapping);

	new_entry.u1.object = object_header;
	if (Inherit)
		new_entry.u1.obattributes |= EX_HANDLE_ENTRY_INHERITABLE;
	else
		new_entry.u1.obattributes &= ~EX_HANDLE_ENTRY_INHERITABLE;
	new_entry.u2.granted_access = GrantedAccess;

	/* Create an ex_handle */
	if (Process)
		handle_table = Process->object_table;
	else {
		handle_table = kernel_handle_table;
		kernel_handle = TRUE;
	}
		ex_handle = create_ex_handle(handle_table, &new_entry);

	if (ex_handle != EX_INVALID_HANDLE) {
		NTSTATUS status;

		atomic_inc(&object_header->HandleCount);
		status = ref_object_by_pointer(ObjectBody, 0, NULL, UserMode);
		if (!NT_SUCCESS(status))
			return status;

		new_handle = EX_HANDLE_TO_HANDLE(ex_handle);
		if (kernel_handle)
			new_handle = HANDLE_TO_KERNEL_HANDLE(new_handle);
		
		*HandleReturn = new_handle;
		return STATUS_SUCCESS;
	}
	else
		return STATUS_UNSUCCESSFUL;
} /* end create_handle */
EXPORT_SYMBOL(create_handle);

struct handle_table_entry *
lookup_handle_table_entry(IN struct handle_table *HandleTable,
			IN LONG Handle)
{
	struct handle_table_entry *entry = NULL;

	if (!HandleTable)
		return NULL;

	if (IS_VALID_EX_HANDLE(Handle)) {
		struct handle_table_entry **mlp;
		ULONG tli, mli, eli;

		tli = TLI_FROM_HANDLE(Handle);
		mli = MLI_FROM_HANDLE(Handle);
		eli = ELI_FROM_HANDLE(Handle);

		mlp = HandleTable->table[tli];

		if (Handle < HandleTable->next_index_needing_pool && mlp && mlp[mli] && mlp[mli][eli].u1.object)
			entry = &mlp[mli][eli];
	}

	return entry;
} /* end lookup_handle_table_entry */
EXPORT_SYMBOL(lookup_handle_table_entry);

struct handle_table_entry *
map_handle_to_pointer(IN struct handle_table *HandleTable,
		IN LONG Handle)
{
	struct handle_table_entry *entry;

	if (!HandleTable)
		return NULL;

	entry = lookup_handle_table_entry(HandleTable, Handle);

	if (entry && entry->u1.object && lock_handle_table_entry(HandleTable, entry))
		return entry;

	return NULL;
} /* end map_handle_to_pointer */
EXPORT_SYMBOL(map_handle_to_pointer);

NTSTATUS
ref_object_by_handle(HANDLE Handle,
			ACCESS_MASK DesiredAccess,
			POBJECT_TYPE ObjectType,
			KPROCESSOR_MODE AccessMode,
			PVOID *Object,
			POBJECT_HANDLE_INFORMATION HandleInformation)
{
	struct ethread *thread = NULL;
	struct eprocess *process = NULL;
	struct handle_table *handle_table;
	struct handle_table_entry *handle_entry;
	LONG ex_handle;
	POBJECT_HEADER object_header;
	PVOID object_body;
	ACCESS_MASK access;
	ULONG attributes;

	if (!Handle)
		return STATUS_INVALID_HANDLE;

	thread = get_current_ethread();
	process = get_current_eprocess();

	/* If it's a process handle */
	if (Handle == NtCurrentProcess()) {
		if (ObjectType == process_object_type || ObjectType == NULL) {
			if (!process)
				return STATUS_UNSUCCESSFUL;
			ref_object(process);

			if (HandleInformation) {
				HandleInformation->HandleAttributes = 0;
				HandleInformation->GrantedAccess = PROCESS_ALL_ACCESS;
			}

			*Object = process;
			return STATUS_SUCCESS;
		}
		else return STATUS_OBJECT_TYPE_MISMATCH;
	}

	/* If it's a thread handle */
	if (Handle == NtCurrentThread()) {
		if (ObjectType == thread_object_type || ObjectType == NULL) {
			if (!thread)
				return STATUS_UNSUCCESSFUL;
			ref_object(thread);

			if (HandleInformation) {
				HandleInformation->HandleAttributes = 0;
				HandleInformation->GrantedAccess = THREAD_ALL_ACCESS;
			}

			*Object = thread;
			return STATUS_SUCCESS;
		}
		else return STATUS_OBJECT_TYPE_MISMATCH;
	}

	/*if the handle is console handle, need console_handle_unmap*/
	if ((long)Handle&0x03 )
	{
		Handle = (HANDLE)((long)Handle^0x03);
	}

	if (DesiredAccess & MAXIMUM_ALLOWED) {
		DesiredAccess &= ~MAXIMUM_ALLOWED;
		DesiredAccess |= GENERIC_ALL;
	}

	if (is_kernel_handle(Handle, KernelMode)) {
		handle_table = kernel_handle_table;
		ex_handle = HANDLE_TO_EX_HANDLE(KERNEL_HANDLE_TO_HANDLE(Handle));
	}
	else {
		if (!process)
			return STATUS_UNSUCCESSFUL;

		handle_table = process->object_table;
		ex_handle = HANDLE_TO_EX_HANDLE(Handle);
	}

	enter_critical_region();

	/* Lookup the entry from the handle table */
	handle_entry = map_handle_to_pointer(handle_table, ex_handle);

	if (!handle_entry) {
		leave_critical_region();
		return STATUS_INVALID_HANDLE;
	}

	object_header = EX_HTE_TO_HDR(handle_entry);
	object_body = &object_header->Body;

	if (ObjectType && ObjectType != object_header->Type && !object_header->ops) {
		unlock_handle_table_entry(handle_table, handle_entry);
		leave_critical_region();
		return STATUS_OBJECT_TYPE_MISMATCH;
	}

	if ((DesiredAccess & GENERIC_ANY) && BODY_TO_HEADER(object_body)->Type)
		map_generic_mask(&DesiredAccess, &BODY_TO_HEADER(object_body)->Type->TypeInfo.GenericMapping);

	access = handle_entry->u2.granted_access;

	if (AccessMode != KernelMode && (~access & DesiredAccess)) {
		unlock_handle_table_entry(handle_table, handle_entry);
		leave_critical_region();
		return STATUS_ACCESS_DENIED;
	}

	ref_object(object_body);

	access = handle_entry->u2.granted_access;
	attributes = handle_entry->u1.obattributes & (EX_HANDLE_ENTRY_PROTECTFROMCLOSE | 
						EX_HANDLE_ENTRY_INHERITABLE |
						EX_HANDLE_ENTRY_AUDITONCLOSE);

	unlock_handle_table_entry(handle_table, handle_entry);
	leave_critical_region();

	if (HandleInformation) {
		HandleInformation->HandleAttributes = attributes;
		HandleInformation->GrantedAccess = access;
	}

	*Object = object_body;

	return STATUS_SUCCESS;
} /* end ref_object_by_handle */
EXPORT_SYMBOL(ref_object_by_handle);

VOID
decrement_handle_count(PVOID ObjectBody)
{
	POBJECT_HEADER object_header;
	POBJECT_HEADER_NAME_INFO object_name;
	POBJECT_HEADER_CREATOR_INFO creator_info;
	LONG new_count;

	object_header = BODY_TO_HEADER(ObjectBody);
	object_name = HEADER_TO_OBJECT_NAME(object_header);
	new_count = atomic_dec_return(&object_header->HandleCount);

	if (object_header->Type && object_header->Type->TypeInfo.CloseProcedure)
		object_header->Type->TypeInfo.CloseProcedure(NULL,
				ObjectBody,
				0,
				0,
				new_count + 1);

	if (new_count == 0) {
		if (object_name && object_name->Directory && !(object_header->Flags & OB_FLAG_PERMANENT)) {
			/* Delete the directory when the last handle got closed */
			lookup_obdir_entry(object_name->Directory, &object_name->Name, OBJ_CASE_INSENSITIVE);
			delete_obdir_entry(object_name->Directory);
		}

		creator_info = HEADER_TO_CREATOR_INFO(object_header);
		if (creator_info && !list_empty(&creator_info->TypeList)) {
			list_del(&creator_info->TypeList);
			INIT_LIST_HEAD(&creator_info->TypeList);
		}
	}
	deref_object(ObjectBody);
} /* end decrement_handle_count */

VOID
free_handle_table_entry(IN struct handle_table *HandleTable,
			IN struct handle_table_entry *Entry,
			IN LONG Handle)
{
	if (!HandleTable || !Entry || !IS_VALID_EX_HANDLE(Handle))
		return;

	__xchg(0, &Entry->u1.object, sizeof(Entry->u1.object));

	Entry->u2.next_free_table_entry = HandleTable->first_free_table_entry;
	HandleTable->first_free_table_entry = Handle;
	HandleTable->handle_count--;
} /* end free_handle_table_entry */

VOID
destroy_handle_by_entry(IN struct handle_table *HandleTable,
		IN struct handle_table_entry *Entry,
		IN LONG Handle)
{
	if (!HandleTable || !Entry)
		return;

	if (!((ULONG_PTR)Entry->u1.object & EX_HANDLE_ENTRY_LOCKED))
		return;

	enter_critical_region();
	spin_lock(&HandleTable->handle_table_lock.spinlock);

	free_handle_table_entry(HandleTable, Entry, Handle);

	spin_unlock(&HandleTable->handle_table_lock.spinlock);
	leave_critical_region();
} /* end destroy_handle_by_entry */

NTSTATUS
delete_handle(struct handle_table *HandleTable,
		HANDLE Handle)
{
	struct handle_table_entry *handle_entry;
	struct handle_table *handle_table = HandleTable;
	POBJECT_HEADER object_header;
	LONG ex_handle;
     
	if (is_kernel_handle(Handle, KernelMode)) {
		handle_table = kernel_handle_table;
		ex_handle = HANDLE_TO_EX_HANDLE(KERNEL_HANDLE_TO_HANDLE(Handle));
	}
	else {
		if (!get_current_eprocess())
			return STATUS_UNSUCCESSFUL;

		handle_table = get_current_eprocess()->object_table;
		ex_handle = HANDLE_TO_EX_HANDLE(Handle);
	}
	enter_critical_region();

	handle_entry = map_handle_to_pointer(handle_table, ex_handle);
	if (!handle_entry) {
		leave_critical_region();
		return STATUS_INVALID_HANDLE;
	}

	if (handle_entry->u1.obattributes & EX_HANDLE_ENTRY_PROTECTFROMCLOSE) {
		unlock_handle_table_entry(HandleTable, handle_entry);
		leave_critical_region();
		return STATUS_HANDLE_NOT_CLOSABLE;
	}

	object_header = EX_HTE_TO_HDR(handle_entry);
	if (IS_WINE_OBJECT(object_header))
		release_object(&object_header->Body);
	else   /* not a wine object */
		decrement_handle_count(&object_header->Body);

	  /* Destroy the handle entry */
	destroy_handle_by_entry(HandleTable, handle_entry, ex_handle);
	leave_critical_region();
	return STATUS_SUCCESS;
} /*end delete_handle */

BOOLEAN
destroy_handle(IN struct handle_table *HandleTable,
		IN LONG Handle)
{
	struct handle_table_entry *entry;
	BOOLEAN ret = FALSE;

	if (!HandleTable)
		return ret;

	enter_critical_region();
	spin_lock(&HandleTable->handle_table_lock.spinlock);

	entry = lookup_handle_table_entry(HandleTable, Handle);

	if (entry && lock_handle_table_entry(HandleTable, entry)) {
		free_handle_table_entry(HandleTable, entry, Handle);
		ret = TRUE;
	}

	spin_unlock(&HandleTable->handle_table_lock.spinlock);
	leave_critical_region();

	return ret;
} /* end destroy_handle */
EXPORT_SYMBOL(destroy_handle);

NTSTATUS SERVICECALL
NtClose(HANDLE handle)
{
	struct handle_table *handle_table;
	struct eprocess *process = NULL;
	NTSTATUS status;

	ktrace("handle %p\n", handle);
	if (!current->ethread) {
		/* use kernel handle table if we have no ethread now */
		handle_table = kernel_handle_table;
		handle = KERNEL_HANDLE_TO_HANDLE(handle);
	}
	else {
		process = get_current_eprocess();
		handle_table = process->object_table;
	}
	
	status = delete_handle(handle_table, handle);

    clear_handle_info(process, handle);

	return status;
} /* end NtClose */
EXPORT_SYMBOL(NtClose);

obj_handle_t alloc_handle(struct w32process* proc, void* p, unsigned int access, int attr)
{
	struct object *obj = p;
	HANDLE handle = NULL;
	NTSTATUS ret;

	if (BODY_TO_HEADER(obj)->ops && BODY_TO_HEADER(obj)->ops->map_access)
		access = BODY_TO_HEADER(obj)->ops->map_access(obj, access);

	ret = create_handle(current->ethread ? get_current_eprocess() : NULL,
			p, access, attr & OBJ_INHERIT, &handle);
	if (!NT_SUCCESS(ret)) {
		set_error((unsigned int)ret);
		return NULL;
	}

    set_handle_info(proc ? proc->eprocess : NULL, handle, p);
	return handle;
}

obj_handle_t alloc_handle_no_access_check(struct w32process *process, void *ptr, unsigned int access, unsigned int attr)
{
	return alloc_handle(process, ptr, access, attr);
}

HANDLE duplicate_handle(HANDLE src, HANDLE src_handle, HANDLE dst,
		unsigned int access, unsigned int attr, unsigned int options)
{
	NTSTATUS ret;
	HANDLE dst_handle;

	ret = NtDuplicateObject(src, src_handle, dst, &dst_handle, access, attr, options);
	if (!NT_SUCCESS(ret)) {
		set_error((unsigned int)ret);
		return NULL;
	}

	return dst_handle;
}

unsigned int get_handle_access(struct eprocess *process, HANDLE handle)
{
	LONG	ex_handle;
	struct handle_table *handle_table;
	struct handle_table_entry *entry;

	if (process) {
		handle_table = process->object_table;
		ex_handle = HANDLE_TO_EX_HANDLE(handle);
	} else {
		handle_table = kernel_handle_table;
		ex_handle = HANDLE_TO_EX_HANDLE(KERNEL_HANDLE_TO_HANDLE(handle));
	}

	enter_critical_region();

	entry = map_handle_to_pointer(handle_table, ex_handle);
	if (!entry) {
		leave_critical_region();
		set_error(STATUS_INVALID_HANDLE);
		return 0;
	}

	unlock_handle_table_entry(handle_table, entry);
	leave_critical_region();

	return entry->u2.granted_access; /* FIXME: & ~RESERVED_ALL; */
}

int close_handle(struct eprocess *process, HANDLE handle)
{
	struct handle_table *handle_table;
	NTSTATUS status;

	if (process)
		handle_table = process->object_table;
	else {
		handle_table = kernel_handle_table;
		handle = KERNEL_HANDLE_TO_HANDLE(handle);
	}

	status = delete_handle(handle_table, handle);

	return status;
}

/* find the first inherited handle of the given type */
/* this is needed for window stations and desktops (don't ask...) */
obj_handle_t find_inherited_handle(struct w32process *process, const struct object_ops *ops)
{
#if 0
    struct handle_table *table = process->handles;
    struct handle_table_entry *ptr;
    int i;

    if (!table) return 0;

    for (i = 0, ptr = table->entries; i <= table->last; i++, ptr++)
    {
        if (!ptr->ptr) continue;
        if (ptr->ptr->ops != ops) continue;
        if (ptr->access & RESERVED_INHERIT) return index_to_handle(i);
    }
#endif
	/* HCZ FIXME: */
    return 0;
}

/* retrieve the object corresponding to a handle, incrementing its refcount */
struct object *get_handle_obj(obj_handle_t handle, unsigned int access)
{
	NTSTATUS status;
	PVOID obj;

	status = ref_object_by_handle((HANDLE)handle,
			STANDARD_RIGHTS_REQUIRED,
			NULL,
			KernelMode,
			(PVOID *)&obj,
			NULL);
	if (!NT_SUCCESS(status)) {
		set_error(status);
		return NULL;
	}

	return (struct object *)obj;
}

static inline unsigned long get_handle_index(obj_handle_t handle)
{
	if (!IS_HANDLE_VALID(handle))
		return 0;

	return ((unsigned long)handle >> 2);
}

struct handle_info_table *alloc_handle_info_table(void)
{
	struct handle_info_table *table;

	table = (struct handle_info_table *)kmalloc(sizeof(struct handle_info_table), GFP_KERNEL);
	if (!table)
		return NULL;

	table->used = 0;
	table->order = 0;
	table->allocated = PAGE_SIZE;
	table->handles = (struct handle_info *)__get_free_page(GFP_KERNEL);
	if (!table->handles) {
		kfree(table);
		return NULL;
	}

	memset(table->handles, 0, PAGE_SIZE);

	return table;
}

int expand_handle_info_table(struct handle_info_table *table, unsigned long new_size)
{
	int order;
	unsigned long new_alloc;
	struct handle_info *new_handles;

	new_alloc = table->allocated;
	order = table->order;
	while (new_alloc < new_size) {
		new_alloc <<= 1;
		order++;
	}

	new_handles = (struct handle_info *)__get_free_pages(GFP_KERNEL, order);
	if (!new_handles)
		return -ENOMEM;

	memcpy(new_handles, table->handles, table->allocated);
	free_pages((unsigned long)table->handles, table->order);

	table->used = new_size;
	table->order = order;
	table->allocated = new_alloc;
	table->handles = new_handles;

	return 0;
}

void free_handle_info_table(struct handle_info_table *table)
{
	free_pages((unsigned long)table->handles, table->order);
}

int set_handle_info(struct eprocess *process, obj_handle_t handle, struct object *obj)
{
	int unix_fd = 0;
	int ret = -EINVAL;
	struct handle_info *info;
	struct fd *fd;
	struct file *unix_file;
	unsigned long index;
	struct handle_info_table *table;

	ktrace("Type=%d, type=%d, ops=%p\n", (int)BODY_TO_HEADER(obj)->Type, 
			obj->header.type, BODY_TO_HEADER(obj)->ops);

    if (!BODY_TO_HEADER(obj)->ops || !BODY_TO_HEADER(obj)->ops->get_fd)
		return ret;

	fd = get_obj_fd(obj);
	if (!fd)
		return ret;
	if (get_unix_fd(fd) != -1)
		unix_fd = get_unix_fd(fd);

	if (!process || !process->ep_handle_info_table)
		goto out;;
	table = process->ep_handle_info_table;

	index = get_handle_index(handle);
	if (!index)
		goto out;

	ret = -ENOMEM;
	if ((((index + 1) << 3) > table->allocated)
			&& expand_handle_info_table(table, (index + 1) << 3))
		goto out;

	info = &table->handles[index];

	if (unix_fd > 0) {
		info->unix_fd = unix_fd;
		info->obj = obj;
		release_object(fd);
		return 0;
	}

	unix_file = get_unix_file(fd);
	if (!unix_file) {
		ret = -EINVAL;
		goto out;
	}

	unix_fd = get_unix_fd(fd);
	if (unix_fd == -1) {
		unix_fd = get_unused_fd_flags(O_CLOEXEC);
		if (unix_fd < 0) {
			ret = unix_fd;
			goto out;
		}

		get_file(unix_file);
		fd_install(unix_fd, unix_file);
	}

	info->unix_fd = unix_fd;
	info->obj = obj; 
    ret = 0;
	if (table->used <= (index << 3))
		table->used += sizeof(struct handle_info);

out:
	release_object(fd);
	return ret;
}

struct handle_info *get_handle_info(struct eprocess *process, obj_handle_t handle)
{
	int index;
	struct handle_info_table *table;

	if (!process || !process->ep_handle_info_table)
		return NULL;

	index = get_handle_index(handle);
	table = process->ep_handle_info_table;

	return index ? &table->handles[index] : NULL;
}

void clear_handle_info(struct eprocess *process, obj_handle_t handle)
{
	unsigned long index;
	struct handle_info_table *table;
	struct handle_info *info;

	if (!process || !process->ep_handle_info_table)
		return;

	index = get_handle_index(handle);
	if (!index)
		return;

	table = process->ep_handle_info_table;
	info = &table->handles[index];

	if (info->unix_fd)
		close(info->unix_fd);
	memset(info, 0, sizeof(struct handle_info));

	if (((index + 1) << 3) >= table->used)
		table->used -= sizeof(struct handle_info);
}

int get_handle_fd(struct eprocess *process, obj_handle_t handle)
{
	int ret;
	struct handle_info *info = get_handle_info(process, handle);

	ret = info ? info->unix_fd : -1;
	return ret;  
}
#endif /* CONFIG_UNIFIED_KERNEL */
