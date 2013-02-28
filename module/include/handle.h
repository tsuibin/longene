/*
 * handle.h
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
 * handle.h: win32 handle definition
 * Refered to ReactOS code
 */
#ifndef _HANDLE_H
#define _HANDLE_H

#include "win32.h"
#include "object.h"
#include "winternl.h"
#include "wineserver/lib.h"

#ifdef CONFIG_UNIFIED_KERNEL

#define UNICODE_NULL L'\0'
#define UNICODE_PATH_SEP L'\\'
#define UNICODE_NO_PATH L"..."

#define EX_HANDLE_ENTRY_LOCKED (1 << ((sizeof(PVOID) * 8) - 1))
#define EX_HANDLE_ENTRY_PROTECTFROMCLOSE (1 << 0)
#define EX_HANDLE_ENTRY_INHERITABLE (1 << 1)
#define EX_HANDLE_ENTRY_AUDITONCLOSE (1 << 2)
#define EX_HANDLE_TABLE_CLOSING 0x1
#define EX_INVALID_HANDLE (~0)
#define EX_HANDLE_ENTRY_FLAGSMASK (EX_HANDLE_ENTRY_LOCKED | \
                                   EX_HANDLE_ENTRY_PROTECTFROMCLOSE | \
                                   EX_HANDLE_ENTRY_INHERITABLE | \
                                   EX_HANDLE_ENTRY_AUDITONCLOSE)

#define N_TLI_BITS 8 /* top level index */
#define N_MLI_BITS 10 /* middle level index */
#define N_EI_BITS 9 /* sub handle index */
#define TLI_OFFSET (N_MLI_BITS + N_EI_BITS)
#define MLI_OFFSET N_EI_BITS
#define EI_OFFSET 0

#define N_TOPLEVEL_POINTERS (1 << N_TLI_BITS)
#define N_MIDDLELEVEL_POINTERS (1 << N_MLI_BITS)
#define N_SUBHANDLE_ENTRIES (1 << N_EI_BITS)
#define EX_MAX_HANDLES (N_TOPLEVEL_POINTERS * N_MIDDLELEVEL_POINTERS * N_SUBHANDLE_ENTRIES)

#define VALID_HANDLE_MASK (((N_TOPLEVEL_POINTERS - 1) << TLI_OFFSET) |         \
  ((N_MIDDLELEVEL_POINTERS - 1) << MLI_OFFSET) | ((N_SUBHANDLE_ENTRIES - 1) << EI_OFFSET))
#define TLI_FROM_HANDLE(index) (ULONG)(((index) >> TLI_OFFSET) & (N_TOPLEVEL_POINTERS - 1))
#define MLI_FROM_HANDLE(index) (ULONG)(((index) >> MLI_OFFSET) & (N_MIDDLELEVEL_POINTERS - 1))
#define ELI_FROM_HANDLE(index) (ULONG)(((index) >> EI_OFFSET) & (N_SUBHANDLE_ENTRIES - 1))

#define EX_HTE_TO_HDR(hte) ((POBJECT_HEADER)((ULONG_PTR)((hte)->u1.object) &	\
	~(EX_HANDLE_ENTRY_PROTECTFROMCLOSE | EX_HANDLE_ENTRY_INHERITABLE |	\
	EX_HANDLE_ENTRY_AUDITONCLOSE)))
#define EX_OBJ_TO_HDR(eob) ((POBJECT_HEADER)((ULONG_PTR)(eob) &                \
  ~(EX_HANDLE_ENTRY_PROTECTFROMCLOSE | EX_HANDLE_ENTRY_INHERITABLE |           \
  EX_HANDLE_ENTRY_AUDITONCLOSE)))
  
#define BUILD_HANDLE(tli, mli, eli) ((((tli) & (N_TOPLEVEL_POINTERS - 1)) << TLI_OFFSET) | \
				(((mli) & (N_MIDDLELEVEL_POINTERS - 1)) << MLI_OFFSET) | \
				(((eli) & (N_SUBHANDLE_ENTRIES - 1)) << EI_OFFSET))

#define IS_INVALID_EX_HANDLE(index)	(((index) & ~VALID_HANDLE_MASK) != 0)
#define IS_VALID_EX_HANDLE(index)		(((index) & ~VALID_HANDLE_MASK) == 0)
  
#define KERNEL_HANDLE_FLAG (1 << ((sizeof(HANDLE) * 8) - 1))
#define is_kernel_handle(Handle, ProcessorMode)		\
	(((ULONG_PTR)(Handle) & KERNEL_HANDLE_FLAG) && ((ProcessorMode) == KernelMode))
#define KERNEL_HANDLE_TO_HANDLE(Handle)		\
	(HANDLE)((ULONG_PTR)(Handle) & ~KERNEL_HANDLE_FLAG)
#define HANDLE_TO_KERNEL_HANDLE(Handle)		\
	(HANDLE)((ULONG_PTR)(Handle) | KERNEL_HANDLE_FLAG)

#define IS_HANDLE_VALID(handle)   (!((ULONG_PTR)handle & KERNEL_HANDLE_FLAG))

extern struct handle_table *cid_table;

struct handle_info
{
    void            *obj;
    int             unix_fd;
};

struct handle_info_table
{
    unsigned long       used;       /* used size */
    int                 order;      /* page orders */
    unsigned long       allocated;  /* available size */
    struct handle_info  *handles;
};

typedef VOID (STDCALL PEX_DESTROY_HANDLE_CALLBACK)(
		struct handle_table *HandleTable,
		PVOID Object,
		ULONG GrantedAccess,
		PVOID Context);

typedef BOOLEAN (STDCALL PEX_DUPLICATE_HANDLE_CALLBACK)(
		struct handle_table *HandleTable,
		struct handle_table_entry *HandleTableEntry,
		PVOID Context);

VOID STDCALL
map_generic_mask(PACCESS_MASK AccessMask, const PGENERIC_MAPPING GenericMapping);

NTSTATUS STDCALL
init_resource(struct eresource *Resource);

NTSTATUS STDCALL
delete_resource(struct eresource *Resource);

VOID
init_handle_tables(VOID);

BOOLEAN
lock_handle_table_entry(IN struct handle_table *HandleTable,
		IN struct handle_table_entry *Entry);

VOID
unlock_handle_table_entry(IN struct handle_table *HandleTable,
		IN struct handle_table_entry *Entry);

struct handle_table *
__create_handle_table(IN struct eprocess *QuotaProcess  OPTIONAL);

struct handle_table *
dup_handle_table(IN struct eprocess *QuotaProcess OPTIONAL,
                IN PEX_DUPLICATE_HANDLE_CALLBACK dup_handle_callback OPTIONAL,
                IN PVOID Context OPTIONAL,
                IN struct handle_table *SourceHandleTable);

VOID
create_handle_table(struct eprocess *Parent,
                BOOLEAN Inherit,
                struct eprocess *Process);

struct handle_table_entry *
alloc_handle_table_entry(IN struct handle_table *HandleTable,
                        OUT PLONG Handle);

LONG
create_ex_handle(IN struct handle_table *HandleTable,
	IN struct handle_table_entry *Entry);

NTSTATUS
create_handle(struct eprocess *Process,
                PVOID ObjectBody,
                ACCESS_MASK GrantedAccess,
                BOOLEAN Inherit,
                PHANDLE HandleReturn);

struct handle_table_entry *
lookup_handle_table_entry(IN struct handle_table *HandleTable,
                        IN LONG Handle);

struct handle_table_entry *
map_handle_to_pointer(IN struct handle_table *HandleTable,
                IN LONG Handle);

VOID
decrement_handle_count(PVOID ObjectBody);

VOID
free_handle_table_entry(IN struct handle_table *HandleTable,
                        IN struct handle_table_entry *Entry,
                        IN LONG Handle);

VOID
destroy_handle_by_entry(IN struct handle_table *HandleTable,
                IN struct handle_table_entry *Entry,
                IN LONG Handle);

NTSTATUS
delete_handle(struct handle_table *HandleTable,
                HANDLE Handle);

BOOLEAN
destroy_handle(IN struct handle_table *HandleTable,
		IN LONG Handle);

VOID
__destroy_handle_table(IN struct handle_table *HandleTable,
		IN PEX_DESTROY_HANDLE_CALLBACK DestroyHandleCallback OPTIONAL,
		IN PVOID Context OPTIONAL);

struct object *get_handle_obj(obj_handle_t handle, unsigned int access);

int set_handle_info(struct eprocess *process, obj_handle_t handle, struct object *obj);
struct handle_info *get_handle_info(struct eprocess *process, obj_handle_t handle);
int get_handle_fd(struct eprocess *process, obj_handle_t handle);
void clear_handle_info(struct eprocess *process, obj_handle_t handle);
struct handle_info_table *alloc_handle_info_table(void);
void free_handle_info_table(struct handle_info_table *table);

/* retrieve the object corresponding to one of the magic pseudo-handles */
static inline void *get_magic_wine_handle(HANDLE handle)
{
	switch((unsigned long)handle)
	{
		case 0xfffffffe:  /* current thread pseudo-handle */
		case 0x7fffffff:  /* current process pseudo-handle */
		case 0xffffffff:  /* current process pseudo-handle */
			return current->ethread ? (struct object *)get_current_w32process() : NULL;
		default:
			return NULL;
	}
}

static inline void *get_wine_handle_obj(struct w32process *proc, HANDLE handle, 
				unsigned int access, const struct object_ops *ops)
{
	void	*obj = NULL;
	NTSTATUS	ret;

	if(!(obj = get_magic_wine_handle(handle))) {
		ret = ref_object_by_handle(handle, access, NULL, KernelMode, &obj, NULL);
		if (!NT_SUCCESS(ret)) {
			set_error((unsigned int)ret);
			return NULL;
		}
	}
	else
		grab_object(obj);

	if (ops && (BODY_TO_HEADER(obj))->ops != ops) {
		release_object(obj);
		set_error(STATUS_OBJECT_TYPE_MISMATCH);
		return NULL;
	}

	return obj;
}

static inline HANDLE alloc_key_handle(void *key, unsigned int access, unsigned int attr)
{
	HANDLE handle = NULL;
	NTSTATUS ret;

	ret = create_handle(current->ethread ? get_current_eprocess() : NULL,
			key, access, attr & OBJ_INHERIT, &handle);
	if (!NT_SUCCESS(ret)) {
		set_error((unsigned int)ret);
		return NULL;
	}

	return handle;
}
#endif /* CONFIG_UNIFIED_KERNEL */
#endif /* _HANDLE_H */
