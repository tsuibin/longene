/* 
 * winternl.h
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
 * winternl.h:
 */
#ifndef _WINTERNL_H_
#define _WINTERNL_H_

#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/nls.h>
#include <linux/wait.h>

#ifdef CONFIG_UNIFIED_KERNEL
struct eprocess;
struct ethread;
struct kthread;

typedef unsigned char kirql_t;
typedef long	ntstatus_t;
typedef void*	ex_rundown_ref_t;
typedef unsigned long	access_mask_t;

#define	INIT_DISP_HEADER(header, tp, sz, state) \
{ \
	(header)->type = (unsigned char)tp; \
	(header)->absolute = 0; \
	(header)->inserted = 0; \
	(header)->size = (unsigned char)sz; \
	(header)->signal_state = state; \
	INIT_LIST_HEAD(&((header)->wait_list_head)); \
}

typedef union _large_integer_t {
	struct {
		long low;
		long high;	
	} u;
	long long quad;
} large_integer_t;

typedef large_integer_t physical_address_t;

enum security_impersonation_level {
	sec_anonymous,
	sec_identification,
	sec_impersonation,
	sec_delegation
};

enum event_type
{
	notification_event,
	synchronization_event
};

struct client_id
{
	void	*unique_process;
	void	*unique_thread;
};

struct dispatcher_header {
	unsigned char  		type;
	unsigned char  		absolute;
	unsigned char  		size;
	unsigned char  		inserted;
	long  			signal_state;
	struct list_head  	wait_list_head;
};

struct kapc_state {
	struct list_head  apc_list_head[2];
	struct kprocess*  process;
	unsigned char     kapc_inprogress;
	unsigned char     kapc_pending;
	unsigned char     uapc_pending;
};

struct kwait_block {
	struct list_head  	wait_list_entry;
	struct kthread*		thread;
	void*			object;
	struct kwait_block*	next_wait_block;
	unsigned short  	wait_key;
	unsigned short  	wait_type;
};

typedef unsigned long kaffinity_t;

struct kqueue {
	struct dispatcher_header  	header;
	struct list_head          	entry_list_head;
	unsigned long               	current_count;
	unsigned long               	maximum_count;
	struct list_head          	thread_list_head;
};

struct ktimer {
	struct dispatcher_header  	header;
	large_integer_t			due_time;
	struct list_head  		timer_list_entry;
	struct kdpc*			dpc;
	long  				period;
};

struct ktrap_frame
{
	void*		debug_ebp;
	void*		debug_eip;
	void*		debug_arg_mark;
	void*		debug_pointer;
	void*		temp_cs;
	void*		temp_eip;
	unsigned long 	dr0;
	unsigned long 	dr1;
	unsigned long 	dr2;
	unsigned long 	dr3;
	unsigned long 	dr6;
	unsigned long 	dr7;
	unsigned short 	gs;
	unsigned short 	reserved1;
	unsigned short 	es;
	unsigned short 	reserved2;
	unsigned short 	ds;
	unsigned short 	reserved3;
	unsigned long 	edx;
	unsigned long 	ecx;
	unsigned long 	eax;
	unsigned long 	previous_mode;
	void*		exception_list;
	unsigned short 	fs;
	unsigned short 	reserved4;
	unsigned long 	edi;
	unsigned long 	esi;
	unsigned long 	ebx;
	unsigned long 	ebp;
	unsigned long 	errorcode;
	unsigned long 	eip;
	unsigned long 	cs;
	unsigned long 	eflags;
	unsigned long 	esp;
	unsigned short 	ss;
	unsigned short 	reserved5;
	unsigned short 	v86_es;
	unsigned short 	reserved6;
	unsigned short 	v86_ds;
	unsigned short 	reserved7;
	unsigned short 	v86_fs;
	unsigned short 	reserved8;
	unsigned short 	v86_gs;
	unsigned short 	reserved9;
};

#ifndef __stdcall
#define	__stdcall __attribute__((stdcall))
#endif

struct kapc;
typedef void (__stdcall *normal_routine_t)(void *context, void *arg1, void *arg2);

typedef void (__stdcall *kernel_routine_t)(struct kapc *apc,
		normal_routine_t *normal_routine, void **context, void **arg1, void **arg2);

typedef void (__stdcall *rundown_routine_t)(struct kapc *apc);

typedef char	kprocessor_mode_t;

struct kapc {
	short  			type;
	short  			size;
	unsigned long  		spare0;
	struct kthread*		thread;
	struct list_head  	apc_list_entry;
	kernel_routine_t  	kernel_routine;
	rundown_routine_t  	rundown_routine;
	normal_routine_t  	normal_routine;
	void*			normal_context;
	void*			system_argument1;
	void*			system_argument2;
	char  			apc_state_index;
	kprocessor_mode_t  	apc_mode;
	unsigned char  		inserted;
	struct object       *owner;
};

#define USER_SHARED_DATA (0x7FFE0000)

/* Global Flags */
#define FLG_STOP_ON_EXCEPTION          0x00000001
#define FLG_SHOW_LDR_SNAPS             0x00000002
#define FLG_DEBUG_INITIAL_COMMAND      0x00000004
#define FLG_STOP_ON_HUNG_GUI           0x00000008
#define FLG_HEAP_ENABLE_TAIL_CHECK     0x00000010
#define FLG_HEAP_ENABLE_FREE_CHECK     0x00000020
#define FLG_HEAP_VALIDATE_PARAMETERS   0x00000040
#define FLG_HEAP_VALIDATE_ALL          0x00000080
#define FLG_POOL_ENABLE_TAIL_CHECK     0x00000100
#define FLG_POOL_ENABLE_FREE_CHECK     0x00000200
#define FLG_POOL_ENABLE_TAGGING        0x00000400
#define FLG_HEAP_ENABLE_TAGGING        0x00000800
#define FLG_USER_STACK_TRACE_DB        0x00001000
#define FLG_KERNEL_STACK_TRACE_DB      0x00002000
#define FLG_MAINTAIN_OBJECT_TYPELIST   0x00004000
#define FLG_HEAP_ENABLE_TAG_BY_DLL     0x00008000
#define FLG_IGNORE_DEBUG_PRIV          0x00010000
#define FLG_ENABLE_CSRDEBUG            0x00020000
#define FLG_ENABLE_KDEBUG_SYMBOL_LOAD  0x00040000
#define FLG_DISABLE_PAGE_KERNEL_STACKS 0x00080000
#define FLG_HEAP_ENABLE_CALL_TRACING   0x00100000
#define FLG_HEAP_DISABLE_COALESCING    0x00200000
#define FLG_ENABLE_CLOSE_EXCEPTIONS    0x00400000
#define FLG_ENABLE_EXCEPTION_LOGGING   0x00800000
#define FLG_ENABLE_void *_TYPE_TAGGING 0x01000000
#define FLG_HEAP_PAGE_ALLOCS           0x02000000
#define FLG_DEBUG_INITIAL_COMMAND_EX   0x04000000

struct kgd_entry {
	unsigned short limit_low;
	unsigned short base_low;
	union {
		struct {
			unsigned char base_mid;
			unsigned char flags1;
			unsigned char flags2;
			unsigned char base_hi;
		} bytes;
		struct {
			unsigned long base_mid	: 8;
			unsigned long type		: 5;
			unsigned long dpl		: 2;
			unsigned long pres		: 1;
			unsigned long limit_h	: 4;
			unsigned long sys		: 1;
			unsigned long reserved_0	: 1;
			unsigned long default_big	: 1;
			unsigned long granularity	: 1;
			unsigned long base_hi	: 8;
		} bits;
	} high_word;
};

struct kidt_entry
{
	unsigned short offset;
	unsigned short selector;
	unsigned short access;
	unsigned short extended_offset;
};

struct kexecute_options
{
	unsigned char execute_disable:1;
	unsigned char execute_enable:1;
	unsigned char disable_thunk_emulation:1;
	unsigned char permanent:1;
	unsigned char execute_dispatch_enable:1;
	unsigned char image_dispatch_enable:1;
	unsigned char spare:2;
};

struct kevent {
	struct dispatcher_header header;
};

struct mmsupport_flags {
	unsigned long session_space:1;
	unsigned long being_trimmed:1;
	unsigned long session_leader:1;
	unsigned long trim_hard:1;
	unsigned long working_set_hard:1;
	unsigned long address_space_being_deleted :1;
	unsigned long available:10;
	unsigned long allow_working_set_adjustment:8;
	unsigned long memory_priority:8;
};

struct mmwslentry {
	unsigned long valid:1;
	unsigned long locked_in_ws:1;
	unsigned long locked_in_memory:1;
	unsigned long protection:5;
	unsigned long hashed:1;
	unsigned long direct:1;
	unsigned long age:2;
	unsigned long virtual_page_number:14;
};

struct mmwsle {
	union
	{
		void* virtual_address;
		unsigned long long_v;
		struct mmwslentry e1;
	};
};

struct mmwsle_hash {
	void* Key;
	unsigned long Index;
};

struct mmwsl
{
	unsigned long 	first_free;
	unsigned long 	first_dynamic;
	unsigned long 	last_entry;
	unsigned long 	next_slot;
	struct mmwsle* 	wsle;
	unsigned long 	last_initialized_wsle;
	unsigned long 	non_directcout;
	struct mmwsle_hash* hash_table;
	unsigned long 	hash_table_size;
	unsigned long 	number_of_committed_page_tables;
	void* 		hash_table_start;
	void* 		highest_permitted_hash_address;
	unsigned long 	number_of_image_waiters;
	unsigned long 	vad_bitmap_hint;
	unsigned short 	used_page_table_entries[768];
	unsigned long 	committed_page_tables[24];
};

struct mmsupport {
	large_integer_t 		last_trim_time;
	struct mmsupport_flags 	flags;
	unsigned long 		page_fault_count;
	unsigned long 		peak_working_set_size;
	unsigned long 		working_set_size;
	unsigned long 		minimum_working_set_size;
	unsigned long 		maximum_working_set_size;
	struct mmwsl* 		mm_working_set_list;
	struct list_head 		working_set_expansion_links;
	unsigned long 		claim;
	unsigned long 		next_estimation_slot;
	unsigned long 		next_aging_slot;
	unsigned long 		estimated_available;
	unsigned long 		growth_since_last_estimate;
};

struct object_ops;
struct object_name;
struct security_descriptor;

struct object
{
	struct dispatcher_header  header;
	unsigned int              refcount;    /* reference count */
	struct list_head          wait_queue;
	struct object_name       *name;
	struct security_descriptor *sd;
};

struct handle_table_entry_info
{
	unsigned long audit_mask;
};

struct handle_table_entry
{
	union
	{
		void*				object;
		unsigned long			obattributes;
		struct handle_table_entry_info* info_table;
		unsigned long			value;

	} u1;
	union
	{
		unsigned long 			granted_access;
		unsigned short 			granted_access_index;
		long 				next_free_table_entry;
	} u2;
	struct object *ptr;       /* object */ 
	/* Is it different to the iabove 1st field "void* object"? */
	unsigned int   access;    /* access rights */
};

typedef unsigned long	eresource_thread_t;

struct owner_entry {
	eresource_thread_t	owner_thread;  	
	union {
		long  		owner_count;
		unsigned long  	table_size;
	} u;
};

struct ksemaphore {
	struct dispatcher_header	header;
	long			limit;
};

struct eresource {
	struct list_head	system_resources_list;
	struct owner_entry*  	owner_table;
	short  		active_count;
	unsigned short  	flag;
	struct ksemaphore*  	shared_waiters;
	struct kevent*	exclusive_waiters;
	struct owner_entry  	owner_threads[2];
	unsigned long  	contention_count;
	unsigned short 	number_of_shared_waiters;
	unsigned short  	number_of_exclusive_waiters;
	union {
		void*	  		address;
		unsigned long long	greator_back_trace_index;
	} u;
	spinlock_t	spinlock;
};

struct handle_table
{
	struct object        obj;         /* object header */

    unsigned long 		flags;
    long 			handle_count;
    struct handle_table_entry*** table;
    struct eprocess*		quota_process;
    void* 			unique_processid;
    long 			first_free_table_entry;
    long 			next_index_needing_pool;
    struct eresource 		handle_table_lock;
    struct list_head 		handle_table_list;
    struct kevent 		handle_contention_event;

    struct w32process    *process;     /* process owning this table */
    int                  count;       /* number of allocated entries */
    int                  last;        /* last used entry */
    int                  free;        /* first entry that may be free */
    struct handle_table_entry *entries;     /* handle entries */
};

struct ex_fast_ref
{
	union
	{
		void* 		object;
		unsigned long 	ref_cnt:3;
		unsigned long 	value;
	};
};


struct kgate
{
	struct dispatcher_header header;
};

struct kguarded_mutex
{
	long 		count;
	struct kthread* 	owner;
	unsigned long 	contention;
	struct kgate 	gate;
	union {
		struct {
			short 	kernel_apc_disable;
			short 	special_apc_disable;
		};
		unsigned long 	combined_apc_disable;
	};
};

struct mmaddress_node
{
	union
	{
		unsigned long 		balance:2;
		struct mmaddress_node*	parent;
	} u1;
	struct mmaddress_node*	left_child;
	struct mmaddress_node*	right_child;
	unsigned long 		starting_vpn;
	unsigned long 		ending_vpn;
};

struct mm_avl_table
{
	struct mmaddress_node 	balanced_root;
	unsigned long 		depth_of_tree:5;
	unsigned long 		unused:3;
	unsigned long 		number_generic_table_elements:24;
	void* 			node_hint;
	void* 			node_free_hint;
};

struct eprocess_quota_entry
{
	unsigned long usage;
	unsigned long limit;
	unsigned long peak;
	unsigned long return_val;
};

struct eprocess_quota_block
{
	struct eprocess_quota_entry 	quota_entry[3];
	struct list_head 			quota_list;
	unsigned long 			reference_count;
	unsigned long 			process_tount;
};

struct proc_ws_watch_info
{
	void* faulting_pc;
	void* faulting_va;
};

struct pagefault_history
{
	unsigned long 		current_index;
	unsigned long 		map_index;
	spinlock_t 			spinlock;
	void* 			reserved;
	struct proc_ws_watch_info 	watch_info[1];
};

struct hardware_pte_x86
{
	unsigned long valid             	: 1;
	unsigned long write             	: 1;
	unsigned long owner             	: 1;
	unsigned long write_through      	: 1;
	unsigned long cache_disable      	: 1;
	unsigned long accessed          	: 1;
	unsigned long dirty             	: 1;
	unsigned long large_page         	: 1;
	unsigned long global            	: 1;
	unsigned long copy_on_write       	: 1;
	unsigned long prototype         	: 1;
	unsigned long reserved          	: 1;
	unsigned long page_frame_number  	: 20;
};
struct unicode_string
{
	unsigned short 	length;
	unsigned short 	max_ength;
	wchar_t*		buffer;
};

struct object_name_info
{
	struct unicode_string	name;
};

struct se_audit_proc_creation_info
{
	struct object_name_info* image_filename;
};

typedef void* fast_mutex_t;

struct maddress_space
{
	void* 		memory_area_root;
	fast_mutex_t	lock;
	void* 		lowest_address;
	struct eprocess* 	process;
	unsigned short*	pt_ref_count_table;
	unsigned long 	pt_ref_count_table_size;
};

struct kdpc;
typedef void
(__stdcall *kdeferred_routine_t)(struct kdpc *dpc, void* deferred_context, 
				 void* system_argument1,void*  system_argument2);

struct kdpc {
	short 			type;
	unsigned char 		number;
	unsigned char 		importance;
	struct list_head  	dpc_list_entry;
	kdeferred_routine_t	deferred_routine;
	void* 			deferred_context;
	void* 			system_argument1;
	void* 			system_argument2;
	void* 			dpc_data;
}; 

struct kmutant {
	struct dispatcher_header	header;
	struct list_head		mutant_list_entry;
	struct kthread*			owner_thread;
	unsigned char			abandoned;
	unsigned char			apc_disable;
};

#endif /* CONFIG_UNIFIED_KERNEL */
#endif /* _WINTERNL_H_ */
