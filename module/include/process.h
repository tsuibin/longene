/*
 * process.h
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
 * process.h:
 * Refered to Kernel-win32 code
 */
 
#ifndef _PROCESS_H
#define _PROCESS_H

#include <linux/module.h>
#include <linux/binfmts.h>
#include "winternl.h"
#include "win32.h"
#include "object.h"
#include "ke.h"
#include "win32_thread.h"

#ifdef CONFIG_UNIFIED_KERNEL
#define	NtCurrentProcess()	((HANDLE)(ULONG_PTR)-1)
#define	PEB_BASE	0x7FFDF000

#define	MAX_PATH	256
#define	PROCESS_PRIO_NORMAL	6
#define	FREE_UNI(uni)	{ if (uni.Length) kfree(uni.Buffer); memset(&uni, 0, sizeof(uni)); }

#define NORMALIZE(x, addr)   if (x) x = (typeof(x))((void *)(x) + (void *)(addr))
#define DENORMALIZE(x, addr) if (x) x = (typeof(x))((void *)(x) - (void *)(addr))
#define	ALIGN_TO_LONG(x)	ALIGN((x), sizeof(LONG))
#define	PPF_NORMALIZED	1

#define	DENORMALIZE_PARAMS(params) \
{ \
	if ((params) && ((params)->Flags & PPF_NORMALIZED)) \
	{ \
		DENORMALIZE((params)->CurrentDirectoryName.Buffer, (params)); \
		DENORMALIZE((params)->DllPath.Buffer, (params)); \
		DENORMALIZE((params)->ImagePathName.Buffer, (params)); \
		DENORMALIZE((params)->CommandLine.Buffer, (params)); \
		DENORMALIZE((params)->WindowTitle.Buffer, (params)); \
		DENORMALIZE((params)->DesktopInfo.Buffer, (params)); \
		DENORMALIZE((params)->ShellInfo.Buffer, (params)); \
		DENORMALIZE((params)->RuntimeInfo.Buffer, (params)); \
		\
		(params)->Flags &= ~PPF_NORMALIZED; \
	} \
}

#define	NORMALIZE_PARAMS(params) \
{ \
	if ((params) && !((params)->Flags & PPF_NORMALIZED)) \
	{ \
		NORMALIZE((params)->CurrentDirectoryName.Buffer, (params)); \
		NORMALIZE((params)->DllPath.Buffer, (params)); \
		NORMALIZE((params)->ImagePathName.Buffer, (params)); \
		NORMALIZE((params)->CommandLine.Buffer, (params)); \
		NORMALIZE((params)->WindowTitle.Buffer, (params)); \
		NORMALIZE((params)->DesktopInfo.Buffer, (params)); \
		NORMALIZE((params)->ShellInfo.Buffer, (params)); \
		NORMALIZE((params)->RuntimeInfo.Buffer, (params)); \
		\
		(params)->Flags |= PPF_NORMALIZED; \
	} \
}

/* Process state */
#define PROCESS_STATE_TERMINATED	1
#define PROCESS_STATE_ACTIVE		2

/* Process priority classes */
#define PROCESS_PRIORITY_CLASS_HIGH	(4) /* FIXME */
#define PROCESS_PRIORITY_CLASS_IDLE	(0) /* FIXME */
#define PROCESS_PRIORITY_CLASS_NORMAL	(2) /* FIXME */
#define PROCESS_PRIORITY_CLASS_REALTIME	(5) /* FIXME */
#define PROCESS_PRIORITY_CLASS_BELOW_NORMAL (1) /* FIXME */
#define PROCESS_PRIORITY_CLASS_ABOVE_NORMAL (3) /* FIXME */

/*
 * kprocess
 */
struct kprocess
{
	struct dispatcher_header	header;		   	/* 000 */
	struct list_head		profile_list_head;	/* 010 */
	physical_address_t		directory_table_base;	/* 018 */
#if defined(_M_IX86)
	struct kgd_entry		ldt_descriptor;		/* 020 */
	struct kidt_entry		Int21_descriptor;  	/* 028 */
	unsigned short			iopm_offset;		/* 030 */
	unsigned char			iopl;		  	/* 032 */
	unsigned char			unused;			/* 033 */
#endif
	unsigned long			active_processors;  	/* 034 */
	unsigned long			kernel_time;		/* 038 */
	unsigned long			user_time;	  	/* 03C */
	struct list_head		ready_list_head;	/* 040 */
	struct list_head		swap_list_entry;	/* 048 */
	void*				vdm_trapc_handler; 	/* 04C */
	struct list_head		thread_list_head;	/* 050 */
	spinlock_t			process_lock;	  	/* 068 */
	unsigned long			affinity;	  	/* 06C */
	union
	{
		struct
		{
			unsigned long	auto_alignment:1;	/* 070.0 */
			unsigned long	disable_boost:1;	/* 070.1 */
			unsigned long	disable_quantum:1;	/* 070.2 */
			unsigned long	reserved_flags:29;	/* 070.3 */
		};
		unsigned long		process_flags;		/* 070 */
	};
	char				base_priority;		/* 074 */
	char				quantum_reset;		/* 075 */
	unsigned char			state;		 	/* 076 */
	unsigned char			thread_seed;		/* 077 */
	unsigned char			power_state;		/* 078 */
	unsigned char			ideal_node;	 	/* 079 */
	unsigned char			visited;	   	/* 07A */
	struct kexecute_options		flags;		 	/* 07B */
	unsigned long			stack_count;		/* 07C */
	struct list_head		process_list_entry; 	/* 080 */
};

struct eprocess
{
	struct kprocess			pcb;			 	/* 000 */
	unsigned long			exit_status;		  	/* 088 */
	spinlock_t			process_lock;		 	/* 08C */
	struct kevent			lock_event;			/* 0A4 */
	unsigned long			lock_count;			/* */
	struct kthread			*lock_owner;		   	/* */
	large_integer_t			create_time;		   	/* */
	large_integer_t			exit_time;		 	/* */
	void 				*rundown_protect;		/* */
	void*				unique_processid;		/* */
	struct list_head		active_process_links;		/* */

	/* quota fields */
	unsigned long			quota_usage[3];			/* */
	unsigned long			quota_peak[3];			/* */
	unsigned long			commit_charge;		 	/* */

	/* vm */
	unsigned long			peak_virtual_size;		/* */
	unsigned long			virtual_size;		  	/* */

	struct mmsupport		vm;			   	/* */
	struct list_head		session_process_links;		/* */

	void*				debug_port;			/* */
	void*				exception_port;			/* */
	struct handle_table*		object_table;		  	/* */

	/* security */
	struct ex_fast_ref		token;				/* */

	unsigned long			working_set_page;		/* */
	struct kguarded_mutex		address_creation_lock;		/* */
	spinlock_t			hyper_spacelock;	   	/* */
	struct ethread*			fork_in_progress;		/* */
	unsigned long			hardware_trigger;	  	/* */
	void*				pae_top;		   	/* */
	unsigned long			modified_page_count;		/* */
	struct mm_avl_table		vad_root;		  	/* */
	void*				vad_free_hint;			/* */
	void*				clone_root;			/* */
	
	struct mm_avl_table		physical_vadroot;	  	/* */

	unsigned long			number_of_private_pages;	/* */
	unsigned long			number_of_locked_pages;		/* */
	unsigned short			next_page_color;		/* */

	/* used by debug subsystem */
	void*				section_object;			/* */

	/* peb */
	void*			peb;			 	/* */
	void*				section_base_address;		/* */

	struct eprocess_quota_block*	quota_block;		  	/* */
	unsigned long			last_thread_exit_status;	/* */

	struct pagefault_history* 	working_set_watch;		/* */
	void*				win32_window_station;		/* */
	void *				inherited_from_unique_pid;	/* */
	access_mask_t			granted_access;			/* */
	unsigned long			def_hard_error_processing; 	/* */
	void*				ldt_information;	   	/* */
	void*				vdm_objects;		 	/* */
	void*				device_map;			/* */

	void*				spare0[3];			/* */

	union
	{
		struct hardware_pte_x86	pagedirectory_pte;	 	/* */
		unsigned long long	filler;				/* */
	};
	char				image_file_name[16];		/* */
	unsigned char			priority_class;			/* */
	union
	{
		struct
		{
			unsigned char	subsystem_minor_version;	/* */
			unsigned char	subsystem_major_version;	/* */
		};
		unsigned short		subsystem_version;		/* */
	};
	struct w32process* 		win32process;
	struct ejob*			job;			 	/* */
	unsigned long			job_status;			/* */
	struct list_head		job_links;		 	/* */
	void*				locked_pages_list;		/* */

	/* used by rdr/security for authentication */
	void*				security_port;		 	/* */

	large_integer_t			read_operation_count;		/* */
	large_integer_t			write_operation_count;		/* */
	large_integer_t			other_operation_count;		/* */
	large_integer_t			read_transfer_count;		/* */
	large_integer_t			write_transfer_count;		/* */
	large_integer_t			other_transfer_count;		/* */

	unsigned long			commit_charge_limit;		/* */
	unsigned long			commit_charge_peak;		/* */

	struct list_head		thread_list_head;		/* */

	union
	{
		struct
		{
			unsigned long	create_reported:1;
			unsigned long	no_debug_inherit:1;
			unsigned long	process_exiting:1;
			unsigned long	process_delete:1;
			unsigned long	wow64_split_pages:1;
			unsigned long	vm_deleted:1;
			unsigned long	outswap_enabled:1;
			unsigned long	outswapped:1;
			unsigned long	fork_failed:1;
			unsigned long	wow64_va_space4Gb:1;
			unsigned long	address_space_initialized:2;
			unsigned long	set_timer_resolution:1;
			unsigned long	break_on_termination:1;
			unsigned long	session_creation_underway:1;
			unsigned long	write_watch:1;
			unsigned long	process_in_session:1;
			unsigned long	override_address_space:1;
			unsigned long	has_address_space:1;
			unsigned long	launch_prefetched:1;
			unsigned long	inject_inpage_errors:1;
			unsigned long	vm_top_down:1;
			unsigned long	image_notify_done:1;
			unsigned long	pde_update_needed:1;
			unsigned long	vdm_allowed:1;
			unsigned long	smap_allowed:1;
			unsigned long	create_failed:1;
			unsigned long	default_io_priority:3;
			unsigned long	spare1:1;
			unsigned long	spare2:1;
		};
		unsigned long		flags;					/* */
	};

	unsigned long			cookie;				   	/* */
	unsigned long			session;			  	/* */
	unsigned long			active_threads;			   	/* */
	struct ex_fast_ref		prefetch_trace;				/* */
	void*				awe_info;				/* */
	struct se_audit_proc_creation_info	se_audit_proc_creation_info;	/* */
	struct list_head			mm_process_links;		/* */

	struct nls_table*		ep_nls;	/* unicode-ascii translation */
	rwlock_t			ep_lock;
	struct list_head		ep_reserved_head;
	struct list_head		ep_mapped_head;
    void                    *ep_handle_info_table;

	/*for NtNotifyDirectoryChange */
	spinlock_t                      watch_lock;
	long				watch_fd;
	pid_t				watch_thread;
	int					epoll_fd;
}; /* struc eprocess */

typedef struct eprocess EPROCESS, *PEPROCESS;

typedef VOID (STDCALL *PPEBLOCKROUTINE)(PVOID);

typedef struct _PEB_LDR_DATA
{
    ULONG               Length;
    BOOLEAN             Initialized;
    PVOID               SsHandle;
    LIST_ENTRY          InLoadOrderModuleList;
    LIST_ENTRY          InMemoryOrderModuleList;
    LIST_ENTRY          InInitializationOrderModuleList;
    PVOID               EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct RTL_DRIVE_LETTER_CURDIR
{
	USHORT              Flags;
	USHORT              Length;
	ULONG               TimeStamp;
	UNICODE_STRING      DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	ULONG  AllocationSize;
	ULONG  Size;
	ULONG  Flags;
	ULONG  DebugFlags;
	HANDLE  hConsole;
	ULONG  ProcessGroup;
	HANDLE  hStdInput;
	HANDLE  hStdOutput;
	HANDLE  hStdError;
	UNICODE_STRING  CurrentDirectoryName;
	HANDLE  CurrentDirectoryHandle;
	UNICODE_STRING  DllPath;
	UNICODE_STRING  ImagePathName;
	UNICODE_STRING  CommandLine;
	PWSTR  Environment;
	ULONG  dwX;
	ULONG  dwY;
	ULONG  dwXSize;
	ULONG  dwYSize;
	ULONG  dwXCountChars;
	ULONG  dwYCountChars;
	ULONG  dwFillAttribute;
	ULONG  dwFlags;
	ULONG  wShowWindow;
	UNICODE_STRING  WindowTitle;
	UNICODE_STRING  DesktopInfo;
	UNICODE_STRING  ShellInfo;
	UNICODE_STRING  RuntimeInfo;
	RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_FREE_BLOCK
{
	struct _PEB_FREE_BLOCK* Next;
	ULONG Size;
} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;

typedef struct _PEB
{
	UCHAR 				InheritedAddressSpace;		/* 00h */
	UCHAR 				ReadImageFileExecOptions;	/* 01h */
	UCHAR 				BeingDebugged;			/* 02h */
	BOOLEAN 			SpareBool;			/* 03h */
	HANDLE 				Mutant;				/* 04h */
	PVOID 				ImageBaseAddress;		/* 08h */
	PPEB_LDR_DATA 			Ldr;				/* 0Ch */
	PRTL_USER_PROCESS_PARAMETERS 	ProcessParameters;		/* 10h */
	PVOID 				SubSystemData;			/* 14h */
	PVOID 				ProcessHeap;			/* 18h */
	PVOID 				FastPebLock;			/* 1Ch */
	PPEBLOCKROUTINE 		FastPebLockRoutine;		/* 20h */
	PPEBLOCKROUTINE 		FastPebUnlockRoutine;		/* 24h */
	ULONG 				EnvironmentUpdateCount;		/* 28h */
	PVOID* 				KernelCallbackTable;		/* 2Ch */
	PVOID 				EventLogSection;		/* 30h */
	PVOID 				EventLog;			/* 34h */
	PPEB_FREE_BLOCK 		FreeList;			/* 38h */
	ULONG 				TlsExpansionCounter;		/* 3Ch */
	PVOID 				TlsBitmap;			/* 40h */
	ULONG 				TlsBitmapBits[0x2];		/* 44h */
	PVOID 				ReadOnlySharedMemoryBase;	/* 4Ch */
	PVOID 				ReadOnlySharedMemoryHeap;	/* 50h */
	PVOID* 				ReadOnlyStaticServerData;	/* 54h */
	PVOID 				AnsiCodePageData;		/* 58h */
	PVOID 				OemCodePageData;		/* 5Ch */
	PVOID 				UnicodeCaseTableData;		/* 60h */
	ULONG 				NumberOfProcessors;		/* 64h */
	ULONG 				NtGlobalFlag;			/* 68h */
	BYTE                            Spare2[4];                      /* 6ch */
	LARGE_INTEGER 			CriticalSectionTimeout;		/* 70h */
	ULONG 				HeapSegmentReserve;		/* 78h */
	ULONG 				HeapSegmentCommit;		/* 7Ch */
	ULONG 				HeapDeCommitTotalFreeThreshold;	/* 80h */
	ULONG 				HeapDeCommitFreeBlockThreshold;	/* 84h */
	ULONG 				NumberOfHeaps;			/* 88h */
	ULONG 				MaximumNumberOfHeaps;		/* 8Ch */
	PVOID* 				ProcessHeaps;			/* 90h */
	PVOID 				GdiSharedHandleTable;		/* 94h */
	PVOID 				ProcessStarterHelper;		/* 98h */
	PVOID 				GdiDCAttributeList;		/* 9Ch */
	PVOID 				LoaderLock;			/* A0h */
	ULONG 				OSMajorVersion;			/* A4h */
	ULONG 				OSMinorVersion;			/* A8h */
	USHORT 				OSBuildNumber;			/* ACh */
	USHORT 				OSCSDVersion;			/* AEh */
	ULONG 				OSPlatformId;			/* B0h */
	ULONG 				ImageSubSystem;			/* B4h */
	ULONG 				ImageSubSystemMajorVersion;	/* B8h */
	ULONG 				ImageSubSystemMinorVersion;	/* BCh */
	ULONG 				ImageProcessAffinityMask;	/* C0h */
	ULONG 				GdiHandleBuffer[0x22];		/* C4h */
	PVOID 				PostProcessInitRoutine;		/* 14Ch */
	PVOID 				*TlsExpansionBitmap;		/* 150h */
	ULONG 				TlsExpansionBitmapBits[0x20];	/* 154h */
	ULONG 				SessionId;			/* 1D4h */
	PVOID 				AppCompatInfo;			/* 1D8h */
	UNICODE_STRING 			CSDVersion;			/* 1DCh */
} PEB, *PPEB;

/* process startup state */
enum startup_state { STARTUP_IN_PROGRESS, STARTUP_DONE, STARTUP_ABORTED };
struct w32process
{
	struct object        obj;             /* object header */
	struct list_head     entry;           /* entry in system-wide process list */
	struct w32process   *parent;          /* parent process */
	struct eprocess     *eprocess;
	struct list_head     thread_list;     /* thread list */
	struct w32thread    *debugger;        /* thread debugging this process */
	process_id_t         group_id;        /* group id of the process */
	struct timeout_user *sigkill_timeout; /* timeout for final SIGKILL */
	int                  exit_code;       /* process exit code */
	int                  running_threads; /* number of threads running in this process */
	timeout_t	         start_time;      /* absolute time at process start */
	timeout_t            end_time;        /* absolute time at process end */
	int                  priority;        /* priority class */
	int                  affinity;        /* process affinity mask */
	int                  suspend;         /* global process suspend count */
	int                  is_system;       /* is it a system process? */
	unsigned int         create_flags;    /* process creation flags */
	struct list_head     locks;           /* list of file locks owned by the process */
	struct list_head     classes;         /* window classes owned by the process */
	struct console_input*console;         /* console input */
	enum startup_state   startup_state;   /* startup state */
	struct startup_info *startup_info;    /* startup info while init is in progress */
	struct kevent       *idle_event;      /* event for input idle */
	struct msg_queue    *queue;           /* main message queue */
	obj_handle_t         winstation;      /* main handle to process window station */
	obj_handle_t         desktop;         /* handle to desktop to use for new threads */
	struct token        *token;           /* security token associated with this process */
	struct list_head     dlls;            /* list of loaded dlls */
	unsigned int         trace_data;      /* opaque data used by the process tracing mechanism */
	int                 dummyfd;
};

extern POBJECT_TYPE process_object_type;
void kprocess_init(struct kprocess *process, char prio,
		unsigned long affinity, physical_address_t dir_table_base);
void eprocess_init(struct eprocess *parent, BOOLEAN inherit, struct eprocess *process);
struct w32process *create_w32process(struct w32process *parent, int inherit_all, struct eprocess *eprocess);
NTSTATUS STDCALL create_peb(struct eprocess *process);
void exit_process_threads(struct eprocess *process, NTSTATUS ExitStatus);
void exit_current_thread(struct task_struct *tsk, NTSTATUS ExitStatus);
VOID delete_process(PVOID Object);
int poll_process(struct wait_table_entry *wte);
int lookup_process_by_pid(HANDLE pid, struct eprocess** process);
NTSTATUS lookup_process_thread_by_cid(PCLIENT_ID cid, PEPROCESS *process, PETHREAD *thread);

void __exit_process(struct eprocess * process);

/* for server process/thread management migration */
struct process_dll
{
	struct list_head          entry;           /* entry in per-process dll list */
	struct uk_file         *file;            /* dll file */
	void                *base;            /* dll base address (in process addr space) */
	size_t               size;            /* dll size */
	void                *name;            /* ptr to ptr to name (in process addr space) */
	int                  dbg_offset;      /* debug info offset */
	int                  dbg_size;        /* debug info size */
	data_size_t          namelen;         /* length of dll file name */
	WCHAR               *filename;        /* dll file name */
};

struct process_snapshot
{
	struct w32process *process;  /* process ptr */
	int             count;    /* process refcount */
	int             threads;  /* number of threads */
	int             priority; /* priority class */
	int             handles;  /* number of handles */
};

struct module_snapshot
{
	void           *base;     /* module base addr */
	size_t          size;     /* module size */
	data_size_t     namelen;  /* length of file name */
	WCHAR          *filename; /* module file name */
};

/* process startup info */
struct startup_info
{
	struct object       obj;          /* object header */
	obj_handle_t        hstdin;       /* handle for stdin */
	obj_handle_t        hstdout;      /* handle for stdout */
	obj_handle_t        hstderr;      /* handle for stderr */
	struct uk_file        *exe_file;  /* file handle for main exe */
	struct w32process     *process;   /* created process */
	data_size_t         data_size;    /* size of startup data */
	void               *data;         /* data for startup info */
};

extern void enum_processes(int (*cb)(struct w32process*, void*), void *user);
extern struct process_snapshot *process_snap(int *count);
extern struct module_snapshot *module_snap(struct w32process *process, int *count);
/* for server process/thread management migration */

static inline struct eprocess *process2eprocess(struct w32process *proc)
{
	return proc->eprocess;
}

static inline struct eprocess *get_current_eprocess(void)
{
	return current->ethread ? current->ethread->threads_process : NULL;
}

static inline struct w32process *get_current_w32process(void)
{
	return current->ethread ? current->ethread->threads_process->win32process : NULL;
}

static inline void lock_process(struct eprocess *process)
{
	enter_critical_region();
	spin_lock(&process->process_lock);
}

static inline void unlock_process(struct eprocess *process)
{
	spin_unlock(&process->process_lock);
	leave_critical_region();
}

static inline unsigned int get_process_id(struct w32process *process)
{
	return process->eprocess ? (unsigned int)process->eprocess->unique_processid : 0; 
}

static inline int is_process_init_done(struct w32process *process)
{
	return process->startup_state == STARTUP_DONE;
}

static inline struct process_dll *get_process_exe_module(struct w32process *process)
{
	struct list_head *ptr = list_head(&process->dlls);
	return ptr ? LIST_ENTRY(ptr, struct process_dll, entry) : NULL;
}

NTSTATUS create_ppb(PRTL_USER_PROCESS_PARAMETERS *ppb_res,
		struct eprocess *process,
		struct linux_binprm *bprm,
		char *image_name,
		char *dll_path,
		char *current_dir,
		PWSTR environ,
		char *window_title,
		char *desktop_info,
		char *shell_info,
		char *rt_info);

NTSTATUS SERVICECALL
NtTerminateProcess(IN HANDLE ProcessHandle  OPTIONAL,
                   IN NTSTATUS ExitStatus);

long init_cid_table(void);
void destroy_cid_table(void);
HANDLE create_cid_handle(PVOID object, POBJECT_TYPE obj_type);
int delete_cid_handle(HANDLE cid_handle, POBJECT_TYPE obj_type);

int flush_old_exec_from_task(struct task_struct *task);

void remove_process_thread(struct w32process *process, struct w32thread *thread);

void set_process_startup_state(struct w32process *process, enum startup_state state);

data_size_t init_process(struct w32thread *thread);

struct w32process *get_process_from_id(unsigned int id);
#endif /* CONFIG_UNIFIED_KERNEL */
#endif /* _PROCESS_H */
