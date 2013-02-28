/*
 * thread.h
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
 * thread.h:
 * Refered to Kernel-win32 code
 */

#ifndef _THREAD_H
#define _THREAD_H

#include <linux/module.h>
#include <linux/sched.h>
#include "win32_thread.h"

#include "win32.h"
#include "object.h"
#include "process.h"

#ifdef CONFIG_UNIFIED_KERNEL

#define NtCurrentThread() ((HANDLE)(ULONG_PTR) - 2)
#define	TEB_BASE	0x7FFDE000
#define	TEB_SELECTOR	0x3b

#define THREAD_ALERT 0x4

typedef void *PKSTART_ROUTINE;
typedef struct _NT_TIB {
	struct _EXCEPTION_REGISTRATION_RECORD *ExceptionList;
	PVOID StackBase;
	PVOID StackLimit;
	PVOID SubSystemTib;
	union {
		PVOID FiberData;
		DWORD Version;
	} DUMMYUNIONNAME;
	PVOID ArbitraryUserPointer;
	struct _NT_TIB *Self;
} NT_TIB,*PNT_TIB;

typedef struct _GDI_TEB_BATCH
{
    ULONG Offset;
    ULONG HDC;
    ULONG Buffer[0x136];
} GDI_TEB_BATCH, *PGDI_TEB_BATCH;

enum run_state
{
    RUNNING,    /* running normally */
    TERMINATED  /* terminated */
};

typedef struct w32thread
{
	struct object          obj;           /* object header */
	struct list_head       entry;
	struct list_head       proc_entry;    /* entry in per-process thread list */
	struct w32process     *process;
	struct ethread        *ethread;
	struct debug_ctx      *debug_ctx;     /* debugger context if this thread is a debugger */
	struct debug_event    *debug_event;   /* debug event being sent to debugger */
	int                    debug_break;   /* debug breakpoint pending? */
	struct msg_queue      *queue;         /* message queue */
	unsigned int           error;         /* current error code */
	unsigned int           wake_up;
	union generic_request  req;           /* current request */
	void                  *req_data;      /* variable-size data for request */
	unsigned int           req_toread;    /* amount of data still to read in request */
	union generic_reply    reply;         /* UnifiedKernel FIXME*/
	void                  *reply_data;    /* variable-size data for reply */
	unsigned int           reply_size;    /* size of reply data */
	unsigned int           reply_towrite; /* amount of data still to write in reply */
	enum run_state         state;         /* running state */
	int                    exit_code;     /* thread exit code */
	CONTEXT               *context;       /* current context if in an exception handler */
	CONTEXT               *suspend_context; /* current context if suspended */
	int                    priority;      /* priority level */
	int                    affinity;      /* affinity mask */
	int                    suspend;       /* suspend count */
	obj_handle_t           desktop;       /* desktop handle */
	int                    desktop_users; /* number of objects using the thread desktop */
	struct token          *token;         /* security token associated with this thread */
} TSB, *PTSB, W32THREAD;

struct thread_snapshot
{
	struct w32thread  *thread;    /* thread ptr */
	int             count;     /* thread refcount */
	int             priority;  /* priority class */
};

typedef struct _TEB
{
	NT_TIB 			Tib;                         	/* 00h */
	PVOID 			EnvironmentPointer;           	/* 1Ch */
	CLIENT_ID 		Cid;                      	/* 20h */
	PVOID 			ActiveRpcInfo;                	/* 28h */
	PVOID 			ThreadLocalStoragePointer;    	/* 2Ch */
	PEB*			Peb;                   		/* 30h */
	ULONG 			LastErrorValue;               	/* 34h */
	ULONG 			CountOfOwnedCriticalSections; 	/* 38h */
	PVOID 			CsrClientThread;              	/* 3Ch */
	W32THREAD*		Win32ThreadInfo;		/* 40h */
	ULONG 			Win32ClientInfo[0x1F];        	/* 44h */
	PVOID 			WOW32Reserved;                	/* C0h */
	LCID 			CurrentLocale;                 	/* C4h */
	ULONG 			FpSoftwareStatusRegister;     	/* C8h */
	PVOID 			SystemReserved1[0x36];        	/* CCh */
	PVOID 			Spare1;                       	/* 1A4h */
	LONG 			ExceptionCode;                 	/* 1A8h */
	UCHAR 			SpareBytes1[0x28];            	/* 1ACh */
	PVOID 			SystemReserved2[0xA];         	/* 1D4h */
	GDI_TEB_BATCH 		GdiTebBatch;          		/* 1FCh */
	ULONG 			gdiRgn;                       	/* 6DCh */
	ULONG 			gdiPen;                       	/* 6E0h */
	ULONG 			gdiBrush;                     	/* 6E4h */
	CLIENT_ID 		RealClientId;             	/* 6E8h */
	PVOID 			GdiCachedProcessHandle;       	/* 6F0h */
	ULONG 			GdiClientPID;                 	/* 6F4h */
	ULONG 			GdiClientTID;                 	/* 6F8h */
	PVOID 			GdiThreadLocaleInfo;          	/* 6FCh */
	PVOID 			UserReserved[5];              	/* 700h */
	PVOID 			glDispatchTable[0x118];       	/* 714h */
	ULONG 			glReserved1[0x1A];            	/* B74h */
	PVOID 			glReserved2;                  	/* BDCh */
	PVOID  			glSectionInfo;                	/* BE0h */
	PVOID  			glSection;                    	/* BE4h */
	PVOID  			glTable;                      	/* BE8h */
	PVOID  			glCurrentRC;                  	/* BECh */
	PVOID  			glContext;                    	/* BF0h */
	NTSTATUS  		LastStatusValue;           	/* BF4h */
	UNICODE_STRING 		StaticUnicodeString; 		/* BF8h */
	WCHAR  			StaticUnicodeBuffer[0x105];   	/* C00h */
	PVOID  			DeallocationStack;            	/* E0Ch */
	PVOID  			TlsSlots[0x40];               	/* E10h */
	LIST_ENTRY  		TlsLinks;                	/* F10h */
	PVOID  			Vdm;                          	/* F18h */
	PVOID  			ReservedForNtRpc;             	/* F1Ch */
	PVOID  			DbgSsReserved[0x2];           	/* F20h */
	ULONG  			HardErrorDisabled;            	/* F28h */
	PVOID  			Instrumentation[0x10];        	/* F2Ch */
	PVOID  			WinSockData;                  	/* F6Ch */
	ULONG  			GdiBatchCount;                	/* F70h */
	USHORT  		_Spare2;                     	/* F74h */
	BOOLEAN 		IsFiber;                    	/* F76h */
	UCHAR  			Spare3;                       	/* F77h */
	ULONG  			_Spare4;                      	/* F78h */
	ULONG  			_Spare5;                      	/* F7Ch */
	PVOID  			ReservedForOle;               	/* F80h */
	ULONG  			WaitingOnLoaderLock;          	/* F84h */
	ULONG  			_Unknown[11];                 	/* F88h */
	PVOID  			FlsSlots;                     	/* FB4h */
}TEB, *PTEB;

#define LOW_PRIORITY                      0
#define LOW_REALTIME_PRIORITY             16
#define HIGH_PRIORITY                     31
#define MAXIMUM_PRIORITY                  32

extern POBJECT_TYPE thread_object_type;
int set_teb_selector(struct task_struct *tsk, long teb);
void kthread_init(struct kthread *thread, struct eprocess *process);
void ethread_init(struct ethread *thread, struct eprocess *process, struct task_struct *tsk);
VOID delete_thread(PVOID Object);
int poll_thread(struct wait_table_entry *wte);
int lookup_thread_by_tid(HANDLE tid, struct ethread** thread);

ULONG STDCALL suspend_thread(PKTHREAD Thread);
ULONG STDCALL resume_thread(PKTHREAD Thread);
VOID STDCALL suspend_thread_kernel_routine(struct kapc *Apc, PKNORMAL_ROUTINE* NormalRoutine, 
		PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArguemnt2);
VOID STDCALL suspend_thread_normal_routine(PVOID NormalContext, PVOID SystemArgument1, 
		PVOID SystemArgument2);

PTEB STDCALL create_teb(struct eprocess* Process,
            PCLIENT_ID ClientId, PINITIAL_TEB InitialTeb);
VOID STDCALL delete_teb(PTEB Teb);

typedef void (STDCALL *PKSYSTEM_ROUTINE)(PKSTART_ROUTINE StartRoutine, PVOID StartContext);

extern struct w32thread *get_thread_from_id(unsigned int id);
extern void uk_wake_up(struct object *obj, int max);
extern int thread_queue_apc(struct w32thread *thread, struct object *owner, 
		const apc_call_t *call_data);
extern void thread_cancel_apc(struct w32thread *thread, struct object *owner, enum apc_type type);
extern struct thread_snapshot *thread_snap(int *count);

VOID
STDCALL
initialize_thread(struct kprocess* Process,
		struct kthread* Thread,
		PKSYSTEM_ROUTINE SystemRoutine,
		PKSTART_ROUTINE StartRoutine,  /* FIXME */
		PVOID StartContext,            /* FIXME */
		PCONTEXT Context,
		PVOID Teb,
		PVOID KernelStack);
VOID
STDCALL
init_thread_with_context(struct kthread* Thread,
		PKSYSTEM_ROUTINE SystemRoutine,
		PKSTART_ROUTINE StartRoutine, /* FIXME */
		PVOID StartContext,           /* FIXME */
		PCONTEXT Context);
VOID
STDCALL
user_thread_startup(PKSTART_ROUTINE StartRoutine,
		PVOID StartContext);

static inline struct ethread *get_current_ethread(void)
{
	return current->ethread;
}

static inline struct ethread *get_first_thread(struct eprocess *process)
{
	struct ethread  *thread;

	local_irq_disable();
	thread = list_empty(&process->thread_list_head) ? 
		NULL : list_entry(process->thread_list_head.next, 
				struct ethread, thread_list_entry);
	local_irq_enable();

	return thread;
}

static inline struct w32thread *get_current_w32thread(void)
{
	return current->ethread ? current->ethread->tcb.win32thread : NULL;
}

#define current_thread current->ethread->tcb.win32thread

static inline struct ethread *thread2ethread(struct w32thread *thread)
{
	return thread->ethread;
}

static  inline unsigned int get_thread_id(struct w32thread *thread)
{
	return thread->ethread ? (unsigned int)thread->ethread->cid.unique_thread : 0;
}

struct w32thread *get_thread_from_id(thread_id_t id);
#endif /* CONFIG_UNIFIED_KERNEL */
#endif /* _THREAD_H */
