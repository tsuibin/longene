/*
 * Win32 threads
 *
 * Copyright 1996 Alexandre Julliard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "config.h"
#include "wine/port.h"

#include <assert.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/types.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winerror.h"
#include "wine/winbase16.h"
#include "wine/exception.h"
#include "wine/library.h"
#include "wine/server.h"
#include "wine/debug.h"

#include "kernel_private.h"
#include "wine/log.h"

WINE_DEFAULT_DEBUG_CHANNEL(thread);

extern int server_abort_thread( int status );

/***********************************************************************
 *           CreateThread   (KERNEL32.@)
 */
HANDLE WINAPI CreateThread( SECURITY_ATTRIBUTES *sa, SIZE_T stack,
                            LPTHREAD_START_ROUTINE start, LPVOID param,
                            DWORD flags, LPDWORD id )
{
     return CreateRemoteThread( GetCurrentProcess(),
                                sa, stack, start, param, flags, id );
}

#define PAGE_SIZE       0x1000
#define ROUNDUP(a, b) ((((a) + (b) - 1)/(b))*(b))

struct debug_info
{
    char *str_pos;       /* current position in strings buffer */
    char *out_pos;       /* current position in output buffer */
    char  strings[1024]; /* buffer for temporary strings */
    char  output[1024];  /* current output line */
};

struct ntdll_thread_data
{
    DWORD              fs;            /* 1d4 TEB selector */
    DWORD              gs;            /* 1d8 libc selector; update winebuild if you move this! */
    struct debug_info *debug_info;    /* 1dc info for debugstr functions */
    int                request_fd;    /* 1e0 fd for sending server requests */
    int                reply_fd;      /* 1e4 fd for receiving server replies */
    int                wait_fd[2];    /* 1e8 fd for sleeping server requests */
    void              *vm86_ptr;      /* 1f0 data for vm86 mode */
    void              *pad[2];        /* 1f4 change this if you add fields! */
};

void ThreadStartup(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter)
{
    volatile UINT uExitCode = 0;
    struct debug_info debug_info;
    struct ntdll_thread_data *thread_data;

    /* signal */
    thread_data = (struct ntdll_thread_data *)NtCurrentTeb()->SystemReserved2;
    thread_data->debug_info = &debug_info;
    debug_info.str_pos = debug_info.strings;
    debug_info.out_pos = debug_info.output;

    __TRY
    {
        uExitCode = (lpStartAddress)((PVOID)lpParameter);
    }
    __EXCEPT(UnhandledExceptionFilter)
    {
        uExitCode = GetExceptionCode();
    }
    __ENDTRY;

    ExitThread(uExitCode);
}

extern NTSTATUS
RtlRosCreateUserThread(IN HANDLE ProcessHandle,
        IN POBJECT_ATTRIBUTES ObjectAttributes,
        IN BOOLEAN CreateSuspended,
        IN LONG StackZeroBits,
        IN OUT PULONG StackReserve OPTIONAL,
        IN OUT PULONG StackCommit OPTIONAL,
        IN PVOID BaseStartAddress,
        OUT PHANDLE ThreadHandle OPTIONAL,
        OUT PCLIENT_ID ClientId OPTIONAL,
        IN ULONG_PTR StartAddress,
        IN ULONG_PTR Parameter);

    HANDLE WINAPI
CreateRemoteThread(HANDLE hProcess,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        SIZE_T dwStackSize,
        LPTHREAD_START_ROUTINE lpStartAddress,
        LPVOID lpParameter,
        DWORD dwCreationFlags,
        LPDWORD lpThreadId)
{
    HANDLE hThread;
    CLIENT_ID cidClientId;
    NTSTATUS nErrCode;
    ULONG nStackReserve;
    ULONG nStackCommit;
    OBJECT_ATTRIBUTES oaThreadAttribs;
    PIMAGE_NT_HEADERS pinhHeader = RtlImageNtHeader(NtCurrentTeb()->Peb->ImageBaseAddress);

    /* FIXME: do more checks - e.g. the image may not have an optional header */
    if(pinhHeader == NULL) {
        nStackReserve = 0x100000;/* FIXME */
        nStackCommit = PAGE_SIZE;
    } else {
        nStackReserve = pinhHeader->OptionalHeader.SizeOfStackReserve;
        nStackCommit = pinhHeader->OptionalHeader.SizeOfStackCommit;
    }

    /* use defaults */
    if(dwStackSize == 0);
    /* dwStackSize specifies the size to reserve */
    else if(dwCreationFlags & STACK_SIZE_PARAM_IS_A_RESERVATION)
        nStackReserve = dwStackSize;
    /* dwStackSize specifies the size to commit */
    else
        nStackCommit = dwStackSize;

    /* fix the stack reserve size */
    if(nStackCommit > nStackReserve)
        nStackReserve = ROUNDUP(nStackCommit, 0x100000);

    /* initialize the attributes for the thread object */
    InitializeObjectAttributes(&oaThreadAttribs,
            NULL,
            0,
            NULL,
            NULL);

    if(lpThreadAttributes) {
        /* make the handle inheritable */
        if(lpThreadAttributes->bInheritHandle)
            oaThreadAttribs.Attributes |= OBJ_INHERIT;

        /* user-defined security descriptor */
        oaThreadAttribs.SecurityDescriptor = lpThreadAttributes->lpSecurityDescriptor;
    }

    /* create the thread */
    nErrCode = RtlRosCreateUserThread(hProcess,
            &oaThreadAttribs,
            dwCreationFlags & CREATE_SUSPENDED,
            0,
            &nStackReserve,
            &nStackCommit,
            (LPTHREAD_START_ROUTINE)ThreadStartup,
            &hThread,
            &cidClientId,
            (ULONG_PTR)lpStartAddress,
            (ULONG_PTR)lpParameter);
    /* failure */
    if(nErrCode) {
        SetLastError(nErrCode);
        return NULL;
    }

    /* success */
    if(lpThreadId)
        *lpThreadId = (DWORD)cidClientId.UniqueThread;

    return hThread;
}


/***********************************************************************
 * OpenThread  [KERNEL32.@]   Retrieves a handle to a thread from its thread id
 */
HANDLE WINAPI OpenThread( DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId )
{
    NTSTATUS status;
    HANDLE handle;
    OBJECT_ATTRIBUTES attr;
    CLIENT_ID cid;

    attr.Length = sizeof(attr);
    attr.RootDirectory = 0;
    attr.Attributes = bInheritHandle ? OBJ_INHERIT : 0;
    attr.ObjectName = NULL;
    attr.SecurityDescriptor = NULL;
    attr.SecurityQualityOfService = NULL;

    cid.UniqueProcess = 0; /* FIXME */
    cid.UniqueThread = ULongToHandle(dwThreadId);
    status = NtOpenThread( &handle, dwDesiredAccess, &attr, &cid );
    if (status)
    {
        SetLastError( RtlNtStatusToDosError(status) );
        handle = 0;
    }
    return handle;
}


/***********************************************************************
 * ExitThread [KERNEL32.@]  Ends a thread
 *
 * RETURNS
 *    None
 */
void WINAPI ExitThread( DWORD code ) /* [in] Exit code for this thread */
{
	ULONG last;
	NTSTATUS status;

	status = NtQueryInformationThread((HANDLE)-2, ThreadAmILastThread, &last, sizeof(last), NULL);

	LOG(LOG_FILE, 0, 0, "back from terminate_thread\n");

	if (status == STATUS_SUCCESS && last)
	{
		LdrShutdownProcess();
		LOG(LOG_FILE, 0, 0, "NtTerminateProcess\n");
		NtTerminateProcess(GetCurrentProcess(), code);
	}
	else
	{
		LOG(LOG_FILE, 0, 0, "RtlFreeThreadActivationContextStack\n");
		RtlFreeThreadActivationContextStack();
		RtlExitUserThread( code );
	}
	LOG(LOG_FILE, 0, 0, "done\n");
}


/**********************************************************************
 * TerminateThread [KERNEL32.@]  Terminates a thread
 *
 * RETURNS
 *    Success: TRUE
 *    Failure: FALSE
 */
BOOL WINAPI TerminateThread( HANDLE handle,    /* [in] Handle to thread */
                             DWORD exit_code)  /* [in] Exit code for thread */
{
    NTSTATUS status = NtTerminateThread( handle, exit_code );
    if (status) SetLastError( RtlNtStatusToDosError(status) );
    return !status;
}


/***********************************************************************
 *           FreeLibraryAndExitThread (KERNEL32.@)
 */
void WINAPI FreeLibraryAndExitThread(HINSTANCE hLibModule, DWORD dwExitCode)
{
    FreeLibrary(hLibModule);
    ExitThread(dwExitCode);
}


/**********************************************************************
 *		GetExitCodeThread (KERNEL32.@)
 *
 * Gets termination status of thread.
 *
 * RETURNS
 *    Success: TRUE
 *    Failure: FALSE
 */
BOOL WINAPI GetExitCodeThread(
    HANDLE hthread, /* [in]  Handle to thread */
    LPDWORD exitcode) /* [out] Address to receive termination status */
{
    THREAD_BASIC_INFORMATION info;
    NTSTATUS status = NtQueryInformationThread( hthread, ThreadBasicInformation,
                                                &info, sizeof(info), NULL );

    if (status)
    {
        SetLastError( RtlNtStatusToDosError(status) );
        return FALSE;
    }
    if (exitcode) *exitcode = info.ExitStatus;
    return TRUE;
}


/***********************************************************************
 * SetThreadContext [KERNEL32.@]  Sets context of thread.
 *
 * RETURNS
 *    Success: TRUE
 *    Failure: FALSE
 */
BOOL WINAPI SetThreadContext( HANDLE handle,           /* [in]  Handle to thread with context */
                              const CONTEXT *context ) /* [in] Address of context structure */
{
    NTSTATUS status = NtSetContextThread( handle, context );
    if (status) SetLastError( RtlNtStatusToDosError(status) );
    return !status;
}


/***********************************************************************
 * GetThreadContext [KERNEL32.@]  Retrieves context of thread.
 *
 * RETURNS
 *    Success: TRUE
 *    Failure: FALSE
 */
BOOL WINAPI GetThreadContext( HANDLE handle,     /* [in]  Handle to thread with context */
                              CONTEXT *context ) /* [out] Address of context structure */
{
    NTSTATUS status = NtGetContextThread( handle, context );
    if (status) SetLastError( RtlNtStatusToDosError(status) );
    return !status;
}


/**********************************************************************
 * SuspendThread [KERNEL32.@]  Suspends a thread.
 *
 * RETURNS
 *    Success: Previous suspend count
 *    Failure: 0xFFFFFFFF
 */
DWORD WINAPI SuspendThread( HANDLE hthread ) /* [in] Handle to the thread */
{
    DWORD ret;
    NTSTATUS status = NtSuspendThread( hthread, &ret );

    if (status)
    {
        ret = ~0U;
        SetLastError( RtlNtStatusToDosError(status) );
    }
    return ret;
}


/**********************************************************************
 * ResumeThread [KERNEL32.@]  Resumes a thread.
 *
 * Decrements a thread's suspend count.  When count is zero, the
 * execution of the thread is resumed.
 *
 * RETURNS
 *    Success: Previous suspend count
 *    Failure: 0xFFFFFFFF
 *    Already running: 0
 */
DWORD WINAPI ResumeThread( HANDLE hthread ) /* [in] Identifies thread to restart */
{
    DWORD ret;
    NTSTATUS status = NtResumeThread( hthread, &ret );

    if (status)
    {
        ret = ~0U;
        SetLastError( RtlNtStatusToDosError(status) );
    }
    return ret;
}


/**********************************************************************
 * GetThreadPriority [KERNEL32.@]  Returns priority for thread.
 *
 * RETURNS
 *    Success: Thread's priority level.
 *    Failure: THREAD_PRIORITY_ERROR_RETURN
 */
INT WINAPI GetThreadPriority(
    HANDLE hthread) /* [in] Handle to thread */
{
    THREAD_BASIC_INFORMATION info;
    NTSTATUS status = NtQueryInformationThread( hthread, ThreadBasicInformation,
                                                &info, sizeof(info), NULL );

    if (status)
    {
        SetLastError( RtlNtStatusToDosError(status) );
        return THREAD_PRIORITY_ERROR_RETURN;
    }
    return info.Priority;
}


/**********************************************************************
 * SetThreadPriority [KERNEL32.@]  Sets priority for thread.
 *
 * RETURNS
 *    Success: TRUE
 *    Failure: FALSE
 */
BOOL WINAPI SetThreadPriority(
    HANDLE hthread, /* [in] Handle to thread */
    INT priority)   /* [in] Thread priority level */
{
    DWORD       prio = priority;
    NTSTATUS    status;

    status = NtSetInformationThread(hthread, ThreadBasePriority,
                                    &prio, sizeof(prio));

    if (status)
    {
        SetLastError( RtlNtStatusToDosError(status) );
        return FALSE;
    }

    return TRUE;
}


/**********************************************************************
 * GetThreadPriorityBoost [KERNEL32.@]  Returns priority boost for thread.
 *
 * Always reports that priority boost is disabled.
 *
 * RETURNS
 *    Success: TRUE.
 *    Failure: FALSE
 */
BOOL WINAPI GetThreadPriorityBoost(
    HANDLE hthread, /* [in] Handle to thread */
    PBOOL pstate)   /* [out] pointer to var that receives the boost state */
{
    if (pstate) *pstate = FALSE;
    return NO_ERROR;
}


/**********************************************************************
 * SetThreadPriorityBoost [KERNEL32.@]  Sets priority boost for thread.
 *
 * Priority boost is not implemented. This function always returns
 * FALSE and sets last error to ERROR_CALL_NOT_IMPLEMENTED
 *
 * RETURNS
 *    Always returns FALSE to indicate a failure
 */
BOOL WINAPI SetThreadPriorityBoost(
    HANDLE hthread, /* [in] Handle to thread */
    BOOL disable)   /* [in] TRUE to disable priority boost */
{
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}


/**********************************************************************
 *           SetThreadAffinityMask   (KERNEL32.@)
 */
DWORD_PTR WINAPI SetThreadAffinityMask( HANDLE hThread, DWORD_PTR dwThreadAffinityMask )
{
    NTSTATUS                    status;
    THREAD_BASIC_INFORMATION    tbi;

    status = NtQueryInformationThread( hThread, ThreadBasicInformation, 
                                       &tbi, sizeof(tbi), NULL );
    if (status)
    {
        SetLastError( RtlNtStatusToDosError(status) );
        return 0;
    }
    status = NtSetInformationThread( hThread, ThreadAffinityMask, 
                                     &dwThreadAffinityMask,
                                     sizeof(dwThreadAffinityMask));
    if (status)
    {
        SetLastError( RtlNtStatusToDosError(status) );
        return 0;
    }
    return tbi.AffinityMask;
}


/**********************************************************************
 * SetThreadIdealProcessor [KERNEL32.@]  Obtains timing information.
 *
 * RETURNS
 *    Success: Value of last call to SetThreadIdealProcessor
 *    Failure: -1
 */
DWORD WINAPI SetThreadIdealProcessor(
    HANDLE hThread,          /* [in] Specifies the thread of interest */
    DWORD dwIdealProcessor)  /* [in] Specifies the new preferred processor */
{
    FIXME("(%p): stub\n",hThread);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return -1L;
}


/* callback for QueueUserAPC */
static void CALLBACK call_user_apc( ULONG_PTR arg1, ULONG_PTR arg2, ULONG_PTR arg3 )
{
    PAPCFUNC func = (PAPCFUNC)arg1;
    func( arg2 );
}

/***********************************************************************
 *              QueueUserAPC  (KERNEL32.@)
 */
DWORD WINAPI QueueUserAPC( PAPCFUNC func, HANDLE hthread, ULONG_PTR data )
{
    NTSTATUS status = NtQueueApcThread( hthread, call_user_apc, (ULONG_PTR)func, data, 0 );

    if (status) SetLastError( RtlNtStatusToDosError(status) );
    return !status;
}

/***********************************************************************
 *              QueueUserWorkItem  (KERNEL32.@)
 */
BOOL WINAPI QueueUserWorkItem( LPTHREAD_START_ROUTINE Function, PVOID Context, ULONG Flags )
{
    NTSTATUS status;

    TRACE("(%p,%p,0x%08x)\n", Function, Context, Flags);

    status = RtlQueueWorkItem( Function, Context, Flags );

    if (status) SetLastError( RtlNtStatusToDosError(status) );
    return !status;
}

/**********************************************************************
 * GetThreadTimes [KERNEL32.@]  Obtains timing information.
 *
 * RETURNS
 *    Success: TRUE
 *    Failure: FALSE
 */
BOOL WINAPI GetThreadTimes(
    HANDLE thread,         /* [in]  Specifies the thread of interest */
    LPFILETIME creationtime, /* [out] When the thread was created */
    LPFILETIME exittime,     /* [out] When the thread was destroyed */
    LPFILETIME kerneltime,   /* [out] Time thread spent in kernel mode */
    LPFILETIME usertime)     /* [out] Time thread spent in user mode */
{
    KERNEL_USER_TIMES   kusrt;
    NTSTATUS            status;

    status = NtQueryInformationThread(thread, ThreadTimes, &kusrt,
                                      sizeof(kusrt), NULL);
    if (status)
    {
        SetLastError( RtlNtStatusToDosError(status) );
        return FALSE;
    }
    if (creationtime)
    {
        creationtime->dwLowDateTime = kusrt.CreateTime.u.LowPart;
        creationtime->dwHighDateTime = kusrt.CreateTime.u.HighPart;
    }
    if (exittime)
    {
        exittime->dwLowDateTime = kusrt.ExitTime.u.LowPart;
        exittime->dwHighDateTime = kusrt.ExitTime.u.HighPart;
    }
    if (kerneltime)
    {
        kerneltime->dwLowDateTime = kusrt.KernelTime.u.LowPart;
        kerneltime->dwHighDateTime = kusrt.KernelTime.u.HighPart;
    }
    if (usertime)
    {
        usertime->dwLowDateTime = kusrt.UserTime.u.LowPart;
        usertime->dwHighDateTime = kusrt.UserTime.u.HighPart;
    }
    
    return TRUE;
}

/**********************************************************************
 * GetThreadId [KERNEL32.@]
 *
 * Retrieve the identifier of a thread.
 *
 * PARAMS
 *  Thread [I] The thread to retrieve the identifier of.
 *
 * RETURNS
 *    Success: Identifier of the target thread.
 *    Failure: 0
 */
DWORD WINAPI GetThreadId(HANDLE Thread)
{
    THREAD_BASIC_INFORMATION tbi;
    NTSTATUS status;

    TRACE("(%p)\n", Thread);

    status = NtQueryInformationThread(Thread, ThreadBasicInformation, &tbi,
                                      sizeof(tbi), NULL);
    if (status)
    {
        SetLastError( RtlNtStatusToDosError(status) );
        return 0;
    }

    return HandleToULong(tbi.ClientId.UniqueThread);
}


/**********************************************************************
 * VWin32_BoostThreadGroup [KERNEL.535]
 */
VOID WINAPI VWin32_BoostThreadGroup( DWORD threadId, INT boost )
{
    FIXME("(0x%08x,%d): stub\n", threadId, boost);
}


/**********************************************************************
 * VWin32_BoostThreadStatic [KERNEL.536]
 */
VOID WINAPI VWin32_BoostThreadStatic( DWORD threadId, INT boost )
{
    FIXME("(0x%08x,%d): stub\n", threadId, boost);
}


/***********************************************************************
 * GetCurrentThread [KERNEL32.@]  Gets pseudohandle for current thread
 *
 * RETURNS
 *    Pseudohandle for the current thread
 */
#undef GetCurrentThread
HANDLE WINAPI GetCurrentThread(void)
{
    return (HANDLE)0xfffffffe;
}


#ifdef __i386__

/***********************************************************************
 *		SetLastError (KERNEL.147)
 *		SetLastError (KERNEL32.@)
 */
/* void WINAPI SetLastError( DWORD error ); */
__ASM_GLOBAL_FUNC( SetLastError,
                   "movl 4(%esp),%eax\n\t"
                   ".byte 0x64\n\t"
                   "movl %eax,0x34\n\t"
                   "ret $4" )

/***********************************************************************
 *		GetLastError (KERNEL.148)
 *		GetLastError (KERNEL32.@)
 */
/* DWORD WINAPI GetLastError(void); */
__ASM_GLOBAL_FUNC( GetLastError, ".byte 0x64\n\tmovl 0x34,%eax\n\tret" )

/***********************************************************************
 *		GetCurrentProcessId (KERNEL.471)
 *		GetCurrentProcessId (KERNEL32.@)
 */
/* DWORD WINAPI GetCurrentProcessId(void) */
__ASM_GLOBAL_FUNC( GetCurrentProcessId, ".byte 0x64\n\tmovl 0x20,%eax\n\tret" )

/***********************************************************************
 *		GetCurrentThreadId (KERNEL.462)
 *		GetCurrentThreadId (KERNEL32.@)
 */
/* DWORD WINAPI GetCurrentThreadId(void) */
__ASM_GLOBAL_FUNC( GetCurrentThreadId, ".byte 0x64\n\tmovl 0x24,%eax\n\tret" )

#else  /* __i386__ */

/**********************************************************************
 *		SetLastError (KERNEL.147)
 *		SetLastError (KERNEL32.@)
 *
 * Sets the last-error code.
 *
 * RETURNS
 * Nothing.
 */
void WINAPI SetLastError( DWORD error ) /* [in] Per-thread error code */
{
    NtCurrentTeb()->LastErrorValue = error;
}

/**********************************************************************
 *		GetLastError (KERNEL.148)
 *              GetLastError (KERNEL32.@)
 *
 * Get the last-error code.
 *
 * RETURNS
 *  last-error code.
 */
DWORD WINAPI GetLastError(void)
{
    return NtCurrentTeb()->LastErrorValue;
}

/***********************************************************************
 *		GetCurrentProcessId (KERNEL.471)
 *		GetCurrentProcessId (KERNEL32.@)
 *
 * Get the current process identifier.
 *
 * RETURNS
 *  current process identifier
 */
DWORD WINAPI GetCurrentProcessId(void)
{
    return HandleToULong(NtCurrentTeb()->ClientId.UniqueProcess);
}

/***********************************************************************
 *		GetCurrentThreadId (KERNEL.462)
 *		GetCurrentThreadId (KERNEL32.@)
 *
 * Get the current thread identifier.
 *
 * RETURNS
 *  current thread identifier
 */
DWORD WINAPI GetCurrentThreadId(void)
{
    return HandleToULong(NtCurrentTeb()->ClientId.UniqueThread);
}

#endif  /* __i386__ */
