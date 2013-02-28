/*
 * NT basis DLL
 *
 * This file contains the Nt* API functions of NTDLL.DLL.
 * In the original ntdll.dll they all seem to just call int 0x2e (down to the NTOSKRNL)
 *
 * Copyright 1996-1998 Marcus Meissner
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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "wine/debug.h"
#include "windef.h"
#include "winternl.h"
#include "ntdll_misc.h"
#include "wine/server.h"
#include "wine/log.h"

WINE_DEFAULT_DEBUG_CHANNEL(ntdll);

/*
 *	Process object
 */

NTSTATUS WINAPI
NtCreateProcess(OUT PHANDLE ProcessHandle,
                IN ACCESS_MASK DesiredAccess,
                IN POBJECT_ATTRIBUTES ObjectAttributes  OPTIONAL,
                IN HANDLE ParentProcess,
                IN BOOLEAN InheritObjectTable,
                IN HANDLE SectionHandle  OPTIONAL,
                IN HANDLE DebugPort  OPTIONAL,
                IN HANDLE ExceptionPort  OPTIONAL)
{
	NTSTATUS ret;
	TRACE("DesiredAccess %x, ObjectAttributes %p, name %s, ParentProcess %p, \
		InheritObjectTable %d, SectionHandle %p, DebugPort %p, ExceptionPort %p\n",
		DesiredAccess, ObjectAttributes, ObjectAttributes->ObjectName ? 
		debugstr_us(ObjectAttributes->ObjectName) : NULL,
		ParentProcess, InheritObjectTable, SectionHandle, DebugPort, ExceptionPort);
	__asm__ __volatile__ (
			"movl $0x22,%%eax\n\t"
			"lea 8(%%ebp),%%edx\n\t"
			"int $0x2E\n\t"
			:"=a" (ret)
			);
	return ret;
}

/******************************************************************************
 *  NtTerminateProcess			[NTDLL.@]
 *
 *  Native applications must kill themselves when done
 */
NTSTATUS WINAPI NtTerminateProcess( HANDLE handle, LONG exit_code )
{
    NTSTATUS ret;
	LOG(LOG_FILE, 0, 0, "handle %p, exit_code %d\n", handle, exit_code);
    /* no return, if handle == 0xffffffff */
    __asm__ __volatile__ (
		    "movl $0xD3,%%eax\n\t"
		    "lea 8(%%ebp),%%edx\n\t"
		    "int $0x2E\n\t"
		    :"=a" (ret)
		    );
    return ret;
}

/******************************************************************************
 *  RtlGetCurrentPeb  [NTDLL.@]
 *
 */
PEB * WINAPI RtlGetCurrentPeb(void)
{
    return NtCurrentTeb()->Peb;
}

/***********************************************************************
 *           __wine_make_process_system   (NTDLL.@)
 *
 * Mark the current process as a system process.
 * Returns the event that is signaled when all non-system processes have exited.
 */
HANDLE __wine_make_process_system(void)
{
    HANDLE ret = 0;
    LOG(LOG_FILE, 0, 0, "\n");
    SERVER_START_REQ( make_process_system )
    {
        if (!wine_server_call( req )) ret = reply->event;
    }
    SERVER_END_REQ;
    return ret;
}


#define UNIMPLEMENTED_INFO_CLASS(c) \
    case c: \
        FIXME("(process=%p) Unimplemented information class: " #c "\n", ProcessHandle); \
        ret = STATUS_INVALID_INFO_CLASS; \
        break

/******************************************************************************
*  NtQueryInformationProcess		[NTDLL.@]
*  ZwQueryInformationProcess		[NTDLL.@]
*
*/
NTSTATUS WINAPI NtQueryInformationProcess(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength)
{
    NTSTATUS ret = STATUS_SUCCESS;

    __asm__ __volatile__ (
            "movl $0x7D,%%eax\n\t"
            "lea 8(%%ebp),%%edx\n\t"
            "int $0x2E\n\t"
            :"=a" (ret)
            );
    
    return ret;
}

/******************************************************************************
 * NtSetInformationProcess [NTDLL.@]
 * ZwSetInformationProcess [NTDLL.@]
 */
NTSTATUS WINAPI NtSetInformationProcess(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	IN PVOID ProcessInformation,
	IN ULONG ProcessInformationLength)
{
    NTSTATUS ret = STATUS_SUCCESS;

    __asm__ __volatile__ (
            "movl $0xBA,%%eax\n\t"
            "lea 8(%%ebp),%%edx\n\t"
            "int $0x2E\n\t"
            :"=a" (ret)
            );
    return ret;
}

/******************************************************************************
 * NtFlushInstructionCache [NTDLL.@]
 * ZwFlushInstructionCache [NTDLL.@]
 */
NTSTATUS WINAPI NtFlushInstructionCache(
        IN HANDLE ProcessHandle,
        IN LPCVOID BaseAddress,
        IN SIZE_T Size)
{
#ifdef __i386__
    TRACE("%p %p %ld - no-op on x86\n", ProcessHandle, BaseAddress, Size );
#else
    FIXME("%p %p %ld\n", ProcessHandle, BaseAddress, Size );
#endif
    return STATUS_SUCCESS;
}

/******************************************************************
 *		NtOpenProcess [NTDLL.@]
 *		ZwOpenProcess [NTDLL.@]
 */
NTSTATUS  WINAPI NtOpenProcess(PHANDLE handle, ACCESS_MASK access,
                               const OBJECT_ATTRIBUTES* attr, const CLIENT_ID* cid)
{
    NTSTATUS    status;

    __asm__ __volatile__ (
            "movl $0x5E,%%eax\n\t"
            "lea 8(%%ebp),%%edx\n\t"
            "int $0x2E\n\t"
            :"=a" (status)
            );	
    return status;
}
