/*
 * apc.h
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
 * apc.h:
 * Refered to ReactOS code
 */

#ifndef _APC_H
#define _APC_H

#include "winternl.h"
#include "ntstatus.h"
#include "win32.h"
#include "thread.h"
#include "process.h"
#include "ke.h"

#ifdef CONFIG_UNIFIED_KERNEL

#ifndef IO_NO_INCREMENT 
#define IO_NO_INCREMENT 0
#endif

#define SystemDllApcDispatcher NULL /* No Used ? */
#define ARGUMENT_PRESENT(ArgumentPointer) /* No Used ? */ \
  ((BOOLEAN) ((PVOID)ArgumentPointer != (PVOID)NULL)) /* No Used ? */

#define PKKERNEL_ROUTINE        kernel_routine_t
#define PKRUNDOWN_ROUTINE       rundown_routine_t
#define PKNORMAL_ROUTINE        normal_routine_t
#define KPROCESSOR_MODE         kprocessor_mode_t

/* Values for contextflags */
#define CONTEXT_i386    0x10000
#define CONTEXT_CONTROL            (CONTEXT_i386 | 1)
#define CONTEXT_INTEGER            (CONTEXT_i386 | 2)
#define CONTEXT_SEGMENTS           (CONTEXT_i386 | 4)
#define CONTEXT_FLOATING_POINT     (CONTEXT_i386 | 8)
#define CONTEXT_DEBUG_REGISTERS    (CONTEXT_i386 | 0x10)
#define CONTEXT_EXTENDED_REGISTERS (CONTEXT_i386 | 0x20)
#define CONTEXT_FULL               (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS)

#define MAXIMUM_SUPPORTED_EXTENSION  512

typedef struct pt_regs *PKTRAP_FRAME;
typedef struct kapc KAPC, *PKAPC;

typedef enum _KAPC_ENVIRONMENT 
{
  OriginalApcEnvironment,
  AttachedApcEnvironment,
  CurrentApcEnvironment
} KAPC_ENVIRONMENT;

typedef struct _FXSAVE_FORMAT{
}FXSAVE_FORMAT,*PFXSAVE_FORMAT;

typedef struct _FNSAVE_FORMAT{
}FNSAVE_FORMAT,*PFNSAVE_FORMAT;

typedef struct _FX_SAVE_AREA {
	union {
		FNSAVE_FORMAT FnArea;
		FXSAVE_FORMAT FxArea;
	} U;
	ULONG NpxSavedCpu;
	ULONG Cr0NpxState;
} FX_SAVE_AREA, *PFX_SAVE_AREA;

VOID 
STDCALL
free_apc_routine(PKAPC Apc,
                 PKNORMAL_ROUTINE* NormalRoutine,
                 PVOID* NormalContext,
                 PVOID* SystemArgument1,
                 PVOID* SystemArgument2);
BOOLEAN
STDCALL
__insert_queue_apc(PKAPC Apc,
                 KPRIORITY PriorityBoost);

VOID
STDCALL
apc_init(IN PKAPC Apc,
                IN struct kthread* Thread,
                IN KAPC_ENVIRONMENT TargetEnvironment,
                IN PKKERNEL_ROUTINE KernelRoutine,
                IN PKRUNDOWN_ROUTINE RundownRoutine OPTIONAL,
                IN PKNORMAL_ROUTINE NormalRoutine,
                IN KPROCESSOR_MODE Mode,
                IN PVOID Context);

BOOLEAN
STDCALL
insert_queue_apc(PKAPC Apc,
                 PVOID SystemArgument1,
                 PVOID SystemArgument2,
                 KPRIORITY PriorityBoost);

VOID 
STDCALL
deliver_apc(KPROCESSOR_MODE DeliveryMode,
	    PVOID Reserved,
	    struct pt_regs * TrapFrame);

BOOLEAN
STDCALL
test_alert_thread(IN KPROCESSOR_MODE AlertMode);

VOID
STDCALL
init_user_apc(IN PVOID Reserved,
                    IN PKTRAP_FRAME TrapFrame,
                    IN PKNORMAL_ROUTINE NormalRoutine,
                    IN PVOID NormalContext,
                    IN PVOID SystemArgument1,
                    IN PVOID SystemArgument2) ; 

VOID
KeContextToTrapFrame(PContext Context,
		     PKTRAP_FRAME TrapFrame);

VOID STDCALL
thread_special_apc(PKAPC Apc,
		PKNORMAL_ROUTINE* NormalRoutine,
		PVOID* NormalContext,
		PVOID* SystemArgument1,
		PVOID* SystemArgument2);

#endif /* CONFIG_UNIFIED_KERNEL */
#endif /* _APC_H */
