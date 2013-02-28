/*
 * attach.h
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
 * attach.h
 * Refered to ReactOS code
 */
 
#ifndef _ATTACH_H
#define _ATTACH_H

#include "win32.h"
#include "process.h"
#include "thread.h"
#include "apc.h"

#ifdef CONFIG_UNIFIED_KERNEL

#define MM_STACK_SIZE             (3 * 4096)

VOID STDCALL
update_page_dir(struct mm_struct *mm, PVOID Address, ULONG Size);

VOID STDCALL
move_apc_state(struct  kapc_state *OldState, struct  kapc_state *NewState);

struct mm_struct *
attach_process(struct kprocess *Process);

VOID STDCALL
detach_process (struct mm_struct *mm);

#endif /* CONFIG_UNIFIED_KERNEL */
#endif /* _ATTACH_H */
