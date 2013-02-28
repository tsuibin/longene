/*
 * switch.S
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
 * switch.S: switch to new waken thread
 */

#include <linux/linkage.h>
#include <asm/dwarf2.h>
#include <asm/thread_info.h>

#ifdef CONFIG_UNIFIED_KERNEL

ENTRY(thread_startup)
	CFI_STARTPROC
	pushl %eax
	CFI_ADJUST_CFA_OFFSET 4
	call schedule_tail
	CFI_ADJUST_CFA_OFFSET 4
	popl %eax                       # used?
	CFI_ADJUST_CFA_OFFSET 4
	popl %ebx                       # popup SystemRoutine
	CFI_ADJUST_CFA_OFFSET 4
	popl %eax                       # popup StartRoutine
	CFI_ADJUST_CFA_OFFSET 4
	popl %edx                       # popup StartContext
	CFI_ADJUST_CFA_OFFSET 4
	call *%ebx
	CFI_ADJUST_CFA_OFFSET 4
	GET_THREAD_INFO(%ebp)
	CFI_ADJUST_CFA_OFFSET -4
	pushl $0x0202			# Reset kernel eflags
	CFI_ADJUST_CFA_OFFSET 4
	popfl
	CFI_ADJUST_CFA_OFFSET -4
	jmp w32syscall_exit
	CFI_ENDPROC
END(thread_startup)

#endif
