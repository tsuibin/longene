/*
 * w32entry.S
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
  * Implements the w32 system call mechanism. The code is basically
  * a merge of the related code in entry.S from Linux 2.6.34 and
  * in syscall.S from Reactos 0.2.6. It is for i386 only.
  */


#include <linux/linkage.h>
#include <asm/thread_info.h>
#include <asm/irqflags.h>
#include <asm/errno.h>
#include <asm/segment.h>
#include <asm/smp.h>
#include <asm/page_types.h>
#include <asm/percpu.h>
#include <asm/dwarf2.h>
#include <asm/processor-flags.h>
#include <asm/ftrace.h>
#include <asm/irq_vectors.h>

CF_MASK		= 0x00000001
TF_MASK		= 0x00000100
IF_MASK		= 0x00000200
DF_MASK		= 0x00000400 
NT_MASK		= 0x00004000
VM_MASK		= 0x00020000

.macro TRACE_IRQS_IRET
#ifdef CONFIG_TRACE_IRQFLAGS
	testl $X86_EFLAGS_IF,PT_EFLAGS(%esp)     # interrupts off?
	jz 1f
	TRACE_IRQS_ON
1:
#endif
.endm

#ifdef CONFIG_VM86
#define w32resume_userspace_sig	w32check_userspace
#else
#define w32resume_userspace_sig	w32resume_userspace
#endif

#ifdef CONFIG_X86_32_LAZY_GS
.macro PUSH_GS
	pushl $0
	CFI_ADJUST_CFA_OFFSET 4
.endm
.macro POP_GS pop=0
	addl $(4 + \pop), %esp
	CFI_ADJUST_CFA_OFFSET -(4 + \pop)
.endm
.macro POP_GS_EX
.endm
.macro SET_KERNEL_GS reg
.endm

#else	/* CONFIG_X86_32_LAZY_GS */

.macro PUSH_GS
	pushl %gs
	CFI_ADJUST_CFA_OFFSET 4
.endm
.macro POP_GS pop=0
98:	popl %gs
	CFI_ADJUST_CFA_OFFSET -4
  .if \pop <> 0
	add $\pop, %esp
	CFI_ADJUST_CFA_OFFSET -\pop
  .endif
.endm
.macro POP_GS_EX
.pushsection .fixup, "ax"
99:	movl $0, (%esp)
	jmp 98b
.section __ex_table, "a"
	.align 4
	.long 98b, 99b
.popsection
.endm
.macro SET_KERNEL_GS reg
	movl $(__KERNEL_STACK_CANARY), \reg
	movl \reg, %gs
.endm

#endif	/* CONFIG_X86_32_LAZY_GS */

.macro SAVE_ALL
	cld
	PUSH_GS
	pushl %fs
	CFI_ADJUST_CFA_OFFSET 4
	/*CFI_REL_OFFSET fs, 0;*/
	pushl %es
	CFI_ADJUST_CFA_OFFSET 4
	/*CFI_REL_OFFSET es, 0;*/
	pushl %ds
	CFI_ADJUST_CFA_OFFSET 4
	/*CFI_REL_OFFSET ds, 0;*/
	pushl %eax
	CFI_ADJUST_CFA_OFFSET 4
	CFI_REL_OFFSET eax, 0
	pushl %ebp
	CFI_ADJUST_CFA_OFFSET 4
	CFI_REL_OFFSET ebp, 0
	pushl %edi
	CFI_ADJUST_CFA_OFFSET 4
	CFI_REL_OFFSET edi, 0
	pushl %esi
	CFI_ADJUST_CFA_OFFSET 4
	CFI_REL_OFFSET esi, 0
	pushl %edx
	CFI_ADJUST_CFA_OFFSET 4
	CFI_REL_OFFSET edx, 0
	pushl %ecx
	CFI_ADJUST_CFA_OFFSET 4
	CFI_REL_OFFSET ecx, 0
	pushl %ebx
	CFI_ADJUST_CFA_OFFSET 4
	CFI_REL_OFFSET ebx, 0
	movl $(__USER_DS), %edx
	movl %edx, %ds
	movl %edx, %es
	movl $(__KERNEL_PERCPU), %edx
	movl %edx, %fs
	SET_KERNEL_GS %edx
.endm

.macro RESTORE_INT_REGS
	popl %ebx
	CFI_ADJUST_CFA_OFFSET -4
	CFI_RESTORE ebx
	popl %ecx
	CFI_ADJUST_CFA_OFFSET -4
	CFI_RESTORE ecx
	popl %edx
	CFI_ADJUST_CFA_OFFSET -4
	CFI_RESTORE edx
	popl %esi
	CFI_ADJUST_CFA_OFFSET -4
	CFI_RESTORE esi
	popl %edi
	CFI_ADJUST_CFA_OFFSET -4
	CFI_RESTORE edi
	popl %ebp
	CFI_ADJUST_CFA_OFFSET -4
	CFI_RESTORE ebp
	popl %eax
	CFI_ADJUST_CFA_OFFSET -4
	CFI_RESTORE eax
.endm

.macro RESTORE_REGS	pop=0
	RESTORE_INT_REGS
1:	popl %ds
	CFI_ADJUST_CFA_OFFSET -4
	/*CFI_RESTORE ds;*/
2:	popl %es
	CFI_ADJUST_CFA_OFFSET -4
	/*CFI_RESTORE es;*/
3:	popl %fs
	CFI_ADJUST_CFA_OFFSET -4
	/*CFI_RESTORE fs;*/
	POP_GS \pop
.pushsection .fixup, "ax"
4:	movl $0, (%esp)
	jmp 1b
5:	movl $0, (%esp)
	jmp 2b
6:	movl $0, (%esp)
	jmp 3b
.section __ex_table, "a"
	.align 4
	.long 1b, 4b
	.long 2b, 5b
	.long 3b, 6b
.popsection
	POP_GS_EX
.endm

.macro RING0_INT_FRAME
	CFI_STARTPROC simple
	CFI_SIGNAL_FRAME
	CFI_DEF_CFA esp, 3*4
	/*CFI_OFFSET cs, -2*4;*/
	CFI_OFFSET eip, -3*4
.endm

.macro RING0_EC_FRAME
	CFI_STARTPROC simple
	CFI_SIGNAL_FRAME
	CFI_DEF_CFA esp, 4*4
	/*CFI_OFFSET cs, -2*4;*/
	CFI_OFFSET eip, -3*4
.endm

.macro RING0_PTREGS_FRAME
	CFI_STARTPROC simple
	CFI_SIGNAL_FRAME
	CFI_DEF_CFA esp, PT_OLDESP-PT_EBX
	/*CFI_OFFSET cs, PT_CS-PT_OLDESP;*/
	CFI_OFFSET eip, PT_EIP-PT_OLDESP
	/*CFI_OFFSET es, PT_ES-PT_OLDESP;*/
	/*CFI_OFFSET ds, PT_DS-PT_OLDESP;*/
	CFI_OFFSET eax, PT_EAX-PT_OLDESP
	CFI_OFFSET ebp, PT_EBP-PT_OLDESP
	CFI_OFFSET edi, PT_EDI-PT_OLDESP
	CFI_OFFSET esi, PT_ESI-PT_OLDESP
	CFI_OFFSET edx, PT_EDX-PT_OLDESP
	CFI_OFFSET ecx, PT_ECX-PT_OLDESP
	CFI_OFFSET ebx, PT_EBX-PT_OLDESP
.endm

#ifdef CONFIG_UNIFIED_KERNEL

ENTRY(w32system_call)
	RING0_INT_FRAME			# can't unwind into user space anyway
	pushl %eax			# save orig_eax
	CFI_ADJUST_CFA_OFFSET 4
	SAVE_ALL
	GET_THREAD_INFO(%ebp)

	movl %esp, %eax
	movl (%ebp), %edx		# get task_struct
	call set_trap_frame
	movl PT_EAX(%esp), %eax

					# system call tracing in operation / emulation
	/* Note, _TIF_SECCOMP is bit number 8, and so it needs testw and not testb */
	testl $_TIF_WORK_SYSCALL_ENTRY,TI_flags(%ebp)
	jnz w32syscall_trace_entry

    	/*
     	 * Find out which syscall table (basic or extended) to use, 
     	 * and get the offset to the table. 
     	 * The offset is related to the Table Index as such: 
     	 * offset = TableIndex x 0x10.   (see the typedef for SSDT_ENTRY)
     	 * For example, if %eax is 0x1124, then the offset is 0x10.
     	*/
	movl %eax, %edi
	shrl $8, %edi
	andl $0x10, %edi
       
    	/* Now add the base system table to the offset */
	addl $(KeServiceDescriptorTable), %edi
    
    	/* Get the true syscall ID and check it */
	andl $0x0FFF, %eax
	cmpl 8(%edi), %eax
	
    	/* Invalid ID, try to load Win32K Table */
	jnb w32syscall_badsys

	pushl %eax
	call log_call_id
	popl %eax	
w32syscall_call:
    	/* For w32syscall_trace_back */ 
    	/* Users's current stack frame pointer is source */
	movl PT_EDX(%esp), %esi
   
    	/* Allocate room for argument list from kernel stack */
	movl 12(%edi), %ecx
	movb (%ecx, %eax), %cl
	movzx %cl, %ecx
	shll $2,%ecx

    	/* Allocate new Kernel stack frame */
	pushl %ebp				
	movl %esp,%ebp  
 
    	/* Allocate space on our stack */
	subl %ecx, %esp
   
    	/* Get pointer to function */
	movl (%edi), %edi
	movl (%edi, %eax, 4), %eax

    	/* Copy the arguments from the user stack to our stack */
	shr $2, %ecx
	movl %esp, %edi
	cld
	rep movsd

	cmp $(NtContinue), %eax
	jnz do_syscall
#ud2

do_syscall:
    	/* Do the System Call */
	pushl %eax
	call enter_win_syscall
	popl %eax	

	call *%eax    /* call the service routine */

	pushl %eax
	call leave_win_syscall
	popl %eax	

    	/* Deallocate the kernel stack frame  */
	movl %ebp, %esp
	popl %ebp				
	movl %eax,PT_EAX(%esp)		# store the return value

ENTRY(w32syscall_exit)
	LOCKDEP_SYS_EXIT
	DISABLE_INTERRUPTS(CLBR_ANY)	# make sure we don't miss an interrupt
					# setting need_resched or sigpending
					# between sampling and the iret
	TRACE_IRQS_OFF
	movl TI_flags(%ebp), %ecx
	testl $_TIF_ALLWORK_MASK, %ecx	# current->work
	jne w32syscall_exit_work

w32restore_all:
	movl PT_EFLAGS(%esp), %eax	# mix EFLAGS, SS and CS
	# Warning: PT_OLDSS(%esp) contains the wrong/random values if we
	# are returning to the kernel.
	# See comments in process.c:copy_thread() for details.
	movb PT_OLDSS(%esp), %ah
	movb PT_CS(%esp), %al
	andl $(X86_EFLAGS_VM | (SEGMENT_TI_MASK << 8) | SEGMENT_RPL_MASK), %eax
	cmpl $((SEGMENT_LDT << 8) | USER_RPL), %eax
	CFI_REMEMBER_STATE
	je w32ldt_ss			# returning to user-space with LDT SS
	
w32restore_nocheck:
	TRACE_IRQS_IRET
w32restore_nocheck_notrace:
	RESTORE_REGS 4			# skip orig_eax/error_code
	CFI_ADJUST_CFA_OFFSET -4
irq_return:
	INTERRUPT_RETURN
#if 0
.section .fixup,"ax"
w32iret_exc:
	pushl $0			# no error code
	pushl $do_iret_error
	jmp error_code
.previous
.section __ex_table,"a"
	.align 4
	.long irq_return,w32iret_exc
.previous
#endif

	CFI_RESTORE_STATE
w32ldt_ss:
	larl PT_OLDSS(%esp), %eax
	jnz w32restore_nocheck
	testl $0x00400000, %eax		# returning to 32bit stack?
	jnz w32restore_nocheck		# allright, normal return

#ifdef CONFIG_PARAVIRT
	/*
	 * The kernel can't run on a non-flat stack if paravirt mode
	 * is active.  Rather than try to fixup the high bits of
	 * ESP, bypass this code entirely.  This may break DOSemu
	 * and/or Wine support in a paravirt VM, although the option
	 * is still available to implement the setting of the high
	 * 16-bits in the INTERRUPT_RETURN paravirt-op.
	 */
	cmpl $0, pv_info+PARAVIRT_enabled
	jne w32restore_nocheck
#endif

	/*
	 * Setup and switch to ESPFIX stack
	 *
	 * We're returning to userspace with a 16 bit stack. The CPU will not
	 * restore the high word of ESP for us on executing iret... This is an
	 * "official" bug of all the x86-compatible CPUs, which we can work
	 * around to make dosemu and wine happy. We do this by preloading the
	 * high word of ESP with the high word of the userspace ESP while
	 * compensating for the offset by changing to the ESPFIX segment with
	 * a base address that matches for the difference.
	 */
	mov %esp, %edx			/* load kernel esp */
	mov PT_OLDESP(%esp), %eax	/* load userspace esp */
	mov %dx, %ax			/* eax: new kernel esp */
	sub %eax, %edx			/* offset (low word is 0) */
	PER_CPU(gdt_page, %ebx)
	shr $16, %edx
	mov %dl, GDT_ENTRY_ESPFIX_SS * 8 + 4(%ebx) /* bits 16..23 */
	mov %dh, GDT_ENTRY_ESPFIX_SS * 8 + 7(%ebx) /* bits 24..31 */
	pushl $__ESPFIX_SS
	CFI_ADJUST_CFA_OFFSET 4
	push %eax			/* new kernel esp */
	CFI_ADJUST_CFA_OFFSET 4
	/* Disable interrupts, but do not irqtrace this section: we
	 * will soon execute iret and the tracer was already set to
	 * the irqstate after the iret */
	DISABLE_INTERRUPTS(CLBR_EAX)
	lss (%esp), %esp		/* switch to espfix segment */
	CFI_ADJUST_CFA_OFFSET -8
	jmp w32restore_nocheck
	CFI_ENDPROC
ENDPROC(w32system_call)

	# perform work that needs to be done immediately before resumption
	ALIGN
	RING0_PTREGS_FRAME		# can't unwind into user space anyway
w32work_pending:
	testb $_TIF_NEED_RESCHED, %cl
	jz w32work_notifysig
	
w32work_resched:
	call schedule
	LOCKDEP_SYS_EXIT
	DISABLE_INTERRUPTS(CLBR_ANY)	# make sure we don't miss an interrupt
					# setting need_resched or sigpending
					# between sampling and the iret
	TRACE_IRQS_OFF
	movl TI_flags(%ebp), %ecx
	andl $_TIF_WORK_MASK, %ecx	# is there any work to be done other
					# than syscall tracing?
	jz w32restore_all
	testb $_TIF_NEED_RESCHED, %cl
	jnz w32work_resched
	
w32work_notifysig:			# deal with pending signals and
					# notify-resume requests
#ifdef CONFIG_VM86
	testl $X86_EFLAGS_VM, PT_EFLAGS(%esp)
	movl %esp, %eax
	je w32apc			# returning to kernel-space or
					# vm86-space
	ALIGN
w32work_notifysig_v86:
	pushl %ecx			# save ti_flags for do_notify_resume
	CFI_ADJUST_CFA_OFFSET 4
	call save_v86_state		# %eax contains pt_regs pointer
	popl %ecx
	CFI_ADJUST_CFA_OFFSET -4
	movl %eax, %esp
#else
	movl %esp, %eax
#endif

w32apc:
	xorl %edx, %edx
	testw $_TIF_APC, %cx
	jz w32signal                

	call do_apc                  	# for Windows Apc    
	movl TI_flags(%ebp), %ecx
	testw $(_TIF_WORK_MASK & ~_TIF_APC), %cx
	jz w32resume_userspace_sig
	xorl %edx, %edx
	movl %esp, %eax

w32signal:
	call do_notify_resume
	jmp w32resume_userspace_sig

END(w32work_pending)

	# perform syscall exit tracing
	ALIGN
w32syscall_trace_entry:
	movl $-ENOSYS,PT_EAX(%esp)
	movl %esp, %eax
	call syscall_trace_enter

    	/* back to w32syscall_call */
	movl %eax, %edi
	shrl $8, %edi
	andl $0x10, %edi
	
	addl $(KeServiceDescriptorTable), %edi

	andl $0x0FFF, %eax
	cmpl 8(%edi), %eax	
	jb w32syscall_call
	
	jmp w32syscall_exit

	# perform syscall exit tracing
	ALIGN
w32syscall_exit_work:
	testl $_TIF_WORK_SYSCALL_EXIT, %ecx
	jz w32work_pending
	TRACE_IRQS_ON
	ENABLE_INTERRUPTS(CLBR_ANY)	# could let syscall_trace_leave() call
					# schedule() instead
	movl %esp, %eax
	call syscall_trace_leave
	jmp w32resume_userspace
END(w32syscall_exit_work)
	CFI_ENDPROC

	ALIGN
w32syscall_badsys:
	movl $-ENOSYS,PT_EAX(%esp)
	jmp w32resume_userspace	

w32check_userspace:
	movl PT_EFLAGS(%esp), %eax	# mix EFLAGS and CS
	movb PT_CS(%esp), %al
	andl $(X86_EFLAGS_VM | SEGMENT_RPL_MASK), %eax
	cmpl $USER_RPL, %eax
	jb w32restore_nocheck		# not returning to v8086 or userspace

w32resume_userspace:
	LOCKDEP_SYS_EXIT
	DISABLE_INTERRUPTS(CLBR_ANY)	# make sure we don't miss an interrupt
					# setting need_resched or sigpending
					# between sampling and the iret
	TRACE_IRQS_OFF
	movl TI_flags(%ebp), %ecx
	andl $_TIF_WORK_MASK, %ecx	# is there any work to be done on
					# int/exception return?
	jne w32work_pending
	jmp w32restore_all

#endif
