/*
 * flush.c
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
 *   Mar 2009 - Created.
 */
 
/*
 * flush.c:
 * Refered to Wine code
 */
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <asm/i387.h>
#include "process.h"

#ifdef CONFIG_UNIFIED_KERNEL
extern int de_thread(struct task_struct *tsk);
extern int copy_files(unsigned long clone_flags, struct task_struct *tsk);
extern void flush_ptrace_hw_breakpoint(struct task_struct *tsk);

static void __put_unused_fd(struct files_struct *files, unsigned int fd)
{
	struct fdtable *fdt = files_fdtable(files);
	__FD_CLR(fd, fdt->open_fds);
	if (fd < files->next_fd)
		files->next_fd = fd;
}

/* Modified from sys_close */
static long close_fd_from_task(struct task_struct *task, unsigned int fd)
{
	struct file * filp;
	struct files_struct *files = task->files;
	struct fdtable *fdt;
	int retval;

	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	if (fd >= fdt->max_fds)
		goto out_unlock;
	filp = fdt->fd[fd];
	if (!filp)
		goto out_unlock;
	rcu_assign_pointer(fdt->fd[fd], NULL);
	FD_CLR(fd, fdt->close_on_exec);
	__put_unused_fd(files, fd);
	spin_unlock(&files->file_lock);
	retval = filp_close(filp, files);

	/* can't restart close syscall because file table entry was cleared */
	if (unlikely(retval == -ERESTARTSYS ||
				retval == -ERESTARTNOINTR ||
				retval == -ERESTARTNOHAND ||
				retval == -ERESTART_RESTARTBLOCK))
		retval = -EINTR;

	return retval;

out_unlock:
	spin_unlock(&files->file_lock);
	return -EBADF;
}

static void flush_thread_from_task(struct task_struct *tsk)
{
	flush_ptrace_hw_breakpoint(tsk);
	memset(tsk->thread.tls_array, 0, sizeof(tsk->thread.tls_array));
	/*
	 * Forget coprocessor state..
	 */
	tsk->fpu_counter = 0;
	clear_fpu(tsk);
	clear_used_math();
}

static void flush_signal_handlers_from_task(struct task_struct *t, int force_default)
{
	int i;
	struct k_sigaction *ka = &t->sighand->action[0];
	for (i = _NSIG ; i != 0 ; i--) {
		if (force_default || ka->sa.sa_handler != SIG_IGN)
			ka->sa.sa_handler = SIG_DFL;
		ka->sa.sa_flags = 0;
		sigemptyset(&ka->sa.sa_mask);
		ka++;
	}
}

static void flush_old_files_from_task(struct task_struct *task)
{
	long j = -1;
	struct fdtable *fdt;
	struct files_struct *files = task->files;

	spin_lock(&files->file_lock);
	for (;;) {
		unsigned long set, i;

		j++;
		i = j * __NFDBITS;
		fdt = files_fdtable(files);
		if (i >= fdt->max_fds)
			break;
		set = fdt->close_on_exec->fds_bits[j];
		if (!set)
			continue;
		fdt->close_on_exec->fds_bits[j] = 0;
		spin_unlock(&files->file_lock);
		for ( ; set ; i++,set >>= 1) {
			if (set & 1) {
				close_fd_from_task(task, i);
			}
		}
		spin_lock(&files->file_lock);
	}
	spin_unlock(&files->file_lock);
}

int flush_old_exec_from_task(struct task_struct *task)
{
	int retval;

	retval = de_thread(task);
	if(retval)
		goto out;

	ethread_notify_execve(task);

	task->sas_ss_sp = task->sas_ss_size = 0;

	if (task->cred->euid == task->cred->uid && task->cred->egid == task->cred->gid)
		set_dumpable(current->mm, 1);
	else
		set_dumpable(current->mm, 0);

	task->flags &= ~PF_RANDOMIZE;
	flush_thread_from_task(task);

	/* Set the new mm task size. We have to do that late because it may
	 * depend on TIF_32BIT which is only updated in flush_thread() on
	 * some architectures like powerpc
	 */
	task->mm->task_size = 0x80000000;

	task->self_exec_id++;

	flush_signal_handlers_from_task(task, 0);
	flush_old_files_from_task(task);

	return 0;
out:
	return retval;
}
#endif /* CONFIG_UNIFIED_KERNEL */
