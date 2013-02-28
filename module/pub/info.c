/*
 * info.c
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
 *   Dec 2008 - Created.
 */

/* 
 * info.c:
 * Refered to Wine code
 */

#include <asm/poll.h>
#include "wineserver/lib.h"

#ifdef CONFIG_UNIFIED_KERNEL

extern char *rootdir;

static unsigned int dummyfile_poll(struct file *f, struct poll_table_struct *p)
{
	if (current_thread->wake_up) {
		current_thread->wake_up = 0;
		ktrace("ret %d\n", current_thread->wake_up);
		return POLLIN;
	} else {
		ktrace("ret 0\n");
		return 0;
	}
}

/* dummy file used in NtWaitforMultipleObjects() */
const struct file_operations dummy_fops = {
	.owner      = THIS_MODULE,
	.poll       = dummyfile_poll,
};

static struct file dummyfile_dft = {
	.f_op       = &dummy_fops,
};

static struct file *dummyfile = &dummyfile_dft;

void open_dummy_file(void)
{
	struct file *filp;

	filp = filp_open("/proc/unifiedkernel/io/dummy", O_RDWR, 0);
	if (!IS_ERR(filp)) {
		dummyfile = filp;
		ktrace("dummy file opened\n");
	}
}

void close_dummy_file(void)
{
	if (dummyfile != &dummyfile_dft)
		filp_close(dummyfile, NULL);
}

void create_dummy_file(struct w32process *process)
{
	int fd;

	if (process->dummyfd != -1)
		return;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd >= 0) {
		get_file(dummyfile);
		fd_install(fd, dummyfile);
    	process->dummyfd = fd;
	}

	ktrace("process %p, dummyfd %d\n", process, process->dummyfd);
}

/* find $HOME from environment varibale and init rootdir */
void init_rootdir(void)
{
	pid_t pid;
	mm_segment_t fs;

	char filename[40];
	struct file *filp;
	char *buf;
	char home[] = "HOME";
	char dotwine[] = "/.wine";
	char *p = NULL;
	int i = 0;

	ktrace("rootdir init....\n");

	rootdir = (char *) malloc(sizeof(char) * 100);

	pid = current->pid;
	snprintf(filename, 40, "/proc/%d/environ", pid);   /* filename=/proc/pid/environ, environ is a environment varibale file */

	filp = filp_open(filename, O_RDONLY, 0);
	if (IS_ERR(filp)) {
		kdebug("filp_open error:%s------rootdir init fail, so fall back to /root/.wine\n", filename);
		strcpy(rootdir, "/root/.wine");
		return;
	}

	fs = get_fs();
	set_fs(KERNEL_DS);
	buf = (char *) malloc(sizeof(char) * 2048);

	while (filp->f_op->read(filp, &buf[i], 1, &(filp->f_pos)) == 1) {
		if (buf[i++] != '\0') {
			continue;     /* read a string */
		} 
		buf[i] = '\0';

		if ((p = strstr(buf, home)) != NULL) {          /* find "HOME" */
			strcpy(rootdir, (p + strlen(home) + 1));    /* copy "$HOME" */
			strcat(rootdir, dotwine);                   /* $HOME/.wine */
			ktrace("rootdir = %s \n", rootdir);
			break;
		}

		i = 0;
		memset(buf, '\0', 2048);
	}

	set_fs(fs);
	free(buf);
	filp_close(filp, NULL);
}

void free_rootdir(void)
{
	free(rootdir);
}
#endif /* CONFIG_UNIFIED_KERNEL */
