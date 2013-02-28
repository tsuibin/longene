/*
 * datasection.c
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
 * datasection.c: data section handling implementation
 */
#include <linux/mm.h>
#include "section.h"
#include "virtual.h"

#ifdef CONFIG_UNIFIED_KERNEL

extern int unistr2charstr(PWSTR unistr, LPCSTR chstr);

static int data_section_map(struct task_struct *tsk, struct win32_section *,
		unsigned long *, unsigned long, unsigned long, unsigned long);

/*
 * setup a data section
 * - if not map a file, creates a file in the shmem filesystem
 */
int data_section_setup(struct win32_section *ws)
{
	char	*name, prefix[] = "win32_";

	/* set the mmap function */
	ws->ws_mmap = data_section_map;
	ws->ws_sections = NULL;

	if (!ws->ws_wfile) {
		int	prefix_len = sizeof(prefix);
		PUNICODE_STRING	obj_name;

		obj_name = &(HEADER_TO_OBJECT_NAME(BODY_TO_HEADER((PVOID)ws))->Name);

		/* determine the name to use for the SHMEM file */

		name = (char *)kmalloc(obj_name->MaximumLength + prefix_len, GFP_KERNEL);
		if (!name)
			return STATUS_NO_MEMORY;

		memcpy(name, prefix, prefix_len - 1);
		unistr2charstr((PWSTR)obj_name->Buffer, name + prefix_len - 1);

		/* create a SHMEM file */
		ws->ws_file = shmem_file_setup(name, ws->ws_len, 0);
		if (IS_ERR(ws->ws_file)) {
			kfree(name);
			return PTR_ERR(ws->ws_file);
		}

		kfree(name);
	}
	else
		ws->ws_file = ws->ws_wfile->wf_file;
	return 0;
} /* end data_section_setup */
EXPORT_SYMBOL(data_section_setup);

/*
 * map a data section
 * mapped address is returned from addr
 */
static int data_section_map(struct task_struct *tsk, struct win32_section *ws,
		unsigned long *addr, unsigned long len, unsigned long flags, unsigned long offset)
{
	struct file	*file = ws->ws_file;
	unsigned long	ret;

	ret = win32_do_mmap_pgoff(tsk, file, *addr, len, ws->ws_protect, flags, offset);

	if (IS_ERR((void *)ret))
		return (int)ret;

	*addr = ret;
	return 0;
} /* end data_section_map */

#endif /* CONFIG_UNIFIED_KERNEL */
