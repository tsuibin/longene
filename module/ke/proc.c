/*
 * proc.c
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
 * proc.c: proc functions
 * Refered to ReactOS code
 */
#include <linux/proc_fs.h>
#include "process.h"

#if defined(CONFIG_EXPRESS_IPC) || defined(CONFIG_UNIFIED_KERNEL)

static int uk_proc_calc_metrics(char *page, char **start,
		off_t off, int count, int *eof, int len)
{
	if (len <= off+count)
		*eof = 1;
	*start = page + off;
	len -= off;
	if (len > count)
		len = count;
	if (len < 0)
		len = 0;
	return len;
}

#endif


#ifdef CONFIG_EXPRESS_IPC

struct proc_vip_file {
	struct list_head entry;
	char *filename;
};

LIST_HEAD(vip_file_list);

static struct proc_dir_entry *proc_vip_dir = NULL;

extern struct dentry *proc_eipc_lookup(struct inode * dir, struct dentry *dentry, struct nameidata *nd);
extern void set_eipc(char *filename, int set);
extern int print_eipc_entry(char *filename, char *buf);
extern int add_vip_entry(char *filename);
extern int del_vip_entry(char *filename);

static int vip_read_proc(char *page, char **start,
		off_t off, int count, int *eof, void *data)
{
	int len;
	struct proc_vip_file *vip_file = (struct proc_vip_file *)data;

	len = print_eipc_entry(vip_file->filename, page);
	return uk_proc_calc_metrics(page, start, off, count, eof, len);
}

static int create_proc_vip_entry(char *filename)
{
	struct proc_dir_entry *proc_vip_entry;
	struct proc_vip_file *vip_file;

	vip_file = (struct proc_vip_file *)kmalloc(sizeof(*vip_file), GFP_KERNEL);
	if (!vip_file)
		return -ENOMEM;
	vip_file->filename = filename;
	list_add_tail(&vip_file->entry, &vip_file_list);

	proc_vip_entry = create_proc_read_entry(filename, 0, proc_vip_dir, vip_read_proc, vip_file);
	if (!proc_vip_entry)
		return -ENOMEM;

	proc_vip_entry->owner = THIS_MODULE;

	return 0;
}

static int proc_vip_create(struct inode *ip, struct dentry *dp, int mode, struct nameidata *nd)
{
	int ret = create_proc_vip_entry((char *)dp->d_name.name);

	if (!ret) {
		add_vip_entry((char *)dp->d_name.name);
		set_eipc((char *)dp->d_name.name, 1);
	}
	return ret;
}

static int proc_vip_unlink(struct inode *ip, struct dentry *dp)
{
	struct proc_dir_entry *pde = PDE(ip);
	struct proc_vip_file *vip_file;

	vip_file = (struct proc_vip_file *)pde->data;
	list_del(&vip_file->entry);

	set_eipc((char *)dp->d_name.name, 0);
	del_vip_entry((char *)dp->d_name.name);
	remove_proc_entry(dp->d_name.name, proc_vip_dir);

	return 0;
}

static struct inode_operations proc_vip_inode_operations = {
	.create		= proc_vip_create,
	.lookup		= proc_eipc_lookup,
	.unlink		= proc_vip_unlink
};

int proc_vip_init(void)
{
	proc_vip_dir = proc_mkdir_mode("eipc", S_IALLUGO, NULL);  /* create "/proc/eipc" */
	if (!proc_vip_dir)
		return -ENOMEM;
	proc_vip_dir->owner = THIS_MODULE;
	proc_vip_dir->proc_iops = &proc_vip_inode_operations;

	return 0;
}

void proc_vip_exit(void)
{
	struct list_head *pos;
	struct proc_vip_file *vip_file;

	if (proc_vip_dir) {
		if (!list_empty_careful(&vip_file_list)) {
			pos = vip_file_list.next;
			list_del(pos);
			vip_file = list_entry(pos, struct proc_vip_file, entry);
			remove_proc_entry(vip_file->filename, proc_vip_dir);
		}
		remove_proc_entry("eipc", NULL);
	}
}

#endif /* CONFIG_EXPRESS_IPC */

#ifdef CONFIG_UNIFIED_KERNEL

static struct proc_dir_entry *proc_uk = NULL;
static struct proc_dir_entry *proc_uk_io = NULL;
static struct proc_dir_entry *proc_uk_mm = NULL;

/* built-in so path */
extern char builtin_dll_path[MAX_PATH];
/* built-in so path */

extern size_t print_dosdriver(char *buf);
extern int parse_dosdriver(char *buf, size_t count, int append);

static int dosdriver_read_proc(char *page, char **start,
		off_t off, int count, int *eof, void *data)
{
	int len;

	len = print_dosdriver(page);
	return uk_proc_calc_metrics(page, start, off, count, eof, len);
}

static int dosdriver_write_proc(struct file *file, const char __user *buf, unsigned long count, void *data)
{
	int	append;
	int	ret = count;
	char	*page;

	if (count > PAGE_SIZE)
		return -EINVAL;

	page = (char *)__get_free_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	if (copy_from_user(page, buf, count)) {
		ret = -EFAULT;
		goto out;
	}

	append = file->f_flags & O_APPEND;
	parse_dosdriver(page, count, append);

out:
	free_page((unsigned long)page);
	return ret;
}

/* built-in so path */
static int builtin_dll_read_proc(char *page, char **start,
		off_t off, int count, int *eof, void *data)
{
	int len = strlen(builtin_dll_path);
	char ent[] = {'\n', 0};
	
	memcpy(page, builtin_dll_path, len);
	memcpy(page + len, ent, strlen(ent));
	return uk_proc_calc_metrics(page, start, off, count, eof, len + 1);
}

static int builtin_dll_write_proc(struct file *file, const char __user *buf, unsigned long count, void *data)
{
	int	ret = count;
	char	*page;

	if (count > MAX_PATH)
		return -EINVAL;

	page = (char *)__get_free_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	if (copy_from_user(page, buf, count)) {
		ret = -EFAULT;
		goto out;
	}

	memcpy(builtin_dll_path, page, count);
out:
	free_page((unsigned long)page);
	return ret;
}
/* built-in so path */

extern const struct file_operations dummy_fops;

int proc_uk_init(void)
{
	struct proc_dir_entry	*dummyfile_entry;
	struct proc_dir_entry	*dosdriver_entry;
	/* built-in so path */
	struct proc_dir_entry	*builtin_dll_entry;
	/* built-in so path */

	proc_uk = proc_mkdir("unifiedkernel", NULL);  /* create "/proc/unifiedkernel" */
	if (!proc_uk)
		goto out;

	proc_uk_io = proc_mkdir("unifiedkernel/io", NULL);
	if (!proc_uk_io)
		goto out_free_proc_uk;

	proc_uk_mm = proc_mkdir("unifiedkernel/mm", NULL);
	if (!proc_uk_mm)
		goto out_free_proc_uk_io;

	dosdriver_entry = create_proc_entry("dosdriver", S_IRUSR | S_IWUSR, proc_uk_io);
	if (!dosdriver_entry)
		goto out_free_proc_uk_mm;
	dosdriver_entry->read_proc = dosdriver_read_proc;
	dosdriver_entry->write_proc = dosdriver_write_proc;

	/* built-in so path */
	builtin_dll_entry = create_proc_entry("builtin_dll", S_IRUSR | S_IWUSR, proc_uk);
	if (!builtin_dll_entry)
		goto out_free_dosdriver;
	builtin_dll_entry->read_proc = builtin_dll_read_proc;
	builtin_dll_entry->write_proc = builtin_dll_write_proc;
	/* built-in so path */

	dummyfile_entry = create_proc_entry("dummy", S_IRUSR | S_IWUSR, proc_uk_io);
	if (!dummyfile_entry) {
		remove_proc_entry("dummy", proc_uk_io);
		goto out_free_dosdriver;
	}
	dummyfile_entry->proc_fops = &dummy_fops;
	return 0;

out_free_dosdriver:
	remove_proc_entry("dosdriver", proc_uk_io);
out_free_proc_uk_mm:
	remove_proc_entry("unifiedkernel/mm", NULL);
out_free_proc_uk_io:
	remove_proc_entry("unifiedkernel/io", NULL);
out_free_proc_uk:
	remove_proc_entry("unifiedkernel", NULL);
out:
	return -ENOMEM;
}

void proc_uk_exit(void)
{
	if (proc_uk_io) {
		remove_proc_entry("dosdriver", proc_uk_io);
		remove_proc_entry("dummy", proc_uk_io);
		remove_proc_entry("unifiedkernel/io", NULL);
	}

	if (proc_uk_mm)
		remove_proc_entry("unifiedkernel/mm", NULL);

	if (proc_uk) {
		/* built-in so path */
		remove_proc_entry("builtin_dll", proc_uk);
		/* built-in so path */
		remove_proc_entry("unifiedkernel", NULL);
	}
}

#endif /* CONFIG_UNIFIED_KERNEL */
