/*
 * file.c
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
 * file.c:
 * Refered to Wine code
 */
#include <linux/poll.h>

#include "section.h"
#include "handle.h"

#ifdef CONFIG_UNIFIED_KERNEL

#define FILE_READ_DATA            0x0001    /* file & pipe */
#define FILE_LIST_DIRECTORY       0x0001    /* directory */
#define FILE_WRITE_DATA           0x0002    /* file & pipe */
#define FILE_ADD_FILE             0x0002    /* directory */
#define FILE_APPEND_DATA          0x0004    /* file */
#define FILE_ADD_SUBDIRECTORY     0x0004    /* directory */
#define FILE_CREATE_PIPE_INSTANCE 0x0004    /* named pipe */
#define FILE_READ_EA              0x0008    /* file & directory */
#define FILE_READ_PROPERTIES      FILE_READ_EA
#define FILE_WRITE_EA             0x0010    /* file & directory */
#define FILE_WRITE_PROPERTIES     FILE_WRITE_EA
#define FILE_EXECUTE              0x0020    /* file */
#define FILE_TRAVERSE             0x0020    /* directory */
#define FILE_DELETE_CHILD         0x0040    /* directory */
#define FILE_READ_ATTRIBUTES      0x0080    /* all */
#define FILE_WRITE_ATTRIBUTES     0x0100    /* all */
#define FILE_ALL_ACCESS           (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x1ff)

#define FILE_GENERIC_READ         (STANDARD_RIGHTS_READ | FILE_READ_DATA | \
		FILE_READ_ATTRIBUTES | FILE_READ_EA | \
		SYNCHRONIZE)
#define FILE_GENERIC_WRITE        (STANDARD_RIGHTS_WRITE | FILE_WRITE_DATA | \
		FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | \
		FILE_APPEND_DATA | SYNCHRONIZE)
#define FILE_GENERIC_EXECUTE      (STANDARD_RIGHTS_EXECUTE | FILE_EXECUTE | \
		FILE_READ_ATTRIBUTES | SYNCHRONIZE)

struct uk_file
{
	struct object       obj;        /* object header */
	struct fd          *fd;         /* file descriptor for this file */
	unsigned int        access;     /* file access (FILE_READ_DATA etc.) */
	mode_t              mode;       /* file stat.st_mode */
	uid_t               uid;        /* file stat.st_uid */
};

static unsigned int generic_file_map_access(unsigned int access);

static void file_dump(struct object *obj, int verbose);
static struct fd *file_get_fd(struct object *obj);
static void file_destroy(struct object *obj);

static int file_get_poll_events(struct fd *fd);
static void file_flush(struct fd *fd, struct kevent **event);
static enum server_fd_type file_get_fd_type(struct fd *fd);

extern unsigned int default_fd_map_access(struct object *obj, unsigned int access);
extern int objattr_is_valid(const struct object_attributes *, int);

static const struct object_ops file_ops =
{
	sizeof(struct uk_file),       /* size */
	file_dump,                    /* dump */
	no_get_type,                  /* get_type */
	file_get_fd,                  /* get_fd */
	default_fd_map_access,        /* map_access */
	no_lookup_name,               /* lookup_name */
	no_open_file,                 /* open_file */
	fd_close_handle,              /* close_handle */
	file_destroy,                 /* destroy */

	default_fd_signaled,       /* signaled */
	no_satisfied,              /* satisfied */
	no_signal,                 /* signal */
	default_get_sd,            /* get_sd */
	default_set_sd             /* set_sd */
};

static const struct fd_ops file_fd_ops =
{
	file_get_poll_events,         /* get_poll_events */
	default_poll_event,           /* poll_event */
	file_flush,                   /* flush */
	file_get_fd_type,             /* get_fd_type */
	default_fd_removable,         /* removable */
	default_fd_ioctl,             /* ioctl */
	default_fd_queue_async,       /* queue_async */
	default_fd_async_event,       /* async_event */
	default_fd_async_terminated,  /* async_terminated */
	default_fd_cancel_async       /* cancel_async */
};

/* flags for NtCreateFile and NtOpenFile */
#define FILE_DIRECTORY_FILE             0x00000001
#define FILE_WRITE_THROUGH              0x00000002
#define FILE_SEQUENTIAL_ONLY            0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING  0x00000008
#define FILE_SYNCHRONOUS_IO_ALERT       0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT    0x00000020
#define FILE_NON_DIRECTORY_FILE         0x00000040
#define FILE_CREATE_TREE_CONNECTION     0x00000080
#define FILE_COMPLETE_IF_OPLOCKED       0x00000100
#define FILE_NO_EA_KNOWLEDGE            0x00000200
#define FILE_OPEN_FOR_RECOVERY          0x00000400
#define FILE_RANDOM_ACCESS              0x00000800
#define FILE_DELETE_ON_CLOSE            0x00001000
#define FILE_OPEN_BY_FILE_ID            0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT     0x00004000
#define FILE_NO_COMPRESSION             0x00008000
#define FILE_RESERVE_OPFILTER           0x00100000
#define FILE_TRANSACTED_MODE            0x00200000
#define FILE_OPEN_OFFLINE_FILE          0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY  0x00800000

#define FILE_ATTRIBUTE_VALID_FLAGS      0x00007fb7
#define FILE_ATTRIBUTE_VALID_SET_FLAGS  0x000031a7

/* disposition for NtCreateFile */
#define FILE_SUPERSEDE                  0

extern struct fd *create_anon_fd_for_filp(const struct fd_ops *fd_user_ops,
		struct file *filp, struct object *user, unsigned int options);
extern struct file *get_unix_file(struct fd *fd);

static inline int is_overlapped(const struct uk_file *file)
{
	return !(get_fd_options(file->fd) & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT));
}

/* create a file from a file struct */
/* if the function fails the fd is closed */
static struct uk_file *create_file_for_filp(struct file *filp, unsigned int access, unsigned int sharing)
{
	struct uk_file *file;

	if ((file = alloc_wine_object(&file_ops))) {
		INIT_DISP_HEADER(&file->obj.header, _FILE, sizeof(struct uk_file) / sizeof(ULONG), 0);
		file->mode = filp->f_path.dentry->d_inode->i_mode;
		file->access = default_fd_map_access(&file->obj, access);
		if (!(file->fd = create_anon_fd_for_filp(&file_fd_ops, filp,
						&file->obj, FILE_SYNCHRONOUS_IO_NONALERT))) {
			release_object(file);
			return NULL;
		}
	}
	return file;
}

static struct object *create_file_obj(struct fd *fd, unsigned int access, mode_t mode)
{
	struct uk_file *file = alloc_wine_object(&file_ops);

	if (!file)
		return NULL;
	INIT_DISP_HEADER(&file->obj.header, _FILE, sizeof(struct uk_file) / sizeof(ULONG), 0);
	file->access  = access;
	file->mode    = mode;
	file->fd      = fd;
	grab_object(fd);
	set_fd_user(fd, &file_fd_ops, &file->obj);
	return &file->obj;
}

static struct object *create_file(const char *nameptr, data_size_t len, unsigned int access,
		unsigned int sharing, int create, unsigned int options,
		unsigned int attrs, const struct security_descriptor *sd)
{
	struct object *obj = NULL;
	struct fd *fd;
	int flags;
	char *name;
	mode_t mode;

	ktrace("name=%s\n", nameptr);
	if (!(name = mem_alloc(len + 1)))
		return NULL;
	memcpy(name, nameptr, len);
	name[len] = 0;

	switch(create) {
		case FILE_CREATE:       flags = O_CREAT | O_EXCL; break;
		case FILE_OVERWRITE_IF: /* FIXME: the difference is whether we trash existing attr or not */
		case FILE_SUPERSEDE:    flags = O_CREAT | O_TRUNC; break;
		case FILE_OPEN:         flags = 0; break;
		case FILE_OPEN_IF:      flags = O_CREAT; break;
		case FILE_OVERWRITE:    flags = O_TRUNC; break;
		default:                set_error(STATUS_INVALID_PARAMETER); goto done;
	}

	if (sd) {
#if 0
		const SID *owner = sd_get_owner(sd);
		if (!owner)
			owner = token_get_user(get_current_w32process()->token);
		mode = sd_to_mode(sd, owner);
#endif
	}
	else
		mode = (attrs & FILE_ATTRIBUTE_READONLY) ? 0444 : 0666;

	if (len >= 4 &&
			(!strcasecmp(name + len - 4, ".exe") || !strcasecmp(name + len - 4, ".com"))) {
		if (mode & S_IRUSR)
			mode |= S_IXUSR;
		if (mode & S_IRGRP)
			mode |= S_IXGRP;
		if (mode & S_IROTH)
			mode |= S_IXOTH;
	}

	access = generic_file_map_access(access);

	/* FIXME: should set error to STATUS_OBJECT_NAME_COLLISION if file existed before */
	fd = open_fd(name, flags | O_NONBLOCK | O_LARGEFILE, &mode, access, sharing, options);
	if (!fd)
		goto done;

	if (S_ISDIR(mode))
		obj = create_dir_obj(fd);
	else if (S_ISCHR(mode) && is_serial_fd(fd))
		obj = create_serial(fd);
	else
		obj = create_file_obj(fd, access, mode);

	release_object(fd);

done:
	free(name);
	return obj;
}

/* check if two file objects point to the same file */
int is_same_file(struct uk_file *file1, struct uk_file *file2)
{
	return is_same_file_fd(file1->fd, file2->fd);
}

/* create a temp file for anonymous mappings */
struct uk_file *create_temp_file(int access)
{
	static char prefixfn[] = "anonmap.";
	char tmpfn[16], *p;
	struct file *filp;
	struct uk_file *ret;
	int value = current->tgid;

	memcpy(tmpfn, prefixfn, sizeof(prefixfn) - 1);
	p = tmpfn + sizeof(prefixfn) - 1;
	do {
		struct timespec ts;

		getnstimeofday(&ts);
		value += 7777777;
		sprintf(p, "%07lx", (ts.tv_nsec + value) / 100);
		filp = filp_open((const char *)tmpfn, O_RDWR | O_CREAT | O_EXCL, 0600);
	} while (PTR_ERR(filp) == -EEXIST);
	if (IS_ERR(filp)) {
		set_error(errno2ntstatus(-PTR_ERR(filp)));
		return NULL;
	}
	unlink(tmpfn);
	ret = create_file_for_filp(filp, access, 0);
	fput(filp);

	return ret;
}

static void file_dump(struct object *obj, int verbose)
{
}

static int file_get_poll_events(struct fd *fd)
{
	struct uk_file *file = get_fd_user(fd);
	int events = 0;

	if (file->access & FILE_UNIX_READ_ACCESS)
		events |= POLLIN;
	if (file->access & FILE_UNIX_WRITE_ACCESS)
		events |= POLLOUT;
	return events;
}

static void file_flush(struct fd *fd, struct kevent **event)
{
	struct file *file = get_unix_file(fd);
	int ret;

	if (file && (ret = vfs_fsync(file, file->f_path.dentry, 0)) < 0) {
		set_error(errno2ntstatus(-ret));
	}
}

static enum server_fd_type file_get_fd_type(struct fd *fd)
{
	struct uk_file *file = get_fd_user(fd);

	if (S_ISREG(file->mode) || S_ISBLK(file->mode))
		return FD_TYPE_FILE;
	if (S_ISDIR(file->mode))
		return FD_TYPE_DIR;
	return FD_TYPE_CHAR;
}

static struct fd *file_get_fd(struct object *obj)
{
	struct uk_file *file = (struct uk_file *)obj;
	return (struct fd *)grab_object(file->fd);
}

static unsigned int generic_file_map_access(unsigned int access)
{
	if (access & GENERIC_READ)
		access |= FILE_GENERIC_READ;
	if (access & GENERIC_WRITE)
		access |= FILE_GENERIC_WRITE;
	if (access & GENERIC_EXECUTE)
		access |= FILE_GENERIC_EXECUTE;
	if (access & GENERIC_ALL)
		access |= FILE_ALL_ACCESS;
	return access & ~(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);
}

static void file_destroy(struct object *obj)
{
	struct uk_file *file = (struct uk_file *)obj;

	if (file->fd)
		release_object(file->fd);
}

struct uk_file *get_file_obj(struct w32process *process, obj_handle_t handle, unsigned int access)
{
	return (struct uk_file *)get_wine_handle_obj(process, handle, access, &file_ops);
}

struct file *get_file_unix_file(struct uk_file *file)
{
	return get_unix_file(file->fd);
}

struct uk_file *grab_file_unless_removable(struct uk_file *file)
{
	if (is_fd_removable(file->fd))
		return NULL;
	return (struct uk_file *)grab_object(file);
}

extern long filp_truncate(struct file *file, loff_t length, int small);

/* extend a file beyond the current end of file */
static int extend_file(struct file *filp, file_pos_t new_size)
{
	int ret;
	off_t size = new_size;

	if (sizeof(new_size) > sizeof(size) && size != new_size) {
		set_error(STATUS_INVALID_PARAMETER);
		return 0;
	}

	if (!(ret = filp_truncate(filp, size, 1)))
		return 1;

	set_error(errno2ntstatus(-ret));
	return 0;
}

/* try to grow the file to the specified size */
int grow_file(struct uk_file *file, file_pos_t size)
{
	struct file *filp = get_unix_file(file->fd);

	if (!filp)
		return 0;

	if (get_file_size(filp) >= size)
		return 1;  /* already large enough */

	return extend_file(filp, size);
}

/* create a file */
DECL_HANDLER(create_file)
{
	struct object *file;
	const struct object_attributes *objattr = get_req_data();
	const struct security_descriptor *sd;
	const char *name;
	data_size_t name_len;

	ktrace("\n");
	reply->handle = 0;

	if (!objattr_is_valid(objattr, get_req_data_size()))
		return;
	/* name is transferred in the unix codepage outside of the objattr structure */
	if (objattr->name_len) {
		set_error(STATUS_INVALID_PARAMETER);
		return;
	}

	sd = objattr->sd_len ? (const struct security_descriptor *)(objattr + 1) : NULL;

	name = (const char *)get_req_data() + sizeof(*objattr) + objattr->sd_len;
	name_len = get_req_data_size() - sizeof(*objattr) - objattr->sd_len;

	reply->handle = 0;
	if ((file = create_file(name, name_len, req->access,
					req->sharing, req->create, req->options,
					req->attrs, sd))) {
		reply->handle = alloc_handle(get_current_w32process(), file, req->access, req->attributes);
		release_object(file);
	}
	ktrace("done file %p\n", file);
}

/* allocate a file handle for a Unix fd */
DECL_HANDLER(alloc_file_handle)
{
	struct uk_file *file;
	struct file *filp;

	filp = fget(req->fd);
	ktrace("fd %d, filp %p\n", req->fd, filp);

	if (!filp) {
		set_error(STATUS_INVALID_HANDLE);
		return;
	}

	reply->handle = (user_handle_t)-1;
	if ((file = create_file_for_filp(filp, req->access, FILE_SHARE_READ | FILE_SHARE_WRITE))) {
		reply->handle =(void*) alloc_handle(get_current_w32process(), file, req->access, req->attributes);
		release_object(file);
	}

	ktrace("done handle=%p\n", (void*)reply->handle);
	fput(filp);
}

/* lock a region of a file */
DECL_HANDLER(lock_file)
{
	struct uk_file *file;

	ktrace("\n");
	if ((file = get_file_obj(get_current_w32process(), req->handle, 0))) {
		reply->handle = lock_fd(file->fd, req->offset, req->count, req->shared, req->wait);
		reply->overlapped = is_overlapped(file);
		release_object(file);
	}
}

/* unlock a region of a file */
DECL_HANDLER(unlock_file)
{
	struct uk_file *file;

	ktrace("\n");
	if ((file = get_file_obj(get_current_w32process(), req->handle, 0))) {
		unlock_fd(file->fd, req->offset, req->count);
		release_object(file);
	}
}
#endif /* CONFIG_UNIFIED_KERNEL */
