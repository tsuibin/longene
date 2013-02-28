/*
 * file.h
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
 * file.h:
 * Refered to Wine code
 */

#ifndef _WINESERVER_FILE_H
#define _WINESERVER_FILE_H 

#include "object.h"
#include "protocol.h"

#ifdef CONFIG_UNIFIED_KERNEL
struct fd;
struct async_queue;
struct async;

/* operations valid on file descriptor objects */
struct fd_ops
{
	/* get the events we want to poll() for on this object */
	int  (*get_poll_events)(struct fd *);
	/* a poll() event occurred */
	void (*poll_event)(struct fd *,int event);
	/* flush the object buffers */
	void (*flush)(struct fd *, struct kevent **);
	/* get file information */
	enum server_fd_type (*get_fd_type)(struct fd *fd);
	/* is this file's fd removable */
	int (*removable)(struct fd *fd);
	/* perform an ioctl on the file */
	obj_handle_t (*ioctl)(struct fd *fd, ioctl_code_t code, const async_data_t *async,
			const void *data, data_size_t size);
	/* queue an async operation */
	void (*queue_async)(struct fd *, const async_data_t *data, int type, int count);
	/* an async request changed state (or being destroyed) */
	void (*async_event)(struct fd *, struct async_queue *queue, struct async *async, int status, int finished);
	/* an async request was terminated, called before user apc */
	int (*async_terminated)(struct fd *, struct async_queue *queue, struct async *async, int status);
	/* cancel an async operation */
	void (*cancel_async)(struct fd *, struct w32process *process, struct w32thread *thread, unsigned __int64 iosb);
};

/* file descriptor functions */

extern struct fd *alloc_pseudo_fd(const struct fd_ops *fd_user_ops, struct object *user,
				unsigned int options);
extern void set_no_fd_status(struct fd *fd, unsigned int status);
extern struct fd *open_fd(const char *name, int flags, mode_t *mode, unsigned int access,
				unsigned int sharing, unsigned int options);
extern void *get_fd_user(struct fd *fd);
extern void set_fd_user(struct fd *fd, const struct fd_ops *ops, struct object *user);
extern unsigned int get_fd_options(struct fd *fd);
extern int is_same_file_fd(struct fd *fd1, struct fd *fd2);
extern int is_fd_removable(struct fd *fd);
extern int fd_close_handle(struct object *obj, struct w32process *process, obj_handle_t handle);
extern int check_fd_events(struct fd *fd, int events);
extern void set_fd_events(struct fd *fd, int events);
extern obj_handle_t lock_fd(struct fd *fd, file_pos_t offset, file_pos_t count, int shared, int wait);
extern void unlock_fd(struct fd *fd, file_pos_t offset, file_pos_t count);
extern void set_fd_signaled(struct fd *fd, int signaled);

extern int default_fd_removable(struct fd *fd);
extern int default_fd_signaled(struct object *obj, struct w32thread *thread);
extern int default_fd_get_poll_events(struct fd *fd);
extern void default_poll_event(struct fd *fd, int event);
extern struct async *fd_queue_async(struct fd *fd, const async_data_t *data, int type, int count);
extern void fd_async_wake_up(struct fd *fd, int type, unsigned int status);
extern void fd_async_event(struct fd *fd, struct async_queue *queue, struct async *async, int status, int finished);
extern int fd_async_terminated(struct fd *fd, struct async_queue *queue, struct async *async, int status);
extern obj_handle_t default_fd_ioctl(struct fd *fd, ioctl_code_t code, const async_data_t *async,
                                      const void *data, data_size_t size);
extern void default_fd_queue_async(struct fd *fd, const async_data_t *data, int type, int count);
extern void default_fd_async_event(struct fd *fd, struct async_queue *queue, struct async *async, int status, int finished);
extern int default_fd_async_terminated(struct fd *fd, struct async_queue *queue, struct async *async, int status);
extern void default_fd_cancel_async(struct fd *fd, struct w32process *process, struct w32thread *thread, unsigned __int64 iosb);
extern void no_flush(struct fd *fd, struct kevent **event);
extern void main_loop(void);
extern void remove_process_locks(struct w32process *process);

static inline struct fd *get_obj_fd(struct object *obj)
{ 
	return BODY_TO_HEADER(obj)->ops ? BODY_TO_HEADER(obj)->ops->get_fd(obj) : NULL; 
}

/* timeout functions */

struct timeout_user;

#define TICKS_PER_SEC 10000000
#define TICKS_1601_TO_1970	((timeout_t)86400 * (369 * 365 + 89) * TICKS_PER_SEC)

typedef void (*timeout_callback)(void *private);

extern struct timeout_user *add_timeout_user(timeout_t when, timeout_callback func, void *private);
extern void remove_timeout_user(struct timeout_user *user);
extern const char *get_timeout_str(timeout_t timeout);
extern int get_next_timeout(void);

extern struct timer_list *add_linux_timer(timeout_t when, timeout_callback func, void *private);
extern void remove_linux_timer(struct timer_list *timer);

/* file functions */
struct uk_file;

extern struct uk_file *get_file_obj(struct w32process *process, obj_handle_t handle, unsigned int access);
extern int get_file_unix_fd(struct uk_file *file);
extern int grow_file(struct uk_file *file, file_pos_t size);

/* change notification functions */

extern void do_change_notify(int unix_fd);
extern void sigio_callback(void);
extern struct object *create_dir_obj(struct fd *fd);

/* serial port functions */

extern int is_serial_fd(struct fd *fd);
extern struct object *create_serial(struct fd *fd);

/* async I/O functions */
extern struct async_queue *create_async_queue(struct fd *fd);
extern void free_async_queue(struct async_queue *queue);
extern struct async *create_async(struct w32thread *thread, struct async_queue *queue,
                                   const async_data_t *data);
extern void async_set_timeout(struct async *async, timeout_t timeout, unsigned int status);
extern int async_queued(struct async_queue *queue);
extern int async_waiting(struct async_queue *queue);
extern void async_terminate(struct async *async, unsigned int status);
extern int async_wake_up_by(struct async_queue *queue, struct w32process *process,
							struct w32thread *thread, unsigned __int64 iosb, unsigned int status);
extern void async_wake_up(struct async_queue *queue, unsigned int status);

extern struct uk_completion *fd_get_completion(struct fd *fd, unsigned long *p_key);
extern void fd_copy_completion(struct fd *src, struct fd *dst);
/* access rights that require Unix read permission */
#define FILE_UNIX_READ_ACCESS (FILE_READ_DATA|FILE_READ_ATTRIBUTES|FILE_READ_EA)

/* access rights that require Unix write permission */
#define FILE_UNIX_WRITE_ACCESS (FILE_WRITE_DATA|FILE_WRITE_ATTRIBUTES|FILE_WRITE_EA)


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

#endif /* CONFIG_UNIFIED_KERNEL */
#endif /* _WINESERVER_FILE_H */
