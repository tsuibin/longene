/*
 * lib.h
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
 * lib.h:
 * Refered to Wine code
 */

#ifndef _WINESERVER_UK_LIB_H
#define _WINESERVER_UK_LIB_H
#include <linux/mm.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/vmalloc.h>
#include <linux/ctype.h>
#include <linux/string.h>
#include <linux/statfs.h>

#include "win32.h"
#include "w32syscall.h"
#include "event.h"

#include "server.h"
#include "request.h"
#include "thread.h"
#include "winerror.h"
#include "object.h"
#include "objwait.h"
#include "user.h"
#include "file.h"
#include "wcstr.h"

#ifdef CONFIG_UNIFIED_KERNEL
#define	errno	get_error()

timeout_t get_current_time(void);
#define current_time get_current_time() 

struct LIBC_FILE
{
	struct file *filp;
	loff_t pos;
	char *buf;
	long buflen;
	long bufpos;
	ssize_t validlen;
};

time_t time(void* v);

#define MAXSIZE_ALLOC (128 * 1024)

void *malloc(size_t size);
void* calloc(size_t nmemb, size_t size);
void *mem_alloc(size_t size);
void *memdup(const void *data, size_t len);
void free(void* p);
void *realloc(void *ptr, size_t new_size, size_t old_size);

WCHAR toupperW(WCHAR ch);
WCHAR tolowerW(WCHAR ch);
int memicmpW(const WCHAR *str1, const WCHAR *str2, int n);

void no_flush(struct fd *fd, struct kevent **event);
int no_add_queue(struct object *obj, struct wait_queue_entry *entry);
int no_close_handle(struct object *o, struct w32process *p, obj_handle_t h);
struct object *no_lookup_name(struct object *obj, struct unicode_str *name, unsigned int attributes);
struct fd *no_get_fd(struct object *obj);
struct object *no_open_file(struct object *o, unsigned int d , unsigned int i , unsigned int u);
int no_satisfied(struct object *obj, struct w32thread *thread);
int no_signal(struct object *obj, unsigned int access);
unsigned int no_map_access(struct object *obj, unsigned int access);

void dump_object_name(struct object *obj);

HANDLE duplicate_handle(HANDLE src, HANDLE src_handle, HANDLE dst,
		unsigned int access, unsigned int attr, unsigned int options);

#define HANDLE_FLAG_INHERIT             0x00000001

#define HANDLE_FLAG_PROTECT_FROM_CLOSE  0x00000002

/* reserved handle access rights */

#define RESERVED_SHIFT         26

#define RESERVED_INHERIT       (HANDLE_FLAG_INHERIT << RESERVED_SHIFT)

#define RESERVED_CLOSE_PROTECT (HANDLE_FLAG_PROTECT_FROM_CLOSE << RESERVED_SHIFT)

#define RESERVED_ALL           (RESERVED_INHERIT | RESERVED_CLOSE_PROTECT)

unsigned int get_handle_access(struct eprocess *process, HANDLE handle);

int close_handle(struct eprocess *process, HANDLE handle);

extern long close(unsigned int fd);
extern ssize_t filp_write(struct file *filp, void *buf, size_t size);
extern long fcntl(unsigned int fd, int cmd, unsigned long arg /* struct flock *flock */);
extern long dup(unsigned int fd);
extern long dup2(unsigned int oldfd, unsigned int newfd);

extern ssize_t filp_pread(struct file *filp, char *buf, size_t count, off_t pos);
extern ssize_t filp_pwrite(struct file *filp, const char *buf, size_t count, off_t pos);
extern long readlink(const char *path, char *buf, size_t bufsiz);
extern long stat(char *filename, struct stat *st);
extern long poll(struct pollfd *pfds, unsigned int nfds, long timeout_msecs);

/* fd */
void remove_timeout_user(struct timeout_user *user);

/* FIXME fd not implemented */
struct fd *create_anonymous_fd(const struct fd_ops *fd_user_ops,
		int unix_fd, struct object *user, unsigned int options);
void *get_fd_user(struct fd *fd);
int get_unix_fd(struct fd *fd);

/* winstation */
obj_handle_t find_inherited_handle(struct w32process *process, const struct object_ops *ops);
void cleanup_clipboard_thread(struct w32thread *thread);
void msg_queue_dump(struct object *obj, int verbose);
/* console */
void kill_console_processes(struct w32thread *renderer, int exit_code);

void get_req_path(struct unicode_str *str, int skip_root);

/* add by solaris 2008/06/23 */
int vsnprintfW(WCHAR *str, size_t len, const WCHAR *format, va_list valist);

int vsprintfW(WCHAR *str, const WCHAR *format, va_list valist);

int snprintfW(WCHAR *str, size_t len, const WCHAR *format, ...);

extern int sprintfW(WCHAR *str, const WCHAR *format, ...);

extern void *fgets(void *buf, int len, struct LIBC_FILE *fp);


extern long fclose(struct LIBC_FILE* fp);

extern struct LIBC_FILE *libc_file_open(struct file *filp, char *readwrite) ;

extern void perror(const char *s);
extern int fprintf(struct LIBC_FILE *fp , char *fmt, ...);
extern ssize_t fwrite(struct LIBC_FILE *fp, void *buf, size_t size);

extern long fstat(unsigned int fd, struct stat *st);
extern void unlink(const char *filename);
extern int rename(const char *oldpath, const char *newpath);
extern ssize_t read(unsigned int fd, void *buf, size_t size);
extern long mkdir(const char *name, int mode);
extern long socket(int family, int type, int protocol);
extern long socketpair(int family, int type, int protocol, int *sockvec);
extern long accept(int fd, struct sockaddr *peer_sockaddr, int *peer_addrlen);
extern long recv(int fd, void *buf, size_t size, unsigned flags);
extern long getsockopt(int fd, int level, int optname, void *optval, unsigned int *optlen);
extern int setsockopt(int fd, int level, int optname, const void *optval, int optlen);
extern long shutdown(int fd, int how);

extern POBJECT_TYPE event_object_type;

static inline void set_error(unsigned int e)
{
	struct w32thread	*w32thread = get_current_w32thread();

	if (w32thread)
		w32thread->error = e;
}

static inline unsigned int get_error(void)
{
	struct w32thread	*w32thread = get_current_w32thread();

	return w32thread ? w32thread->error : 0;
}

static inline void clear_error(void)
{
	set_error(STATUS_SUCCESS);
}

static inline pid_t getpid(void)
{
	return current->tgid;
}

static inline char *strdup(const char *src)
{
	char	*ret;

	ret = kstrdup(src, GFP_KERNEL);
	if (!ret)
		set_error(STATUS_NO_MEMORY);

	return ret;
}

static inline void *get_req_data(void)
{
	return get_current_w32thread() ? get_current_w32thread()->req_data : NULL;
}

static inline unsigned int get_req_data_size(void)
{
	return get_current_w32thread() ? get_current_w32thread()->req.request_header.request_size : 0;
}

static inline unsigned int get_reply_max_size(void)
{
	return get_current_w32thread() ? get_current_w32thread()->req.request_header.reply_size : 0;
}

static inline void set_reply_data_ptr(void *data, unsigned int size)
{
	struct w32thread *thread = get_current_w32thread();

	if (!thread)
		return;

	if (size <= get_reply_max_size()) {
		thread->reply_size = size;
		thread->reply_data = data;
	} else
		kdebug("size large err\n"); /* TODO */
}

static inline void *set_reply_data_size(int size)
{
	struct w32thread *thread = get_current_w32thread();

	if (!thread)
		return NULL;

	if (size <= get_reply_max_size()) {
		if (size && !(thread->reply_data = mem_alloc(size)))
			size = 0;
		thread->reply_size = size;
		return thread->reply_data;

	} else {
		kdebug("size large err\n"); /* TODO */
		return NULL;
	}
}

static inline void *set_reply_data(const void *data, unsigned int size)
{
	void *ret = set_reply_data_size(size);

	if (ret)
		memcpy(ret, data, size);

	return ret;
}

static inline void get_req_unicode_str(struct unicode_str *s)
{
	s->str = get_req_data();
	s->len = (get_req_data_size() / sizeof(WCHAR)) * sizeof(WCHAR);
}

static inline int fputc(char c, struct LIBC_FILE *f)
{
	return fprintf(f,"%c",c);;
}

static inline WCHAR *strcpyW(WCHAR *dst, const WCHAR *src)
{
	return wcscpy(dst, src);
}

static inline int strlenW(const WCHAR *str)
{
	return wcslen((PWSTR)str) / sizeof(WCHAR);
}

static inline WCHAR *memchrW(const WCHAR *ptr, WCHAR ch, size_t n)
{
	return wmemchr(ptr, ch, n);
}

#if 0
static WCHAR *memchrW(const WCHAR *ptr, WCHAR ch, size_t n)
{
	const WCHAR *end;
	for (end = ptr + n; ptr < end; ptr++) if (*ptr == ch) return (WCHAR *)(ULONG_PTR)ptr;
	return NULL;
}
#endif

static inline int strncmpW(const WCHAR *str1, const WCHAR *str2, int n)
{
	return wcsncmp(str1, str2, n);
}

static inline int isdigitW(WCHAR wc)
{
	return (wc >= '0') && (wc <= '9');
}

static inline void set_win32_error(int e)
{
	set_error(0xc0010000 | e);
}

static inline int send_thread_signal(struct ethread *thread, int sig)
{
	return send_sig_info(sig, (void *)2L, thread->et_task);
}

static inline int interlocked_xchg(int *dest, int val)
{
	int ret;

	asm volatile("lock; xchgl %0,(%1)"
			: "=r" (ret)
			: "r" (dest), "0" (val)
			: "memory");

	return ret;
}

static inline int interlocked_xchg_add(int *dest, int incr)
{
	int ret;

	asm volatile("lock; xaddl %0,(%1)"
			: "=r" (ret)
			: "r" (dest), "0" (incr)
			: "memory");

	return ret;
}

static inline struct inode *get_file_inode(struct file *file)
{
    return file->f_path.dentry->d_inode;
}

static inline loff_t get_file_size(struct file *file)
{
    return file->f_path.dentry->d_inode->i_size;
}

/* return the context flag that contains the CPU id */
static inline unsigned int get_context_cpu_flag(void)
{
    return CONTEXT_i386;
}

/* return only the context flags that correspond to system regs */
/* (system regs are the ones we can't access on the client side) */
static inline unsigned int get_context_system_regs(unsigned int flags)
{
    return flags & (CONTEXT_DEBUG_REGISTERS & ~CONTEXT_i386);
}

NTSTATUS errno2ntstatus(int error);

enum
{
	SHUT_RD = 0,      /* No more receptions.  */
#define SHUT_RD     SHUT_RD
	SHUT_WR,      /* No more transmissions.  */
#define SHUT_WR     SHUT_WR
	SHUT_RDWR     /* No more receptions or transmissions.  */
#define SHUT_RDWR   SHUT_RDWR
};

#endif /* CONFIG_UNIFIED_KERNEL */
#endif /* _WINESERVER_UK_LIB_H */
