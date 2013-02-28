/*
 * lib.c
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
 * lib.c:
 * Refered to Wine code
 */

#include "wineserver/lib.h"

#ifdef CONFIG_UNIFIED_KERNEL

#define PREPARE_KERNEL_CALL	\
	mm_segment_t oldfs; \
	oldfs = get_fs(); \
	set_fs(KERNEL_DS);
#define END_KERNEL_CALL	set_fs(oldfs);

#define DEFAULT_FILE_MODE		(0666)

timeout_t start_time;

void perror(const char *s)
{
	kdebug("%s\n", s);
	/* FIXME */
	kdebug(": %d\n", errno);
}

time_t time(void* v)
{
	return 0;
}

void *malloc(size_t size)
{
	void	*addr;

	if (size > MAXSIZE_ALLOC || !(addr = kmalloc(size, GFP_KERNEL))) {
		kdebug("kmalloc size %x err, too large\n", size);
		set_error(STATUS_NO_MEMORY);
		return NULL;
	}

	return addr;
}

void *calloc(size_t nmemb, size_t size)
{
	void	*addr;
	size_t	total = nmemb * size;

	if (total > MAXSIZE_ALLOC || !(addr = kmalloc(total, GFP_KERNEL))) {
		kdebug("kmalloc size %x err, too large\n", total);
		set_error(STATUS_NO_MEMORY);
		return NULL;
	}

	memset(addr, 0, total);

	return addr;
}

void *mem_alloc(size_t size)
{
	void	*addr = malloc(size);

	if (addr)
		memset(addr, 0x55, size);
	else
		set_error(STATUS_NO_MEMORY);

	return addr;
}

void *memdup(const void *data, size_t len)
{
	void	*ptr = malloc(len);

	if (ptr)
		memcpy(ptr, data, len);

	return ptr;
}

void free(void *p)
{
	if (p)
		kfree(p);
}

void *realloc(void *ptr, size_t new_size, size_t old_size)
{
	void	*new_ptr;

	if (!new_size) {
		free(ptr);
		return ptr;
	}

	if (!ptr)
		return malloc(new_size);

	new_ptr = malloc(new_size);
	if (new_ptr) {
		memcpy(new_ptr, ptr, new_size > old_size ? old_size : new_size);
		free(ptr);
	}

	return new_ptr;
}

WCHAR toupperW(WCHAR ch)
{
	extern const WCHAR wine_casemap_upper[];

	return ch + wine_casemap_upper[wine_casemap_upper[ch >> 8] + (ch & 0xff)];
}

WCHAR tolowerW(WCHAR ch)
{
	extern const WCHAR wine_casemap_lower[];

	return ch + wine_casemap_lower[wine_casemap_lower[ch >> 8] + (ch & 0xff)];
}

int memicmpW(const WCHAR *str1, const WCHAR *str2, int n)
{
	int ret = 0;

	for (; n > 0; n--, str1++, str2++)
		if ((ret = tolowerW(*str1) - tolowerW(*str2))) 
			break;

	return ret;
}

void no_flush(struct fd *fd, struct kevent **event)
{
	set_error(STATUS_OBJECT_TYPE_MISMATCH);
	return;
}

int no_add_queue(struct object *obj, struct wait_queue_entry *entry)
{
	set_error(STATUS_OBJECT_TYPE_MISMATCH);
	return 0;
}

int no_close_handle(struct object *o, struct w32process *p, obj_handle_t h)
{
	return 1;  /* ok to close */
}

struct object *no_lookup_name(struct object *obj, struct unicode_str *name, unsigned int attributes)
{
	return NULL;
}

struct fd *no_get_fd(struct object *obj)
{
#if 0
	set_error(STATUS_OBJECT_TYPE_MISMATCH);
#endif
	return NULL;
}

struct object *no_open_file(struct object *o, unsigned int d , unsigned int i , unsigned int u)
{
	set_error(STATUS_OBJECT_TYPE_MISMATCH);
	return NULL;
}

int no_satisfied(struct object *obj, struct w32thread *thread)
{
	return 0;  /* not abandoned */
}

int no_signal(struct object *obj, unsigned int access)
{
	set_error(STATUS_OBJECT_TYPE_MISMATCH);
	return 0;
}

unsigned int no_map_access(struct object *obj, unsigned int access)
{
	if (access & GENERIC_READ)
		access |= STANDARD_RIGHTS_READ;
	if (access & GENERIC_WRITE)
		access |= STANDARD_RIGHTS_WRITE;
	if (access & GENERIC_EXECUTE)
		access |= STANDARD_RIGHTS_EXECUTE;
	if (access & GENERIC_ALL)
		access |= STANDARD_RIGHTS_ALL;
	return access & ~(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);
}

void dump_object_name(struct object *obj)
{
}

void get_req_path(struct unicode_str *str, int skip_root)
{
	static const WCHAR root_name[] = { '\\','R','e','g','i','s','t','r','y','\\' };

	str->str = get_req_data();
	str->len = (get_req_data_size() / sizeof(WCHAR)) * sizeof(WCHAR);

	if (skip_root && str->len >= sizeof(root_name) &&
			!memicmpW(str->str, root_name, sizeof(root_name) / sizeof(WCHAR))) {
		str->str += sizeof(root_name) / sizeof(WCHAR);
		str->len -= sizeof(root_name);
	}
}

int vsnprintfW(WCHAR *str, size_t len, const WCHAR *format, va_list valist)
{
	unsigned int written = 0;
	const WCHAR *iter = format;
	char bufa[256], fmtbufa[64], *fmta;

	while (*iter) {
		while (*iter && *iter != '%') {
			if (written++ >= len)
				return -1;
			*str++ = *iter++;
		}
		if (*iter == '%') {
			if (iter[1] == '%') {
				if (written++ >= len)
					return -1;
				*str++ = '%'; /* "%%"->'%' */
				iter += 2;
				continue;
			}

			fmta = fmtbufa;
			*fmta++ = *iter++;
			while (*iter == '0' || *iter == '+' ||
					*iter == '-' || *iter == ' ' ||
					*iter == '*' || *iter == '#') {
				if (*iter == '*') {
					char *buffiter = bufa;
					int fieldlen = va_arg(valist, int);
					sprintf(buffiter, "%d", fieldlen);
					while (*buffiter)
						*fmta++ = *buffiter++;
				}
				else
					*fmta++ = *iter;
				iter++;
			}

			while (isdigitW(*iter))
				*fmta++ = *iter++;

			if (*iter == '.') {
				*fmta++ = *iter++;
				if (*iter == '*') {
					char *buffiter = bufa;
					int fieldlen = va_arg(valist, int);
					sprintf(buffiter, "%d", fieldlen);
					while (*buffiter)
						*fmta++ = *buffiter++;
				}
				else
					while (isdigitW(*iter))
						*fmta++ = *iter++;
			}
			if (*iter == 'h' || *iter == 'l')
				*fmta++ = *iter++;

			switch (*iter) {
				case 's':
					{
						static const WCHAR none[] = { '(','n','u','l','l',')',0 };
						const WCHAR *wstr = va_arg(valist, const WCHAR *);
						const WCHAR *striter = wstr ? wstr : none;
						while (*striter) {
							if (written++ >= len)
								return -1;
							*str++ = *striter++;
						}
						iter++;
						break;
					}

				case 'c':
					if (written++ >= len)
						return -1;
					*str++ = (WCHAR)va_arg(valist, int);
					iter++;
					break;

				default:
					{
						/* For non wc types, use system sprintf and append to wide char output */
						/* FIXME: for unrecognised types, should ignore % when printing */
						char *bufaiter = bufa;
						if (*iter == 'p')
							sprintf(bufaiter, "%08lX", va_arg(valist, long));
						else {
							*fmta++ = *iter;
							*fmta = '\0';
							if (*iter == 'a' || *iter == 'A' ||
									*iter == 'e' || *iter == 'E' ||
									*iter == 'f' || *iter == 'F' ||
									*iter == 'g' || *iter == 'G')
								sprintf(bufaiter, fmtbufa, va_arg(valist, double));
							else {
								sprintf(bufaiter, fmtbufa, va_arg(valist, void *));
							}
						}
						while (*bufaiter) {
							if (written++ >= len)
								return -1;
							*str++ = *bufaiter++;
						}
						iter++;
						break;
					}
			}
		}
	}
	if (written >= len)
		return -1;
	*str++ = 0;
	return (int)written;
}

int vsprintfW(WCHAR *str, const WCHAR *format, va_list valist)
{
	return vsnprintfW(str, INT_MAX, format, valist);
}

int snprintfW(WCHAR *str, size_t len, const WCHAR *format, ...)
{
	int retval;
	va_list valist;
	va_start(valist, format);
	retval = vsnprintfW(str, len, format, valist);
	va_end(valist);
	return retval;
}

int sprintfW(WCHAR *str, const WCHAR *format, ...)
{
	int retval;
	va_list valist;
	va_start(valist, format);
	retval = vsnprintfW(str, INT_MAX, format, valist);
	va_end(valist);
	return retval;
}

/* need PREPARE_KERNEL_CALL ? */
long close(unsigned int fd)
{
	long ret;

	PREPARE_KERNEL_CALL;
	if (!current->files) /* in this case, close is called after do_exit */
		ret = 0;
	else
		ret = sys_close(fd);
	END_KERNEL_CALL;

	return ret;
}

long fclose(struct LIBC_FILE *fp)
{
	int ret;
	if (fp) {
		if (fp->buf) {
			ret = filp_write(fp->filp, (fp->buf + fp->bufpos-fp->validlen), fp->validlen);
			free_pages((unsigned long)fp->buf, 1);
			fp->buf = NULL;
			fp->validlen = 0;
		}
		fput(fp->filp);

		kfree(fp);
		return 0;
	}

	return -1;
}

ssize_t read(unsigned int fd, void *buf, size_t size)
{
	ssize_t ret;

	PREPARE_KERNEL_CALL;
	ret = sys_read(fd, buf, size);
	END_KERNEL_CALL;

	return ret;
}

ssize_t filp_write(struct file *filp, void *buf, size_t size)
{
	ssize_t ret;
	loff_t pos;

	PREPARE_KERNEL_CALL;
	pos = filp->f_pos;
	ret = vfs_write(filp, buf, size, &pos);
	filp->f_pos = pos;
	END_KERNEL_CALL;

	return ret;
}

ssize_t fwrite(struct LIBC_FILE *fp, void *buf, size_t size)
{
	unsigned int ret=0;
	size_t len = size;
	int pos;

	if(fp->buf == NULL){
		fp->buf = (char *)__get_free_pages(GFP_KERNEL, 1);
		fp->buflen = PAGE_SIZE * 2;
		fp->validlen = 0;
		fp->bufpos = 0;
		if (!fp->buf) {
			set_error(STATUS_NO_MEMORY);
			perror("no memory");
			return 0;
		}
	}
	if(len < 0)
		return 0;
	pos = 0;
    	while (len > 0) {
        	if (fp->bufpos + len < PAGE_SIZE) {
            	memcpy(fp->buf + fp->bufpos, buf + pos, len);
            	fp->bufpos += len;
            	fp->validlen +=len ;
            	break;
        	}

        	if (!fp->bufpos) {
            		ret = filp_write(fp->filp, buf + pos, PAGE_SIZE);
            		if (ret != PAGE_SIZE) {
                		set_error(errno2ntstatus(-ret));
                		return ret;
            		}
            		pos += PAGE_SIZE;
            		len -= PAGE_SIZE;
        	} else {
            		memcpy(fp->buf + fp->bufpos, buf + pos, PAGE_SIZE - fp->bufpos);
            		ret = filp_write(fp->filp, fp->buf, PAGE_SIZE);
            		if (ret != PAGE_SIZE) {
                	set_error(errno2ntstatus(-ret));
                	return ret;
            		}
            		pos += PAGE_SIZE - fp->bufpos;
            		len -= PAGE_SIZE - fp->bufpos;
            		fp->bufpos = 0;
            		fp->validlen = 0;
        	}
    	}	

	return ret;
}

long dup(unsigned int fd)
{
	long ret;

	PREPARE_KERNEL_CALL;
	ret = sys_dup(fd);
	END_KERNEL_CALL;

	return ret;
}

long dup2(unsigned int oldfd, unsigned int newfd)
{
	long ret;

	PREPARE_KERNEL_CALL;
	ret = sys_dup2(oldfd, newfd);
	END_KERNEL_CALL;

	return ret;
}

int fprintf(struct LIBC_FILE *fp , char *fmt, ...)
{
	int ret;
	va_list args;
	if(fp->buf==NULL){
		fp->buf = (char *)__get_free_pages(GFP_KERNEL, 1);
		fp->buflen = PAGE_SIZE * 2;
		fp->validlen = 0;
		fp->bufpos = 0;
		if (!fp->buf) {
			set_error(STATUS_NO_MEMORY);
			perror("no memory");
			return 0;
		}
	}

	va_start(args, fmt);
	ret = vsnprintf(fp->buf+fp->bufpos, 2 * PAGE_SIZE-fp->bufpos, fmt, args);
	va_end(args);

	if (ret <= 0) {
		set_error(STATUS_INVALID_PARAMETER);
		perror("vsnprintf error");
		return ret;
	}
	fp->validlen += (long)ret;
	fp->bufpos += (long)ret;
	if(fp->validlen >= PAGE_SIZE){
		ret = filp_write(fp->filp, fp->buf, PAGE_SIZE);
		if (ret < 0){
			set_error(ret);
			return ret;
		}
		fp->validlen -= ret;
		memcpy(fp->buf, fp->buf + ret, fp->validlen);
		fp->bufpos = fp->validlen;
	}

	return ret;
}

long fstat(unsigned int fd, struct stat *st)
{
	long ret;

	PREPARE_KERNEL_CALL;
	ret = sys_newfstat(fd, st);
	END_KERNEL_CALL;

	return ret;
}

void unlink(const char *filename)
{
	PREPARE_KERNEL_CALL;
	sys_unlink(filename);
	END_KERNEL_CALL;
}

int rename(const char *oldpath, const char *newpath)
{
	int ret;

	PREPARE_KERNEL_CALL;
	ret = sys_rename(oldpath, newpath);
	END_KERNEL_CALL;

	return ret;
}

struct LIBC_FILE *libc_file_open(struct file *filp, char *readwrite)
{
	struct LIBC_FILE *ret;

	ret = (struct LIBC_FILE *)malloc(sizeof(struct LIBC_FILE));
	if (!ret) {
		perror("no memory!\n");
		return NULL;
	}

	memset(ret, 0, sizeof(struct LIBC_FILE));
	ret->filp = filp;
	ret->buf=NULL;
	ret->bufpos=0;

	return ret;
}

void *fgets(void *buf, int len, struct LIBC_FILE *fp)
{
	char *p;
	ssize_t nread;
	struct file *file;

	if (!len)
		return NULL;

	file = fp->filp;
	nread = kernel_read(file, file->f_pos, buf, (size_t)len - 1);

	if (nread <= 0)
		return NULL;

	p = memchr(buf, '\n', nread);
	if (!p) {
		*((char *)buf + nread) = 0;
		file->f_pos += nread;
	}
	else {
		*++p = 0;
		file->f_pos += ((void *)p - buf);
	}

	return buf;
}

ssize_t filp_pread(struct file *filp, char *buf, size_t count, off_t pos)
{
	ssize_t ret;
	loff_t lpos = (loff_t)pos;

	PREPARE_KERNEL_CALL;
	ret = vfs_read(filp, buf, count, &lpos);
	END_KERNEL_CALL;

	return ret;
}

ssize_t filp_pwrite(struct file *filp, const char *buf, size_t count, off_t pos)
{
	ssize_t ret;
	loff_t lpos = (loff_t)pos;

	PREPARE_KERNEL_CALL;
	ret = vfs_write(filp, buf, count, &lpos);
	END_KERNEL_CALL;

	return ret;
}

long readlink(const char *path, char *buf, size_t bufsiz)
{
	long ret;

	PREPARE_KERNEL_CALL;
	ret = sys_readlink(path, buf, bufsiz);
	END_KERNEL_CALL;

	return ret;
}

long fcntl(unsigned int fd, int cmd, unsigned long arg)
{
	long ret;

	PREPARE_KERNEL_CALL;
	ret = sys_fcntl(fd, cmd, arg);
	END_KERNEL_CALL;

	return ret;
}

long stat(char *filename, struct stat *st)
{
	long ret;

	PREPARE_KERNEL_CALL;
	ret = sys_newstat(filename, st);
	END_KERNEL_CALL;

	return ret;
}

long poll(struct pollfd *pfds, unsigned int nfds, long timeout_msecs)
{
	long ret;

	PREPARE_KERNEL_CALL;
	ret = sys_poll(pfds, nfds, timeout_msecs);
	END_KERNEL_CALL;

	return ret;
}

long socket(int family, int type, int protocol)
{
	return sys_socket(family, type, protocol);
}

long socketpair(int family, int type, int protocol, int *sockvec)
{
	long ret;

	PREPARE_KERNEL_CALL;
	ret = sys_socketpair(family, type, protocol, sockvec);
	END_KERNEL_CALL;

	return ret;
}

long accept(int fd, struct sockaddr *peer_sockaddr, int *peer_addrlen)
{
	long ret;

	PREPARE_KERNEL_CALL;
	ret = sys_accept(fd, peer_sockaddr, peer_addrlen);
	if (ret < 0) {
		set_error(-ret);
		ret = -1;
	}
	END_KERNEL_CALL;

	return ret;
}

long recv(int fd, void *buf, size_t size, unsigned flags)
{
	long ret;

	PREPARE_KERNEL_CALL;
	ret = sys_recvfrom(fd, buf, size, flags, NULL, NULL);
	END_KERNEL_CALL;

	return ret;
}

long getsockopt(int fd, int level, int optname, void *optval, unsigned int *optlen)
{
	long ret;

	PREPARE_KERNEL_CALL;
	ret = sys_getsockopt(fd, level, optname, optval, optlen);
	END_KERNEL_CALL;

	return ret;
}

int setsockopt(int fd, int level, int optname, const void *optval, int optlen)
{
	long ret;

	PREPARE_KERNEL_CALL;
	ret = sys_setsockopt(fd, level, optname, (char *)optval, optlen);
	END_KERNEL_CALL;

	return ret;
}

long mkdir(const char *name, int mode)
{
	long ret;

	PREPARE_KERNEL_CALL;
	ret = sys_mkdir(name, mode);
	END_KERNEL_CALL;

	return ret;
}

long shutdown(int fd, int how)
{
	return sys_shutdown(fd, how);
}

long filp_truncate(struct file *file, loff_t length, int small)
{
	struct inode * inode;
	struct dentry *dentry;
	int error;

	error = -EINVAL;
	if (length < 0)
		goto out;
	if (!file)
		goto out;

	/* explicitly opened as large or we are on 64-bit box */
	if (file->f_flags & O_LARGEFILE)
		small = 0;

	dentry = file->f_path.dentry;
	inode = dentry->d_inode;
	error = -EINVAL;
	if (!S_ISREG(inode->i_mode) || !(file->f_mode & FMODE_WRITE))
		goto out;

	error = -EINVAL;
	/* Cannot ftruncate over 2^31 bytes without large file support */
	if (small && length > MAX_NON_LFS)
		goto out;

	error = -EPERM;
	if (IS_APPEND(inode))
		goto out;

	error = locks_verify_truncate(inode, file, length);
	if (!error)
		error = do_truncate(dentry, length, ATTR_MTIME | ATTR_CTIME, file);

out:
	return error;
}

/*********** 2 for time **************/
/* start_time set in w32_init */
int get_tick_count(void)
{
	int rem;
	return div_s64_rem((get_current_time() - start_time), 10000, &rem);
}

timeout_t get_current_time(void)
{
	struct timespec ts;

	getnstimeofday(&ts);
	return (timeout_t)ts.tv_sec * TICKS_PER_SEC + ts.tv_nsec / 100 + TICKS_1601_TO_1970;
}

void uk_wake_up(struct object *obj, int max)
{
	if (!max) {
		obj->header.signal_state = 1;
		wait_test((struct dispatcher_header *)obj, IO_NO_INCREMENT);
	} else {
		ktrace("max != 0, not supported yet!\n");
		/* TODO */
	}
}

#endif /* CONFIG_UNIFIED_KERNEL */
