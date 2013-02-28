/*
 * fd.c
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
 * fd.c:
 * Refered to Wine code
 */
#include <linux/security.h>
#include <linux/major.h>
#include <linux/poll.h>

#include "handle.h"
#include "file.h"
#include "wineserver/file.h"

#ifdef CONFIG_UNIFIED_KERNEL
/* Because of the stupid Posix locking semantics, we need to keep
 * track of all file descriptors referencing a given file, and not
 * close a single one until all the locks are gone (sigh).
 */

extern long filp_truncate(struct file *file, loff_t length, int small);
extern struct uk_completion *get_completion_obj(struct w32process *process, obj_handle_t handle, unsigned int access);
extern void add_completion(struct uk_completion *completion, unsigned long ckey, unsigned long cvalue,
		unsigned int status, unsigned long information);

#define IO_COMPLETION_QUERY_STATE  0x0001
#define IO_COMPLETION_MODIFY_STATE 0x0002
#define IO_COMPLETION_ALL_ACCESS   (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x3)

#define DEVICE_HASH_SIZE 7
#define INODE_HASH_SIZE 17

#define OFF_T_MAX       (~((file_pos_t)1 << (8*sizeof(off_t)-1)))
#define FILE_POS_T_MAX  (~(file_pos_t)0)

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

/* file descriptor object */

/* closed_fd is used to keep track of the unix fd belonging to a closed fd object */
struct closed_fd
{
	struct list_head entry;       /* entry in inode closed list */
	struct file *unix_file;       /* the unix file */
	char        unlink[1];        /* name to unlink on close (if any) */
};

struct fd
{
	struct object         obj;         /* object header */
	const struct fd_ops  *fd_ops;      /* file descriptor operations */
	struct uk_inode      *inode;       /* inode that this fd belongs to */
	struct list_head      inode_entry; /* entry in inode fd list */
	struct closed_fd     *closed;      /* structure to store the unix fd at destroy time */
	struct object        *user;        /* object using this file descriptor */
	struct list_head      locks;       /* list of locks on this fd */
	unsigned int          access;      /* file access (FILE_READ_DATA etc.) */
	unsigned int          options;     /* file options (FILE_DELETE_ON_CLOSE, FILE_SYNCHRONOUS...) */
	unsigned int          sharing;     /* file sharing mode */
	struct file          *unix_file;   /* unix file struct */
	int                   unix_fd;
	unsigned int          no_fd_status;/* status to return when unix_file is NULL */
	int                   signaled :1; /* is the fd signaled? */
	int                   fs_locks :1; /* can we use filesystem locks for this fd? */
	int                   poll_index;  /* index of fd in poll array */
	struct async_queue   *read_q;      /* async readers of this fd */
	struct async_queue   *write_q;     /* async writers of this fd */
	struct async_queue   *wait_q;      /* other async waiters of this fd */
	struct uk_completion *completion;  /* completion object attached to this fd */
	unsigned long         comp_key;    /* completion key to set in completion events */
};

static void fd_dump(struct object *obj, int verbose);
static void fd_destroy(struct object *obj);

static const struct object_ops fd_ops =
{
	sizeof(struct fd),        /* size */
	fd_dump,                  /* dump */
	no_get_type,              /* get_type */
	no_get_fd,                /* get_fd */
	no_map_access,            /* map_access */
	no_lookup_name,           /* lookup_name */
	no_open_file,             /* open_file */
	no_close_handle,          /* close_handle */
	fd_destroy,               /* destroy */

	NULL,                      /* signaled */
	NULL,                      /* satisfied */
	no_signal,                 /* signal */
	default_get_sd,            /* get_sd */
	default_set_sd             /* set_sd */
};

/* device object */

struct device
{
	struct object       obj;        /* object header */
	struct list_head    entry;      /* entry in device hash list */
	dev_t               dev;        /* device number */
	int                 removable;  /* removable device? (or -1 if unknown) */
	struct list_head    inode_hash[INODE_HASH_SIZE];  /* inodes hash table */
};

static void device_dump(struct object *obj, int verbose);
static void device_destroy(struct object *obj);

static const struct object_ops device_ops =
{
	sizeof(struct device),    /* size */
	device_dump,              /* dump */
	no_get_type,              /* get_type */
	no_get_fd,                /* get_fd */
	no_map_access,            /* map_access */
	no_lookup_name,           /* lookup_name */
	no_open_file,             /* open_file */
	no_close_handle,          /* close_handle */
	device_destroy,           /* destroy */

	NULL,                      /* signaled */
	NULL,                      /* satisfied */
	no_signal,                 /* signal */
	default_get_sd,            /* get_sd */
	default_set_sd             /* set_sd */
};

/* inode object */

struct uk_inode
{
	struct object       obj;        /* object header */
	struct list_head    entry;      /* inode hash list entry */
	struct device      *device;     /* device containing this inode */
	ino_t               ino;        /* inode number */
	struct list_head    open;       /* list of open file descriptors */
	struct list_head    locks;      /* list of file locks */
	struct list_head    closed;     /* list of file descriptors to close at destroy time */
};

static void inode_dump(struct object *obj, int verbose);
static void inode_destroy(struct object *obj);

static const struct object_ops inode_ops =
{
	sizeof(struct uk_inode),     /* size */
	inode_dump,               /* dump */
	no_get_type,              /* get_type */
	no_get_fd,                /* get_fd */
	no_map_access,            /* map_access */
	no_lookup_name,           /* lookup_name */
	no_open_file,             /* open_file */
	no_close_handle,          /* close_handle */
	inode_destroy,            /* destroy */

	NULL,                      /* signaled */
	NULL,                      /* satisfied */
	no_signal,                 /* signal */
	default_get_sd,            /* get_sd */
	default_set_sd             /* set_sd */
};

/* file lock object */

struct uk_file_lock
{
	struct object       obj;         /* object header */
	struct fd          *fd;          /* fd owning this lock */
	struct list_head    fd_entry;    /* entry in list of locks on a given fd */
	struct list_head    inode_entry; /* entry in inode list of locks */
	int                 shared;      /* shared lock? */
	file_pos_t          start;       /* locked region is interval [start;end) */
	file_pos_t          end;
	struct w32process  *process;     /* process owning this lock */
	struct list_head    proc_entry;  /* entry in list of locks owned by the process */
};

static void file_lock_dump(struct object *obj, int verbose);

static const struct object_ops file_lock_ops =
{
	sizeof(struct uk_file_lock),   /* size */
	file_lock_dump,             /* dump */
	no_get_type,                /* get_type */
	no_get_fd,                  /* get_fd */
	no_map_access,              /* map_access */
	no_lookup_name,             /* lookup_name */
	no_open_file,               /* open_file */
	no_close_handle,            /* close_handle */
	no_destroy,                 /* destroy */

	NULL,                      /* signaled */
	no_satisfied,              /* satisfied */
	no_signal,                 /* signal */
	default_get_sd,            /* get_sd */
	default_set_sd             /* set_sd */
};

static file_pos_t max_unix_offset = OFF_T_MAX;

/****************************************************************/
/* timeouts support */

struct timeout_user
{
	struct list_head      entry;      /* entry in sorted timeout list */
	timeout_t             when;       /* timeout expiry (absolute time) */
	timeout_callback      callback;   /* callback function */
	void                 *private;    /* callback private data */
};

static struct list_head timeout_list = LIST_INIT(timeout_list);   /* sorted timeouts list */

# define EPOLL_CTL_ADD 1
# define EPOLL_CTL_DEL 2
# define EPOLL_CTL_MOD 3

static struct fd **poll_users;              /* users array */
static struct pollfd *pollfd;               /* poll fd array */
static struct fd **freelist;                /* list of free entries in the array */
static int nb_users;                        /* count of array entries actually in use */
static int allocated_users;                 /* count of allocated entries in the array */
static int active_users = 0;
static int epoll_fd = -1;

typedef union epoll_data
{
  void *ptr;
  int fd;
  uint32_t u32;
  uint64_t u64;
} epoll_data_t;

struct epoll_event
{
  uint32_t events;
  epoll_data_t data;
};

void init_epoll(void)
{
	pid_t thread_id;
    current->ethread->threads_process->epoll_fd = sys_epoll_create( 128 );
   
	thread_id = kernel_thread((void *)main_loop, NULL, CLONE_KERNEL);
	if (thread_id < 0)
		printk("kernel_thread error %d\n", thread_id);
	else
		printk("kernel_thread id %d\n", thread_id);
}

/* add a timeout user */
struct timeout_user *add_timeout_user(timeout_t when, timeout_callback func, void *private)
{
	struct timeout_user *user;
	struct list_head *ptr;

	if (!(user = mem_alloc(sizeof(*user))))
		return NULL;
	user->when     = (when > 0) ? when : current_time - when;
	user->callback = func;
	user->private  = private;

	/* Now insert it in the linked list */

	LIST_FOR_EACH(ptr, &timeout_list) {
		struct timeout_user *timeout = LIST_ENTRY(ptr, struct timeout_user, entry);
		if (timeout->when >= user->when)
			break;
	}
	list_add_before(ptr, &user->entry);
	return user;
}

/* add a linux timer */
struct timer_list *add_linux_timer(timeout_t when, timeout_callback func, void *private)
{
	struct timer_list *timer;
	struct timespec ts = { 0, 0 };

	kdebug("\n");
	timer = (struct timer_list *)kmalloc(sizeof(struct timer_list), GFP_ATOMIC);
	if (!timer) {
		kdebug("kmalloc(timer_list) atomic error.\n");
		set_error(STATUS_NO_MEMORY);
		return NULL;
	}
	init_timer(timer);
	timespec_add_ns(&ts, when * 100);
	kdebug("jiffies = %ld\n", jiffies);
	timer->expires = jiffies + timespec_to_jiffies(&ts);
	kdebug("timer->expires = %ld\n", timer->expires);
	timer->data = (unsigned long)private;
	timer->function = (void *)func;
	add_timer(timer);

	return timer;
}

/* remove a timeout user */
void remove_timeout_user(struct timeout_user *user)
{
	list_del(&user->entry);
	free(user);
}

/* remove a linux timer */
void remove_linux_timer(struct timer_list *timer)
{
	kdebug("\n");
	del_timer(timer);
	kfree(timer);
}

/* return a text description of a timeout for debugging purposes */
const char *get_timeout_str(timeout_t timeout)
{
	return NULL;
}

/* process pending timeouts and return the time until the next timeout, in milliseconds */
int get_next_timeout(void)
{
	if (!list_empty(&timeout_list)) {
		struct list_head expired_list, *ptr;
		timeout_t now;

		local_irq_disable();
		now = current_time;

		/* first remove all expired timers from the list */

		INIT_LIST_HEAD(&expired_list);
		while ((ptr = list_head(&timeout_list)) != NULL) {
			struct timeout_user *timeout = LIST_ENTRY(ptr, struct timeout_user, entry);

			if (timeout->when <= now) {
				list_del(&timeout->entry);
				list_add_before(&expired_list, &timeout->entry);
			}
			else break;
		}

		local_irq_enable();

		/* now call the callback for all the removed timers */

		while ((ptr = list_head(&expired_list)) != NULL) {
			struct timeout_user *timeout = LIST_ENTRY(ptr, struct timeout_user, entry);
			list_del(&timeout->entry);
			timeout->callback(timeout->private);
			free(timeout);
		}

		if ((ptr = list_head(&timeout_list)) != NULL) {
			struct timeout_user *timeout = LIST_ENTRY(ptr, struct timeout_user, entry);
			int diff;
			timeout_t result = timeout->when - current_time + 9999;
			do_div(result, 10000);
			diff = result;
			if (diff < 0)
				diff = 0;
			return diff;
		}
	}
	return -1;  /* no pending timeouts */
}


/****************************************************************/
/* device functions */

static struct list_head device_hash[DEVICE_HASH_SIZE];

static inline int is_device_removable(dev_t dev, struct file *unix_file)
{
	struct kstatfs stfs;

	/* check for floppy disk */
	if (MAJOR(dev) == FLOPPY_MAJOR)
		return 1;

	if (vfs_statfs(unix_file->f_path.dentry, &stfs) < 0)
		return 0;

	return (stfs.f_type == 0x9660 ||    /* iso9660 */
			stfs.f_type == 0x9fa1 ||    /* supermount */
			stfs.f_type == 0x15013346); /* udf */
}

/* retrieve the device object for a given fd, creating it if needed */
static struct device *get_device(dev_t dev, struct file *unix_file)
{
	struct device *device;
	unsigned int i, hash = dev % DEVICE_HASH_SIZE;

	if (device_hash[hash].next) {
		LIST_FOR_EACH_ENTRY(device, &device_hash[hash], struct device, entry)
			if (device->dev == dev)
				return (struct device *)grab_object(device);
	}
	else INIT_LIST_HEAD(&device_hash[hash]);

	/* not found, create it */

	if (!unix_file)
		return NULL;
	if ((device = alloc_wine_object(&device_ops))) {
		INIT_DISP_HEADER(&device->obj.header, FD_DEVICE, sizeof(struct device) / sizeof(ULONG), 0);
		device->dev = dev;
		device->removable = is_device_removable(dev, unix_file);
		for (i = 0; i < INODE_HASH_SIZE; i++)
			INIT_LIST_HEAD(&device->inode_hash[i]);
		list_add_head(&device_hash[hash], &device->entry);
	}
	return device;
}

static void device_dump(struct object *obj, int verbose)
{
}

static void device_destroy(struct object *obj)
{
	struct device *device = (struct device *)obj;
	list_del(&device->entry);  /* remove it from the hash table */
}


/****************************************************************/
/* inode functions */

/* close all pending file descriptors in the closed list */
static void inode_close_pending(struct uk_inode *inode, int keep_unlinks)
{
	struct list_head *ptr = list_head(&inode->closed);

	while (ptr) {
		struct closed_fd *fd = LIST_ENTRY(ptr, struct closed_fd, entry);
		struct list_head *next = list_next(&inode->closed, ptr);

		if (fd->unix_file) {
			fput(fd->unix_file);
			fd->unix_file = NULL;
		}
		if (!keep_unlinks || !fd->unlink[0]) { /* get rid of it unless there's an unlink pending on that file */
			list_del(ptr);
			free(fd);
		}
		ptr = next;
	}
}

static void inode_dump(struct object *obj, int verbose)
{
}

static void inode_destroy(struct object *obj)
{
	struct uk_inode *inode = (struct uk_inode *)obj;
	struct list_head *ptr;

	list_del(&inode->entry);

	while ((ptr = list_head(&inode->closed))) {
		struct closed_fd *fd = LIST_ENTRY(ptr, struct closed_fd, entry);
		list_del(ptr);
		if (fd->unlink[0] && fd->unix_file) {
			struct dentry *dentry = fd->unix_file->f_path.dentry;
			struct dentry *parent = dentry->d_parent;
			struct inode *inode = dentry->d_inode;

			mutex_lock_nested(&parent->d_inode->i_mutex, I_MUTEX_PARENT);
			dget(dentry);
			if (S_ISDIR(inode->i_mode))
				vfs_rmdir(parent->d_inode, dentry);
			else
				vfs_unlink(parent->d_inode, dentry);
			mutex_unlock(&parent->d_inode->i_mutex);
			dput(dentry);
		}
		if (fd->unix_file) {
			fput(fd->unix_file);
			fd->unix_file = NULL;
		}
		free(fd);
	}
	release_object(inode->device);
}

/* retrieve the inode object for a given fd, creating it if needed */
static struct uk_inode *get_inode(dev_t dev, ino_t ino, struct file *unix_file)
{
	struct device *device;
	struct uk_inode *inode;
	unsigned int hash = ino % INODE_HASH_SIZE;

	if (!(device = get_device(dev, unix_file)))
		return NULL;

	LIST_FOR_EACH_ENTRY(inode, &device->inode_hash[hash], struct uk_inode, entry) {
		if (inode->ino == ino) {
			release_object(device);
			return (struct uk_inode *)grab_object(inode);
		}
	}

	/* not found, create it */
	if ((inode = alloc_wine_object(&inode_ops))) {
		INIT_DISP_HEADER(&inode->obj.header, INODE, sizeof(struct uk_inode) / sizeof(ULONG), 0);
		inode->device = device;
		inode->ino    = ino;
		INIT_LIST_HEAD(&inode->open);
		INIT_LIST_HEAD(&inode->locks);
		INIT_LIST_HEAD(&inode->closed);
		list_add_head(&device->inode_hash[hash], &inode->entry);
	}
	else release_object(device);

	return inode;
}

/* add fd to the inode list of file descriptors to close */
static void inode_add_closed_fd(struct uk_inode *inode, struct closed_fd *fd)
{
	if (!list_empty(&inode->locks)) {
		list_add_head(&inode->closed, &fd->entry);
	} else if (fd->unlink[0]) { /* close the fd but keep the structure around for unlink */
		list_add_head(&inode->closed, &fd->entry);
	} else { /* no locks on this inode and no unlink, get rid of the fd */
		if (fd->unix_file)
			fput(fd->unix_file);
		free(fd);
	}
}


/****************************************************************/
/* file lock functions */

static void file_lock_dump(struct object *obj, int verbose)
{
}

/* set (or remove) a Unix lock if possible for the given range */
static int set_unix_lock(struct fd *fd, file_pos_t start, file_pos_t end, int type)
{
	NTSTATUS status;
	int error;
	struct file_lock file_lock;
	struct file *filp = fd->unix_file;

	if (!fd->fs_locks)
		return 1;  /* no fs locks possible for this fd */
	for (;;) {
		if (start == end)
			return 1;  /* can't set zero-byte lock */
		if (start > max_unix_offset)
			return 1;  /* ignore it */
		switch (type) {
			case F_RDLCK:
				if (!(filp->f_mode & FMODE_READ))
					return 1;
				break;
			case F_WRLCK:
				if (!(filp->f_mode & FMODE_WRITE))
					return 1;
				break;
			case F_UNLCK:
				break;
			default:
				status = STATUS_INVALID_PARAMETER;
				goto out;
		}
		if (start > end) {
			status = STATUS_INVALID_PARAMETER;
			goto out;
		}
		file_lock.fl_type   = type;
		file_lock.fl_start  = start;
		file_lock.fl_end  = end - 1;
		file_lock.fl_owner = current->files;
		file_lock.fl_pid = current->tgid;
		file_lock.fl_file = filp;
		file_lock.fl_flags = FL_POSIX;
		file_lock.fl_ops = NULL;
		file_lock.fl_lmops = NULL;

		error = security_file_lock(filp, file_lock.fl_type);
		if (error) {
			status = errno2ntstatus(-error);
			goto out;
		}

		error = vfs_lock_file(filp, F_SETLK, &file_lock, NULL);
		if (!error)
			return 1;

		switch (error) {
			case -EACCES:
				/* check whether locks work at all on this file system */
				if (vfs_test_lock(filp, &file_lock) >= 0 && (file_lock.fl_type != F_UNLCK)) {
					status = STATUS_FILE_LOCK_CONFLICT;
					goto out;
				}
				/* fall through */
			case -EIO:
			case -ENOLCK:
				/* no locking on this fs, just ignore it */
				fd->fs_locks = 0;
				return 1;
			case -EAGAIN:
				status = STATUS_FILE_LOCK_CONFLICT;
				goto out;
			default:
				status = errno2ntstatus(-error);
				goto out;
		}
	}

out:
	set_error(status);
	return 0;
}

/* check if interval [start;end) overlaps the lock */
static inline int lock_overlaps(struct uk_file_lock *lock, file_pos_t start, file_pos_t end)
{
	if (lock->end && start >= lock->end)
		return 0;
	if (end && lock->start >= end)
		return 0;
	return 1;
}

/* remove Unix locks for all bytes in the specified area that are no longer locked */
static void remove_unix_locks(struct fd *fd, file_pos_t start, file_pos_t end)
{
	struct hole
	{
		struct hole *next;
		struct hole *prev;
		file_pos_t   start;
		file_pos_t   end;
	} *first, *cur, *next, *buffer;

	struct list_head *ptr;
	int count = 0;

	if (!fd->inode)
		return;
	if (!fd->fs_locks)
		return;
	if (start == end || start > max_unix_offset)
		return;
	if (!end || end > max_unix_offset)
		end = max_unix_offset + 1;

	/* count the number of locks overlapping the specified area */

	LIST_FOR_EACH(ptr, &fd->inode->locks) {
		struct uk_file_lock *lock = LIST_ENTRY(ptr, struct uk_file_lock, inode_entry);
		if (lock->start == lock->end)
			continue;
		if (lock_overlaps(lock, start, end))
			count++;
	}

	if (!count) { /* no locks at all, we can unlock everything */
		set_unix_lock(fd, start, end, F_UNLCK);
		return;
	}

	/* allocate space for the list of holes */
	/* max. number of holes is number of locks + 1 */

	if (!(buffer = malloc(sizeof(*buffer) * (count+1))))
		return;
	first = buffer;
	first->next  = NULL;
	first->prev  = NULL;
	first->start = start;
	first->end   = end;
	next = first + 1;

	/* build a sorted list of unlocked holes in the specified area */

	LIST_FOR_EACH(ptr, &fd->inode->locks) {
		struct uk_file_lock *lock = LIST_ENTRY(ptr, struct uk_file_lock, inode_entry);
		if (lock->start == lock->end)
			continue;
		if (!lock_overlaps(lock, start, end))
			continue;

		/* go through all the holes touched by this lock */
		for (cur = first; cur; cur = cur->next) {
			if (cur->end <= lock->start)
				continue; /* hole is before start of lock */
			if (lock->end && cur->start >= lock->end)
				break;  /* hole is after end of lock */

			/* now we know that lock is overlapping hole */

			if (cur->start >= lock->start) { /* lock starts before hole, shrink from start */
				cur->start = lock->end;
				if (cur->start && cur->start < cur->end)
					break;  /* done with this lock */
				/* now hole is empty, remove it */
				if (cur->next) 
					cur->next->prev = cur->prev;
				if (cur->prev)
					cur->prev->next = cur->next;
				else if (!(first = cur->next))
					goto done;  /* no more holes at all */
			}
			else if (!lock->end || cur->end <= lock->end) { /* lock larger than hole, shrink from end */
				cur->end = lock->start;
			}
			else { /* lock is in the middle of hole, split hole in two */
				next->prev = cur;
				next->next = cur->next;
				cur->next = next;
				next->start = lock->end;
				next->end = cur->end;
				cur->end = lock->start;
				next++;
				break;  /* done with this lock */
			}
		}
	}

	/* clear Unix locks for all the holes */

	for (cur = first; cur; cur = cur->next)
		set_unix_lock(fd, cur->start, cur->end, F_UNLCK);

done:
	free(buffer);
}

/* create a new lock on a fd */
static struct uk_file_lock *add_lock(struct fd *fd, int shared, file_pos_t start, file_pos_t end)
{
	struct uk_file_lock *lock;

	if (!(lock = alloc_wine_object(&file_lock_ops)))
	{
		set_error(STATUS_NO_MEMORY);
		return NULL;
	}
	INIT_DISP_HEADER(&lock->obj.header, FILE_LOCK, sizeof(struct uk_file_lock) / sizeof(ULONG), 0);
	lock->shared  = shared;
	lock->start   = start;
	lock->end     = end;
	lock->fd      = fd;
	lock->process = get_current_w32process();

	/* now try to set a Unix lock */
	if (!set_unix_lock(lock->fd, lock->start, lock->end, lock->shared ? F_RDLCK : F_WRLCK)) {
		release_object(lock);
		return NULL;
	}
	list_add_head(&fd->locks, &lock->fd_entry);
	list_add_head(&fd->inode->locks, &lock->inode_entry);
	list_add_head(&lock->process->locks, &lock->proc_entry);
	return lock;
}

/* remove an existing lock */
static void remove_lock(struct uk_file_lock *lock, int remove_unix)
{
	struct uk_inode *inode = lock->fd->inode;

	list_del(&lock->fd_entry);
	list_del(&lock->inode_entry);
	list_del(&lock->proc_entry);
	if (remove_unix)
		remove_unix_locks(lock->fd, lock->start, lock->end);
	if (list_empty(&inode->locks))
		inode_close_pending(inode, 1);
	lock->process = NULL;
	uk_wake_up(&lock->obj, 0);
	release_object(lock);
}

/* remove all locks owned by a given process */
void remove_process_locks(struct w32process *process)
{
	struct list_head *ptr;

	while ((ptr = list_head(&process->locks))) {
		struct uk_file_lock *lock = LIST_ENTRY(ptr, struct uk_file_lock, proc_entry);
		remove_lock(lock, 1);  /* this removes it from the list */
	}
}

/* remove all locks on a given fd */
static void remove_fd_locks(struct fd *fd)
{
	file_pos_t start = FILE_POS_T_MAX, end = 0;
	struct list_head *ptr;

	while ((ptr = list_head(&fd->locks))) {
		struct uk_file_lock *lock = LIST_ENTRY(ptr, struct uk_file_lock, fd_entry);
		if (lock->start < start)
			start = lock->start;
		if (!lock->end || lock->end > end)
			end = lock->end - 1;
		remove_lock(lock, 0);
	}
	if (start < end)
		remove_unix_locks(fd, start, end + 1);
}

/* add a lock on an fd */
/* returns handle to wait on */
obj_handle_t lock_fd(struct fd *fd, file_pos_t start, file_pos_t count, int shared, int wait)
{
	struct list_head *ptr;
	file_pos_t end = start + count;

	if (!fd->inode) { /* not a regular file */
		set_error(STATUS_INVALID_DEVICE_REQUEST);
		return 0;
	}

	/* don't allow wrapping locks */
	if (end && end < start) {
		set_error(STATUS_INVALID_PARAMETER);
		return 0;
	}

	/* check if another lock on that file overlaps the area */
	LIST_FOR_EACH(ptr, &fd->inode->locks) {
		struct uk_file_lock *lock = LIST_ENTRY(ptr, struct uk_file_lock, inode_entry);
		if (!lock_overlaps(lock, start, end))
			continue;
		if (lock->shared && shared)
			continue;
		/* found one */
		if (!wait) {
			set_error(STATUS_FILE_LOCK_CONFLICT);
			return 0;
		}
		set_error(STATUS_PENDING);
		return alloc_handle(get_current_w32process(), lock, SYNCHRONIZE, 0);
	}

	/* not found, add it */
	if (add_lock(fd, shared, start, end))
		return 0;
	if (get_error() == STATUS_FILE_LOCK_CONFLICT) {
		/* Unix lock conflict -> tell client to wait and retry */
		if (wait)
			set_error(STATUS_PENDING);
	}
	return 0;
}

/* remove a lock on an fd */
void unlock_fd(struct fd *fd, file_pos_t start, file_pos_t count)
{
	struct list_head *ptr;
	file_pos_t end = start + count;

	/* find an existing lock with the exact same parameters */
	LIST_FOR_EACH(ptr, &fd->locks) {
		struct uk_file_lock *lock = LIST_ENTRY(ptr, struct uk_file_lock, fd_entry);
		if ((lock->start == start) && (lock->end == end)) {
			remove_lock(lock, 1);
			return;
		}
	}
	set_error(STATUS_FILE_LOCK_CONFLICT);
}


static inline void fd_poll_event( struct fd *fd, int event )
{
    fd->fd_ops->poll_event( fd, event );
}

static int add_poll_user( struct fd *fd )
{
    int ret;

	if (current->ethread->threads_process->epoll_fd == -1) init_epoll();

    if (freelist)
    {
        ret = freelist - poll_users;
        freelist = (struct fd **)poll_users[ret];
    }
    else
    {
        if (nb_users == allocated_users)
        {
            struct fd **newusers;
            struct pollfd *newpoll;
            int new_count = allocated_users ? (allocated_users + allocated_users / 2) : 16;
            if (!(newusers = realloc( poll_users, new_count * sizeof(*poll_users), allocated_users * sizeof(*poll_users) ))) return -1;
            if (!(newpoll = realloc( pollfd, new_count * sizeof(*pollfd), allocated_users * sizeof(*pollfd) )))
            {
                if (allocated_users)
                    poll_users = newusers;
                else
                    free( newusers );
                return -1;
            }
            poll_users = newusers;
            pollfd = newpoll;
//            if (!allocated_users) init_epoll();
            allocated_users = new_count;
        }
        ret = nb_users++;
    }
    pollfd[ret].fd = -1;
    pollfd[ret].events = 0;
    pollfd[ret].revents = 0;
    poll_users[ret] = fd;
    active_users++;
    return ret;
}

static inline void remove_epoll_user( struct fd *fd, int user )
{
    if (current->ethread->threads_process->epoll_fd == -1) return;

    if (pollfd[user].fd != -1)
    {
        struct epoll_event dummy;
        sys_epoll_ctl( current->ethread->threads_process->epoll_fd, EPOLL_CTL_DEL, fd->unix_fd, &dummy );
    }
}

/* remove a user from the poll list */
static void remove_poll_user( struct fd *fd, int user )
{
    remove_epoll_user( fd, user );
    pollfd[user].fd = -1;
    pollfd[user].events = 0;
    pollfd[user].revents = 0;
    poll_users[user] = (struct fd *)freelist;
    freelist = &poll_users[user];
    active_users--;
}

/****************************************************************/
/* file descriptor functions */

static void fd_dump(struct object *obj, int verbose)
{
}

static void fd_destroy(struct object *obj)
{
	struct fd *fd = (struct fd *)obj;

	free_async_queue(fd->read_q);
	free_async_queue(fd->write_q);
	free_async_queue(fd->wait_q);

	if (fd->completion)
		release_object(fd->completion);
	remove_fd_locks(fd);
	list_del(&fd->inode_entry);
    if (fd->poll_index != -1) remove_poll_user( fd, fd->poll_index );

	if (fd->unix_file) {
		fput(fd->unix_file);
		fd->unix_file = NULL;
	}
	if (fd->unix_fd != -1)
		close(fd->unix_fd);

	if (fd->inode) {
		inode_add_closed_fd(fd->inode, fd->closed);
		release_object(fd->inode);
	}
}

/* set the events that epoll waits for on this fd; helper for set_fd_events */
static inline void set_fd_epoll_events( struct fd *fd, int user, int events )
{
    struct epoll_event ev;
    int ctl;
	struct eprocess *process;

	if (current->ethread)
		process = current->ethread->threads_process;
	else if (current->parent && current->parent->ethread)
		process = current->parent->ethread->threads_process;
	else
		return;

    if (process->epoll_fd == -1) return;

    if (events == -1)  /* stop waiting on this fd completely */
    {
        if (pollfd[user].fd == -1) return;  /* already removed */
        ctl = EPOLL_CTL_DEL;
    }
    else if (pollfd[user].fd == -1)
    {
        if (pollfd[user].events) return;  /* stopped waiting on it, don't restart */
        ctl = EPOLL_CTL_ADD;
    }
    else
    {
        if (pollfd[user].events == events) return;  /* nothing to do */
        ctl = EPOLL_CTL_MOD;
    }

    ev.events = events;
    memset(&ev.data, 0, sizeof(ev.data));
    ev.data.u32 = user;

    if (sys_epoll_ctl( process->epoll_fd, ctl, fd->unix_fd, &ev ) == -1)
    {
        if (errno == ENOMEM)  /* not enough memory, give up on epoll */
        {
            close( process->epoll_fd );
            process->epoll_fd = -1;
        }
        else perror( "epoll_ctl" );  /* should not happen */
    }
}

void set_fd_events(struct fd *fd, int events)
{
    int user = fd->poll_index;

    set_fd_epoll_events( fd, user, events );

    if (events == -1)  /* stop waiting on this fd completely */
    {
        pollfd[user].fd = -1;
        pollfd[user].events = POLLERR;
        pollfd[user].revents = 0;
    }
    else if (pollfd[user].fd != -1 || !pollfd[user].events)
    {
        pollfd[user].fd = fd->unix_fd;
        pollfd[user].events = events;
    }
}

/* prepare an fd for unmounting its corresponding device */
static inline void unmount_fd(struct fd *fd)
{
	async_wake_up(fd->read_q, STATUS_VOLUME_DISMOUNTED);
	async_wake_up(fd->write_q, STATUS_VOLUME_DISMOUNTED);

	if (fd->unix_file) {
		fput(fd->unix_file);
		fd->unix_file = NULL;
	}
	if (fd->unix_fd != -1)
		close(fd->unix_fd);

	fd->unix_fd = -1;
	fd->no_fd_status = STATUS_VOLUME_DISMOUNTED;
	if (fd->closed->unix_file) {
		fput(fd->closed->unix_file); /* hcz, modify it */
		fd->closed->unix_file = NULL;
	}
	fd->closed->unlink[0] = 0;

	/* stop using Unix locks on this fd (existing locks have been removed by close) */
	fd->fs_locks = 0;
}

/* allocate an fd object, without setting the unix fd yet */
static struct fd *alloc_fd_object(void)
{
	struct fd *fd = alloc_wine_object(&fd_ops);

	if (!fd)
	{
		set_error(STATUS_NO_MEMORY);
		return NULL;
	}

	INIT_DISP_HEADER(&fd->obj.header, FD, sizeof(struct fd) / sizeof(ULONG), 0);
	fd->fd_ops     = NULL;
	fd->user       = NULL;
	fd->inode      = NULL;
	fd->closed     = NULL;
	fd->access     = 0;
	fd->options    = 0;
	fd->sharing    = 0;
	fd->unix_fd    = -1;
	fd->unix_file  = NULL;
	fd->signaled   = 1;
	fd->fs_locks   = 1;
	fd->read_q     = NULL;
	fd->write_q    = NULL;
	fd->wait_q     = NULL;
	fd->completion = NULL;
	INIT_LIST_HEAD(&fd->inode_entry);
	INIT_LIST_HEAD(&fd->locks);

    if ((fd->poll_index = add_poll_user( fd )) == -1)
    {
        release_object( fd );
        return NULL;
    }
	return fd;
}

/* allocate a pseudo fd object, for objects that need to behave like files but don't have a unix fd */
struct fd *alloc_pseudo_fd(const struct fd_ops *fd_user_ops, struct object *user, unsigned int options)
{
	struct fd *fd = alloc_wine_object(&fd_ops);

	if (!fd)
		return NULL;

	INIT_DISP_HEADER(&fd->obj.header, FD, sizeof(struct fd) / sizeof(ULONG), 0);
	fd->fd_ops     = fd_user_ops;
	fd->user       = user;
	fd->inode      = NULL;
	fd->closed     = NULL;
	fd->access     = 0;
	fd->options    = options;
	fd->sharing    = 0;
	fd->unix_file  = NULL;
	fd->unix_fd    = -1;
	fd->signaled   = 0;
	fd->fs_locks   = 0;
	fd->read_q     = NULL;
	fd->write_q    = NULL;
	fd->wait_q     = NULL;
	fd->completion = NULL;
	fd->no_fd_status = STATUS_BAD_DEVICE_TYPE;
	INIT_LIST_HEAD(&fd->inode_entry);
	INIT_LIST_HEAD(&fd->locks);
	return fd;
}

/* set the status to return when the fd has no associated unix fd */
void set_no_fd_status(struct fd *fd, unsigned int status)
{
	fd->no_fd_status = status;
}

/* check if the desired access is possible without violating */
/* the sharing mode of other opens of the same file */
static int check_sharing(struct fd *fd, unsigned int access, unsigned int sharing)
{
	unsigned int existing_sharing = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
	unsigned int existing_access = 0;
	struct list_head *ptr;

	/* if access mode is 0, sharing mode is ignored */
	if (!access)
		sharing = existing_sharing;
	fd->access = access;
	fd->sharing = sharing;

	LIST_FOR_EACH(ptr, &fd->inode->open) {
		struct fd *fd_ptr = LIST_ENTRY(ptr, struct fd, inode_entry);
		if (fd_ptr != fd) {
			existing_sharing &= fd_ptr->sharing;
			existing_access  |= fd_ptr->access;
		}
	}

	if ((access & FILE_UNIX_READ_ACCESS) && !(existing_sharing & FILE_SHARE_READ))
		return 0;
	if ((access & FILE_UNIX_WRITE_ACCESS) && !(existing_sharing & FILE_SHARE_WRITE))
		return 0;
	if ((access & DELETE) && !(existing_sharing & FILE_SHARE_DELETE))
		return 0;
	if ((existing_access & FILE_UNIX_READ_ACCESS) && !(sharing & FILE_SHARE_READ))
		return 0;
	if ((existing_access & FILE_UNIX_WRITE_ACCESS) && !(sharing & FILE_SHARE_WRITE))
		return 0;
	if ((existing_access & DELETE) && !(sharing & FILE_SHARE_DELETE))
		return 0;
	return 1;
}

/* sets the user of an fd that previously had no user */
void set_fd_user(struct fd *fd, const struct fd_ops *user_ops, struct object *user)
{
	fd->fd_ops = user_ops;
	fd->user   = user;
}


/* open() wrapper that returns a struct fd with no fd user set */
struct fd *open_fd(const char *name, int flags, mode_t *mode,
		unsigned int access, unsigned int sharing, unsigned int options)
{
	struct kstat st;
	struct closed_fd *closed_fd;
	struct fd *fd;
	const char *unlink_name = "";
	int rw_mode, ret;

	ktrace("name=%s\n", name);
	if ((options & FILE_DELETE_ON_CLOSE) && !(access & DELETE)) {
		set_error(STATUS_INVALID_PARAMETER);
		return NULL;
	}

	if (!(fd = alloc_fd_object()))
		return NULL;
	kdebug("fd %p\n", fd);

	fd->options = options;
	if (options & FILE_DELETE_ON_CLOSE)
		unlink_name = name;
	if (!(closed_fd = mem_alloc(sizeof(*closed_fd) + strlen(unlink_name)))) {
		release_object(fd);
		return NULL;
	}

	/* create the directory if needed */
	if ((options & FILE_DIRECTORY_FILE) && (flags & O_CREAT)) {
		if ((ret = mkdir(name, 0777))) {
			if (ret != -EEXIST || (flags & O_EXCL)) {
				set_error(errno2ntstatus(-ret));
				goto error;
			}
		}
		flags &= ~(O_CREAT | O_EXCL | O_TRUNC);
	}

	if ((access & FILE_UNIX_WRITE_ACCESS) && !(options & FILE_DIRECTORY_FILE)) {
		if (access & FILE_UNIX_READ_ACCESS)
			rw_mode = O_RDWR;
		else rw_mode = O_WRONLY;
	}
	else rw_mode = O_RDONLY;

	if (IS_ERR(fd->unix_file = filp_open(name, rw_mode | (flags & ~O_TRUNC), *mode))) {
		/* if we tried to open a directory for write access, retry read-only */
		if (PTR_ERR(fd->unix_file) != -EISDIR ||
				!(access & FILE_UNIX_WRITE_ACCESS) ||
				IS_ERR(fd->unix_file = filp_open(name, O_RDONLY | (flags & ~O_TRUNC), *mode))) {
			set_error(errno2ntstatus(-PTR_ERR(fd->unix_file)));
			fd->unix_file = NULL;
			goto error;
		}
	}

	closed_fd->unlink[0] = 0;
	vfs_getattr(fd->unix_file->f_path.mnt, fd->unix_file->f_path.dentry, &st);
	*mode = st.mode;

	/* only bother with an inode for normal files and directories */
	if (S_ISREG(st.mode) || S_ISDIR(st.mode)) {
		struct uk_inode *inode = get_inode(old_encode_dev(st.dev), st.ino, fd->unix_file);

		if (!inode) {
			/* we can close the fd because there are no others open on the same file,
			 * otherwise we wouldn't have failed to allocate a new inode
			 */
			goto error;
		}
		fd->inode = inode;
		fd->closed = closed_fd;
		closed_fd->unix_file = fd->unix_file;
		get_file(closed_fd->unix_file);
		list_add_head(&inode->open, &fd->inode_entry);

		/* check directory options */
		if ((options & FILE_DIRECTORY_FILE) && !S_ISDIR(st.mode)) {
			release_object(fd);
			set_error(STATUS_NOT_A_DIRECTORY);
			return NULL;
		}
		if ((options & FILE_NON_DIRECTORY_FILE) && S_ISDIR(st.mode)) {
			release_object(fd);
			set_error(STATUS_FILE_IS_A_DIRECTORY);
			return NULL;
		}
		if (!check_sharing(fd, access, sharing)) {
			release_object(fd);
			set_error(STATUS_SHARING_VIOLATION);
			return NULL;
		}
		strcpy(closed_fd->unlink, unlink_name);
		if (flags & O_TRUNC)
			filp_truncate(fd->unix_file, 0, 1);
	} else { /* special file */
		if (options & FILE_DIRECTORY_FILE) {
			set_error(STATUS_NOT_A_DIRECTORY);
			goto error;
		}
		if (unlink_name[0]) { /* we can't unlink special files */
			set_error(STATUS_INVALID_PARAMETER);
			goto error;
		}
		free(closed_fd);
	}
	ktrace("done fd %p\n", fd);
	return fd;

error:
	ktrace("error %x\n", get_error());
	release_object(fd);
	free(closed_fd);
	return NULL;
}

/* create an fd for an anonymous file */
/* if the function fails the unix fd is closed */
struct fd *create_anonymous_fd(const struct fd_ops *fd_user_ops,
		int unix_fd, struct object *user, unsigned int options)
{
	struct fd *fd = alloc_fd_object();

	if (fd) {
		set_fd_user(fd, fd_user_ops, user);
		fd->unix_fd = unix_fd;
		fd->unix_file = fget(unix_fd);
		fd->options = options;
		return fd;
	}
	return NULL;
}

struct fd *create_anon_fd_for_filp(const struct fd_ops *fd_user_ops,
		struct file *filp, struct object *user, unsigned int options)
{
	struct fd *fd = alloc_fd_object();

	if (fd) {
		set_fd_user(fd, fd_user_ops, user);
		get_file(filp);
		fd->unix_fd = -1;
		fd->unix_file = filp;
		fd->options = options;
		return fd;
	}
	return NULL;
}

/* retrieve the object that is using an fd */
void *get_fd_user(struct fd *fd)
{
	return fd->user;
}

/* retrieve the opening options for the fd */
unsigned int get_fd_options(struct fd *fd)
{
	return fd->options;
}

struct file *get_unix_file(struct fd *fd)
{
	return fd->unix_file;
}

/* retrieve the unix fd for an handle */
int get_unix_fd(struct fd *fd)
{
	if (fd->unix_fd == -1)
		set_error(fd->no_fd_status);
	return fd->unix_fd;
}

int extract_unix_fd(struct fd *fdp)
{
	return fdp->unix_fd;
}

/* check if two file descriptors point to the same file */
int is_same_file_fd(struct fd *fd1, struct fd *fd2)
{
	return fd1->inode == fd2->inode;
}

/* set or clear the fd signaled state */
void set_fd_signaled(struct fd *fd, int signaled)
{
	fd->signaled = signaled;
	if (signaled)
		uk_wake_up(fd->user, 0);
}

/* handler for close_handle that refuses to close fd-associated handles in other processes */
int fd_close_handle(struct object *obj, struct w32process *process, obj_handle_t handle)
{
	return (get_current_w32process() == process);
}

/* check if events are pending and if yes return which one(s) */
int check_fd_events(struct fd *fd, int events)
{
	struct pollfd pfd;
	int ret;

	ktrace("unix_fd=%d\n", fd->unix_fd);
	if (fd->unix_fd == -1)
		return POLLERR;
	if (fd->inode)
		return events;  /* regular files are always signaled */

	pfd.fd     = fd->unix_fd;
	pfd.events = events;
	pfd.revents = 0;
	if ((ret = poll(&pfd, 1, 0)) <= 0) {
		ktrace("ret=%d\n", ret);
		return 0;
	}
	return pfd.revents;
}

/* default signaled() routine for objects that poll() on an fd */
int default_fd_signaled(struct object *obj, struct w32thread *thread)
{
	struct fd *fd = get_obj_fd(obj);
	int ret = fd->signaled;
	release_object(fd);
	return ret;
}

/* default map_access() routine for objects that behave like an fd */
unsigned int default_fd_map_access(struct object *obj, unsigned int access)
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

int default_fd_get_poll_events(struct fd *fd)
{
	int events = 0;
#if 0  /* D.M. TBD */
	if (async_waiting(fd->read_q))
		events |= POLLIN;
	if (async_waiting(fd->write_q))
		events |= POLLOUT;
#endif
	return events;
}

/* default handler for poll() events */
void default_poll_event(struct fd *fd, int event)
{
#if 0
	if (event & (POLLIN | POLLERR | POLLHUP))
		async_wake_up(fd->read_q, STATUS_ALERTED);
	if (event & (POLLOUT | POLLERR | POLLHUP))
		async_wake_up(fd->write_q, STATUS_ALERTED);

	/* if an error occurred, stop polling this fd to avoid busy-looping */
	if (event & (POLLERR | POLLHUP))
		set_fd_events(fd, -1);
	else if (!fd->inode)
		set_fd_events(fd, fd->fd_ops->get_poll_events(fd));
#endif
}

/* default removable() */
int default_fd_removable(struct fd *fd)
{
	return (fd->inode && fd->inode->device->removable);
}

/* check whether an fd can be abruptly removed (ie don't cache it) */
int is_fd_removable(struct fd *fd)
{
	return fd->fd_ops->removable(fd);
}

struct async *fd_queue_async(struct fd *fd, const async_data_t *data, int type, int count)
{
	struct async_queue *queue;
	struct async *async;

	switch (type) {
		case ASYNC_TYPE_READ:
			if (!fd->read_q && !(fd->read_q = create_async_queue(fd)))
				return NULL;
			queue = fd->read_q;
			break;
		case ASYNC_TYPE_WRITE:
			if (!fd->write_q && !(fd->write_q = create_async_queue(fd)))
				return NULL;
			queue = fd->write_q;
			break;
		case ASYNC_TYPE_WAIT:
			if (!fd->wait_q && !(fd->wait_q = create_async_queue(fd)))
				return NULL;
			queue = fd->wait_q;
			break;
		default:
			queue = NULL;
	}

	if ((async = create_async(current_thread, queue, data)) && type != ASYNC_TYPE_WAIT) {
		if (!fd->inode)
			set_fd_events(fd, fd->fd_ops->get_poll_events(fd));
		else  /* regular files are always ready for read and write */
			async_wake_up(queue, STATUS_ALERTED);
	}
	return async;
}

void fd_async_wake_up(struct fd *fd, int type, unsigned int status)
{
	switch (type) {
		case ASYNC_TYPE_READ:
			async_wake_up(fd->read_q, status);
			break;
		case ASYNC_TYPE_WRITE:
			async_wake_up(fd->write_q, status);
			break;
		case ASYNC_TYPE_WAIT:
			async_wake_up(fd->wait_q, status);
			break;
		default:
			break;
	}
}

void fd_async_event(struct fd *fd, struct async_queue *queue, struct async *async, int status, int finished)
{
	fd->fd_ops->async_event(fd, queue, async, status, finished);
}

int fd_async_terminated(struct fd *fd, struct async_queue *queue, struct async *async, int status)
{
	return fd->fd_ops->async_terminated(fd, queue, async, status);
}

void default_fd_queue_async(struct fd *fd, const async_data_t *data, int type, int count)
{
	struct async *async;

	if ((async = fd_queue_async(fd, data, type, count))) {
		release_object(async);
		set_error(STATUS_PENDING);
	}
}

/* default async_event() fd routine */
void default_fd_async_event(struct fd *fd, struct async_queue *queue, struct async *async, int status, int finished)
{
	if (queue != fd->wait_q) {
		int poll_events = fd->fd_ops->get_poll_events(fd);
		int events = check_fd_events(fd, poll_events);
		if (events)
			fd->fd_ops->poll_event(fd, events);
		else
			set_fd_events(fd, poll_events);
	}
}

/* default async_terminated() fd routine */
int default_fd_async_terminated(struct fd *fd, struct async_queue *queue, struct async *async, int status)
{
	return status;
}

/* default cancel_async() fd routine */
void default_fd_cancel_async(struct fd *fd, struct w32process *process, struct w32thread *thread, unsigned __int64 iosb)
{
	int n = 0;

	n += async_wake_up_by(fd->read_q, process, thread, iosb, STATUS_CANCELLED);
	n += async_wake_up_by(fd->write_q, process, thread, iosb, STATUS_CANCELLED);
	n += async_wake_up_by(fd->wait_q, process, thread, iosb, STATUS_CANCELLED);
	if (!n && iosb)
		set_error(STATUS_NOT_FOUND);
}

/* default ioctl() routine */
obj_handle_t default_fd_ioctl(struct fd *fd, ioctl_code_t code, const async_data_t *async,
		const void *data, data_size_t size)
{
	switch(code) {
#if 0
		case FSCTL_DISMOUNT_VOLUME:
			unmount_device(fd);
			return 0;
#endif
		default:
			set_error(STATUS_NOT_SUPPORTED);
			return 0;
	}
}


/* same as get_handle_obj but retrieve the struct fd associated to the object */
static struct fd *get_handle_fd_obj(struct w32process *process, obj_handle_t handle,
		unsigned int access)
{
	struct fd *fd = NULL;
	struct object *obj;

	if ((obj = get_wine_handle_obj(process, handle, access, NULL))) {
		fd = get_obj_fd(obj);
		release_object(obj);
	}
	return fd;
}

struct uk_completion *fd_get_completion(struct fd *fd, unsigned long *p_key)
{
	*p_key = fd->comp_key;
	return fd->completion ? (struct uk_completion *)grab_object(fd->completion) : NULL;
}

void fd_copy_completion(struct fd *src, struct fd *dst)
{
	dst->completion = fd_get_completion(src, &dst->comp_key);
}

void add_completion_by_fd(struct fd *fd, unsigned long cvalue, unsigned int status, unsigned long total)
{
	if (fd && fd->completion && cvalue)
		add_completion(fd->completion, fd->comp_key, cvalue, status, total);
}

/* flush a file buffers */
DECL_HANDLER(flush_file)
{
	struct fd *fd; 
	struct kevent * event = NULL;

	ktrace("\n");
	fd = get_handle_fd_obj(get_current_w32process(), req->handle, 0);
	if (fd) {
		fd->fd_ops->flush(fd, &event);
		if (event) {
			reply->event = alloc_handle(get_current_w32process(), event, SYNCHRONIZE, 0);
		}
		release_object(fd);
	}
}

/* open a file object */
DECL_HANDLER(open_file_object)
{
	struct unicode_str name;
	struct object *obj, *result;

	ktrace("\n");
	get_req_unicode_str(&name);
	if ((obj = open_object_dir(req->rootdir, &name, req->attributes, NULL))) {
		if (BODY_TO_HEADER(obj)->ops) {
			if ((result = BODY_TO_HEADER(obj)->ops->open_file(obj, req->access, req->sharing, req->options))) {
				reply->handle = alloc_handle(get_current_w32process(), result, req->access, req->attributes);
				release_object(result);
			}
		}
		release_object(obj);
	}
}

/* get a Unix fd to access a file */
DECL_HANDLER(get_handle_fd)
{
	struct fd *fd;

	ktrace("\n");
	reply->fd = -1;
	if ((fd = get_handle_fd_obj(get_current_w32process(), req->handle, 0))) {
		int unix_fd = get_handle_fd(get_current_eprocess(), req->handle);
		if (unix_fd != -1) {
			reply->type = fd->fd_ops->get_fd_type(fd);
			reply->removable = is_fd_removable(fd);
			reply->options = fd->options;
			reply->access = get_handle_access(current->ethread ? get_current_eprocess() : NULL, req->handle);
			reply->fd = unix_fd;
		}
		release_object(fd);
	}
	ktrace("done, fd=%d\n", reply->fd);
}

/* perform an ioctl on a file */
DECL_HANDLER(ioctl)
{
	unsigned int access; 
	struct fd *fd; 

	ktrace("\n");
	access = (req->code >> 14) & (FILE_READ_DATA|FILE_WRITE_DATA);
	fd = get_handle_fd_obj(get_current_w32process(), req->handle, access);
	if (fd) {
		reply->wait = fd->fd_ops->ioctl(fd, req->code, &req->async,
				get_req_data(), get_req_data_size());
		reply->options = fd->options;
		release_object(fd);
	}
}

/* create / reschedule an async I/O */
DECL_HANDLER(register_async)
{
	unsigned int access;
	struct fd *fd;

	ktrace("\n");
	switch(req->type) {
		case ASYNC_TYPE_READ:
			access = FILE_READ_DATA;
			break;
		case ASYNC_TYPE_WRITE:
			access = FILE_WRITE_DATA;
			break;
		default:
			set_error(STATUS_INVALID_PARAMETER);
			return;
	}

	if ((fd = get_handle_fd_obj(get_current_w32process(), req->handle, access))) {
		if (fd->unix_file)
			fd->fd_ops->queue_async(fd, &req->async, req->type, req->count);
		release_object(fd);
	}
}

/* cancels all async I/O */
DECL_HANDLER(cancel_async)
{
	struct fd *fd; 
	struct w32thread *thread;

	ktrace("\n");
	fd = get_handle_fd_obj(get_current_w32process(), req->handle, 0);
	thread = req->only_thread ? get_current_w32thread() : NULL;
	if (fd) {
		if (fd->unix_file)
			fd->fd_ops->cancel_async(fd, get_current_w32process(), thread, req->iosb);
		release_object(fd);
	}
}

/* attach completion object to a fd */
DECL_HANDLER(set_completion_info)
{
	struct fd *fd; 

	ktrace("\n");
	fd = get_handle_fd_obj(get_current_w32process(), req->handle, 0);
	if (fd) {
		if (!(fd->options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT)) && !fd->completion) {
			fd->completion = get_completion_obj(get_current_w32process(), req->chandle, IO_COMPLETION_MODIFY_STATE);
			fd->comp_key = req->ckey;
		}
		else set_error(STATUS_INVALID_PARAMETER);
		release_object(fd);
	}
}

/* push new completion msg into a completion queue attached to the fd */
DECL_HANDLER(add_fd_completion)
{
	struct fd *fd;

	ktrace("\n");
	fd = get_handle_fd_obj(get_current_w32process(), req->handle, 0);
	if (fd) {
		if (fd->completion)
			add_completion(fd->completion, fd->comp_key, req->cvalue, req->status, req->information);
		release_object(fd);
	}
}

extern int uk_epoll_wait(int epfd, struct epoll_event * events, int maxevents, int timeout);
void main_loop(void)
{
    int i, ret = 0;
    struct epoll_event events[128];
	unsigned int msecs,timeout;

	msecs = 10;
	timeout = msecs_to_jiffies(msecs)+1;

	while (1)
	{
//		timeout = get_next_timeout();
		if (active_users) break;
		schedule_timeout_interruptible(timeout);
	}

    while (current->parent->pid != 1)//(active_users)
    {
//        timeout = get_next_timeout();

//        if (!active_users) do_exit(0);  /* last user removed by a timeout */

	if (current->parent->ethread && current->parent->ethread->threads_process && current->parent->ethread->threads_process->epoll_fd != -1) {
        ret = uk_epoll_wait( current->parent->ethread->threads_process->epoll_fd, events, sizeof(events)/sizeof(events[0]), 1000 );
	}
//        set_current_time();

        /* put the events into the pollfd array first, like poll does */
        for (i = 0; i < ret; i++)
        {
            int user = events[i].data.u32;
            pollfd[user].revents = events[i].events;
        }

        /* read events from the pollfd array, as set_fd_events may modify them */
        for (i = 0; i < ret; i++)
        {
            int user = events[i].data.u32;
            if (pollfd[user].revents) fd_poll_event( poll_users[user], pollfd[user].revents );
        }

		schedule_timeout_interruptible(timeout);
    }
}
#endif /* CONFIG_UNIFIED_KERNEL */
