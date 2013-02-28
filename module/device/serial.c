/*
 * serial.c
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
 * serial.c:
 * Refered to Wine code
 */
#include "unistr.h"
#include "handle.h"

#ifdef CONFIG_UNIFIED_KERNEL

#define NCCS 19

static void serial_dump(struct object *obj, int verbose);
static struct fd *serial_get_fd(struct object *obj);
static void serial_destroy(struct object *obj);

static enum server_fd_type serial_get_fd_type(struct fd *fd);
static void serial_flush(struct fd *fd, struct kevent **event);
static void serial_queue_async(struct fd *fd, const async_data_t *data, int type, int count);

typedef unsigned char   cc_t;
typedef unsigned int    speed_t;
typedef unsigned int    tcflag_t;

struct termios {
	tcflag_t c_iflag;       /* input mode flags */
	tcflag_t c_oflag;       /* output mode flags */
	tcflag_t c_cflag;       /* control mode flags */
	tcflag_t c_lflag;       /* local mode flags */
	cc_t c_line;            /* line discipline */
	cc_t c_cc[NCCS];        /* control characters */
};

struct serial
{
	struct object       obj;
	struct fd          *fd;

	/* timeout values */
	unsigned int        readinterval;
	unsigned int        readconst;
	unsigned int        readmult;
	unsigned int        writeconst;
	unsigned int        writemult;

	unsigned int        eventmask;

	struct termios      original;

	/* FIXME: add dcb, comm status, handler module, sharing */
};

extern unsigned int default_fd_map_access(struct object *obj, unsigned int access);

static const struct object_ops serial_ops =
{
	sizeof(struct serial),        /* size */
	serial_dump,                  /* dump */
	no_get_type,                  /* get_type */
	serial_get_fd,                /* get_fd */
	default_fd_map_access,        /* map_access */
	no_lookup_name,               /* lookup_name */
	no_open_file,                 /* open_file */
	fd_close_handle,              /* close_handle */
	serial_destroy,               /* destroy */

	default_fd_signaled,        /* signaled */
	no_satisfied,              /* satisfied */
	no_signal,                 /* signal */
	default_get_sd,            /* get_sd */
	default_set_sd             /* set_sd */
};

static const struct fd_ops serial_fd_ops =
{
	default_fd_get_poll_events,   /* get_poll_events */
	default_poll_event,           /* poll_event */
	serial_flush,                 /* flush */
	serial_get_fd_type,           /* get_file_info */
	default_fd_removable,         /* removable */
	default_fd_ioctl,             /* ioctl */
	serial_queue_async,           /* queue_async */
	default_fd_async_event,       /* async_event */
	default_fd_async_terminated,  /* async_terminated */
	default_fd_cancel_async       /* cancel_async */
};

static WCHAR serial_name[] = {'S','e','r','i','a','l',0};

POBJECT_TYPE serial_object_type = NULL;
EXPORT_SYMBOL(serial_object_type);

static GENERIC_MAPPING mapping =
{
	STANDARD_RIGHTS_READ | SYNCHRONIZE | 0x1 /* QUERY_STATE */,
	STANDARD_RIGHTS_WRITE | SYNCHRONIZE | 0x2 /* MODIFY_STATE */,
	STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE | 0x1 /* QUERY_STATE */,
	STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3
};

VOID
init_serial_implement(VOID)
{
	OBJECT_TYPE_INITIALIZER ObjectTypeInitializer;
	UNICODE_STRING Name;

	memset(&ObjectTypeInitializer, 0, sizeof(ObjectTypeInitializer));
	init_unistr(&Name, serial_name);
	ObjectTypeInitializer.Length = sizeof(ObjectTypeInitializer);
	ObjectTypeInitializer.DefaultNonPagedPoolCharge = sizeof(struct serial);
	ObjectTypeInitializer.GenericMapping = mapping;
	ObjectTypeInitializer.PoolType = NonPagedPool;
	ObjectTypeInitializer.ValidAccessMask = EVENT_ALL_ACCESS;
	ObjectTypeInitializer.UseDefaultObject = TRUE;
	create_type_object(&ObjectTypeInitializer, &Name, &serial_object_type);
}

/* check if the given fd is a serial port */
int is_serial_fd(struct fd *fd)
{
	return 0;
}

/* create a serial object for a given fd */
struct object *create_serial(struct fd *fd)
{
	struct serial *serial;
	NTSTATUS status;

	status = create_object(KernelMode,
			serial_object_type,
			NULL /* obj_attr*/,
			KernelMode,
			NULL,
			sizeof(struct serial),
			0,
			0,
			(PVOID *)&serial);

	if (NT_SUCCESS(status) && serial) {
		INIT_DISP_HEADER(&serial->obj.header, SERIAL,
				sizeof(struct serial) / sizeof(ULONG), 0);
		BODY_TO_HEADER(&serial->obj)->ops = &serial_ops;
	}
	else
		return NULL;

	serial->readinterval = 0;
	serial->readmult     = 0;
	serial->readconst    = 0;
	serial->writemult    = 0;
	serial->writeconst   = 0;
	serial->eventmask    = 0;
	serial->fd = (struct fd *)grab_object(fd);
	set_fd_user(fd, &serial_fd_ops, &serial->obj);
	return &serial->obj;
}

static struct fd *serial_get_fd(struct object *obj)
{
	struct serial *serial = (struct serial *)obj;
	return (struct fd *)grab_object(serial->fd);
}

static void serial_destroy(struct object *obj)
{
	struct serial *serial = (struct serial *)obj;
	release_object(serial->fd);
}

static void serial_dump(struct object *obj, int verbose)
{
}

static struct serial *get_serial_obj(struct w32process *process, obj_handle_t handle, unsigned int access)
{
	return (struct serial *)get_wine_handle_obj(process, handle, access, &serial_ops);
}

static enum server_fd_type serial_get_fd_type(struct fd *fd)
{
	return FD_TYPE_SERIAL;
}

static void serial_queue_async(struct fd *fd, const async_data_t *data, int type, int count)
{
	struct serial *serial = get_fd_user(fd);
	timeout_t timeout = 0;
	struct async *async;

	switch (type) {
		case ASYNC_TYPE_READ:
			timeout = serial->readconst + (timeout_t)serial->readmult * count;
			break;
		case ASYNC_TYPE_WRITE:
			timeout = serial->writeconst + (timeout_t)serial->writemult * count;
			break;
	}

	if ((async = fd_queue_async(fd, data, type, count))) {
		if (timeout)
			async_set_timeout(async, timeout * -10000, STATUS_TIMEOUT);
		release_object(async);
		set_error(STATUS_PENDING);
	}
}

static void serial_flush(struct fd *fd, struct kevent **event)
{
	/* MSDN says: If hFile is a handle to a communications device,
	 * the function only flushes the transmit buffer.
	 */
}

DECL_HANDLER(get_serial_info)
{
	struct serial *serial;

	ktrace("\n");
	if ((serial = get_serial_obj(get_current_w32process(), req->handle, 0))) {
		/* timeouts */
		reply->readinterval = serial->readinterval;
		reply->readconst    = serial->readconst;
		reply->readmult     = serial->readmult;
		reply->writeconst   = serial->writeconst;
		reply->writemult    = serial->writemult;

		/* event mask */
		reply->eventmask    = serial->eventmask;

		release_object(serial);
	}
}

DECL_HANDLER(set_serial_info)
{
	struct serial *serial;

	ktrace("\n");
	if ((serial = get_serial_obj(get_current_w32process(), req->handle, 0))) {
		/* timeouts */
		if (req->flags & SERIALINFO_SET_TIMEOUTS) {
			serial->readinterval = req->readinterval;
			serial->readconst    = req->readconst;
			serial->readmult     = req->readmult;
			serial->writeconst   = req->writeconst;
			serial->writemult    = req->writemult;
		}

		/* event mask */
		if (req->flags & SERIALINFO_SET_MASK) {
			serial->eventmask = req->eventmask;
			if (!serial->eventmask) {
				fd_async_wake_up(serial->fd, ASYNC_TYPE_WAIT, STATUS_SUCCESS);
			}
		}

		release_object(serial);
	}
}
#endif /* CONFIG_UNIFIED_KERNEL */
