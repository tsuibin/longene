/*
 * named_pipe.c
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
 * named_pipe.c:
 * Refered to Wine code
 */
#include <linux/poll.h>

#include "io.h"
#include "unistr.h"
#include "handle.h"
#include "file.h"

#ifdef CONFIG_UNIFIED_KERNEL

#define NAMED_PIPE_ALL_ACCESS    (STANDARD_RIGHTS_REQUIRED | 0x1)
#define FILE_SYNCHRONOUS_IO_ALERT       0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT    0x00000020

#define AF_UNIX     1   /* Unix domain sockets      */
#define PF_UNIX                    AF_UNIX
#define SOCK_STREAM 1
#define SOL_SOCKET                 0xffff
#define SO_SNDBUF                  0x1001
#define SO_RCVBUF                  0x1002

#define FIELD_OFFSET(type, field) (/*(LONG)(INT_PTR)&*/(((type *)0)->field))  /* D.M. TBD */

typedef struct _FILE_PIPE_WAIT_FOR_BUFFER {
    LARGE_INTEGER   Timeout;
    ULONG           NameLength;
    BOOLEAN         TimeoutSpecified;
    WCHAR           Name[1];
} FILE_PIPE_WAIT_FOR_BUFFER, *PFILE_PIPE_WAIT_FOR_BUFFER;
typedef signed __int64   INT_PTR, *PINT_PTR;

extern HANDLE device_handle;
extern struct object_type *get_object_type(const struct unicode_str*);
POBJECT_TYPE namedpipe_object_type;

static WCHAR NamedPipeName[] = {'N', 'a', 'm', 'e', 'd', 'P', 'i', 'p', 'e', 0};
static WCHAR dir_named_pipe[] = {'\\', 'D', 'e', 'v', 'i', 'c', 'e', '\\', 'N', 'a', 'm', 'e', 'd', 'P', 'i', 'p', 'e', 0};
static WCHAR link_pipe[] = {'\\', '?', '?', '\\', 'P', 'I', 'P', 'E', 0};
static WCHAR link_pipe_lower[] = {'\\', '?', '?', '\\', 'p', 'i', 'p', 'e', 0};
static WCHAR named_pipe[] = {'N', 'a', 'm', 'e', 'd', 'P', 'i', 'p', 'e', 0};
static WCHAR named_pipe_net[] = {'n', 'e', 't', 0};

static WCHAR PipeRoot[] = {'P', 'i', 'p', 'e', 'R', 'o', 'o', 't', 0};
static POBJECT_DIRECTORY PipeNameSpace;

enum pipe_state
{
	ps_idle_server,
	ps_wait_open,
	ps_connected_server,
	ps_wait_disconnect,
	ps_disconnected_server,
	ps_wait_connect
};

struct named_pipe;

struct pipe_server
{
	struct object        obj;        /* object header */
	struct fd           *fd;         /* pipe file descriptor */
	struct fd           *ioctl_fd;   /* file descriptor for ioctls when not connected */
	struct list_head     entry;      /* entry in named pipe servers list */
	enum pipe_state      state;      /* server state */
	struct pipe_client  *client;     /* client that this server is connected to */
	struct named_pipe   *pipe;
	struct timeout_user *flush_poll;
	struct kevent       *event;
	unsigned int         options;    /* pipe options */
};

struct pipe_client
{
	struct object        obj;        /* object header */
	struct fd           *fd;         /* pipe file descriptor */
	struct pipe_server  *server;     /* server that this client is connected to */
	unsigned int         flags;      /* file flags */
};

struct named_pipe
{
	struct object       obj;         /* object header */
	unsigned int        flags;
	unsigned int        maxinstances;
	unsigned int        outsize;
	unsigned int        insize;
	unsigned int        instances;
	timeout_t           timeout;
	struct list_head    servers;     /* list of servers using this pipe */
	struct async_queue *waiters;     /* list of clients waiting to connect */
};

struct named_pipe_device
{
	struct object       obj;         /* object header */
	struct fd           *fd;         /* pseudo-fd for ioctls */
	obj_handle_t        *pipes;      /* named pipe namespace */
};

static void named_pipe_dump(struct object *obj, int verbose);
static unsigned int named_pipe_map_access(struct object *obj, unsigned int access);
static struct object *named_pipe_open_file(struct object *obj, unsigned int access,
                                            unsigned int sharing, unsigned int options);
static void named_pipe_destroy(struct object *obj);

static const struct object_ops named_pipe_ops =
{
	sizeof(struct named_pipe),    /* size */
	named_pipe_dump,              /* dump */
	no_get_type,                  /* get_type */
	no_get_fd,                    /* get_fd */
	named_pipe_map_access,        /* map_access */
	no_lookup_name,               /* lookup_name */
	named_pipe_open_file,         /* open_file */
	no_close_handle,              /* close_handle */
	named_pipe_destroy,           /* destroy */

	NULL,                      /* signaled */
	NULL,                      /* satisfied */
	no_signal,                 /* signal */
	default_get_sd,            /* get_sd */
	default_set_sd             /* set_sd */
};

/* server end functions */
static void pipe_server_dump(struct object *obj, int verbose);
static struct fd *pipe_server_get_fd(struct object *obj);
static void pipe_server_destroy(struct object *obj);
static void pipe_server_flush(struct fd *fd, struct kevent **event);
static enum server_fd_type pipe_server_get_fd_type(struct fd *fd);
static obj_handle_t pipe_server_ioctl(struct fd *fd, ioctl_code_t code, const async_data_t *async,
								const void *data, data_size_t size);
extern unsigned int default_fd_map_access(struct object *obj, unsigned int access);

static const struct object_ops pipe_server_ops =
{
	sizeof(struct pipe_server),   /* size */
	pipe_server_dump,             /* dump */
	no_get_type,                  /* get_type */
	pipe_server_get_fd,           /* get_fd */
	default_fd_map_access,        /* map_access */
	no_lookup_name,               /* lookup_name */
	no_open_file,                 /* open_file */
	fd_close_handle,              /* close_handle */
	pipe_server_destroy,          /* destroy */

	default_fd_signaled,       /* signaled */
	no_satisfied,              /* satisfied */
	no_signal,                 /* signal */
	default_get_sd,            /* get_sd */
	default_set_sd             /* set_sd */
};

static const struct fd_ops pipe_server_fd_ops =
{
	default_fd_get_poll_events,   /* get_poll_events */
	default_poll_event,           /* poll_event */
	pipe_server_flush,            /* flush */
	pipe_server_get_fd_type,      /* get_fd_type */
	default_fd_removable,         /* removable */
	pipe_server_ioctl,            /* ioctl */
	default_fd_queue_async,       /* queue_async */
	default_fd_async_event,       /* async_event */
	default_fd_async_terminated,  /* async_terminated */
	default_fd_cancel_async,      /* cancel_async */
};

/* client end functions */
static void pipe_client_dump(struct object *obj, int verbose);
static struct fd *pipe_client_get_fd(struct object *obj);
static void pipe_client_destroy(struct object *obj);
static void pipe_client_flush(struct fd *fd, struct kevent **event);
static enum server_fd_type pipe_client_get_fd_type(struct fd *fd);

static const struct object_ops pipe_client_ops =
{
	sizeof(struct pipe_client),   /* size */
	pipe_client_dump,             /* dump */
	no_get_type,                  /* get_type */
	pipe_client_get_fd,           /* get_fd */
	default_fd_map_access,        /* map_access */
	no_lookup_name,               /* lookup_name */
	no_open_file,                 /* open_file */
	fd_close_handle,              /* close_handle */
	pipe_client_destroy,          /* destroy */

	default_fd_signaled,       /* signaled */
	no_satisfied,              /* satisfied */
	no_signal,                 /* signal */
	default_get_sd,            /* get_sd */
	default_set_sd             /* set_sd */
};

static const struct fd_ops pipe_client_fd_ops =
{
	default_fd_get_poll_events,   /* get_poll_events */
	default_poll_event,           /* poll_event */
	pipe_client_flush,            /* flush */
	pipe_client_get_fd_type,      /* get_fd_type */
	default_fd_removable,         /* removable */
	default_fd_ioctl,             /* ioctl */
	default_fd_queue_async,       /* queue_async */
	default_fd_async_event,       /* async_event */
	default_fd_async_terminated,  /* async_terminated */
	default_fd_cancel_async       /* cancel_async */
};

static void named_pipe_device_dump(struct object *obj, int verbose);
static struct object_type *named_pipe_device_get_type(struct object *obj);
static struct fd *named_pipe_device_get_fd(struct object *obj);
static struct object *named_pipe_device_lookup_name(struct object *obj,
									struct unicode_str *name, unsigned int attr);
static struct object *named_pipe_device_open_file(struct object *obj, unsigned int access,
									unsigned int sharing, unsigned int options);
static void named_pipe_device_destroy(struct object *obj);
static enum server_fd_type named_pipe_device_get_fd_type(struct fd *fd);
static obj_handle_t named_pipe_device_ioctl(struct fd *fd, ioctl_code_t code, const async_data_t *async_data,
									const void *data, data_size_t size);

static const struct object_ops named_pipe_device_ops =
{
	sizeof(struct named_pipe_device), /* size */
	named_pipe_device_dump,           /* dump */
	named_pipe_device_get_type,       /* get_type */
	named_pipe_device_get_fd,         /* get_fd */
	no_map_access,                    /* map_access */
	named_pipe_device_lookup_name,    /* lookup_name */
	named_pipe_device_open_file,      /* open_file */
	fd_close_handle,                  /* close_handle */
	named_pipe_device_destroy,        /* destroy */

	NULL,                      /* signaled */
	no_satisfied,              /* satisfied */
	no_signal,                 /* signal */
	default_get_sd,            /* get_sd */
	default_set_sd             /* set_sd */
};

static const struct fd_ops named_pipe_device_fd_ops =
{
	default_fd_get_poll_events,       /* get_poll_events */
	default_poll_event,               /* poll_event */
	no_flush,                         /* flush */
	named_pipe_device_get_fd_type,    /* get_fd_type */
	default_fd_removable,             /* removable */
	named_pipe_device_ioctl,          /* ioctl */
	default_fd_queue_async,           /* queue_async */
	default_fd_async_event,           /* async_event */
	default_fd_async_terminated,      /* async_terminated */
	default_fd_cancel_async           /* cancel_async */
};

static NTSTATUS
parse_named_pipe(
		IN PVOID ParseObject,
		IN PVOID ObjectType,
		IN OUT PACCESS_STATE AccessState,
		IN KPROCESSOR_MODE AccessMode,
		IN ULONG Attributes,
		IN OUT PUNICODE_STRING CompleteName,
		IN OUT PUNICODE_STRING RemainingName,
		IN OUT PVOID Context OPTIONAL,
		IN PSECURITY_QUALITY_OF_SERVICE SecurityQos OPTIONAL,
		OUT PVOID *Object
		);

static WCHAR named_pipe_name[] = {'N','a','m','e','d','_','P','i','p','e',0};
static WCHAR pipe_server_name[] = {'P','i','p','e','_','S','e','r','v','e','r',0};
static WCHAR pipe_client_name[] = {'P','i','p','e','_','C','l','i','n','e','t',0};
static WCHAR named_pipe_device_name[] =
	{'N','a','m','e','d','_','P','i','p','e','_','D','e','v','i','c','e',0};

POBJECT_TYPE named_pipe_object_type = NULL;
EXPORT_SYMBOL(named_pipe_object_type);

POBJECT_TYPE pipe_server_object_type = NULL;
EXPORT_SYMBOL(pipe_server_object_type);

POBJECT_TYPE pipe_client_object_type = NULL;
EXPORT_SYMBOL(pipe_client_object_type);

POBJECT_TYPE named_pipe_device_object_type = NULL;
EXPORT_SYMBOL(named_pipe_device_object_type);

static GENERIC_MAPPING mapping =
{
	STANDARD_RIGHTS_READ | SYNCHRONIZE | 0x1 /* QUERY_STATE */,
	STANDARD_RIGHTS_WRITE | SYNCHRONIZE | 0x2 /* MODIFY_STATE */,
	STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE | 0x1 /* QUERY_STATE */,
	STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3
};

VOID
init_named_pipe_implement(VOID)
{
	OBJECT_TYPE_INITIALIZER ObjectTypeInitializer;
	UNICODE_STRING Name;

	memset(&ObjectTypeInitializer, 0, sizeof(ObjectTypeInitializer));
	init_unistr(&Name, named_pipe_name);
	ObjectTypeInitializer.Length = sizeof(ObjectTypeInitializer);
	ObjectTypeInitializer.DefaultNonPagedPoolCharge = sizeof(struct named_pipe);
	ObjectTypeInitializer.GenericMapping = mapping;
	ObjectTypeInitializer.PoolType = NonPagedPool;
	ObjectTypeInitializer.ValidAccessMask = EVENT_ALL_ACCESS;
	ObjectTypeInitializer.UseDefaultObject = TRUE;
	create_type_object(&ObjectTypeInitializer, &Name, &named_pipe_object_type);
}

VOID
init_pipe_server_implement(VOID)
{
	OBJECT_TYPE_INITIALIZER ObjectTypeInitializer;
	UNICODE_STRING Name;

	memset(&ObjectTypeInitializer, 0, sizeof(ObjectTypeInitializer));
	init_unistr(&Name, pipe_server_name);
	ObjectTypeInitializer.Length = sizeof(ObjectTypeInitializer);
	ObjectTypeInitializer.DefaultNonPagedPoolCharge = sizeof(struct pipe_server);
	ObjectTypeInitializer.GenericMapping = mapping;
	ObjectTypeInitializer.PoolType = NonPagedPool;
	ObjectTypeInitializer.ValidAccessMask = EVENT_ALL_ACCESS;
	ObjectTypeInitializer.UseDefaultObject = TRUE;
	create_type_object(&ObjectTypeInitializer, &Name, &pipe_server_object_type);
}

VOID
init_pipe_client_implement(VOID)
{
	OBJECT_TYPE_INITIALIZER ObjectTypeInitializer;
	UNICODE_STRING Name;

	memset(&ObjectTypeInitializer, 0, sizeof(ObjectTypeInitializer));
	init_unistr(&Name, pipe_client_name);
	ObjectTypeInitializer.Length = sizeof(ObjectTypeInitializer);
	ObjectTypeInitializer.DefaultNonPagedPoolCharge = sizeof(struct pipe_client);
	ObjectTypeInitializer.GenericMapping = mapping;
	ObjectTypeInitializer.PoolType = NonPagedPool;
	ObjectTypeInitializer.ValidAccessMask = EVENT_ALL_ACCESS;
	ObjectTypeInitializer.UseDefaultObject = TRUE;
	create_type_object(&ObjectTypeInitializer, &Name, &pipe_client_object_type);
}

VOID
init_named_pipe_device_implement(VOID)
{
	OBJECT_TYPE_INITIALIZER ObjectTypeInitializer;
	UNICODE_STRING Name;

	memset(&ObjectTypeInitializer, 0, sizeof(ObjectTypeInitializer));
	init_unistr(&Name, named_pipe_device_name);
	ObjectTypeInitializer.Length = sizeof(ObjectTypeInitializer);
	ObjectTypeInitializer.DefaultNonPagedPoolCharge = sizeof(struct named_pipe);
	ObjectTypeInitializer.GenericMapping = mapping;
	ObjectTypeInitializer.PoolType = NonPagedPool;
	ObjectTypeInitializer.ValidAccessMask = EVENT_ALL_ACCESS;
	ObjectTypeInitializer.UseDefaultObject = TRUE;
	create_type_object(&ObjectTypeInitializer, &Name, &named_pipe_device_object_type);
}

void init_named_pipe(void)
{
	OBJECT_TYPE_INITIALIZER ObjectTypeInitializer;
	UNICODE_STRING Name, LinkName;
	OBJECT_ATTRIBUTES obj_attr;
	PVOID object;
	HANDLE handle;
	NTSTATUS status;

	ktrace("\n");
	/* Initialize the File object type  */
	memset(&ObjectTypeInitializer, 0, sizeof(ObjectTypeInitializer));
	init_unistr(&Name, (PWSTR)NamedPipeName);
	ObjectTypeInitializer.Length = sizeof(ObjectTypeInitializer);
	ObjectTypeInitializer.DefaultNonPagedPoolCharge = sizeof(struct named_pipe_device);
	ObjectTypeInitializer.ParseProcedure = parse_named_pipe;
	create_type_object(&ObjectTypeInitializer, &Name, &namedpipe_object_type);

	init_unistr(&Name, (PWSTR)named_pipe);
	INIT_OBJECT_ATTR(&obj_attr, &Name, 0, device_handle, NULL);

	status = create_object(KernelMode,
			dir_object_type,
			&obj_attr,
			KernelMode,
			NULL,
			sizeof(OBJECT_DIRECTORY),
			0,
			0,
			(PVOID *)&object);
	if (!NT_SUCCESS(status))
		return;

	status = insert_object(object,
			NULL,
			0,
			0,
			NULL,
			&handle);
	if (!NT_SUCCESS(status))
		return;

	init_unistr(&Name, (PWSTR)named_pipe_net);
	INIT_OBJECT_ATTR(&obj_attr, &Name, 0, handle, NULL);

	status = create_object(KernelMode,
			dir_object_type,
			&obj_attr,
			KernelMode,
			NULL,
			sizeof(OBJECT_DIRECTORY),
			0,
			0,
			(PVOID *)&object);
	if (!NT_SUCCESS(status)) {
		NtClose(handle);
		return;
	}

	status = insert_object(object,
			NULL,
			0,
			0,
			NULL,
			NULL);
	NtClose(handle);
	if (!NT_SUCCESS(status))
		return;

	init_unistr(&Name, (PWSTR)dir_named_pipe);
	init_unistr(&LinkName, (PWSTR)link_pipe);
	io_create_symbol_link(&LinkName, &Name);

	init_unistr(&Name, (PWSTR)dir_named_pipe);
	init_unistr(&LinkName, (PWSTR)link_pipe_lower);
	io_create_symbol_link(&LinkName, &Name);
}

static void named_pipe_dump(struct object *obj, int verbose)
{
}

static unsigned int named_pipe_map_access(struct object *obj, unsigned int access)
{
	if (access & GENERIC_READ)
		access |= STANDARD_RIGHTS_READ;
	if (access & GENERIC_WRITE)
		access |= STANDARD_RIGHTS_WRITE | FILE_CREATE_PIPE_INSTANCE;
	if (access & GENERIC_EXECUTE)
		access |= STANDARD_RIGHTS_EXECUTE;
	if (access & GENERIC_ALL)
		access |= STANDARD_RIGHTS_ALL;
	return access & ~(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);
}

static void pipe_server_dump(struct object *obj, int verbose)
{
}

static void pipe_client_dump(struct object *obj, int verbose)
{
}

static void named_pipe_destroy(struct object *obj)
{
	struct named_pipe *pipe = (struct named_pipe *) obj;

	free_async_queue(pipe->waiters);
}

static struct fd *pipe_client_get_fd(struct object *obj)
{
	struct pipe_client *client = (struct pipe_client *) obj;
	if (client->fd)
		return (struct fd *)grab_object(client->fd);
	set_error(STATUS_PIPE_DISCONNECTED);
	return NULL;
}

static void set_server_state(struct pipe_server *server, enum pipe_state state)
{
	server->state = state;

	switch(state) {
		case ps_connected_server:
		case ps_wait_disconnect:
			break;
		case ps_wait_open:
		case ps_idle_server:
			set_no_fd_status(server->ioctl_fd, STATUS_PIPE_LISTENING);
			break;
		case ps_disconnected_server:
		case ps_wait_connect:
			set_no_fd_status(server->ioctl_fd, STATUS_PIPE_DISCONNECTED);
			break;
	}
}

static struct fd *pipe_server_get_fd(struct object *obj)
{
	struct pipe_server *server = (struct pipe_server *) obj;

	return (struct fd *)grab_object(server->fd ? server->fd : server->ioctl_fd);
}


static void notify_empty(struct pipe_server *server)
{
	if (!server->flush_poll)
		return;
	remove_timeout_user(server->flush_poll);
	server->flush_poll = NULL;
	set_event(server->event, EVENT_INCREMENT, FALSE);
	release_object(server->event);
	server->event = NULL;
}

static void do_disconnect(struct pipe_server *server)
{
	/* we may only have a server fd, if the client disconnected */
	if (server->client) {
		release_object(server->client->fd);
		server->client->fd = NULL;
	}
	shutdown(get_unix_fd(server->fd), SHUT_RDWR);
	release_object(server->fd);
	server->fd = NULL;
}

static void pipe_server_destroy(struct object *obj)
{
	struct pipe_server *server = (struct pipe_server *)obj;

	if (server->fd) {
		notify_empty(server);
		do_disconnect(server);
	}

	if (server->client) {
		server->client->server = NULL;
		server->client = NULL;
	}

	server->pipe->instances--;

	if (server->ioctl_fd)
		release_object(server->ioctl_fd);
	list_remove(&server->entry);
	release_object(server->pipe);
}

static void pipe_client_destroy(struct object *obj)
{
	struct pipe_client *client = (struct pipe_client *)obj;
	struct pipe_server *server = client->server;

	if (server) {
		notify_empty(server);

		switch(server->state) {
			case ps_connected_server:
				/* Don't destroy the server's fd here as we can't
				   do a successful flush without it. */
				set_server_state(server, ps_wait_disconnect);
				break;
			case ps_disconnected_server:
				set_server_state(server, ps_wait_connect);
				break;
			case ps_idle_server:
			case ps_wait_open:
			case ps_wait_disconnect:
			case ps_wait_connect:
				;
		}
		server->client = NULL;
		client->server = NULL;
	}
	if (client->fd)
		release_object(client->fd);
}

static void named_pipe_device_dump(struct object *obj, int verbose)
{
}

static struct object_type *named_pipe_device_get_type(struct object *obj)
{
	static const WCHAR name[] = {'D','e','v','i','c','e'};
	static const struct unicode_str str = {name, sizeof(name)};
	return get_object_type(&str);
}

static struct fd *named_pipe_device_get_fd(struct object *obj)
{
	struct named_pipe_device *device = (struct named_pipe_device *)obj;
	return (struct fd *)grab_object(device->fd);
}

static struct object *named_pipe_device_lookup_name(struct object *obj, struct unicode_str *name,
											unsigned int attr)
{
    return NULL;
}

static struct object *named_pipe_device_open_file(struct object *obj, unsigned int access,
											unsigned int sharing, unsigned int options)
{
	return grab_object(obj);
}

static void named_pipe_device_destroy(struct object *obj)
{
	struct named_pipe_device *device = (struct named_pipe_device*)obj;

	if (device->fd)
		release_object(device->fd);
	NtClose(device->pipes);
}

static enum server_fd_type named_pipe_device_get_fd_type(struct fd *fd)
{
	return FD_TYPE_DEVICE;
}

void create_named_pipe_device(struct directory *root, const struct unicode_str *name)
{
	struct named_pipe_device *dev;
	UNICODE_STRING pipe_root;
	OBJECT_ATTRIBUTES ObjectAttributes;

	if ((dev = create_named_object_dir(root, name, 0, &named_pipe_device_ops)) &&
			get_error() != STATUS_OBJECT_NAME_EXISTS) {
		INIT_DISP_HEADER(&dev->obj.header, NAMED_PIPE_DEVICE,
				sizeof(struct named_pipe_device) / sizeof(ULONG), 0);
		init_unistr(&pipe_root, (PWSTR)PipeRoot);
		INIT_OBJECT_ATTR(&ObjectAttributes,
				&pipe_root,
				0,
				NULL,
				NULL);
		create_object(KernelMode,
				dir_object_type,
				&ObjectAttributes,
				KernelMode,
				NULL,
				sizeof(OBJECT_DIRECTORY),
				0,
				0,
				(PVOID *)&PipeNameSpace);
		create_handle(NULL,
				PipeNameSpace,
				0,
				ObjectAttributes.Attributes & OBJ_INHERIT,
				(PHANDLE)&dev->pipes);

		if (!dev->pipes || !(dev->fd = alloc_pseudo_fd(&named_pipe_device_fd_ops, &dev->obj, 0))) {
			release_object(dev);
			dev = NULL;
		}
	}
	if (dev)
		make_object_static(&dev->obj);
}

static int pipe_data_remaining(struct pipe_server *server)
{
	struct pollfd pfd;
	int fd;

	fd = get_unix_fd(server->client->fd);
	if (fd < 0)
		return 0;
	pfd.fd = fd;
	pfd.events = POLLIN;
	pfd.revents = 0;

	if (0 > poll(&pfd, 1, 0))
		return 0;

	return pfd.revents&POLLIN;
}

static void check_flushed(void *arg)
{
	struct pipe_server *server = (struct pipe_server*)arg;

	if (pipe_data_remaining(server)) {
		server->flush_poll = add_timeout_user(-TICKS_PER_SEC / 10, check_flushed, server);
	}
	else {
		/* notify_empty(server); */
		server->flush_poll = NULL;
		set_event(server->event, EVENT_INCREMENT, FALSE);
		release_object(server->event);
		server->event = NULL;
	}
}

static void pipe_server_flush(struct fd *fd, struct kevent **event)
{
	struct pipe_server *server = get_fd_user(fd);

	if (!server || server->state != ps_connected_server)
		return;

	/* FIXME: if multiple threads flush the same pipe,
	   maybe should create a list of processes to notify */
	if (server->flush_poll)
		return;

	if (pipe_data_remaining(server)) {
		/* this kind of sux -
		   there's no unix way to be alerted when a pipe becomes empty */
		server->event = create_event(NULL, NULL, 0, 0, 0, NULL);
		if (!server->event)
			return;
		server->flush_poll = add_timeout_user(-TICKS_PER_SEC / 10, check_flushed, server);
		*event = server->event;
	}
}

static void pipe_client_flush(struct fd *fd, struct kevent **event)
{
	/* FIXME: what do we have to do for this? */
}

static inline int is_overlapped(unsigned int options)
{
	return !(options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT));
}

static enum server_fd_type pipe_server_get_fd_type(struct fd *fd)
{
	return FD_TYPE_PIPE;
}

static enum server_fd_type pipe_client_get_fd_type(struct fd *fd)
{
	return FD_TYPE_PIPE;
}

static obj_handle_t alloc_wait_event(struct w32process *process)
{
	obj_handle_t handle = 0;
	struct kevent *event = create_event(NULL, NULL, 0, 1, 0, NULL);

	if (event) {
		handle = alloc_handle(process, event, EVENT_ALL_ACCESS, 0);
		release_object(event);
	}
	return handle;
}

static obj_handle_t pipe_server_ioctl(struct fd *fd, ioctl_code_t code, const async_data_t *async_data,
						const void *data, data_size_t size)
{
	struct pipe_server *server = get_fd_user(fd);
	struct async *async;
	obj_handle_t wait_handle = 0;

	switch(code) {
		case FSCTL_PIPE_LISTEN:
			switch(server->state) {
				case ps_idle_server:
				case ps_wait_connect:
					if (!async_data->event && !async_data->apc) {
						async_data_t new_data = *async_data;
						if (!(wait_handle = alloc_wait_event(get_current_w32process())))
							break;
						new_data.event = wait_handle;
						if (!(async = fd_queue_async(server->ioctl_fd, &new_data, ASYNC_TYPE_WAIT, 0))) {
							close_handle(get_current_eprocess(), wait_handle);
							break;
						}
					}
					else async = fd_queue_async(server->ioctl_fd, async_data, ASYNC_TYPE_WAIT, 0);

					if (async) {
						set_server_state(server, ps_wait_open);
						if (server->pipe->waiters)
							async_wake_up(server->pipe->waiters, STATUS_SUCCESS);
						release_object(async);
						set_error(STATUS_PENDING);
						return wait_handle;
					}
					break;
				case ps_connected_server:
					set_error(STATUS_PIPE_CONNECTED);
					break;
				case ps_disconnected_server:
					set_error(STATUS_PIPE_BUSY);
					break;
				case ps_wait_disconnect:
					set_error(STATUS_NO_DATA_DETECTED);
					break;
				case ps_wait_open:
					set_error(STATUS_INVALID_HANDLE);
					break;
			}
			return 0;

		case FSCTL_PIPE_DISCONNECT:
			switch(server->state) {
				case ps_connected_server:
					notify_empty(server);

					/* dump the client and server fds, but keep the pointers
					   around - client loses all waiting data */
					do_disconnect(server);
					set_server_state(server, ps_disconnected_server);
					break;
				case ps_wait_disconnect:
					do_disconnect(server);
					set_server_state(server, ps_wait_connect);
					break;
				case ps_idle_server:
				case ps_wait_open:
					set_error(STATUS_PIPE_LISTENING);
					break;
				case ps_disconnected_server:
				case ps_wait_connect:
					set_error(STATUS_PIPE_DISCONNECTED);
					break;
			}
			return 0;

		default:
			return default_fd_ioctl(fd, code, async_data, data, size);
	}
}


static struct named_pipe *create_named_pipe(obj_handle_t root, const struct unicode_str *name,
						unsigned int attr)
{
    struct named_pipe *pipe = NULL;
    NTSTATUS status;

    if (!name || !name->len) {
        status = create_object(KernelMode,
                named_pipe_device_object_type,
                NULL /* obj_attr*/,
                KernelMode,
                NULL,
                sizeof(struct named_pipe),
                0,
                0,
                (PVOID *)&pipe);

        if (NT_SUCCESS(status) && pipe) {
            INIT_DISP_HEADER(&pipe->obj.header, NAMED_PIPE,
                    sizeof(struct named_pipe) / sizeof(ULONG), 0);
            BODY_TO_HEADER(&pipe->obj)->ops = &named_pipe_ops;
        }
		return pipe;
    }
    pipe = create_wine_object(root, &named_pipe_ops, name, NULL);
    if (pipe)
        clear_error();
    return pipe;
}

static struct pipe_server *get_pipe_server_obj(struct w32process *process,
					obj_handle_t handle, unsigned int access)
{
	struct object *obj;
	obj = get_wine_handle_obj(process, handle, access, &pipe_server_ops);
	return (struct pipe_server *)obj;
}

static struct pipe_server *create_pipe_server(struct named_pipe *pipe, unsigned int options)
{
	struct pipe_server *server;
	NTSTATUS status;

	status = create_object(KernelMode,
			pipe_server_object_type,
			NULL /* obj_attr*/,
			KernelMode,
			NULL,
			sizeof(struct pipe_server),
			0,
			0,
			(PVOID *)&server);

	if (NT_SUCCESS(status) && server) {
		INIT_DISP_HEADER(&server->obj.header, PIPE_SERVER,
				sizeof(struct pipe_server) / sizeof(ULONG), 0);
		BODY_TO_HEADER(&server->obj)->ops = &pipe_server_ops;
	}
	else
		return NULL;

	server->fd = NULL;
	server->pipe = pipe;
	server->client = NULL;
	server->flush_poll = NULL;
	server->options = options;

	list_add_head(&pipe->servers, &server->entry);
	grab_object(pipe);
	if (!(server->ioctl_fd = alloc_pseudo_fd(&pipe_server_fd_ops, &server->obj, options))) {
		release_object(server);
		return NULL;
	}
	set_server_state(server, ps_idle_server);
	return server;
}

static struct pipe_client *create_pipe_client(unsigned int flags)
{
	struct pipe_client *client;
	NTSTATUS status;

	status = create_object(KernelMode,
			pipe_client_object_type,
			NULL /* obj_attr*/,
			KernelMode,
			NULL,
			sizeof(struct pipe_client),
			0,
			0,
			(PVOID *)&client);

	if (NT_SUCCESS(status) && client) {
		INIT_DISP_HEADER(&client->obj.header, PIPE_CLIENT,
				sizeof(struct pipe_client)/sizeof(ULONG), 0);
		BODY_TO_HEADER(&client->obj)->ops = &pipe_client_ops;
	}
	else
		return NULL;

	client->fd = NULL;
	client->server = NULL;
	client->flags = flags;

	return client;
}

static struct pipe_server *find_available_server(struct named_pipe *pipe)
{
	struct pipe_server *server;

	/* look for pipe servers that are listening */
	LIST_FOR_EACH_ENTRY(server, &pipe->servers, struct pipe_server, entry) {
		if (server->state == ps_wait_open)
			return (struct pipe_server *)grab_object(server);
	}

	/* fall back to pipe servers that are idle */
	LIST_FOR_EACH_ENTRY(server, &pipe->servers, struct pipe_server, entry) {
		if (server->state == ps_idle_server)
			return (struct pipe_server *)grab_object(server);
	}

	return NULL;
}


struct object *named_pipe_open_file(struct object *obj, unsigned int access,
					unsigned int sharing, unsigned int options)
{
	struct named_pipe *pipe = (struct named_pipe *)obj;
	struct pipe_server *server;
	struct pipe_client *client;
	int fds[2];

	if (!(server = find_available_server(pipe))) {
		set_error(STATUS_PIPE_NOT_AVAILABLE);
		return NULL;
	}

	if ((client = create_pipe_client(options))) {
		if (socketpair(PF_UNIX, SOCK_STREAM, 0, fds) >= 0) {
			/* for performance reasons, only set nonblocking mode when using
			 * overlapped I/O. Otherwise, we will be doing too much busy
			 * looping */
			if (is_overlapped(options))
				fcntl(fds[1], F_SETFL, O_NONBLOCK);
			if (is_overlapped(server->options))
				fcntl(fds[0], F_SETFL, O_NONBLOCK);

			if (pipe->insize) {
				setsockopt(fds[0], SOL_SOCKET, SO_RCVBUF, &pipe->insize, sizeof(pipe->insize));
				setsockopt(fds[1], SOL_SOCKET, SO_RCVBUF, &pipe->insize, sizeof(pipe->insize));
			}
			if (pipe->outsize) {
				setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &pipe->outsize, sizeof(pipe->outsize));
				setsockopt(fds[1], SOL_SOCKET, SO_SNDBUF, &pipe->outsize, sizeof(pipe->outsize));
			}

			client->fd = create_anonymous_fd(&pipe_client_fd_ops, fds[1], &client->obj, options);
			server->fd = create_anonymous_fd(&pipe_server_fd_ops, fds[0], &server->obj, server->options);
			if (client->fd && server->fd) {
				fd_copy_completion(server->ioctl_fd, server->fd);
				if (server->state == ps_wait_open)
					fd_async_wake_up(server->ioctl_fd, ASYNC_TYPE_WAIT, STATUS_SUCCESS);
				set_server_state(server, ps_connected_server);
				server->client = client;
				client->server = server;
			}
			else {
				release_object(client);
				client = NULL;
			}
		}
		else {
			release_object(client);
			client = NULL;
		}
	}
	release_object(server);
	return &client->obj;
}


static obj_handle_t named_pipe_device_ioctl(struct fd *fd, ioctl_code_t code, const async_data_t *async_data,
					const void *data, data_size_t size)
{
	struct named_pipe_device *device = get_fd_user(fd);

	switch(code) {
		case FSCTL_PIPE_WAIT:
			{
				const FILE_PIPE_WAIT_FOR_BUFFER *buffer = data;
				obj_handle_t wait_handle = 0;
				struct named_pipe *pipe;
				struct pipe_server *server;
				struct unicode_str name;

				if (size < sizeof(*buffer) ||
						size < FIELD_OFFSET(FILE_PIPE_WAIT_FOR_BUFFER, Name[buffer->NameLength/sizeof(WCHAR)])) {
					set_error(STATUS_INVALID_PARAMETER);
					return 0;
				}
				name.str = buffer->Name;
				name.len = (buffer->NameLength / sizeof(WCHAR)) * sizeof(WCHAR);
				if (!(pipe = (struct named_pipe *)find_object(device->pipes, &name, OBJ_CASE_INSENSITIVE))) {
					set_error(STATUS_PIPE_NOT_AVAILABLE);
					return 0;
				}
				if (!(server = find_available_server(pipe))) {
					struct async *async;

					if (!pipe->waiters && !(pipe->waiters = create_async_queue(NULL)))
						goto done;

					if (!async_data->event && !async_data->apc) {
						async_data_t new_data = *async_data;
						if (!(wait_handle = alloc_wait_event(get_current_w32process())))
							goto done;
						new_data.event = wait_handle;
						if (!(async = create_async(current_thread, pipe->waiters, &new_data))) {
							close_handle(get_current_eprocess(), wait_handle);
							wait_handle = 0;
						}
					}
					else async = create_async(current_thread, pipe->waiters, async_data);

					if (async) {
						timeout_t when = buffer->TimeoutSpecified ? buffer->Timeout.QuadPart : pipe->timeout;
						async_set_timeout(async, when, STATUS_IO_TIMEOUT);
						release_object(async);
						set_error(STATUS_PENDING);
					}
				}
				else release_object(server);

done:
				release_object(pipe);
				return wait_handle;
			}

		default:
			return default_fd_ioctl(fd, code, async_data, data, size);
	}
}

static NTSTATUS
parse_named_pipe(
		IN PVOID ParseObject,
		IN PVOID ObjectType,
		IN OUT PACCESS_STATE AccessState,
		IN KPROCESSOR_MODE AccessMode,
		IN ULONG Attributes,
		IN OUT PUNICODE_STRING CompleteName,
		IN OUT PUNICODE_STRING RemainingName,
		IN OUT PVOID Context OPTIONAL,
		IN PSECURITY_QUALITY_OF_SERVICE SecurityQos OPTIONAL,
		OUT PVOID *Object
		)
{
	struct named_pipe_device *device = (struct named_pipe_device *)ParseObject;
	NTSTATUS status;

	status = ref_object_by_handle(
			device->pipes,
			NAMED_PIPE_ALL_ACCESS,
			NULL,
			KernelMode,
			Object,
			NULL);

	return status;
}

DECL_HANDLER(create_named_pipe)
{
	struct named_pipe *pipe;
	struct pipe_server *server;
	struct unicode_str name;
	struct directory *root = NULL;

	ktrace("\n");
	reply->handle = 0;
	get_req_unicode_str(&name);

	pipe = create_named_pipe(req->rootdir, &name, req->attributes | OBJ_OPENIF);

	if (root)
		release_object(root);
	if (!pipe)
		return;

	if (get_error() != STATUS_OBJECT_NAME_EXISTS) {
		/* initialize it if it didn't already exist */
		pipe->instances = 0;
		pipe->waiters = NULL;
		INIT_LIST_HEAD(&pipe->servers);
		pipe->insize = req->insize;
		pipe->outsize = req->outsize;
		pipe->maxinstances = req->maxinstances;
		pipe->timeout = req->timeout;
		pipe->flags = req->flags;
	}
	else {
		if (pipe->maxinstances <= pipe->instances) {
			set_error(STATUS_INSTANCE_NOT_AVAILABLE);
			release_object(pipe);
			return;
		}
		if ((pipe->maxinstances != req->maxinstances) ||
				(pipe->timeout != req->timeout) ||
				(pipe->flags != req->flags)) {
			set_error(STATUS_ACCESS_DENIED);
			release_object(pipe);
			return;
		}
		clear_error(); /* clear the name collision */
	}

	server = create_pipe_server(pipe, req->options);
	if (server) {
		reply->handle = alloc_handle(get_current_w32process(), server, req->access, req->attributes);
		server->pipe->instances++;
		release_object(server);
	}

	release_object(pipe);
}

DECL_HANDLER(get_named_pipe_info)
{
	struct pipe_server *server;
	struct pipe_client *client = NULL;

	ktrace("\n");
	server = get_pipe_server_obj(get_current_w32process(), req->handle, FILE_READ_ATTRIBUTES);
	if (!server) {
		clear_error();
		client = (struct pipe_client *)get_wine_handle_obj(get_current_w32process(), req->handle,
				FILE_READ_ATTRIBUTES, &pipe_client_ops);
		if (!client)
			return;
		server = client->server;
	}

	reply->flags        = server->pipe->flags;
	reply->maxinstances = server->pipe->maxinstances;
	reply->instances    = server->pipe->instances;
	reply->insize       = server->pipe->insize;
	reply->outsize      = server->pipe->outsize;

	if (client)
		release_object(client);
	else {
		reply->flags |= NAMED_PIPE_SERVER_END;
		release_object(server);
	}
}
#endif /* CONFIG_UNIFIED_KERNEL */
