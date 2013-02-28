/*
 * async.c
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
 * async.c:
 * Refered to Wine code
 */
#include "handle.h"
#include "unistr.h"
#include "wineserver/lib.h"

#ifdef CONFIG_UNIFIED_KERNEL
struct uk_completion;
extern void fd_assign_completion(struct fd *fd, struct uk_completion **p_port, unsigned long *p_key);
extern void add_completion(struct uk_completion *completion, unsigned long ckey,
				unsigned long cvalue, unsigned int status, unsigned long information);
extern void add_completion_by_fd(struct fd *fd, unsigned long cvalue, unsigned int status, unsigned long total);

struct async
{
	struct object        obj;             /* object header */
	struct w32thread    *thread;          /* owning thread */
	struct list_head     queue_entry;     /* entry in async queue list */
	struct async_queue  *queue;           /* queue containing this async */
	unsigned int         status;          /* current status */
	struct timeout_user *timeout;
	unsigned int         timeout_status;  /* status to report upon timeout */
	struct kevent        *event;
	struct uk_completion *completion;
	unsigned long        comp_key;
	async_data_t         data;            /* data for async I/O call */
};

static void async_dump(struct object *obj, int verbose);
static void async_destroy(struct object *obj);

static const struct object_ops async_ops =
{
	sizeof(struct async),      /* size */
	async_dump,                /* dump */
	no_get_type,               /* get_type */
	no_get_fd,                 /* get_fd */
	no_map_access,             /* map_access */
	no_lookup_name,            /* lookup_name */
	no_open_file,              /* open_file */
	no_close_handle,           /* close_handle */
	async_destroy,             /* destroy */

	NULL,                      /* signaled */
	NULL,                      /* satisfied */
	no_signal,                 /* signal */
	default_get_sd,            /* get_sd */
	default_set_sd             /* set_sd */
};


struct async_queue
{
	struct object        obj;             /* object header */
	struct fd           *fd;              /* file descriptor owning this queue */
	struct list_head     queue;           /* queue of async objects */
};

static void async_queue_dump(struct object *obj, int verbose);

static const struct object_ops async_queue_ops =
{
	sizeof(struct async_queue),      /* size */
	async_queue_dump,                /* dump */
	no_get_type,                     /* get_type */
	no_get_fd,                       /* get_fd */
	no_map_access,                   /* map_access */
	no_lookup_name,                  /* lookup_name */
	no_open_file,                    /* open_file */
	no_close_handle,                 /* close_handle */
	no_destroy,                      /* destroy */

	NULL,                            /* signaled */
	NULL,                            /* satisfied */
	no_signal,                       /* signal */
	default_get_sd,                  /* get_sd */
	default_set_sd                   /* set_sd */
};

static WCHAR async_type_name[] = {'A', 's', 'y', 'n', 'c', 0};
static WCHAR async_queue_type_name[] = {'A', 's', 'y', 'n', 'c', '_', 'Q', 'u', 'e', 'u', 'e', 0};

POBJECT_TYPE async_object_type = NULL;
EXPORT_SYMBOL(async_object_type);

POBJECT_TYPE async_queue_object_type = NULL;
EXPORT_SYMBOL(async_queue_object_type);

static GENERIC_MAPPING async_mapping =
{
	STANDARD_RIGHTS_READ | SYNCHRONIZE | 0x1 /* QUERY_STATE */,
	STANDARD_RIGHTS_WRITE | SYNCHRONIZE | 0x2 /* MODIFY_STATE */,
	STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE | 0x1 /* QUERY_STATE */,
	STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3
};

static GENERIC_MAPPING async_queue_mapping =
{
	STANDARD_RIGHTS_READ | SYNCHRONIZE | 0x1 /* QUERY_STATE */,
	STANDARD_RIGHTS_WRITE | SYNCHRONIZE | 0x2 /* MODIFY_STATE */,
	STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE | 0x1 /* QUERY_STATE */,
	STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3
};

VOID
init_async_implement(VOID)
{
	OBJECT_TYPE_INITIALIZER ObjectTypeInitializer;
	UNICODE_STRING Name;

	memset(&ObjectTypeInitializer, 0, sizeof(ObjectTypeInitializer));
	init_unistr(&Name, async_type_name);
	ObjectTypeInitializer.Length = sizeof(ObjectTypeInitializer);
	ObjectTypeInitializer.DefaultNonPagedPoolCharge = sizeof(struct async);
	ObjectTypeInitializer.GenericMapping = async_mapping;
	ObjectTypeInitializer.PoolType = NonPagedPool;
	ObjectTypeInitializer.ValidAccessMask = EVENT_ALL_ACCESS;
	ObjectTypeInitializer.UseDefaultObject = TRUE;
	create_type_object(&ObjectTypeInitializer, &Name, &async_object_type);
}

VOID
init_async_queue_implement(VOID)
{
	OBJECT_TYPE_INITIALIZER ObjectTypeInitializer;
	UNICODE_STRING Name;

	memset(&ObjectTypeInitializer, 0, sizeof(ObjectTypeInitializer));
	init_unistr(&Name, async_queue_type_name);
	ObjectTypeInitializer.Length = sizeof(ObjectTypeInitializer);
	ObjectTypeInitializer.DefaultNonPagedPoolCharge = sizeof(struct async_queue);
	ObjectTypeInitializer.GenericMapping = async_queue_mapping;
	ObjectTypeInitializer.PoolType = NonPagedPool;
	ObjectTypeInitializer.ValidAccessMask = EVENT_ALL_ACCESS;
	ObjectTypeInitializer.UseDefaultObject = TRUE;
	create_type_object(&ObjectTypeInitializer, &Name, &async_queue_object_type);
}

static inline void async_event(struct async *async, int finished)
{
	if (async->queue->fd)
		fd_async_event(async->queue->fd, async->queue, async, async->status, finished);
}

static void async_dump(struct object *obj, int verbose)
{
}

static void async_destroy(struct object *obj)
{
	struct async *async = (struct async *)obj;

	list_del(&async->queue_entry);
	async_event(async, TRUE);

	if (async->timeout)
		remove_timeout_user(async->timeout);
	if (async->event)
		release_object(async->event);
	if (async->completion)
		release_object(async->completion);
	release_object(async->queue);
	release_object(async->thread);
}

static void async_queue_dump(struct object *obj, int verbose)
{
}

/* notifies client thread of new status of its async request */
void async_terminate(struct async *async, unsigned int status)
{
	PKAPC thread_apc;
	struct ethread *thread = async->thread->ethread;

	if (async->status != STATUS_PENDING) {
		/* already terminated, just update status */
		async->status = status;
		return;
	}

	if (async->queue->fd)
		status = fd_async_terminated(async->queue->fd, async->queue, async, status);

	if (status != STATUS_PENDING) {
		copy_to_user(&(((PIO_STATUS_BLOCK)(async->data.iosb))->async_status), &status, sizeof(unsigned int));

		thread_apc = kmalloc(sizeof(KAPC), GFP_KERNEL);
		apc_init(thread_apc,
				&thread->tcb,
				OriginalApcEnvironment,
				thread_special_apc,
				NULL,
				(PKNORMAL_ROUTINE)async->data.callback,
				UserMode,
				async->data.arg);

		insert_queue_apc(thread_apc, async->data.iosb, NULL, IO_NO_INCREMENT);

		/* set flag in block_thread() */
//		set_tsk_thread_flag(thread->et_task, TIF_APC);

		if (thread->et_task) {
			thread->tcb.wait_status = STATUS_USER_APC;
			set_tsk_need_resched(current);
			wake_up_process(thread->et_task);

			sys_kill(thread->et_task->pid, SIGUSR2);
		}
		async->status = status;
		async_event( async, FALSE );
		release_object(async);  /* so that it gets destroyed when the async is done */
	} else 
		async_event(async, FALSE);
}

/* callback for timeout on an async request */
static void async_timeout(void *private)
{
	struct async *async = private;

	async->timeout = NULL;
	async_terminate(async, async->timeout_status);
}

/* create a new async queue for a given fd */
struct async_queue *create_async_queue(struct fd *fd)
{
	struct async_queue *queue;
	NTSTATUS status = STATUS_SUCCESS;

	status = create_object(KernelMode,
			async_queue_object_type,
			NULL /* obj_attr*/,
			KernelMode,
			NULL,
			sizeof(struct async_queue),
			0,
			0,
			(PVOID *)&queue);

	if (NT_SUCCESS(status) && queue) {
		INIT_DISP_HEADER(&queue->obj.header, ASYNC_QUEUE, 
				sizeof(struct async_queue) / sizeof(ULONG), 0);
		BODY_TO_HEADER(&(queue->obj))->ops = &async_queue_ops;

		queue->fd = fd;
		INIT_LIST_HEAD(&queue->queue);
		INIT_DISP_HEADER(&queue->obj.header, ASYNC_QUEUE, sizeof(struct async_queue), 0);
	}
	return queue;
}

/* free an async queue, cancelling all async operations */
void free_async_queue(struct async_queue *queue)
{
	if (!queue)
		return;
	queue->fd = NULL;
	async_wake_up(queue, STATUS_HANDLES_CLOSED);
	release_object(queue);
}


/* create an async on a given queue of a fd */
struct async *create_async(struct w32thread *thread, struct async_queue *queue, const async_data_t *data)
{
	struct kevent *event = NULL;
	struct async *async;
	NTSTATUS status = STATUS_SUCCESS;

	if (data->event && !(event = get_event_obj(thread->process, data->event, EVENT_MODIFY_STATE)))
		return NULL;

	status = create_object(KernelMode,
			async_object_type,
			NULL /* obj_attr*/,
			KernelMode,
			NULL,
			sizeof(struct async),
			0,
			0,
			(PVOID *)&async);

	if (NT_SUCCESS(status) && async) {
		INIT_DISP_HEADER(&async->obj.header, ASYNC, 
				sizeof(struct async) / sizeof(ULONG), 0);
		BODY_TO_HEADER(&(async->obj))->ops = &async_ops;

		INIT_DISP_HEADER(&async->obj.header, ASYNC, sizeof(struct async), 0);
		async->thread  = (struct w32thread *)grab_object(thread);
		async->event   = event;
		async->status  = STATUS_PENDING;
		async->data    = *data;
		async->timeout = NULL;
		async->queue   = (struct async_queue *)grab_object(queue);
		async->completion = NULL;
		if (queue->fd)
			async->completion = fd_get_completion(queue->fd, &async->comp_key);

		list_add_before(&queue->queue, &async->queue_entry);
		grab_object(async);

		if (queue->fd)
			set_fd_signaled(queue->fd, 0);
		if (event)
			reset_event(event);
		return async;
	} else {
		if (event)
			release_object(event);
		return NULL;
	}
}

/* set the timeout of an async operation */
void async_set_timeout(struct async *async, timeout_t timeout, unsigned int status)
{
	if (async->timeout)
		remove_timeout_user(async->timeout);
	if (timeout != TIMEOUT_INFINITE)
		async->timeout = add_timeout_user(timeout, async_timeout, async);
	else async->timeout = NULL;
	async->timeout_status = status;
}

/* store the result of the client-side async callback */
void async_set_result(struct object *obj, unsigned int status, unsigned long total)
{
	struct async *async = (struct async *)obj;

	if (BODY_TO_HEADER(obj)->ops != &async_ops)
		return;  /* in case the client messed up the APC results */

	if (status == STATUS_PENDING) { /* restart it */
		status = async->status;
		async->status = STATUS_PENDING;
		grab_object(async);

		if (status != STATUS_ALERTED)  /* it was terminated in the meantime */
			async_terminate(async, status);
		else
			async_event(async, FALSE);
	}
	else {
		if (async->timeout)
			remove_timeout_user(async->timeout);
		async->timeout = NULL;
		async->status = status;
		if (async->completion && async->data.cvalue)
			add_completion(async->completion, async->comp_key, async->data.cvalue, status, total);
		if (async->data.apc) {
			apc_call_t data;
			memset(&data, 0, sizeof(data));
			data.type         = APC_USER;
			data.user.func    = async->data.apc;
			data.user.args[0] = (unsigned long)async->data.arg;
			data.user.args[1] = (unsigned long)async->data.iosb;
			data.user.args[2] = 0;
			thread_queue_apc(async->thread, NULL, &data);
		}
		if (async->event)
			set_event(async->event, EVENT_INCREMENT, FALSE);
		else if (async->queue->fd)
			set_fd_signaled(async->queue->fd, 1);
	}
}

/* check if there are any queued async operations */
int async_queued(struct async_queue *queue)
{
	return queue && list_head(&queue->queue);
}

/* check if an async operation is waiting to be alerted */
int async_waiting(struct async_queue *queue)
{
	struct list_head *ptr;
	struct async *async;

	if (!queue)
		return 0;
	if (!(ptr = (((&queue->queue)->next == &queue->queue) ? NULL: (&queue->queue)->next)))
		return 0;
	async = list_entry(ptr, struct async, queue_entry);
	return async->status == STATUS_PENDING;
}

int async_wake_up_by( struct async_queue *queue, struct w32process *process,
                      struct w32thread *thread, unsigned __int64 iosb, unsigned int status )
{
    struct list_head *ptr, *next;
    int woken = 0;

    if (!queue || (!process && !thread && !iosb)) return 0;

    LIST_FOR_EACH_SAFE( ptr, next, &queue->queue )
    {
        struct async *async = list_entry( ptr, struct async, queue_entry );
        if ( (!process || async->thread->process == process) &&
             (!thread || async->thread == thread) &&
             (!iosb || async->data.iosb == iosb) )
        {
            async_terminate( async, status );
            woken++;
        }
    }
    return woken;
}

/* wake up async operations on the queue */
void async_wake_up(struct async_queue *queue, unsigned int status)
{
	struct list_head *ptr, *next;

	if (!queue)
		return;

	list_for_each_safe(ptr, next, &queue->queue) {
		struct async *async = list_entry(ptr, struct async, queue_entry);
		async_terminate(async, status);
		if (status == STATUS_ALERTED)
			break;  /* only wake up the first one */
	}
}

DECL_HANDLER(async_set_result)
{
	struct object *object = (struct object *)get_wine_handle_obj(get_current_w32process(), req->handle, 0, NULL);
	struct fd *fd = NULL;

	if ((BODY_TO_HEADER(object))->ops->get_fd)
		fd = (BODY_TO_HEADER(object))->ops->get_fd(object);
	if (fd == NULL)
		return;

	add_completion_by_fd(fd, req->cvalue, req->status, req->total); 

	NtSetEvent(req->event, NULL);
	set_fd_signaled(fd, 1);
}
#endif /* CONFIG_UNIFIED_KERNEL */
