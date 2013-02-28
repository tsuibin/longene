/*
 * timer.c
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
 * timer.c:
 * Refered to Wine code
 */
#include "unistr.h"
#include "handle.h"

#ifdef CONFIG_UNIFIED_KERNEL

#define TIMER_QUERY_STATE          0x0001
#define TIMER_MODIFY_STATE         0x0002
#define TIMER_ALL_ACCESS           (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x3)

extern struct object_type *get_object_type(const struct unicode_str*);

struct timer
{
	struct object        obj;       /* object header */
	int                  manual;    /* manual reset */
	int                  signaled;  /* current signaled state */
	unsigned int         period;    /* timer period in ms */
	timeout_t            when;      /* next expiration */
	struct timeout_user *timeout; 	/* linux timer */
	struct w32thread    *thread;    /* thread that set the APC function */
	void                *callback;  /* callback APC function */
	void                *arg;       /* callback argument */
};

static void timer_dump(struct object *obj, int verbose);
static int timer_signaled(struct object *obj, struct w32thread *thread);
static int timer_satisfied(struct object *obj, struct w32thread *thread);
static struct object_type *timer_get_type(struct object *obj);
static unsigned int timer_map_access(struct object *obj, unsigned int access);
static void timer_destroy(struct object *obj);
struct security_descriptor *default_get_sd(struct object *obj);
int default_set_sd(struct object *obj, const struct security_descriptor *sd, unsigned int set_info);

static const struct object_ops timer_ops =
{
	sizeof(struct timer),      /* size */
	timer_dump,                /* dump */
	timer_get_type,            /* get_type */
	no_get_fd,                 /* get_fd */
	timer_map_access,          /* map_access */
	no_lookup_name,            /* lookup_name */
	no_open_file,              /* open_file */
	no_close_handle,           /* close_handle */
	timer_destroy,             /* destroy */

	timer_signaled,            /* signaled */
	timer_satisfied,           /* satisfied */
	no_signal,                 /* signal */
	default_get_sd,            /* get_sd */
	default_set_sd             /* set_sd */
};

static unsigned int timer_map_access(struct object *obj, unsigned int access)
{
    if (access & GENERIC_READ)
        access |= STANDARD_RIGHTS_READ | SYNCHRONIZE | TIMER_QUERY_STATE;
    if (access & GENERIC_WRITE)
        access |= STANDARD_RIGHTS_WRITE | TIMER_MODIFY_STATE;
    if (access & GENERIC_EXECUTE)
        access |= STANDARD_RIGHTS_EXECUTE;
    if (access & GENERIC_ALL)
        access |= TIMER_ALL_ACCESS;
    return access & ~(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);
}

static WCHAR timer_name[] = {'T','i','m','e','r',0};

POBJECT_TYPE timer_object_type = NULL;
EXPORT_SYMBOL(timer_object_type);

static GENERIC_MAPPING mapping =
{
	STANDARD_RIGHTS_READ | SYNCHRONIZE | 0x1 /* QUERY_STATE */,
	STANDARD_RIGHTS_WRITE | SYNCHRONIZE | 0x2 /* MODIFY_STATE */,
	STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE | 0x1 /* QUERY_STATE */,
	STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3
};

VOID
init_timer_implement(VOID)
{
	OBJECT_TYPE_INITIALIZER ObjectTypeInitializer;
	UNICODE_STRING Name;

	memset(&ObjectTypeInitializer, 0, sizeof(ObjectTypeInitializer));
	init_unistr(&Name, timer_name);
	ObjectTypeInitializer.Length = sizeof(ObjectTypeInitializer);
	ObjectTypeInitializer.DefaultNonPagedPoolCharge = sizeof(struct timer);
	ObjectTypeInitializer.GenericMapping = mapping;
	ObjectTypeInitializer.PoolType = NonPagedPool;
	ObjectTypeInitializer.ValidAccessMask = EVENT_ALL_ACCESS;
	ObjectTypeInitializer.UseDefaultObject = TRUE;
	create_type_object(&ObjectTypeInitializer, &Name, &timer_object_type);
}
/* create a timer object */
static struct timer *create_timer(struct directory *root, const struct unicode_str *name,
					unsigned int attr, int manual)
{
	struct timer *timer;

	kdebug("\n");
	if ((timer = create_named_object_dir(root, name, attr, &timer_ops))) {
		if (get_error() != STATUS_OBJECT_NAME_EXISTS) {
			/* initialize it if it didn't already exist */
			INIT_DISP_HEADER(&timer->obj.header, TIMER, 
					sizeof(struct timer) / sizeof(ULONG), 0);
			timer->manual   = manual;
			timer->signaled = 0;
			timer->when     = 0;
			timer->period   = 0;
			timer->timeout  = NULL;
			timer->thread   = NULL;
		}
	}
	return timer;
}

/* callback on timer expiration */
static void timer_callback(void *private)
{
	struct timer *timer = (struct timer *)private;

	kdebug("\n");
	/* queue an APC */
	if (timer->thread) {
		apc_call_t data;

		memset(&data, 0, sizeof(data));
		if (timer->callback) {
			data.type       = APC_TIMER;
			data.timer.func = timer->callback;
			data.timer.time = timer->when;
			data.timer.arg  = timer->arg;
		}
		else data.type = APC_NONE;  /* wake up only */

		if (!thread_queue_apc(timer->thread, &timer->obj, &data)) {
			release_object(timer->thread);
			timer->thread = NULL;
		}
	}

	if (timer->period)  /* schedule the next expiration */ {
		timer->when += (timeout_t)timer->period * 10000;
		timer->timeout = add_timeout_user(timer->when, timer_callback, timer);
	}
	else timer->timeout = NULL;

	/* wake up waiters */
	timer->signaled = 1;
	uk_wake_up(&timer->obj, 0);
}

/* cancel a running timer */
static int cancel_timer(struct timer *timer)
{
	int signaled = timer->signaled;

	kdebug("\n");
	if (timer->timeout) {
		remove_timeout_user(timer->timeout);
		timer->timeout = NULL;
	}
	if (timer->thread) {
		thread_cancel_apc(timer->thread, &timer->obj, APC_TIMER);
		release_object(timer->thread);
		timer->thread = NULL;
	}
	return signaled;
}

/* set the timer expiration and period */
static int set_timer(struct timer *timer, timeout_t expire, unsigned int period,
				void *callback, void *arg)
{
	int signaled = cancel_timer(timer);

	kdebug("\n");
	if (timer->manual) {
		period = 0;  /* period doesn't make any sense for a manual timer */
		timer->signaled = 0;
	}
	timer->when 	= (expire <= 0) ? current_time - expire : max(expire, current_time);
	kdebug("timer->when = %lld\n", timer->when);
	timer->period   = period;
	timer->callback = callback;
	timer->arg      = arg;
	if (callback)
		timer->thread = (struct w32thread *)grab_object(current_thread);
	timer->timeout = add_timeout_user(timer->when, timer_callback, timer);
	return signaled;
}

static void timer_dump(struct object *obj, int verbose)
{
}

static struct object_type *timer_get_type(struct object *obj)
{
	static const WCHAR name[] = {'T','i','m','e','r'};
	static const struct unicode_str str = {name, sizeof(name)};
	return get_object_type(&str);
}

static int timer_signaled(struct object *obj, struct w32thread *thread)
{
	struct timer *timer = (struct timer *)obj;
	return timer->signaled;
}

static int timer_satisfied(struct object *obj, struct w32thread *thread)
{
	struct timer *timer = (struct timer *)obj;
	kdebug("\n");
	if (!timer->manual)
		timer->signaled = 0;
	return 0;
}

static void timer_destroy(struct object *obj)
{
	struct timer *timer = (struct timer *)obj;
	kdebug("\n");
	if (timer->timeout)
		remove_timeout_user(timer->timeout);
	if (timer->thread)
		release_object(timer->thread);
}

/* create a timer */
DECL_HANDLER(create_timer)
{
	struct timer *timer;
	struct unicode_str name;
	struct directory *root = NULL;

	kdebug("\n");
	reply->handle = 0;
	get_req_unicode_str(&name);

	if ((timer = create_timer(req->rootdir, &name, req->attributes, req->manual))) {
		reply->handle = alloc_handle(get_current_w32process(), timer, req->access, req->attributes);
		release_object(timer);
	}

	if (root)
		release_object(root);
}

/* open a handle to a timer */
DECL_HANDLER(open_timer)
{
	struct unicode_str name;
	struct directory *root = NULL;
	struct timer *timer;

	kdebug("\n");
	get_req_unicode_str(&name);

	if ((timer = open_object_dir(req->rootdir, &name, req->attributes, &timer_ops))) {
		reply->handle = alloc_handle(get_current_w32process(), &timer->obj, req->access, req->attributes);
		release_object(timer);
	}

	if (root)
		release_object(root);
}

/* set a waitable timer */
DECL_HANDLER(set_timer)
{
	struct timer *timer;

	kdebug("\n");
	if ((timer = (struct timer *)get_wine_handle_obj(get_current_w32process(), req->handle,
					TIMER_MODIFY_STATE, &timer_ops))) {
		reply->signaled = set_timer(timer, req->expire, req->period, req->callback, req->arg);
		release_object(timer);
	}
}

/* cancel a waitable timer */
DECL_HANDLER(cancel_timer)
{
	struct timer *timer;

	kdebug("\n");
	if ((timer = (struct timer *)get_wine_handle_obj(get_current_w32process(), req->handle,
					TIMER_MODIFY_STATE, &timer_ops))) {
		reply->signaled = cancel_timer(timer);
		release_object(timer);
	}
}

/* Get information on a waitable timer */
DECL_HANDLER(get_timer_info)
{
	struct timer *timer;

	kdebug("\n");
	if ((timer = (struct timer *)get_wine_handle_obj(get_current_w32process(), req->handle,
					TIMER_QUERY_STATE, &timer_ops))) {
		reply->when      = timer->when;
		reply->signaled  = timer->signaled;
		release_object(timer);
	}
}
#endif /* CONFIG_UNIFIED_KERNEL */
