/*
 * completion.c
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
 * completion.c:
 * Refered to Wine code
 */
#include "unistr.h"
#include "handle.h"

#ifdef CONFIG_UNIFIED_KERNEL

#define IO_COMPLETION_QUERY_STATE  0x0001
#define IO_COMPLETION_MODIFY_STATE 0x0002
#define IO_COMPLETION_ALL_ACCESS   (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x3)

extern struct object_type *get_object_type(const struct unicode_str *name);

struct uk_completion
{
	struct object  obj;
	struct list_head    queue;
	unsigned int   depth;
};

static void completion_dump(struct object*, int);
static struct object_type *completion_get_type(struct object *obj);
static void completion_destroy(struct object *);
static int completion_signaled(struct object *obj, struct w32thread *thread);

static const struct object_ops completion_ops =
{
	sizeof(struct uk_completion), /* size */
	completion_dump,           /* dump */
	completion_get_type,       /* get_type */
	no_get_fd,                 /* get_fd */
	no_map_access,             /* map_access */
	no_lookup_name,            /* lookup_name */
	no_open_file,              /* open_file */
	no_close_handle,           /* close_handle */
	completion_destroy,        /* destroy */

	completion_signaled,       /* signaled */
	no_satisfied,              /* satisfied */
	no_signal,                 /* signal */
	default_get_sd,            /* get_sd */
	default_set_sd             /* set_sd */
};

struct comp_msg
{
	struct   list_head queue_entry;
	unsigned long ckey;
	unsigned long cvalue;
	unsigned long information;
	unsigned int  status;
};

static WCHAR completion_type_name[] = {'C', 'o', 'm', 'p', 'l', 'e', 't', 'i', 'o', 'n', 0};

POBJECT_TYPE completion_object_type = NULL;
EXPORT_SYMBOL(completion_object_type);

static GENERIC_MAPPING completion_mapping =
{
	STANDARD_RIGHTS_READ | SYNCHRONIZE | 0x1 /* QUERY_STATE */,
	STANDARD_RIGHTS_WRITE | SYNCHRONIZE | 0x2 /* MODIFY_STATE */,
	STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE | 0x1 /* QUERY_STATE */,
	STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3
};

VOID
init_completion_implement(VOID)
{
	OBJECT_TYPE_INITIALIZER ObjectTypeInitializer;
	UNICODE_STRING Name;

	memset(&ObjectTypeInitializer, 0, sizeof(ObjectTypeInitializer));
	init_unistr(&Name, completion_type_name);
	ObjectTypeInitializer.Length = sizeof(ObjectTypeInitializer);
	ObjectTypeInitializer.DefaultNonPagedPoolCharge = sizeof(struct uk_completion);
	ObjectTypeInitializer.GenericMapping = completion_mapping;
	ObjectTypeInitializer.PoolType = NonPagedPool;
	ObjectTypeInitializer.ValidAccessMask = EVENT_ALL_ACCESS;
	ObjectTypeInitializer.UseDefaultObject = TRUE;
	create_type_object(&ObjectTypeInitializer, &Name, &completion_object_type);
}

static void completion_destroy(struct object *obj)
{
	struct uk_completion *completion = (struct uk_completion *) obj;
	struct comp_msg *tmp, *next;

	LIST_FOR_EACH_ENTRY_SAFE(tmp, next, &completion->queue, struct comp_msg, queue_entry) {
		free(tmp);
	}
}

static void completion_dump(struct object *obj, int verbose)
{
}

static struct object_type *completion_get_type(struct object *obj)
{
	static const WCHAR name[] = {'C','o','m','p','l','e','t','i','o','n'};
	static const struct unicode_str str = {name, sizeof(name)};
	return get_object_type(&str);
}

static int completion_signaled(struct object *obj, struct w32thread *thread)
{
	struct uk_completion *completion = (struct uk_completion *)obj;

	return !list_empty(&completion->queue);
}

static struct uk_completion *create_completion(struct directory *root, 
				const struct unicode_str *name, unsigned int attr, unsigned int concurrent)
{
	struct uk_completion *completion;

	if ((completion = create_named_object_dir(root, name, attr, &completion_ops))) {
		if (get_error() != STATUS_OBJECT_NAME_EXISTS) {
			INIT_DISP_HEADER(&completion->obj.header, COMPLETION,
					sizeof(struct completion) / sizeof(ULONG), 0);
			INIT_LIST_HEAD(&completion->queue);
			completion->depth = 0;
		}
	}

	return completion;
}

struct uk_completion *get_completion_obj(struct w32process *process, obj_handle_t handle, unsigned int access)
{
	return (struct uk_completion *)get_wine_handle_obj(process, handle, access, &completion_ops);
}

void add_completion(struct uk_completion *completion, unsigned long ckey,
				unsigned long cvalue, unsigned int status, unsigned long information)
{
	struct comp_msg *msg = mem_alloc(sizeof(*msg));

	if (!msg)
		return;

	msg->ckey = ckey;
	msg->cvalue = cvalue;
	msg->status = status;
	msg->information = information;
	list_add_before(&completion->queue, &msg->queue_entry);
	completion->depth++;
	uk_wake_up(&completion->obj, 0);
}

/* create a completion */
DECL_HANDLER(create_completion)
{
	struct uk_completion *completion;
	struct unicode_str name;
	struct directory *root = NULL;

	ktrace("\n");
	reply->handle = 0;

	get_req_unicode_str(&name);

	if ((completion = create_completion(req->rootdir, &name, req->attributes, req->concurrent)) != NULL) {
		reply->handle = alloc_handle(get_current_w32process(), completion, req->access, req->attributes);
		release_object(completion);
	}

	if (root)
		release_object(root);
}

/* open a completion */
DECL_HANDLER(open_completion)
{
	struct uk_completion *completion;
	struct unicode_str name;
	struct directory *root = NULL;

	ktrace("\n");
	reply->handle = 0;

	get_req_unicode_str(&name);

	if ((completion = open_object_dir(req->rootdir, &name, req->attributes, &completion_ops)) != NULL) {
		reply->handle = alloc_handle(get_current_w32process(), completion, req->access, req->attributes);
		release_object(completion);
	}

	if (root)
		release_object(root);
}

/* add completion to completion port */
DECL_HANDLER(add_completion)
{
	struct uk_completion* completion; 

	ktrace("\n");
	completion = get_completion_obj(get_current_w32process(), req->handle, IO_COMPLETION_MODIFY_STATE);
	if (!completion)
		return;

	add_completion(completion, req->ckey, req->cvalue, req->status, req->information);

	release_object(completion);
}

/* get completion from completion port */
DECL_HANDLER(remove_completion)
{
	struct uk_completion* completion; 
	struct list_head *entry;
	struct comp_msg *msg;

	ktrace("\n");
	completion = get_completion_obj(get_current_w32process(), req->handle, IO_COMPLETION_MODIFY_STATE);
	if (!completion)
		return;

	entry = list_head(&completion->queue);
	if (!entry)
		set_error(STATUS_PENDING);
	else {
		list_del(entry);
		completion->depth--;
		msg = LIST_ENTRY(entry, struct comp_msg, queue_entry);
		reply->ckey = msg->ckey;
		reply->cvalue = msg->cvalue;
		reply->status = msg->status;
		reply->information = msg->information;
		free(msg);
	}

	release_object(completion);
}

/* get queue depth for completion port */
DECL_HANDLER(query_completion)
{
	struct uk_completion* completion; 

	ktrace("\n");
	completion = get_completion_obj(get_current_w32process(), req->handle, IO_COMPLETION_QUERY_STATE);
	if (!completion)
		return;

	reply->depth = completion->depth;

	release_object(completion);
}
#endif /* CONFIG_UNIFIED_KERNEL */
