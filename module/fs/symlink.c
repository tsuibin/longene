/*
 * symlink.c
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
 * symlink.c:
 * Refered to Wine code
 */
#include "handle.h"

#ifdef CONFIG_UNIFIED_KERNEL

#define SYMBOLIC_LINK_QUERY 0x0001
#define SYMBOLIC_LINK_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x1)

struct symlink
{
	struct object    obj;       /* object header */
	WCHAR           *target;    /* target of the symlink */
	data_size_t      len;       /* target len in bytes */
};

static void symlink_dump(struct object *obj, int verbose);
static struct object_type *symlink_get_type(struct object *obj);
static unsigned int symlink_map_access(struct object *obj, unsigned int access);
static struct object *symlink_lookup_name(struct object *obj, struct unicode_str *name,
					unsigned int attr);
static void symlink_destroy(struct object *obj);

extern struct object_type *get_object_type(const struct unicode_str*);

static const struct object_ops symlink_ops =
{
	sizeof(struct symlink),       /* size */
	symlink_dump,                 /* dump */
	symlink_get_type,             /* get_type */
	no_get_fd,                    /* get_fd */
	symlink_map_access,           /* map_access */
	symlink_lookup_name,          /* lookup_name */
	no_open_file,                 /* open_file */
	no_close_handle,              /* close_handle */
	symlink_destroy,              /* destroy */

	NULL,                      /* signaled */
	NULL,                      /* satisfied */
	no_signal,                 /* signal */
	default_get_sd,            /* get_sd */
	default_set_sd             /* set_sd */
};

static void symlink_dump(struct object *obj, int verbose)
{
}

static struct object_type *symlink_get_type(struct object *obj)
{
	static const WCHAR name[] = {'S','y','m','b','o','l','i','c','L','i','n','k'};
	static const struct unicode_str str = {name, sizeof(name)};
	return get_object_type(&str);
}

static struct object *symlink_lookup_name(struct object *obj, struct unicode_str *name,
					unsigned int attr)
{
	struct symlink *symlink = (struct symlink *)obj;
	struct unicode_str target_str, name_left;
	struct object *target;

	if (attr & OBJ_OPENLINK)
		return NULL;

	target_str.str = symlink->target;
	target_str.len = symlink->len;
	if ((target = find_object_dir(NULL, &target_str, attr, &name_left))) {
		if (name_left.len) {
			release_object(target);
			target = NULL;
			set_error(STATUS_OBJECT_PATH_NOT_FOUND);
		}
	}
	return target;
}

static unsigned int symlink_map_access(struct object *obj, unsigned int access)
{
	if (access & GENERIC_READ)
		access |= STANDARD_RIGHTS_READ | SYMBOLIC_LINK_QUERY;
	if (access & GENERIC_WRITE)
		access |= STANDARD_RIGHTS_WRITE;
	if (access & GENERIC_EXECUTE)
		access |= STANDARD_RIGHTS_EXECUTE;
	if (access & GENERIC_ALL)
		access |= SYMBOLIC_LINK_ALL_ACCESS;
	return access & ~(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);
}

static void symlink_destroy(struct object *obj)
{
	struct symlink *symlink = (struct symlink *)obj;
	free(symlink->target);
}

struct symlink *create_symlink(struct directory *root, const struct unicode_str *name,
				unsigned int attr, const struct unicode_str *target)
{
	struct symlink *symlink;

	if (!target->len) {
		set_error(STATUS_INVALID_PARAMETER);
		return NULL;
	}
	if ((symlink = create_named_object_dir(root, name, attr, &symlink_ops)) &&
			(get_error() != STATUS_OBJECT_NAME_EXISTS)) {
		INIT_DISP_HEADER(&symlink->obj.header, SYMLINK, sizeof(struct symlink) / sizeof(ULONG), 0);
		if ((symlink->target = memdup(target->str, target->len)))
			symlink->len = target->len;
		else {
			release_object(symlink);
			symlink = NULL;
		}
	}
	return symlink;
}

NTSTATUS
io_create_symbol_link(PUNICODE_STRING SymbolicLinkName,
		PUNICODE_STRING TargetName)
{
	OBJECT_ATTRIBUTES ObjectAttributes;
	HANDLE Handle;
	NTSTATUS Status;

	INIT_OBJECT_ATTR(&ObjectAttributes,
			SymbolicLinkName,
			OBJ_PERMANENT,
			NULL,
			NULL);

	Status = NtCreateSymbolicLinkObject(&Handle,
			STANDARD_RIGHTS_REQUIRED | 0x1,
			&ObjectAttributes,
			TargetName);
	if (Status != STATUS_SUCCESS) {
		return(Status);
	}

	NtClose(Handle);

	return STATUS_SUCCESS;
}

/* create a symbolic link object */
DECL_HANDLER(create_symlink)
{
	struct symlink *symlink;
	struct unicode_str name, target;
	struct directory *root = NULL;

	ktrace("\n");
	if (req->name_len > get_req_data_size()) {
		set_error(STATUS_INVALID_PARAMETER);
		return;
	}
	name.str   = get_req_data();
	target.str = name.str + req->name_len / sizeof(WCHAR);
	name.len   = (target.str - name.str) * sizeof(WCHAR);
	target.len = ((get_req_data_size() - name.len) / sizeof(WCHAR)) * sizeof(WCHAR);

	if ((symlink = create_symlink(req->rootdir, &name, req->attributes, &target))) {
		reply->handle = alloc_handle(get_current_w32process(), symlink, req->access, req->attributes);
		release_object(symlink);
	}

	if (root)
		release_object(root);
}

/* open a symbolic link object */
DECL_HANDLER(open_symlink)
{
	struct unicode_str name;
	struct directory *root = NULL;
	struct symlink *symlink;

	ktrace("\n");
	get_req_unicode_str(&name);

	if ((symlink = open_object_dir(req->rootdir, &name, req->attributes | OBJ_OPENLINK, &symlink_ops))) {
		reply->handle = alloc_handle(get_current_w32process(), &symlink->obj, req->access, req->attributes);
		release_object(symlink);
	}

	if (root)
		release_object(root);
}

/* query a symbolic link object */
DECL_HANDLER(query_symlink)
{
	struct symlink *symlink;

	ktrace("\n");
	symlink = (struct symlink *)get_wine_handle_obj(get_current_w32process(), req->handle,
			SYMBOLIC_LINK_QUERY, &symlink_ops);
	if (!symlink)
		return;

	if (get_reply_max_size() < symlink->len)
		set_error(STATUS_BUFFER_TOO_SMALL);
	else
		set_reply_data(symlink->target, symlink->len);
	release_object(symlink);
}
#endif /* CONFIG_UNIFIED_KERNEL */
