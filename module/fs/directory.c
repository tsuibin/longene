/*
 * directory.c
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
 * directory.c:
 * Refered to Wine code
 */
#include "io.h"
#include "unistr.h"
#include "wineserver/lib.h"

#ifdef CONFIG_UNIFIED_KERNEL

#define HASH_SIZE 7  /* default hash size */

struct object_type
{
	struct object     obj;        /* object header */
};
struct object_type *get_object_type(const struct unicode_str *name);

static void object_type_dump(struct object *obj, int verbose);
static struct object_type *object_type_get_type(struct object *obj);

static const struct object_ops object_type_ops =
{
	sizeof(struct object_type),   /* size */
	object_type_dump,             /* dump */
	object_type_get_type,         /* get_type */
	no_get_fd,                    /* get_fd */
	no_map_access,                /* map_access */
	no_lookup_name,               /* lookup_name */
	no_open_file,                 /* open_file */
	no_close_handle,              /* close_handle */
	no_destroy,                   /* destroy */

	NULL,                      /* signaled */
	NULL,                      /* satisfied */
	no_signal,                 /* signal */
	default_get_sd,            /* get_sd */
	default_set_sd             /* set_sd */
};


struct directory
{
	struct object     obj;        /* object header */
	struct namespace *entries;    /* directory's name space */
};

extern HANDLE base_dir_handle;
static void directory_dump(struct object *obj, int verbose);
static struct object_type *directory_get_type(struct object *obj);
static struct object *directory_lookup_name(struct object *obj, struct unicode_str *name,
					unsigned int attr);
static void directory_destroy(struct object *obj);
extern unsigned int default_fd_map_access(struct object *obj, unsigned int access);

static const struct object_ops directory_ops =
{
	sizeof(struct directory),     /* size */
	directory_dump,               /* dump */
	directory_get_type,           /* get_type */
	no_get_fd,                    /* get_fd */
	default_fd_map_access,        /* map_access */
	directory_lookup_name,        /* lookup_name */
	no_open_file,                 /* open_file */
	no_close_handle,              /* close_handle */
	directory_destroy,            /* destroy */

	NULL,                      /* signaled */
	NULL,                      /* satisfied */
	no_signal,                 /* signal */
	default_get_sd,            /* get_sd */
	default_set_sd             /* set_sd */
};

static struct directory *dir_objtype;

static WCHAR link_local[] = {'\\', 'B', 'a', 's', 'e', 'N', 'a', 'm', 'e', 'd', 'O', 'b', 'j', 'e', 'c', 't', 's', '\\', 'L', 'o', 'c', 'a', 'l', 0};
static WCHAR link_global1[] = {'\\', '?', '?', '\\', 'G', 'l', 'o', 'b', 'a', 'l', 0};
static WCHAR link_global2[] = {'\\', 'B', 'a', 's', 'e', 'N', 'a', 'm', 'e', 'd', 'O', 'b', 'j', 'e', 'c', 't', 's', '\\', 'G', 'l', 'o', 'b', 'a', 'l', 0};
static WCHAR base_dir[] = {'\\', 'B', 'a', 's', 'e', 'N', 'a', 'm', 'e', 'd', 'O', 'b', 'j', 'e', 'c', 't', 's', 0};
static WCHAR dos_root[] = {'\\', '?', '?', 0};

void init_directories(void)
{
	UNICODE_STRING Name, LinkName;

	init_unistr(&Name, (PWSTR)base_dir);
	init_unistr(&LinkName, (PWSTR)link_local);
	io_create_symbol_link(&LinkName, &Name);

	init_unistr(&Name, (PWSTR)dos_root);
	init_unistr(&LinkName, (PWSTR)link_global1);
	io_create_symbol_link(&LinkName, &Name);

	init_unistr(&Name, (PWSTR)base_dir);
	init_unistr(&LinkName, (PWSTR)link_global2);
	io_create_symbol_link(&LinkName, &Name);
}

static void object_type_dump(struct object *obj, int verbose)
{
}


static struct object_type *object_type_get_type(struct object *obj)
{
	static const WCHAR name[] = {'O','b','j','e','c','t','T','y','p','e'};
	static const struct unicode_str str = {name, sizeof(name)};
	return get_object_type(&str);
}

static void directory_dump(struct object *obj, int verbose)
{
}

static struct object_type *directory_get_type(struct object *obj)
{
	static const WCHAR name[] = {'D','i','r','e','c','t','o','r','y'};
	static const struct unicode_str str = {name, sizeof(name)};
	return get_object_type(&str);
}

static struct object *directory_lookup_name(struct object *obj, struct unicode_str *name,
					unsigned int attr)
{
	POBJECT_DIRECTORY dir = (POBJECT_DIRECTORY)obj;
	struct object *found;
	UNICODE_STRING tmp;
	const WCHAR *p;

	if (!(p = memchrW(name->str, '\\', name->len / sizeof(WCHAR))))
		/* Last element in the path name */
		tmp.Length = name->len;
	else
		tmp.Length = (p - name->str) * sizeof(WCHAR);
	tmp.MaximumLength = tmp.Length + sizeof(WCHAR);

	tmp.Buffer = (PWSTR)name->str;
	if ((found = lookup_obdir_entry(dir, &tmp, attr))) {
		/* Skip trailing \\ */
		if (p) {
			p++;
			tmp.Length += sizeof(WCHAR);
		}
		/* Move to the next element*/
		name->str = p;
		name->len -= tmp.Length;
		return found;
	}

	if (name->str) {
		if (tmp.Length == 0) /* Double backslash */
			set_error(STATUS_OBJECT_NAME_INVALID);
		else if (p)  /* Path still has backslashes */
			set_error(STATUS_OBJECT_PATH_NOT_FOUND);
		else
			clear_error();
	}
	return NULL;
}

static void directory_destroy(struct object *obj)
{
	POBJECT_DIRECTORY dir = (POBJECT_DIRECTORY)obj;
	delete_obdir_entry(dir);
}

static POBJECT_DIRECTORY create_directory(HANDLE root, const struct unicode_str *name,
					unsigned int attr, unsigned int hash_size)
{
	POBJECT_DIRECTORY dir;

	if ((dir = create_named_object_dir(root, name, attr, &directory_ops)) &&
			get_error() != STATUS_OBJECT_NAME_EXISTS) {
		INIT_DISP_HEADER(&dir->obj.header, DIRECTORY,
				sizeof(OBJECT_DIRECTORY) / sizeof(ULONG), 0);
	}
	return dir;
}


/******************************************************************************
 * Find an object by its name in a given root object
 *
 * PARAMS
 *  root      [I] directory to start search from or NULL to start from \\
 *  name      [I] object name to search for
 *  attr      [I] OBJECT_ATTRIBUTES.Attributes
 *  name_left [O] [optional] leftover name if object is not found
 *
 * RETURNS
 *  NULL:      If params are invalid
 *  Found:     If object with exact name is found returns that object
 *             (name_left->len == 0). Object's refcount is incremented
 *  Not found: The last matched parent. (name_left->len > 0)
 *             Parent's refcount is incremented.
 */
struct object *find_object_dir(HANDLE root, const struct unicode_str *name,
					unsigned int attr, struct unicode_str *name_left)
{
	UNICODE_STRING obj_name;
	PACCESS_STATE access = NULL;
	BOOLEAN locked;
	PVOID object = NULL;
	NTSTATUS status;

	obj_name.Length = (USHORT)name->len;
	obj_name.MaximumLength = obj_name.Length + sizeof(WCHAR);
	obj_name.Buffer = (PWSTR)name->str;

	status = lookup_object_name(root,
			&obj_name,
			attr,
			NULL,
			KernelMode,
			NULL,
			NULL,
			NULL,
			&access,
			&locked,
			&object);

	if (!NT_SUCCESS(status)) {
		return NULL;
	}

	name_left = NULL;

	return (struct object *)object;
}

/* create a named (if name is present) or unnamed object. */
void *create_named_object_dir(HANDLE root, const struct unicode_str *name,
					unsigned int attributes, const struct object_ops *ops)
{
	return create_wine_object(root, ops, name, NULL);
}

/* open a new handle to an existing object */
void *open_object_dir(HANDLE root, const struct unicode_str *name,
				unsigned int attr, const struct object_ops *ops)
{
	UNICODE_STRING obj_name;
	PACCESS_STATE access = NULL;
	BOOLEAN locked;
	PVOID object = NULL;
	NTSTATUS status;

	obj_name.Length = (USHORT)name->len;
	obj_name.MaximumLength = obj_name.Length + sizeof(WCHAR);
	obj_name.Buffer = (PWSTR)kmalloc(obj_name.MaximumLength, GFP_KERNEL);
	memcpy(obj_name.Buffer, name->str, obj_name.Length);
	obj_name.Buffer[obj_name.Length / sizeof(WCHAR)] = 0;

	status = lookup_object_name(root,
			&obj_name,
			attr,
			NULL,
			(KPROCESSOR_MODE)KernelMode,
			NULL,
			NULL,
			NULL,
			access,
			&locked,
			&object);
	kfree(obj_name.Buffer);

	if (!NT_SUCCESS(status))
		set_error(status);
	if (!object)
		set_error(STATUS_OBJECT_NAME_NOT_FOUND);

	return object;
}

/* retrieve an object type, creating it if needed */
struct object_type *get_object_type(const struct unicode_str *name)
{
	struct object_type *type;

	if ((type = open_object_dir(dir_objtype, name, 0, &object_type_ops)))
		return type;

	if ((type = create_named_object_dir(dir_objtype, name, 0, &object_type_ops)))
	{
		grab_object(type);
		make_object_static(&type->obj);
		clear_error();
	}
	return type;
}

/* create a directory object */
DECL_HANDLER(create_directory)
{
	struct unicode_str name;
	POBJECT_DIRECTORY dir;

	ktrace("\n");
	reply->handle = 0;
	get_req_unicode_str(&name);

	if ((dir = create_directory(req->rootdir, &name, req->attributes, HASH_SIZE))) {
		reply->handle = alloc_handle(get_current_w32process(), dir, req->access, req->attributes);
		release_object(dir);
	}
}

/* open a directory object */
DECL_HANDLER(open_directory)
{
	struct unicode_str name;
	POBJECT_DIRECTORY dir;

	ktrace("\n");
	get_req_unicode_str(&name);

	if ((dir = open_object_dir(req->rootdir, &name, req->attributes, &directory_ops)))
	{
		reply->handle = alloc_handle(get_current_w32process(), dir, req->access, req->attributes);
		release_object(dir);
	}
}

/* FIXME we don't need it */
/* get a directory entry by index */
DECL_HANDLER(get_directory_entry)
{
	ktrace("\n");
}
#endif /* CONFIG_UNIFIED_KERNEL */
