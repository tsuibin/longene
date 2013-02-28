/*
 * winstation.c
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
 * winstation.c:
 * Refered to Wine code
 */
#define WIN32_NO_STATUS

#include "unistr.h"
#include "handle.h"
#include "winuser.h"

#ifdef CONFIG_UNIFIED_KERNEL

extern struct object_type *get_object_type(const struct unicode_str*);
extern HANDLE open_object(HANDLE RootDirectory, const struct unicode_str *name,
		const struct object_ops*, unsigned int access, unsigned int attr);
extern struct msg_queue *get_current_queue(void);
extern BOOL check_object_access(struct object*, unsigned int*);

static WCHAR WinStationName[] = {'W', 'i', 'n', 'S', 't', 'a', 't', 'i', 'o', 'n', 0};
static POBJECT_DIRECTORY winsta_root = NULL;
static HANDLE winsta_root_handle = NULL;
NTSTATUS create_winsta_root(void);

static struct list_head winstation_list = LIST_INIT(winstation_list);

static void winstation_dump(struct object *obj, int verbose);
static struct object_type *winstation_get_type(struct object *obj);
static int winstation_close_handle(struct object *obj, struct w32process *process, obj_handle_t handle);
static void winstation_destroy(struct object *obj);
static unsigned int winstation_map_access(struct object *obj, unsigned int access);
static void desktop_dump(struct object *obj, int verbose);
static struct object_type *desktop_get_type(struct object *obj);
static int desktop_close_handle(struct object *obj, struct w32process *process, obj_handle_t handle);
static void desktop_destroy(struct object *obj);
static unsigned int desktop_map_access(struct object *obj, unsigned int access);

static const struct object_ops winstation_ops =
{
	sizeof(struct winstation),    /* size */
	winstation_dump,              /* dump */
	winstation_get_type,          /* get_type */
	no_get_fd,                    /* get_fd */
	winstation_map_access,        /* map_access */
	no_lookup_name,               /* lookup_name */
	no_open_file,                 /* open_file */
	winstation_close_handle,      /* close_handle */
	winstation_destroy,           /* destroy */

	NULL,                         /* signaled */
	NULL,                         /* satisfied */
	no_signal,                    /* signal */
	default_get_sd,               /* get_sd */
	default_set_sd                /* set_sd */
};

static const struct object_ops desktop_ops =
{
	sizeof(struct desktop),       /* size */
	desktop_dump,                 /* dump */
	desktop_get_type,             /* get_type */
	no_get_fd,                    /* get_fd */
	desktop_map_access,           /* map_access */
	no_lookup_name,               /* lookup_name */
	no_open_file,                 /* open_file */
	desktop_close_handle,         /* close_handle */
	desktop_destroy,              /* destroy */

	NULL,                         /* signaled */
	NULL,                         /* satisfied */
	no_signal,                    /* signal */
	default_get_sd,               /* get_sd */
	default_set_sd                /* set_sd */
};

#define DESKTOP_ALL_ACCESS 0x01ff

static WCHAR winstation_type_name[] = {'W', 'i', 'n', 's', 't', 'a', 't', 'i', 'o', 'n', 0};
static WCHAR desktop_type_name[] = {'D', 'e', 's', 'k', 't', 'o', 'p', 0};

POBJECT_TYPE winstation_object_type = NULL;
EXPORT_SYMBOL(winstation_object_type);

POBJECT_TYPE desktop_object_type = NULL;
EXPORT_SYMBOL(desktop_object_type);

static GENERIC_MAPPING winstation_mapping =
{
	STANDARD_RIGHTS_READ | SYNCHRONIZE | 0x1 /* QUERY_STATE */,
	STANDARD_RIGHTS_WRITE | SYNCHRONIZE | 0x2 /* MODIFY_STATE */,
	STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE | 0x1 /* QUERY_STATE */,
	STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3
};

static GENERIC_MAPPING desktop_mapping =
{
	STANDARD_RIGHTS_READ | SYNCHRONIZE | 0x1 /* QUERY_STATE */,
	STANDARD_RIGHTS_WRITE | SYNCHRONIZE | 0x2 /* MODIFY_STATE */,
	STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE | 0x1 /* QUERY_STATE */,
	STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3
};

VOID
init_winstation_implement(VOID)
{
	OBJECT_TYPE_INITIALIZER ObjectTypeInitializer;
	UNICODE_STRING Name;

	memset(&ObjectTypeInitializer, 0, sizeof(ObjectTypeInitializer));
	init_unistr(&Name, winstation_type_name);
	ObjectTypeInitializer.Length = sizeof(ObjectTypeInitializer);
	ObjectTypeInitializer.DefaultNonPagedPoolCharge = sizeof(struct winstation);
	ObjectTypeInitializer.GenericMapping = winstation_mapping;
	ObjectTypeInitializer.PoolType = NonPagedPool;
	ObjectTypeInitializer.ValidAccessMask = EVENT_ALL_ACCESS;
	ObjectTypeInitializer.UseDefaultObject = TRUE;
	create_type_object(&ObjectTypeInitializer, &Name, &winstation_object_type);
}

VOID
init_desktop_implement(VOID)
{
	OBJECT_TYPE_INITIALIZER ObjectTypeInitializer;
	UNICODE_STRING Name;

	memset(&ObjectTypeInitializer, 0, sizeof(ObjectTypeInitializer));
	init_unistr(&Name, desktop_type_name);
	ObjectTypeInitializer.Length = sizeof(ObjectTypeInitializer);
	ObjectTypeInitializer.DefaultNonPagedPoolCharge = sizeof(struct desktop);
	ObjectTypeInitializer.GenericMapping = desktop_mapping;
	ObjectTypeInitializer.PoolType = NonPagedPool;
	ObjectTypeInitializer.ValidAccessMask = EVENT_ALL_ACCESS;
	ObjectTypeInitializer.UseDefaultObject = TRUE;
	create_type_object(&ObjectTypeInitializer, &Name, &desktop_object_type);
}

/* create a winstation object */
static struct winstation *create_winstation(const struct unicode_str *name, unsigned int attr,
					unsigned int flags)
{
	struct winstation *winstation;

	if (!winsta_root && !NT_SUCCESS(create_winsta_root()))
		return NULL;

	ktrace("winstation handle %p\n", winsta_root_handle);
	if (memchrW(name->str, '\\', name->len / sizeof(WCHAR))) { /* no backslash allowed in name */
		set_error(STATUS_INVALID_PARAMETER);
		return NULL;
	}

	if ((winstation = create_named_object(winsta_root_handle, &winstation_ops, name, attr))) { /* D.M. TBD */
		if (get_error() != STATUS_OBJECT_NAME_EXISTS) {
			/* initialize it if it didn't already exist */
			INIT_DISP_HEADER(&winstation->obj.header, WINSTATION, 
					sizeof(struct winstation)/sizeof(ULONG), 0);
			winstation->flags = flags;
			winstation->clipboard = NULL;
			winstation->atom_table = NULL;
			list_add_before(&winstation_list, &winstation->entry);
			INIT_LIST_HEAD(&winstation->desktops);
		}
	}

	return winstation;
}

static void winstation_dump(struct object *obj, int verbose)
{
	struct winstation *winstation = (struct winstation *)obj;

	ktrace("Winstation flags=%x clipboard=%p atoms=%p\n",
			winstation->flags, winstation->clipboard, winstation->atom_table);
	dump_object_name(&winstation->obj);
}

static struct object_type *winstation_get_type(struct object *obj)
{
	static const WCHAR name[] = {'W','i','n','d','o','w','S','t','a','t','i','o','n'};
	static const struct unicode_str str = {name, sizeof(name)};
	return get_object_type(&str);
}

static int winstation_close_handle(struct object *obj, struct w32process *process, obj_handle_t handle)
{
	return (process->winstation != handle);
}

static void winstation_destroy(struct object *obj)
{
	struct winstation *winstation = (struct winstation *)obj;

	list_remove(&winstation->entry);
	if (winstation->clipboard)
		release_object(winstation->clipboard);
	if (winstation->atom_table)
		release_object(winstation->atom_table);
}

static unsigned int winstation_map_access(struct object *obj, unsigned int access)
{
	if (access & GENERIC_READ)
		access |= STANDARD_RIGHTS_READ | WINSTA_ENUMDESKTOPS | WINSTA_READATTRIBUTES |
			WINSTA_ENUMERATE | WINSTA_READSCREEN;
	if (access & GENERIC_WRITE)
		access |= STANDARD_RIGHTS_WRITE | WINSTA_ACCESSCLIPBOARD | WINSTA_CREATEDESKTOP |
			WINSTA_WRITEATTRIBUTES;
	if (access & GENERIC_EXECUTE)
		access |= STANDARD_RIGHTS_EXECUTE | WINSTA_ACCESSGLOBALATOMS | WINSTA_EXITWINDOWS;
	if (access & GENERIC_ALL)
		access |= STANDARD_RIGHTS_REQUIRED | WINSTA_ALL_ACCESS;
	return access & ~(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);
}

/* retrieve the process window station, checking the handle access rights */
struct winstation *get_process_winstation(struct w32process *process, unsigned int access)
{
	return (struct winstation *)get_wine_handle_obj(process, process->winstation,
					access, &winstation_ops);
}

/* build the full name of a desktop object */
static WCHAR *build_desktop_name(const struct unicode_str *name,
				struct winstation *winstation, struct unicode_str *res)
{
	const WCHAR *winstation_name;
	WCHAR *full_name;
	data_size_t winstation_len;

	if (memchrW(name->str, '\\', name->len / sizeof(WCHAR))) {
		set_error(STATUS_INVALID_PARAMETER);
		return NULL;
	}

	if (!(winstation_name = get_object_name(&winstation->obj, &winstation_len)))
		winstation_len = 0;

	res->len = winstation_len + name->len + sizeof(WCHAR);
	if (!(full_name = mem_alloc(res->len)))
		return NULL;
	memcpy(full_name, winstation_name, winstation_len);
	full_name[winstation_len / sizeof(WCHAR)] = '/';//'\\';
	memcpy(full_name + winstation_len / sizeof(WCHAR) + 1, name->str, name->len);
	res->str = full_name;
	return full_name;
}

/* retrieve a pointer to a desktop object */
struct desktop *get_desktop_obj(struct w32process *process, obj_handle_t handle, unsigned int access)
{
	return (struct desktop *)get_wine_handle_obj(process, handle, access, &desktop_ops);
}

static inline void print_wcs(WCHAR *wcs, int len)
{
	int	i;
	char buf[128];

	for (i = 0; i < len; i++)
		buf[i] = (char)wcs[i];
	buf[i] = 0;
	ktrace("name %s, len %d\n", buf, i);
}

/* create a desktop object */
static struct desktop *create_desktop(const struct unicode_str *name, unsigned int attr,
                                       unsigned int flags, struct winstation *winstation)
{
	struct desktop *desktop;
	struct unicode_str full_str;
	WCHAR *full_name;

	if (!(full_name = build_desktop_name(name, winstation, &full_str)))
		return NULL;
	print_wcs(full_name, full_str.len); /* just for debug */

	if ((desktop = create_named_object(winsta_root_handle, &desktop_ops, &full_str, attr))) {
		if (get_error() != STATUS_OBJECT_NAME_EXISTS) {
			/* initialize it if it didn't already exist */
			INIT_DISP_HEADER(&desktop->obj.header, DESKTOP, 
					sizeof(struct desktop)/sizeof(ULONG), 0);
			desktop->flags = flags;
			desktop->winstation = (struct winstation *)grab_object(winstation);
			desktop->top_window = NULL;
			desktop->global_hooks = NULL;
			desktop->close_timeout = NULL;
			desktop->users = 0;
			list_add_before(&winstation->desktops, &desktop->entry);
		}
	}
	free(full_name);
	return desktop;
}

static void desktop_dump(struct object *obj, int verbose)
{
	struct desktop *desktop = (struct desktop *)obj;

	ktrace("Desktop flags=%x winstation=%p top_win=%p hooks=%p\n",
			desktop->flags, desktop->winstation, desktop->top_window, desktop->global_hooks);
	dump_object_name(&desktop->obj);
}

static struct object_type *desktop_get_type(struct object *obj)
{
	static const WCHAR name[] = {'D','e','s','k','t','o','p'};
	static const struct unicode_str str = {name, sizeof(name)};
	return get_object_type(&str);
}

static int desktop_close_handle(struct object *obj, struct w32process *process, obj_handle_t handle)
{
	struct w32thread *thread;

	/* check if the handle is currently used by the process or one of its threads */
	if (process->desktop == handle)
		return 0;
	LIST_FOR_EACH_ENTRY(thread, &process->thread_list, struct w32thread, proc_entry)
		if (thread->desktop == handle)
			return 0;
	return 1;
}

static void desktop_destroy(struct object *obj)
{
	struct desktop *desktop = (struct desktop *)obj;

	if (desktop->top_window)
		destroy_window(desktop->top_window);
	if (desktop->global_hooks)
		release_object(desktop->global_hooks);
	if (desktop->close_timeout)
		remove_timeout_user(desktop->close_timeout);
	list_remove(&desktop->entry);
	release_object(desktop->winstation);
}

static unsigned int desktop_map_access(struct object *obj, unsigned int access)
{
	if (access & GENERIC_READ)
		access |= STANDARD_RIGHTS_READ | DESKTOP_READOBJECTS | DESKTOP_ENUMERATE;
	if (access & GENERIC_WRITE)
		access |= STANDARD_RIGHTS_WRITE | DESKTOP_CREATEMENU | DESKTOP_CREATEWINDOW |
			DESKTOP_HOOKCONTROL | DESKTOP_JOURNALRECORD | DESKTOP_JOURNALPLAYBACK |
			DESKTOP_WRITEOBJECTS;
	if (access & GENERIC_EXECUTE)
		access |= STANDARD_RIGHTS_EXECUTE | DESKTOP_SWITCHDESKTOP;
	if (access & GENERIC_ALL)
		access |= STANDARD_RIGHTS_REQUIRED | DESKTOP_ALL_ACCESS;
	return access & ~(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);
}

/* retrieve the thread desktop, checking the handle access rights */
struct desktop *get_thread_desktop(struct w32thread *thread, unsigned int access)
{
	return get_desktop_obj(thread->process, thread->desktop, access);
}

/* set the process default desktop handle */
void set_process_default_desktop(struct w32process *process, struct desktop *desktop,
				obj_handle_t handle)
{
	struct w32thread *thread;
	struct desktop *old_desktop;

	if (process->desktop == handle)
		return;  /* nothing to do */

	if (!(old_desktop = get_desktop_obj(process, process->desktop, 0)))
		clear_error();
	process->desktop = handle;

	/* set desktop for threads that don't have one yet */
	LIST_FOR_EACH_ENTRY(thread, &process->thread_list, struct w32thread, proc_entry)
		if (!thread->desktop)
			thread->desktop = handle;

	if (!process->is_system) {
		desktop->users++;
		if (desktop->close_timeout) {
			remove_timeout_user(desktop->close_timeout);
			desktop->close_timeout = NULL;
		}
		if (old_desktop)
			old_desktop->users--;
	}

	if (old_desktop)
		release_object(old_desktop);
}

/* connect a process to its window station */
void connect_process_winstation(struct w32process *process, struct w32thread *parent)
{
	struct winstation *winstation = NULL;
	struct desktop *desktop = NULL;
	obj_handle_t handle;

	/* check for an inherited winstation handle (don't ask...) */
	if ((handle = find_inherited_handle(process, &winstation_ops))) {
		winstation = (struct winstation *)get_wine_handle_obj(process, handle, 0, &winstation_ops);
	}
	else if (parent && parent->process->winstation) {
		handle = duplicate_handle(parent->process, parent->process->winstation,
				process, 0, 0, DUP_HANDLE_SAME_ACCESS);
		winstation = (struct winstation *)get_wine_handle_obj(process, handle, 0, &winstation_ops);
	}
	if (!winstation)
		goto done;
	process->winstation = handle;

	if ((handle = find_inherited_handle(process, &desktop_ops))) {
		desktop = get_desktop_obj(process, handle, 0);
		if (!desktop || desktop->winstation != winstation)
			goto done;
	}
	else if (parent && parent->desktop) {
		desktop = get_desktop_obj(parent->process, parent->desktop, 0);
		if (!desktop || desktop->winstation != winstation)
			goto done;
		handle = duplicate_handle(parent->process, parent->desktop,
				process, 0, 0, DUP_HANDLE_SAME_ACCESS);
	}

	if (handle)
		set_process_default_desktop(process, desktop, handle);

done:
	if (desktop)
		release_object(desktop);
	if (winstation)
		release_object(winstation);
	clear_error();
}

static void close_desktop_timeout(void *private)
{
	struct desktop *desktop = private;
	ktrace("\n");

	desktop->close_timeout = NULL;
	unlink_named_object(&desktop->obj);  /* make sure no other process can open it */
	close_desktop_window(desktop);  /* and signal the owner to quit */
}

/* close the desktop of a given process */
void close_process_desktop(struct w32process *process)
{
	struct desktop *desktop;

	ktrace("process %p, desktop %p\n", process, process->desktop);
	if (process->desktop && (desktop = get_desktop_obj(process, process->desktop, 0))) {
		desktop->users--;
		/* if we have one remaining user, it has to be the manager of the desktop window */
		if (desktop->users == 1 && get_top_window_owner(desktop)) {
			close_desktop_timeout(desktop);
		}
		release_object(desktop);
	}
	clear_error();  /* ignore errors */
}

/* close the desktop of a given thread */
void close_thread_desktop(struct w32thread *thread)
{
	obj_handle_t handle = thread->desktop;
	struct w32thread *other;
	struct w32process *process = thread->process;

	thread->desktop = NULL;
	if (!handle || handle == process->desktop)
		goto out;

	LIST_FOR_EACH_ENTRY(other, &process->thread_list, struct w32thread, proc_entry)
		if (other != thread && other->desktop == handle)
			goto out;

	/* here, need close this handle */
	close_handle(thread->process->eprocess, handle);

out:
	clear_error();  /* ignore errors */
}

/* set the reply data from the object name */
static void set_reply_data_obj_name(struct object *obj)
{
	data_size_t len;
	const WCHAR *ptr, *name = get_object_name(obj, &len);

	/* if there is a backslash return the part of the name after it */
	if (name && (ptr = memchrW(name, '/', len/sizeof(WCHAR)))) {
		len -= (ptr + 1 - name) * sizeof(WCHAR);
		name = ptr + 1;
	}
	if (name)
		set_reply_data(name, min(len, get_reply_max_size()));
}

/* create a window station */
DECL_HANDLER(create_winstation)
{
	struct winstation *winstation;
	struct unicode_str name;

	ktrace("\n");
	reply->handle = 0;
	get_req_unicode_str(&name);
	if ((winstation = create_winstation(&name, req->attributes, req->flags))) {
		reply->handle = alloc_handle(get_current_w32process(), winstation, req->access, req->attributes);  
		release_object(winstation);
	}
}

/* open a handle to a window station */
DECL_HANDLER(open_winstation)
{
	struct unicode_str name;

	ktrace("\n");
	get_req_unicode_str(&name);
	if (winsta_root_handle)
		reply->handle = open_object(winsta_root_handle, &name, &winstation_ops, req->access,
				req->attributes);
	else
		set_error(STATUS_OBJECT_NAME_NOT_FOUND);
}

/* close a window station */
DECL_HANDLER(close_winstation)
{
	struct winstation *winstation;
	struct w32process *process = get_current_w32process();

	if (req->handle == process->winstation) {
		set_error(STATUS_ACCESS_DENIED);
		return;
	}

	ktrace("\n");
	if ((winstation = (struct winstation *)get_wine_handle_obj(process, req->handle,
					0, &winstation_ops))) {
		if (!NT_SUCCESS(close_handle(get_current_eprocess(), req->handle)))
			set_error(STATUS_ACCESS_DENIED);   /* D.M. TBD */
		release_object(winstation);
	}
}

/* get the process current window station */
DECL_HANDLER(get_process_winstation)
{
	ktrace("\n");
	reply->handle = get_current_w32process()->winstation; 
}

/* set the process current window station */
DECL_HANDLER(set_process_winstation)
{
	struct winstation *winstation;

	ktrace("\n");
	if ((winstation = (struct winstation *)get_wine_handle_obj(get_current_w32process(), req->handle,
					0, &winstation_ops))) {
		/* FIXME: should we close the old one? */
		get_current_w32process()->winstation = req->handle;
		release_object(winstation);
	}
}

/* create a desktop */
DECL_HANDLER(create_desktop)
{
	struct desktop *desktop;
	struct winstation *winstation;
	struct unicode_str name;

	ktrace("\n");
	reply->handle = 0;
	get_req_unicode_str(&name);
	if ((winstation = get_process_winstation(get_current_w32process(), WINSTA_CREATEDESKTOP))) {
		if ((desktop = create_desktop(&name, req->attributes, req->flags, winstation))) {
			reply->handle = alloc_handle(get_current_w32process(), desktop, req->access, req->attributes);  
			release_object(desktop);
		}
		release_object(winstation);
	}
}

/* open a handle to a desktop */
DECL_HANDLER(open_desktop)
{
	struct winstation *winstation;
	struct unicode_str name;

	ktrace("\n");
	get_req_unicode_str(&name);

	/* FIXME: check access rights */
	if (!req->winsta)
		winstation = get_process_winstation(get_current_w32process(), 0);
	else
		winstation = (struct winstation *)get_wine_handle_obj(get_current_w32process(), req->winsta, 0, &winstation_ops);

	if (winstation) {
		struct unicode_str full_str;
		WCHAR *full_name;

		if ((full_name = build_desktop_name(&name, winstation, &full_str))) {
			reply->handle = open_object(winsta_root_handle, &full_str, &desktop_ops, req->access,
					req->attributes);
			free(full_name);
		}
		release_object(winstation);
	}
}

/* close a desktop */
DECL_HANDLER(close_desktop)
{
	struct desktop *desktop;
	struct w32thread *thread;
	struct w32process *process = get_current_w32process();

	ktrace("\n");
	if (req->handle == process->desktop) {
		set_error(STATUS_DEVICE_BUSY);
		return;
	}

	LIST_FOR_EACH_ENTRY(thread, &process->thread_list, struct w32thread, proc_entry)
		if (thread->desktop == req->handle) {
			set_error(STATUS_DEVICE_BUSY);
			return;
		}

	/* make sure it is a desktop handle */
	if ((desktop = (struct desktop *)get_wine_handle_obj(process, req->handle,
					0, &desktop_ops))) {
		if (!close_handle(get_current_eprocess(), req->handle))
			set_error(STATUS_DEVICE_BUSY);  /* D.M. TBD */
		release_object(desktop);
	}
}

/* get the thread current desktop */
DECL_HANDLER(get_thread_desktop)
{
	struct w32thread *thread;

	ktrace("tid=%d\n", req->tid);
	if (!(thread = get_thread_from_id(req->tid)))
		return;
	reply->handle = thread->desktop;
	release_object(thread);
}

/* set the thread current desktop */
DECL_HANDLER(set_thread_desktop)
{
	struct desktop *old_desktop, *new_desktop;
	struct winstation *winstation;

	ktrace("\n");
	if (!(winstation = get_process_winstation(get_current_w32process(), 0 /* FIXME: access rights? */))) 
		return;

	if (!(new_desktop = get_desktop_obj(get_current_w32process(), req->handle, 0))) {
		release_object(winstation);
		return;
	}
	if (new_desktop->winstation != winstation) {
		set_error(STATUS_ACCESS_DENIED);
		release_object(new_desktop);
		release_object(winstation);
		return;
	}

	/* check if we are changing to a new desktop */

	if (!(old_desktop = get_desktop_obj(get_current_w32process(), current_thread->desktop, 0))) 
		clear_error();  /* ignore error */

	/* when changing desktop, we can't have any users on the current one */
	if (old_desktop != new_desktop && current_thread->desktop_users > 0)
		set_error(STATUS_DEVICE_BUSY);
	else {
		current_thread->desktop = req->handle;  /* FIXME: should we close the old one? */ 
	}

	if (!get_current_w32process()->desktop) 
		set_process_default_desktop(get_current_w32process(), new_desktop, req->handle); 

	if (old_desktop != new_desktop && get_current_queue())
		detach_thread_input(current_thread);  /* D.M. TBD */

	if (old_desktop)
		release_object(old_desktop);
	release_object(new_desktop);
	release_object(winstation);
}

/* get/set information about a user object (window station or desktop) */
DECL_HANDLER(set_user_object_info)
{
	struct object *obj;

	ktrace("\n");
	if (!(obj = get_wine_handle_obj(get_current_w32process(), req->handle, 0, NULL)))
		return;  

	if (BODY_TO_HEADER(obj)->ops == &desktop_ops) {
		struct desktop *desktop = (struct desktop *)obj;
		reply->is_desktop = 1;
		reply->old_obj_flags = desktop->flags;
		if (req->flags & SET_USER_OBJECT_FLAGS)
			desktop->flags = req->obj_flags;
	}
	else if (BODY_TO_HEADER(obj)->ops == &winstation_ops) {
		struct winstation *winstation = (struct winstation *)obj;
		reply->is_desktop = 0;
		reply->old_obj_flags = winstation->flags;
		if (req->flags & SET_USER_OBJECT_FLAGS)
			winstation->flags = req->obj_flags;
	}
	else {
		set_error(STATUS_OBJECT_TYPE_MISMATCH);
		release_object(obj);
		return;
	}
	if (get_reply_max_size())
		set_reply_data_obj_name(obj);
	release_object(obj);
}

/* enumerate window stations */
DECL_HANDLER(enum_winstation)
{
	unsigned int index = 0;
	struct winstation *winsta;

	ktrace("\n");
	LIST_FOR_EACH_ENTRY(winsta, &winstation_list, struct winstation, entry) {
		unsigned int access = WINSTA_ENUMERATE;
		if (req->index > index++)
			continue;
		if (!check_object_access(&winsta->obj, &access))
			continue;
		set_reply_data_obj_name(&winsta->obj);
		clear_error();
		reply->next = index;
		return;
	}
	set_error(STATUS_NO_MORE_ENTRIES);
}

/* enumerate desktops */
DECL_HANDLER(enum_desktop)
{
	struct winstation *winstation;
	struct desktop *desktop;
	unsigned int index = 0;

	ktrace("req->winstation=%p\n", req->winstation);
	if (!(winstation = (struct winstation *)get_wine_handle_obj(get_current_w32process(), req->winstation,
					WINSTA_ENUMDESKTOPS, &winstation_ops))) 
		return;

	LIST_FOR_EACH_ENTRY(desktop, &winstation->desktops, struct desktop, entry) {
		unsigned int access = DESKTOP_ENUMERATE;
		if (req->index > index++)
			continue;
		if (!HEADER_TO_OBJECT_NAME(BODY_TO_HEADER(desktop)))
			continue;
		if (!check_object_access(&desktop->obj, &access))
			continue;
		set_reply_data_obj_name(&desktop->obj);
		release_object(winstation);
		clear_error();
		reply->next = index;
		return;
	}

	release_object(winstation);
	set_error(STATUS_NO_MORE_ENTRIES);
}

struct namespace *create_namespace(unsigned int hash_size)
{
	struct namespace *namespace;
	unsigned int i;

	namespace = (struct namespace*)mem_alloc(sizeof(*namespace) + (hash_size - 1) * sizeof(namespace->names[0]));
	if (namespace) {
		namespace->hash_size      = hash_size;
		for (i = 0; i < hash_size; i++)
			INIT_LIST_HEAD(&namespace->names[i]);
	}
	return namespace;
}

NTSTATUS create_winsta_root(void)
{
	UNICODE_STRING Name;
	OBJECT_ATTRIBUTES ObjectAttributes;
	NTSTATUS Status;

	init_unistr(&Name, (PWSTR)WinStationName);
	INIT_OBJECT_ATTR(&ObjectAttributes,
			&Name,
			0,
			NULL,
			NULL);

	Status = create_object(KernelMode,
			dir_object_type,
			&ObjectAttributes,
			KernelMode,
			NULL,
			sizeof(OBJECT_DIRECTORY),
			0,
			0,
			(PVOID *)&winsta_root);
	if (!NT_SUCCESS(Status))
		return Status;

	Status = create_handle(NULL,
			winsta_root,
			0,
			ObjectAttributes.Attributes & OBJ_INHERIT,
			&winsta_root_handle);
	if (!NT_SUCCESS(Status)) {
		deref_object(winsta_root);
		winsta_root = NULL;
		return Status;
	}

	return STATUS_SUCCESS;
}
#endif /* CONFIG_UNIFIED_KERNEL */
