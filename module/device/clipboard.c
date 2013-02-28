/*
 * clipboard.c
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
 * clipboard.c:
 * Refered to Wine code
 */
#include "unistr.h"
#include "winuser.h"
#include "wineserver/file.h"
#include "wineserver/lib.h"

#ifdef CONFIG_UNIFIED_KERNEL

#define MINUPDATELAPSE 2

struct clipboard
{
	struct object  obj;              /* object header */
	struct w32thread *open_thread;   /* thread id that has clipboard open */
	user_handle_t  open_win;         /* window that has clipboard open */
	struct w32thread *owner_thread;  /* thread id that owns the clipboard */
	user_handle_t  owner_win;        /* window that owns the clipboard data */
	user_handle_t  viewer;           /* first window in clipboard viewer list */
	unsigned int   seqno;            /* clipboard change sequence number */
	time_t         seqno_timestamp;  /* time stamp of last seqno increment */
};

static void clipboard_dump(struct object *obj, int verbose);

static const struct object_ops clipboard_ops =
{
	sizeof(struct clipboard),     /* size */
	clipboard_dump,               /* dump */
	no_get_type,                  /* get_type */
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

static WCHAR clipboard_name[] = {'C','l','i','p','b','o','a','r','d',0};

POBJECT_TYPE clipboard_object_type = NULL;
EXPORT_SYMBOL(clipboard_object_type);

static GENERIC_MAPPING mapping = 
{
	STANDARD_RIGHTS_READ | SYNCHRONIZE | 0x1 /* QUERY_STATE */,
	STANDARD_RIGHTS_WRITE | SYNCHRONIZE | 0x2 /* MODIFY_STATE */,
	STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE | 0x1 /* QUERY_STATE */,
	STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3
};

VOID
init_clipboard_implement(VOID)
{
	OBJECT_TYPE_INITIALIZER ObjectTypeInitializer;
	UNICODE_STRING Name;

	memset(&ObjectTypeInitializer, 0, sizeof(ObjectTypeInitializer));
	init_unistr(&Name, clipboard_name);
	ObjectTypeInitializer.Length = sizeof(ObjectTypeInitializer);
	ObjectTypeInitializer.DefaultNonPagedPoolCharge = sizeof(struct clipboard);
	ObjectTypeInitializer.GenericMapping = mapping;
	ObjectTypeInitializer.PoolType = NonPagedPool;
	ObjectTypeInitializer.ValidAccessMask = EVENT_ALL_ACCESS;
	ObjectTypeInitializer.UseDefaultObject = TRUE;
	create_type_object(&ObjectTypeInitializer, &Name, &clipboard_object_type);
}

/* dump a clipboard object */
static void clipboard_dump(struct object *obj, int verbose)
{
}

/* retrieve the clipboard info for the current process, allocating it if needed */
static struct clipboard *get_process_clipboard(void)
{
	NTSTATUS status;
	struct clipboard *clipboard;
	struct winstation *winstation = get_process_winstation(get_current_w32process(), WINSTA_ACCESSCLIPBOARD);

	if (!winstation) {
		ktrace("get_process_winstation return NULL!\n");
		return NULL;
	}

	if (!(clipboard = winstation->clipboard)) {
		status = create_object(KernelMode,
				clipboard_object_type,
				NULL /* obj_attr*/,
				KernelMode,
				NULL,
				sizeof(struct clipboard),
				0,
				0,
				(PVOID *)&clipboard);

		if (NT_SUCCESS(status) && clipboard) {
			INIT_DISP_HEADER(&clipboard->obj.header, CLIPBOARD,
					sizeof(struct clipboard) / sizeof(ULONG), 0);
			BODY_TO_HEADER(&(clipboard->obj))->ops = &clipboard_ops;
			clipboard->open_thread = NULL;
			clipboard->open_win = 0;
			clipboard->owner_thread = NULL;
			clipboard->owner_win = 0;
			clipboard->viewer = 0;
			clipboard->seqno = 0;
			clipboard->seqno_timestamp = 0;
			winstation->clipboard = clipboard;
		}
	}
	release_object(winstation);
	return clipboard;
}

/* Called when thread terminates to allow release of clipboard */
void cleanup_clipboard_thread(struct w32thread *thread)
{
	struct clipboard *clipboard;
	struct winstation *winstation = get_process_winstation(thread->process, WINSTA_ACCESSCLIPBOARD);

	if (!winstation)
		return;

	if ((clipboard = winstation->clipboard)) {
		if (thread == clipboard->open_thread) {
			clipboard->open_win = 0;
			clipboard->open_thread = NULL;
		}
		if (thread == clipboard->owner_thread) {
			clipboard->owner_win = 0;
			clipboard->owner_thread = NULL;
		}
	}
	release_object(winstation);
}

static int set_clipboard_window(struct clipboard *clipboard, user_handle_t win, int clear)
{
	if (clipboard->open_thread && clipboard->open_thread != current_thread) {
		set_error(STATUS_WAS_LOCKED);
		return 0;
	}
	else if (!clear) {
		clipboard->open_win = win;
		clipboard->open_thread = current_thread;
	}
	else {
		clipboard->open_thread = NULL;
		clipboard->open_win = 0;
	}
	return 1;
}

static int set_clipboard_owner(struct clipboard *clipboard, user_handle_t win, int clear)
{
	if (clipboard->open_thread && clipboard->open_thread->process != get_current_w32process()) {
		set_error(STATUS_WAS_LOCKED);
		return 0;
	}
	else if (!clear) {
		clipboard->owner_win = win;
		clipboard->owner_thread = current_thread;
	}
	else {
		clipboard->owner_win = 0;
		clipboard->owner_thread = NULL;
	}
	return 1;
}

static int get_seqno(struct clipboard *clipboard)
{
	time_t tm = time(NULL);

	if (!clipboard->owner_thread && (tm > (clipboard->seqno_timestamp + MINUPDATELAPSE))) {
		clipboard->seqno_timestamp = tm;
		clipboard->seqno++;
	}
	return clipboard->seqno;
}


DECL_HANDLER(set_clipboard_info)
{
	struct clipboard *clipboard = get_process_clipboard();

	if (!clipboard)
		return;

	ktrace("set_clipboard_info begin to work\n");

	/* FIXME: add spin_lock to ob functions */

	reply->old_clipboard = clipboard->open_win;
	reply->old_owner     = clipboard->owner_win;
	reply->old_viewer    = clipboard->viewer;

	if (req->flags & SET_CB_OPEN) {
		if (clipboard->open_thread) {
			/* clipboard already opened */
			set_error(STATUS_WAS_LOCKED);
			return;
		}

		if (!set_clipboard_window(clipboard, req->clipboard, 0))
			return;
	}
	else if (req->flags & SET_CB_CLOSE) {
		if (clipboard->open_thread != current_thread) {
			set_win32_error(ERROR_CLIPBOARD_NOT_OPEN);
			return;
		}

		if (!set_clipboard_window(clipboard, 0, 1))
			return;
	}

	if (req->flags & SET_CB_OWNER) {
		if (!set_clipboard_owner(clipboard, req->owner, 0))
			return;
	}
	else if (req->flags & SET_CB_RELOWNER) {
		if (!set_clipboard_owner(clipboard, 0, 1))
			return;
	}

	if (req->flags & SET_CB_VIEWER)
		clipboard->viewer = req->viewer;

	if (req->flags & SET_CB_SEQNO)
		clipboard->seqno++;

	reply->seqno = get_seqno(clipboard);

	if (clipboard->open_thread == current_thread)
		reply->flags |= CB_OPEN;
	if (clipboard->owner_thread == current_thread)
		reply->flags |= CB_OWNER;
	if (clipboard->owner_thread &&
			clipboard->owner_thread->process == get_current_w32process())
		reply->flags |= CB_PROCESS;
}
#endif /* CONFIG_UNIFIED_KERNEL */
