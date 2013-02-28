/*
 * reg.c
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
 * reg.c:
 * Refered to Wine code
 */

#include "io.h"
#include "unistr.h"
#include "handle.h"
#include "wineserver/reg.h"

#ifdef CONFIG_UNIFIED_KERNEL
static const SID world_sid = { SID_REVISION, 1, { SECURITY_WORLD_SID_AUTHORITY }, 
	{ SECURITY_WORLD_RID } };
static const SID local_sid = { SID_REVISION, 1, { SECURITY_LOCAL_SID_AUTHORITY }, 
	{ SECURITY_LOCAL_RID } };
static const SID interactive_sid = { SID_REVISION, 1, { SECURITY_NT_AUTHORITY }, 
	{ SECURITY_INTERACTIVE_RID } };
static const SID authenticated_user_sid = { SID_REVISION, 1, { SECURITY_NT_AUTHORITY }, 
	{ SECURITY_AUTHENTICATED_USER_RID } };
static const SID local_system_sid = { SID_REVISION, 1, { SECURITY_NT_AUTHORITY }, 
	{ SECURITY_LOCAL_SYSTEM_RID } };
static const PSID security_world_sid = (PSID)&world_sid;
static const PSID security_local_sid = (PSID)&local_sid;
extern const PSID security_interactive_sid;
static const PSID security_authenticated_user_sid = (PSID)&authenticated_user_sid;
static const PSID security_local_system_sid = (PSID)&local_system_sid;

static struct reg_key *root_key;

struct task_struct* save_kernel_task = NULL;
EXPORT_SYMBOL(save_kernel_task);
extern int kthread_should_stop(void);
extern struct task_struct* kthread_create(int (*fn)(void* data),void* data,
		const char namefmt[],...);
#define DEFAULT_FILE_MODE (0666)

/* save a registry branch to a file */

static WCHAR    key_type_name[] = {'K', 'e', 'y', 0};
POBJECT_TYPE    key_object_type = NULL;
EXPORT_SYMBOL(key_object_type);

static GENERIC_MAPPING key_mapping = {KEY_READ, KEY_WRITE, KEY_EXECUTE, KEY_ALL_ACCESS};

static int save_branch_count;
static struct save_branch_info save_branch_info[MAX_SAVE_BRANCH_INFO];
struct reg_key *sys_key, *user_key, *udef_key;
void write_back_branches(void);
void write_registry(void);

extern char* rootdir;
extern int unistr2charstr(PWSTR unistr, LPCSTR chstr);
static char debug_buf[1024];

char *wcsdebug(WCHAR *wcs)
{
	int ret;

	if (!wcs)
		return "null";
	ret = unistr2charstr((PWSTR)wcs, debug_buf);
	if (ret > 0) {
		debug_buf[ret] = 0;
		return debug_buf;
	} else
		return "(invalid wchar string)";
}

static void delete_reg_key(PVOID key)
{
	kdebug("delete key %p\n", key);
}

	VOID
init_key_implement(VOID)
{
	OBJECT_TYPE_INITIALIZER ObjectTypeInitializer;
	UNICODE_STRING Name;

	memset(&ObjectTypeInitializer, 0, sizeof(ObjectTypeInitializer));
	init_unistr(&Name, (PWSTR)key_type_name);
	ObjectTypeInitializer.Length = sizeof(ObjectTypeInitializer);
	ObjectTypeInitializer.DefaultNonPagedPoolCharge = sizeof(struct reg_key);
	ObjectTypeInitializer.GenericMapping = key_mapping;
	ObjectTypeInitializer.PoolType = PagedPool;
	ObjectTypeInitializer.ValidAccessMask = KEY_ALL_ACCESS;
	ObjectTypeInitializer.DeleteProcedure = delete_reg_key;
	/*FIXME*/
	ObjectTypeInitializer.ParseProcedure = NULL;
	ObjectTypeInitializer.SecurityProcedure = NULL;
	ObjectTypeInitializer.QueryNameProcedure = NULL;
	ObjectTypeInitializer.UseDefaultObject = TRUE;
	create_type_object(&ObjectTypeInitializer, &Name, &key_object_type);
}

/* notify waiter and maybe delete the notification */
void do_notification(struct reg_key *key, struct notify *notify, int del)
{
	if (notify->event) {
		set_event(notify->event, EVENT_INCREMENT, FALSE);
		release_object(notify->event);
		notify->event = NULL;
	}
	if (del) {
		list_del(&notify->entry);
		free(notify);
	}
}

/* go through all the notifications and send them if necessary */
void check_notify(struct reg_key *key, unsigned int change, int not_subtree)
{
	struct list_head *ptr, *next;

	for (ptr = key->notify_list.next, next = ptr->next;
			ptr != &key->notify_list;
			ptr = next, next = ptr->next) {
		struct notify *notify = list_entry(ptr, struct notify, entry);

		if ((not_subtree || notify->subtree) && (change & notify->filter))
			do_notification(key, notify, 0);
	}
}

/* parse an escaped string back into Unicode */
/* return the number of chars read from the input, or -1 on output overflow */
int parse_strW(WCHAR *buffer, data_size_t *len, const char *src, char endchar)
{
	WCHAR *dest = buffer;
	WCHAR *end = buffer + *len / sizeof(WCHAR);
	const char *p = src;
	unsigned char ch;

	while (*p && *p != endchar && dest < end) {
		if (*p == '\\') {
			p++;
			if (!*p)
				break;
			switch (*p) {
				case 'a': *dest++ = '\a'; p++; continue;
				case 'b': *dest++ = '\b'; p++; continue;
				case 'e': *dest++ = '\e'; p++; continue;
				case 'f': *dest++ = '\f'; p++; continue;
				case 'n': *dest++ = '\n'; p++; continue;
				case 'r': *dest++ = '\r'; p++; continue;
				case 't': *dest++ = '\t'; p++; continue;
				case 'v': *dest++ = '\v'; p++; continue;
				case 'x':  /* hex escape */
						  p++;
						  if (!isxdigit(*p))
							  *dest = 'x';
						  else {
							  *dest = to_hex(*p++);
							  if (isxdigit(*p)) *dest = (*dest * 16) + to_hex(*p++);
							  if (isxdigit(*p)) *dest = (*dest * 16) + to_hex(*p++);
							  if (isxdigit(*p)) *dest = (*dest * 16) + to_hex(*p++);
						  }
						  dest++;
						  continue;
				case '0':
				case '1':
				case '2':
				case '3':
				case '4':
				case '5':
				case '6':
				case '7':  /* octal escape */
						  *dest = *p++ - '0';
						  if (*p >= '0' && *p <= '7') *dest = (*dest * 8) + (*p++ - '0');
						  if (*p >= '0' && *p <= '7') *dest = (*dest * 8) + (*p++ - '0');
						  dest++;
						  continue;
			}
			/* unrecognized escape: fall through to normal char handling */
		}
		ch = *p++;
		*dest++ = ch;
	}
	if (dest >= end)
		return -1;  /* overflow */
	*dest++ = 0;
	if (!*p)
		return -1;  /* delimiter not found */
	*len = (dest - buffer) * sizeof(WCHAR);
	return p + 1 - src;
}

/* convert a data type tag to a value type */
int get_data_type(const char *buffer, int *type, int *parse_type)
{
	struct data_type { const char *tag; int len; int type; int parse_type; };

	static const struct data_type data_types[] = {
		/* actual type */  /* type to assume for parsing */
		{ "\"",        1,   REG_SZ,              REG_SZ },
		{ "str:\"",    5,   REG_SZ,              REG_SZ },
		{ "str(2):\"", 8,   REG_EXPAND_SZ,       REG_SZ },
		{ "str(7):\"", 8,   REG_MULTI_SZ,        REG_SZ },
		{ "hex:",      4,   REG_BINARY,          REG_BINARY },
		{ "dword:",    6,   REG_DWORD,           REG_DWORD },
		{ "hex(",      4,   -1,                  REG_BINARY },
		{ NULL,        0,    0,                  0 }
	};

	const struct data_type *ptr;
	char *end;

	for (ptr = data_types; ptr->tag; ptr++) {
		if (memcmp(ptr->tag, buffer, ptr->len))
			continue;
		*parse_type = ptr->parse_type;
		if ((*type = ptr->type) != -1)
			return ptr->len;
		*type = (int)simple_strtoul(buffer + 4, &end, 16);
		if ((end <= buffer) || memcmp(end, "):", 2))
			return 0;
		return end + 2 - buffer;
	}
	return 0;
}

/* mark a key and all its parents as dirty (modified) */
void make_dirty(struct reg_key *key)
{
	while (key) {
		if (key->flags & (KEY_DIRTY | KEY_VOLATILE))
			return;  /* nothing to do */
		key->flags |= KEY_DIRTY;
		key = key->parent;
	}
}

/* mark a key and all its subkeys as clean (not modified) */
void make_clean(struct reg_key *key)
{
	int i;

	if (key->flags & KEY_VOLATILE)
		return;
	if (!(key->flags & KEY_DIRTY))
		return;
	key->flags &= ~KEY_DIRTY;
	for (i = 0; i <= key->last_subkey; i++)
		make_clean(key->subkeys[i]);
}

/* return the next token in a given path */
/* token->str must point inside the path, or be NULL for the first call */
struct unicode_str *get_path_token(const struct unicode_str *path, struct unicode_str *token)
{
	data_size_t i = 0, len = path->len / sizeof(WCHAR);

	if (!token->str) { /* first time */
		/* path cannot start with a backslash */
		if (len && path->str[0] == '\\') {
			set_error(STATUS_OBJECT_PATH_INVALID);
			return NULL;
		}
	} else {
		i = token->str - path->str;
		i += token->len / sizeof(WCHAR);
		while (i < len && path->str[i] == '\\')
			i++;
	}
	token->str = path->str + i;
	while (i < len && path->str[i] != '\\')
		i++;
	token->len = (path->str + i - token->str) * sizeof(WCHAR);

	return token;
}

/* find the named child of a given key and return its index */
struct reg_key *find_subkey(const struct reg_key *key, const struct unicode_str *name, int *index)
{
	int i, min, max, res;
	data_size_t len;

	min = 0;
	max = key->last_subkey;
	while (min <= max) {
		i = (min + max) / 2;
		len = min((int)key->subkeys[i]->namelen, (int)name->len);
		res = memicmpW(key->subkeys[i]->name, name->str, len / sizeof(WCHAR));
		if (!res)
			res = key->subkeys[i]->namelen - name->len;
		if (!res) {
			*index = i;
			return key->subkeys[i];
		}
		if (res > 0)
			max = i - 1;
		else
			min = i + 1;
	}
	*index = min;  /* this is where we should insert it */

	/* not found */
	return NULL;
}

/* try to grow the array of subkeys; return 1 if OK, 0 on error */
int grow_subkeys(struct reg_key *key)
{
	struct reg_key **new_subkeys;
	int nb_subkeys;

	if (key->nb_subkeys) {
		nb_subkeys = key->nb_subkeys + (key->nb_subkeys / 2);  /* grow by 50% */
		if (!(new_subkeys = realloc(key->subkeys,
						nb_subkeys * sizeof(*new_subkeys),
						key->nb_subkeys * sizeof(*new_subkeys))))
			return 0;
	} else {
		nb_subkeys = MIN_VALUES;
		if (!(new_subkeys = mem_alloc(nb_subkeys * sizeof(*new_subkeys))))
			return 0;
	}
	key->subkeys    = new_subkeys;
	key->nb_subkeys = nb_subkeys;

	return 1;
}

static struct reg_key *alloc_key(const struct unicode_str *name, time_t modif)
{
	NTSTATUS	status;
	struct reg_key	*key = NULL;
	UNICODE_STRING	KeyName;
	OBJECT_ATTRIBUTES       obj_attr;

	KeyName.Length = (USHORT)name->len;
	KeyName.MaximumLength = KeyName.Length + sizeof(WCHAR);
	KeyName.Buffer = (PWSTR)name->str;
	INIT_OBJECT_ATTR(&obj_attr, &KeyName, 0, NULL, NULL);
	status = create_object(KernelMode,
			key_object_type,
			&obj_attr,
			KernelMode,
			0,
			sizeof(struct reg_key),
			0,
			0,
			(PVOID *)&key);

	if (NT_SUCCESS(status)) {
		key->name        = NULL;
		key->class       = NULL;
		key->namelen     = name->len;
		key->classlen    = 0;
		key->flags       = 0;
		key->last_subkey = -1;
		key->nb_subkeys  = 0;
		key->subkeys     = NULL;
		key->nb_values   = 0;
		key->last_value  = -1;
		key->values[0] = key->values[1] = key->values[2] = key->values[3] = NULL;
		key->modif       = modif;
		key->parent      = NULL;
		INIT_LIST_HEAD(&key->notify_list);
		if (name->len && !(key->name = memdup(name->str, name->len))) {
			release_object(key);
			key = NULL;
		}
	}

	return key;
}

/* allocate a subkey for a given key, and return its index */
struct reg_key *alloc_subkey(struct reg_key *parent, const struct unicode_str *name,
		int index, time_t modif)
{
	struct reg_key *key;
	int i;

	if (name->len > MAX_NAME_LEN * sizeof(WCHAR)) {
		set_error(STATUS_NAME_TOO_LONG);
		return NULL;
	}
	if (parent->last_subkey + 1 == parent->nb_subkeys) /* need to grow the array */
		if (!grow_subkeys(parent))
			return NULL;

	if ((key = alloc_key(name, modif))) {
		key->parent = parent;
		for (i = ++parent->last_subkey; i > index; i--)
			parent->subkeys[i] = parent->subkeys[i - 1];
		parent->subkeys[index] = key;
	}

	return key;
}

/* free a subkey of a given key */
void free_subkey(struct reg_key *parent, int index)
{
	struct reg_key *key;
	int i;

	key = parent->subkeys[index];
	for (i = index; i < parent->last_subkey; i++)
		parent->subkeys[i] = parent->subkeys[i + 1];
	parent->last_subkey--;
	key->flags |= KEY_DELETED;
	key->parent = NULL;
	release_object(key); /* TODO */
}

/* create a subkey */
struct reg_key *create_key(struct reg_key *key, const struct unicode_str *name,
		const struct unicode_str *class, int flags, time_t modif, int *created)
{
	struct reg_key *base;
	int index;
	struct unicode_str token;

	/* we cannot create a subkey under a deleted key */
	if (key->flags & KEY_DELETED) {
		set_error(STATUS_KEY_DELETED);
		return NULL;
	}

	if (!(flags & KEY_VOLATILE) && (key->flags & KEY_VOLATILE)) {
		set_error(STATUS_CHILD_MUST_BE_VOLATILE);
		return NULL;
	}

	if (!modif)
		modif = time(NULL);

	token.str = NULL;
	if (!get_path_token(name, &token))
		return NULL;
	*created = 0;

	while (token.len) {
		struct reg_key *subkey;

		if (!(subkey = find_subkey(key, &token, &index)))
			break;
		key = subkey;
		get_path_token(name, &token);
	}

	if (!token.len)
		goto done;

	/* create the remaining part */
	*created = 1;
	if (flags & KEY_DIRTY)
		make_dirty(key);
	if (!(key = alloc_subkey(key, &token, index, modif)))
		return NULL;
	base = key;

	for (;;) {
		key->flags |= flags;
		get_path_token(name, &token);
		if (!token.len)
			break;

		/* we know the index is always 0 in a new key */
		if (!(key = alloc_subkey(key, &token, 0, modif))) {
			free_subkey(base, index);
			return NULL;
		}
	}

done:
	if (class && class->len) {
		key->classlen = class->len;
		free(key->class);
		if (!(key->class = memdup(class->str, key->classlen)))
			key->classlen = 0;
	}
	grab_object(key);

	return key;
}

/* update key modification time */
void touch_key(struct reg_key *key, unsigned int change)
{
	struct reg_key *k;

	key->modif = time(NULL);
	make_dirty(key);

	/* do notifications */
	check_notify(key, change, 1);
	for (k = key->parent; k; k = k->parent)
		check_notify(k, change & ~REG_NOTIFY_CHANGE_LAST_SET, 0);
}

/* delete a key and its values */
int delete_key(struct reg_key *key, int recurse)
{
	int index;
	struct reg_key *parent;

	/* must find parent and index */
	if (key == root_key) {
		set_error(STATUS_ACCESS_DENIED);
		return -1;
	}

	if (!(parent = key->parent) || (key->flags & KEY_DELETED)) {
		set_error(STATUS_KEY_DELETED);
		return -1;
	}

	while (recurse && (key->last_subkey >= 0))
		if (delete_key(key->subkeys[key->last_subkey], 1) == -1)
			return -1;

	for (index = 0; index <= parent->last_subkey; index++)
		if (parent->subkeys[index] == key)
			break;

	/* we can only delete a key that has no subkeys */
	if (key->last_subkey >= 0) {
		set_error(STATUS_ACCESS_DENIED);
		return -1;
	}

	free_subkey(parent, index);
	touch_key(parent, REG_NOTIFY_CHANGE_NAME);

	set_error(STATUS_SUCCESS);
	return 0;
}

/* query information about a key or a subkey */
void enum_key(const struct reg_key *key, int index, int info_class,
		struct enum_key_reply *reply)
{
	int i;
	data_size_t len, namelen, classlen;
	data_size_t max_subkey = 0, max_class = 0;
	data_size_t max_value = 0, max_data = 0;
	char *data;

	if (index != -1) { /* -1 means use the specified key directly */
		if ((index < 0) || (index > key->last_subkey)) {
			set_error(STATUS_NO_MORE_ENTRIES);
			return;
		}
		key = key->subkeys[index];
	}

	namelen = key->namelen;
	classlen = key->classlen;

	switch (info_class) {
		case KeyBasicInformation:
			classlen = 0; /* only return the name */
			/* fall through */
		case KeyNodeInformation:
			reply->max_subkey = 0;
			reply->max_class  = 0;
			reply->max_value  = 0;
			reply->max_data   = 0;
			break;
		case KeyFullInformation:
			for (i = 0; i <= key->last_subkey; i++) {
				struct reg_key *subkey = key->subkeys[i];

				len = subkey->namelen / sizeof(WCHAR);
				if (len > max_subkey)
					max_subkey = len;
				len = subkey->classlen / sizeof(WCHAR);
				if (len > max_class)
					max_class = len;
			}
			for (i = 0; i <= key->last_value; i++) {
				int m = i / VALUES_PER_BLOCK, n = i % VALUES_PER_BLOCK;

				len = key->values[m][n].namelen / sizeof(WCHAR);
				if (len > max_value)
					max_value = len;
				len = key->values[m][n].len;
				if (len > max_data)
					max_data = len;
			}
			reply->max_subkey = max_subkey;
			reply->max_class  = max_class;
			reply->max_value  = max_value;
			reply->max_data   = max_data;
			namelen = 0;  /* only return the class */
			break;
		default:
			set_error(STATUS_INVALID_PARAMETER);
			return;
	}
	reply->subkeys = key->last_subkey + 1;
	reply->values  = key->last_value + 1;
	reply->modif   = key->modif;
	reply->total   = namelen + classlen;

	len = min(reply->total, get_reply_max_size());
	if (len && (data = set_reply_data_size(len))) {
		if (len > namelen) {
			reply->namelen = namelen;
			memcpy(data, key->name, namelen);
			memcpy(data + namelen, key->class, len - namelen);
		} else {
			reply->namelen = len;
			memcpy(data, key->name, len);
		}
	}
	set_error(STATUS_SUCCESS);
}

/* try to grow the array of values; return 1 if OK, 0 on error */
int grow_values(struct reg_key *key)
{
	struct key_value *new_val;
	int nb_values, m;

	nb_values = key->nb_values;
	if (key->nb_values) {
		if (key->nb_values < (VALUES_PER_BLOCK)) {
			if (key->nb_values < (VALUES_PER_BLOCK / 2))
				nb_values = key->nb_values + (key->nb_values / 2);  /* grow by 50% */
			else
				nb_values = VALUES_PER_BLOCK;

			if (!(new_val = realloc(key->values[0], 
							nb_values * sizeof(*new_val), key->nb_values * sizeof(*new_val)))) {
				kdebug("fails\n");
				return 0;
			}
		} else {
			nb_values += VALUES_PER_BLOCK;
			if (!(new_val = mem_alloc(VALUES_PER_BLOCK * sizeof(*new_val))))
				return 0;
		}
	} else {
		nb_values = MIN_VALUES;
		if (!(new_val = mem_alloc(nb_values * sizeof(*new_val))))
			return 0;
	}
	m = (nb_values - 1) / VALUES_PER_BLOCK;
	key->values[m] = new_val;
	key->nb_values = nb_values;

	return 1;
}

/* find the named value of a given key and return its index in the array */
struct key_value *find_value(const struct reg_key *key, const struct unicode_str *name, int *index)
{
	int i, min, max, res;
	int m, n;
	data_size_t len;

	min = 0;
	max = key->last_value;
	while (min <= max) {
		i = (min + max) / 2;
		m = i / VALUES_PER_BLOCK;
		n = i % VALUES_PER_BLOCK;
		len = min((int)key->values[m][n].namelen, (int)name->len);
		res = memicmpW(key->values[m][n].name, name->str, len / sizeof(WCHAR));
		if (!res)
			res = key->values[m][n].namelen - name->len;
		if (!res) {
			*index = i;
			return &key->values[m][n];
		}
		if (res > 0)
			max = i - 1;
		else
			min = i + 1;
	}

	*index = min;  /* this is where we should insert it */
	return NULL;
}

/* insert a new value; the index must have been returned by find_value */
struct key_value *insert_value(struct reg_key *key, const struct unicode_str *name, int index)
{
	struct key_value *value;
	WCHAR *new_name = NULL;
	int i;

	if (name->len > MAX_VALUE_LEN * sizeof(WCHAR)) {
		set_error(STATUS_NAME_TOO_LONG);
		return NULL;
	}
	if (key->last_value + 1 == key->nb_values) {
		if (!grow_values(key))
			return NULL;
	}
	if (name->len && !(new_name = memdup(name->str, name->len)))
		return NULL;
	for (i = ++key->last_value; i > index; i--) {
		int m = i / VALUES_PER_BLOCK, n = i % VALUES_PER_BLOCK;
		int j = (i - 1) / VALUES_PER_BLOCK, k = (i - 1) % VALUES_PER_BLOCK;
		key->values[m][n] = key->values[j][k];
	}
	value = &key->values[index / VALUES_PER_BLOCK][index % VALUES_PER_BLOCK];
	value->name    = new_name;
	value->namelen = name->len;
	value->len     = 0;
	value->data    = NULL;
	return value;
}

/* set a key value */
void set_value(struct reg_key *key, const struct unicode_str *name,
		int type, const void *data, data_size_t len)
{
	struct key_value *value;
	void *ptr = NULL;
	int index;

	if ((value = find_value(key, name, &index))) {
		/* check if the new value is identical to the existing one */
		if (value->type == type && value->len == len &&
				value->data && !memcmp(value->data, data, len)) {
			return;
		}
	}

	if (len && !(ptr = memdup(data, len)))
		return;

	if (!value) {
		if (!(value = insert_value(key, name, index))) {
			free(ptr);
			return;
		}
	} else
		free(value->data); /* already existing, free previous data */

	value->type  = type;
	value->len   = len;
	value->data  = ptr;
	touch_key(key, REG_NOTIFY_CHANGE_LAST_SET);
	set_error(STATUS_SUCCESS);
}

/* enumerate a key value */
void enum_value(struct reg_key *key, int i, int info_class, struct enum_key_value_reply *reply)
{
	struct key_value *value;

	if (i < 0 || i > key->last_value)
		set_error(STATUS_NO_MORE_ENTRIES);
	else {
		void *data;
		data_size_t namelen, maxlen;
		int m = i / VALUES_PER_BLOCK;
		int n = i % VALUES_PER_BLOCK;

		value = &key->values[m][n];
		reply->type = value->type;
		namelen = value->namelen;

		switch (info_class) {
			case KeyValueBasicInformation:
				reply->total = namelen;
				break;
			case KeyValueFullInformation:
				reply->total = namelen + value->len;
				break;
			case KeyValuePartialInformation:
				reply->total = value->len;
				namelen = 0;
				break;
			default:
				set_error(STATUS_INVALID_PARAMETER);
				return;
		}

		maxlen = min(reply->total, get_reply_max_size());
		if (maxlen && ((data = set_reply_data_size(maxlen)))) {
			if (maxlen > namelen) {
				reply->namelen = namelen;
				memcpy(data, value->name, namelen);
				memcpy((char *)data + namelen, value->data, maxlen - namelen);
			} else {
				reply->namelen = maxlen;
				memcpy(data, value->name, maxlen);
			}
		}
		set_error(STATUS_SUCCESS);
	}
}

/* get a key value */
void get_value(struct reg_key *key, const struct unicode_str *name, int *type, data_size_t *len)
{
	struct key_value *value;
	int index;

	if ((value = find_value(key, name, &index))) {
		*type = value->type;
		*len  = value->len;
		if (value->data)
			set_reply_data(value->data, min(value->len, get_reply_max_size()));
		set_error(STATUS_SUCCESS);
	} else {
		kdebug("not found\n");
		*type = -1;
		set_error(STATUS_OBJECT_NAME_NOT_FOUND);
	}
}

/* delete a value */
void delete_value(struct reg_key *key, const struct unicode_str *name)
{
	struct key_value *value;
	int i, index;

	if (!(value = find_value(key, name, &index))) {
		set_error(STATUS_OBJECT_NAME_NOT_FOUND);
		return;
	}

	free(value->name);
	free(value->data);
	for (i = index; i < key->last_value; i++) {
		int m = i / VALUES_PER_BLOCK, n = i % VALUES_PER_BLOCK;
		int j = (i + 1) / VALUES_PER_BLOCK, k = (i + 1) % VALUES_PER_BLOCK;

		key->values[m][n] = key->values[j][k];
	}
	key->last_value--;
	touch_key(key, REG_NOTIFY_CHANGE_LAST_SET);
	set_error(STATUS_SUCCESS);
}

/* read a line from the input file */
int read_next_line(struct file_load_info *info)
{
	char *newbuf;
	int newlen, pos = 0;

	info->line++;
	for (;;) {
		if (!fgets(info->buffer + pos, info->len  - pos, info->file))
			return (pos != 0);  /* EOF */

		pos = strlen(info->buffer);

		if (info->buffer[pos - 1] == '\n') {
			/* got a full line */
			info->buffer[--pos] = 0;
			if (pos > 0 && info->buffer[pos-1] == '\r')
				info->buffer[pos - 1] = 0;
			return 1;
		}

		if (pos < info->len - 1) {
			kdebug("line %d, pos %x, len %x\n", info->line, pos, info->len);
			return 1;  /* EOF but something was read */
		}

		/* need to enlarge the buffer */
		newlen = info->len + info->len / 2;
		if (!(newbuf = realloc(info->buffer, newlen,pos))) {
			return -1;
		}
		info->buffer = newbuf;
		info->len = newlen;
	}
}

/* report an error while loading an input file */
void file_read_error(const char *err, struct file_load_info *info)
{
	if (info->filename)
		kdebug("%s:%d: %s '%s'\n", info->filename, info->line, err, info->buffer);
	else
		kdebug("<fd>:%d: %s '%s'\n", info->line, err, info->buffer);
}

/* make sure the temp buffer holds enough space */
int get_file_tmp_space(struct file_load_info *info, size_t size)
{
	WCHAR *tmp;

	if (info->tmplen >= size)
		return 1;

	if (!(tmp = realloc(info->tmp, size ,info->tmplen)))
		return 0;

	info->tmp = tmp;
	info->tmplen = size;

	return 1;
}

/* return the length (in path elements) of name that is part of the key name */
/* for instance if key is USER\foo\bar and name is foo\bar\baz, return 2 */
int get_prefix_len(struct reg_key *key, const char *name, struct file_load_info *info)
{
	WCHAR *p;
	int res;
	data_size_t len = strlen(name) * sizeof(WCHAR);

	if (!get_file_tmp_space(info, len))
		return 0;

	if ((res = parse_strW(info->tmp, &len, name, ']')) == -1) {
		file_read_error("Malformed key", info);
		return 0;
	}

	for (p = info->tmp; *p; p++)
		if (*p == '\\')
			break;
	len = (p - info->tmp) * sizeof(WCHAR);
	for (res = 1; key != root_key; res++) {
		if (len == key->namelen && !memicmpW(info->tmp, key->name, len / sizeof(WCHAR))) break;
		key = key->parent;
	}
	if (key == root_key)
		res = 0;  /* no matching name */

	return res;
}

struct reg_key *load_key(struct reg_key *base, const char *buffer, int flags,
		int prefix_len, struct file_load_info *info, int default_modif)
{
	WCHAR *p;
	struct unicode_str name;
	int res, modif;
	data_size_t len = strlen(buffer) * sizeof(WCHAR);

	if (!get_file_tmp_space(info, len))
		return NULL;

	if ((res = parse_strW(info->tmp, &len, buffer, ']')) == -1) {
		file_read_error("Malformed key", info);
		return NULL;
	}
	if (sscanf(buffer + res, " %d", &modif) != 1)
		modif = default_modif;

	p = info->tmp;
	while (prefix_len && *p) {
		if (*p++ == '\\')
			prefix_len--;
	}

	if (!*p) {
		if (prefix_len > 1) {
			file_read_error("Malformed key", info);
			return NULL;
		}
		/* empty key name, return base key */
		return (struct reg_key *)grab_object(base);
	}

	name.str = p;
	name.len = len - (p - info->tmp + 1) * sizeof(WCHAR);
	return create_key(base, &name, NULL, flags, modif, &res);
}

/* parse a value name and create the corresponding value */
struct key_value *parse_value_name(struct reg_key *key, const char *buffer,
		data_size_t *len, struct file_load_info *info)
{
	struct key_value *value;
	struct unicode_str name;
	int index;
	data_size_t maxlen = strlen(buffer) * sizeof(WCHAR);

	if (!get_file_tmp_space(info, maxlen))
		return NULL;

	name.str = info->tmp;
	if (buffer[0] == '@') {
		name.len = 0;
		*len = 1;
	} else {
		int r = parse_strW(info->tmp, &maxlen, buffer + 1, '\"');
		if (r == -1)
			goto error;
		*len = r + 1; /* for initial quote */
		name.len = maxlen - sizeof(WCHAR);
	}

	while (isspace(buffer[*len]))
		(*len)++;
	if (buffer[*len] != '=')
		goto error;
	(*len)++;
	while (isspace(buffer[*len]))
		(*len)++;
	if (!(value = find_value(key, &name, &index)))
		value = insert_value(key, &name, index);
	return value;

error:
	file_read_error("Malformed value name", info);
	return NULL;
}

/* load and create a key from the input file */
/* parse a comma-separated list of hex digits */
int parse_hex(unsigned char *dest, data_size_t *len, const char *buffer)
{
	const char *p = buffer;
	data_size_t count = 0;

	while (isxdigit(*p)) {
		int val;
		char buf[3];

		memcpy(buf, p, 2);
		buf[2] = 0;
		sscanf(buf, "%x", &val);
		if (count++ >= *len)
			return -1;  /* dest buffer overflow */
		*dest++ = (unsigned char)val;
		p += 2;
		if (*p == ',') p++;
	}
	*len = count;
	return p - buffer;
}

/* load a value from the input file */
int load_value(struct reg_key *key, const char *buffer, struct file_load_info *info)
{
	DWORD dw;
	void *ptr, *newptr;
	int res, type, parse_type;
	data_size_t maxlen, len;
	struct key_value *value;

	if (!(value = parse_value_name(key, buffer, &len, info)))
		return 0;

	if (!(res = get_data_type(buffer + len, &type, &parse_type)))
		goto error;
	buffer += len + res;

	switch (parse_type) {
		case REG_SZ:
			len = strlen(buffer) * sizeof(WCHAR);
			if (!get_file_tmp_space(info, len))
				return 0;
			if ((res = parse_strW(info->tmp, &len, buffer, '"')) == -1)
				goto error;
			ptr = info->tmp;
			break;
		case REG_DWORD:
			dw = simple_strtoul(buffer, NULL, 16);
			ptr = &dw;
			len = sizeof(dw);
			break;
		case REG_BINARY:  /* hex digits */
			len = 0;
			for (;;) {
				maxlen = 1 + strlen(buffer)/3;  /* 3 chars for one hex byte */
				if (!get_file_tmp_space(info, len + maxlen))
					return 0;
				if ((res = parse_hex((unsigned char *)info->tmp + len, &maxlen, buffer)) == -1)
					goto error;
				len += maxlen;
				buffer += res;
				while (isspace(*buffer))
					buffer++;
				if (!*buffer)
					break;
				if (*buffer != '\\')
					goto error;
				if (read_next_line(info) != 1)
					goto error;
				buffer = info->buffer;
				while (isspace(*buffer))
					buffer++;
			}
			ptr = info->tmp;
			break;
		default:
			ptr = NULL;  /* keep compiler quiet */
			break;
	}

	if (!len)
		newptr = NULL;
	else if (!(newptr = memdup(ptr, len)))
		return 0;

	free(value->data);
	value->data = newptr;
	value->len  = len;
	value->type = type;
	make_dirty(key);
	return 1;

error:
	file_read_error("Malformed value", info);
	return 0;
}

struct file_load_info info;

void load_keys(struct reg_key *key, const char *filename, struct LIBC_FILE *fp, int prefix_len)
{
	struct reg_key	*subkey = NULL;
	char *p;
	int default_modif = time(NULL);
	int flags = (key->flags & KEY_VOLATILE) ? KEY_VOLATILE : KEY_DIRTY;

	ktrace("load_keys begin, file %s\n", filename);

	info.filename = filename;
	info.file   = fp;
	info.len    = 511;
	info.tmplen = 511;
	info.line   = 0;
	if (!(info.buffer = mem_alloc(info.len + 1)))
		return;
	if (!(info.tmp = mem_alloc(info.tmplen + 1))) {
		free(info.buffer);
		return;
	}

	if ((read_next_line(&info) != 1) || strcmp(info.buffer, "WINE REGISTRY Version 2")) {
		set_error(STATUS_NOT_REGISTRY_FILE);
		kdebug("%s is not a valid registry file\n", filename);
		goto done;
	}

	while (read_next_line(&info) == 1) {
		p = info.buffer;
		while (*p && isspace(*p))
			p++;
		switch (*p) {
			case '[':   /* new key */
				if (subkey)
					release_object(subkey);
				if (prefix_len == -1)
					prefix_len = get_prefix_len(key, p + 1, &info);
				if (!(subkey = load_key(key, p + 1, flags, prefix_len, &info, default_modif)))
					file_read_error("Error creating key", &info);
				break;
			case '@':   /* default value */
			case '"':  /* value */
				if (subkey)
					load_value(subkey, p, &info);
				else
					file_read_error("Value without key", &info);
				break;
			case '#':   /* comment */
			case ';':   /* comment */
			case 0:     /* empty line */
				break;
			default:
				file_read_error("Unrecognized input", &info);
				break;
		}
	}

done:
	ktrace("done, line %d\n", info.line);
	if (subkey)
		release_object(subkey);

	free(info.buffer);
	free(info.tmp);
}

/* load one of the initial registry files */
void load_init_registry_from_file(const char *filename, struct reg_key *key)
{
	struct LIBC_FILE	*fp;
	struct file* filp;

	ktrace("file %s\n", filename);

	/* FIXME Don't create reg file when insmod module, because there is no .wine now */
	filp = filp_open(filename, O_RDONLY, DEFAULT_FILE_MODE);
	if (IS_ERR(filp)) {
		kdebug("filp_open error:%s\n",filename);
		if (PTR_ERR(filp) == -ENOENT)
			goto dotwine_not_exist;
		else
			return;
	}

	if ((fp = libc_file_open(filp, "r"))) {
		load_keys(key, filename, fp, 0);
		fclose(fp);
	}

dotwine_not_exist:
	if ((save_branch_info[save_branch_count].path = strdup(filename)))
		save_branch_info[save_branch_count++].key = (struct reg_key *)grab_object(key);
}

WCHAR *format_user_registry_path(const SID *sid, struct unicode_str *path)
{
	static const WCHAR prefixW[] = {'U','s','e','r','\\','S',0};
	static const WCHAR formatW[] = {'-','%','u',0};
	WCHAR buffer[7 + 10 + 10 + 10 * SID_MAX_SUB_AUTHORITIES];
	WCHAR *p = buffer;
	unsigned int i;

	strcpyW(p, prefixW);
	p += strlenW(prefixW);
	p += sprintfW(p, formatW, sid->Revision);
	p += sprintfW(p, formatW, MAKELONG(MAKEWORD(sid->IdentifierAuthority.Value[5],
					sid->IdentifierAuthority.Value[4]),
					MAKEWORD(sid->IdentifierAuthority.Value[3],
					sid->IdentifierAuthority.Value[2])));
	for (i = 0; i < sid->SubAuthorityCount; i++)
		p += sprintfW(p, formatW, sid->SubAuthority[i]);

	path->len = (p - buffer) * sizeof(WCHAR);
	path->str = p = memdup(buffer, path->len);
	return p;
}

void free_registry(void)
{
	release_object(root_key);
}

void kernel_init_registry(void)
{
	static const WCHAR HKLM[] = { 'M','a','c','h','i','n','e' };
	static const WCHAR HKU_default[] = { 'U','s','e','r','\\','.','D','e','f','a','u','l','t' };
	static const struct unicode_str root_name = { NULL, 0 };
	static const struct unicode_str HKLM_name = { HKLM, sizeof(HKLM) };
	static const struct unicode_str HKU_name = { HKU_default, sizeof(HKU_default) };

	WCHAR *current_user_path = NULL;
	struct unicode_str current_user_str;
	int dummy, prefix_len;

	const char *config = rootdir;
	char *p, *filename;
#if 0
	int ret;

	/* FIXME Don't create .wine when insmod module, because the user who insmod module is root. */
	ret = mkdir(config, 0777);
	if(ret && ret != -EEXIST)
		kdebug("sys_mkdir error\n");
#endif

	init_key_implement();

	prefix_len = strlen(config);
	filename = (char *)malloc(prefix_len + 16);
	memcpy(filename, config, prefix_len);
	p = filename + prefix_len;

	/* create the root key */
	root_key = alloc_key(&root_name, time(NULL));
	/* FIXME: if (!root_key) */

	/* create sys_key */
	if (!(sys_key = create_key(root_key, &HKLM_name, NULL, KEY_DIRTY, time(NULL), &dummy)))
		kdebug("could not create Machine registry key\n"); /* FIXME: */
	memcpy(p, "/system.reg", sizeof("/system.reg"));
	load_init_registry_from_file(filename, sys_key);
	release_object(sys_key); /* FIXME: */

	/* create udef_key */
	if (!(udef_key = create_key(root_key, &HKU_name, NULL, KEY_DIRTY, time(NULL), &dummy)))
		kdebug("could not create User\\.Default registry key\n"); /* FIXME: */
	memcpy(p, "/userdef.reg", sizeof("/userdef.reg"));
	load_init_registry_from_file(filename, udef_key);
	release_object(udef_key); /* FIXME: */

	/* FIXME: match default user in token.c. should get from process token instead */
	current_user_path = format_user_registry_path(security_interactive_sid, &current_user_str);
	if (!current_user_path ||
			!(user_key = create_key(root_key, &current_user_str, NULL, KEY_DIRTY, time(NULL), &dummy)))
		kdebug("could not create HKEY_CURRENT_USER registry key\n");
	memcpy(p, "/user.reg", sizeof("/user.reg"));
	load_init_registry_from_file(filename, user_key);
	release_object(user_key); /* FIXME: */

	save_kernel_task=kthread_create((void*)write_registry, NULL, "save_thread");
	if(!IS_ERR(save_kernel_task))
		wake_up_process(save_kernel_task);

	free(current_user_path);
	free(filename);
}

static struct reg_key *get_parent_key_obj(obj_handle_t hkey)
{
	ktrace("hkey %p\n", hkey);
	if (!hkey)
		return (struct reg_key *)grab_object(root_key);

	return (struct reg_key *)get_handle_obj(hkey, 0);
}

static inline struct reg_key *get_key_obj(obj_handle_t hkey, unsigned int access)
{
	return (struct reg_key *)get_handle_obj(hkey, access);
}

static struct notify *find_notify(struct reg_key *key, struct eprocess *process, obj_handle_t hkey)
{
	struct notify *notify;

	for (notify = list_entry((&key->notify_list)->next, struct notify, entry); 
			&notify->entry != &key->notify_list; 
			notify = list_entry(notify->entry.next, struct notify, entry)) {
		if (notify->process == process && notify->hkey == hkey)
			return notify;
	}

	return NULL;
}

/* open a subkey */
struct reg_key *open_key(struct reg_key *key, const struct unicode_str *name)
{
	int index;
	struct unicode_str token;

	token.str = NULL;
	if (!get_path_token(name, &token))
		return NULL;
	while (token.len) {
		WCHAR *wcs = kmalloc(token.len + sizeof(WCHAR), GFP_KERNEL);
		if (!wcs) {
			set_error(STATUS_NO_MEMORY);
			break;
		}
		memcpy(wcs, token.str, token.len);
		wcs[token.len / sizeof(WCHAR)] = 0;
		if (!(key = find_subkey(key, &token, &index))) {
			set_error(STATUS_OBJECT_NAME_NOT_FOUND);
			break;
		}
		get_path_token(name, &token);
	}

	if (key)
		grab_object(key);

	return key;
}

/* dump a Unicode string with proper escaping */
int dump_strW(const WCHAR *str, size_t len, struct LIBC_FILE *fp, const char escape[2])
{
	static const char escapes[32] = ".......abtnvfr.............e....";
	char buffer[256];
	char *pos = buffer;
	int count = 0;

	for (; len; str++, len--) {
		if (pos > buffer + sizeof(buffer) - 8) {
			fwrite(fp, buffer, pos - buffer);
			count += pos - buffer;
			pos = buffer;
		}
		if (*str > 127) { /* hex escape */
			if (len > 1 && str[1] < 128 && isxdigit((char)str[1]))
				pos += sprintf(pos, "\\x%04x", *str);
			else
				pos += sprintf(pos, "\\x%x", *str);
			continue;
		}
		if (*str < 32) { /* octal or C escape */
			if (!*str && len == 1)
				continue;  /* do not output terminating NULL */
			if (escapes[*str] != '.')
				pos += sprintf(pos, "\\%c", escapes[*str]);
			else if (len > 1 && str[1] >= '0' && str[1] <= '7')
				pos += sprintf(pos, "\\%03o", *str);
			else
				pos += sprintf(pos, "\\%o", *str);
			continue;
		}
		if (*str == '\\' || *str == escape[0] || *str == escape[1])
			*pos++ = '\\';
		*pos++ = *str;
	}

	fwrite(fp, buffer, pos - buffer);
	count += pos - buffer;
	return count;
}

/* dump the full path of a key */
void dump_path(const struct reg_key *key, const struct reg_key *base, struct LIBC_FILE *fp)
{
	if (key->parent && key->parent != base) {
		dump_path(key->parent, base, fp);
		fprintf(fp, "\\\\");
	}
	dump_strW(key->name, key->namelen / sizeof(WCHAR), fp, "[]");
}

/* dump a value to a text file */
void dump_value(const struct key_value *value, struct LIBC_FILE *fp)
{
	unsigned int i;
	int count;

	if (value->namelen) {
		fputc('\"', fp);
		count = 1 + dump_strW(value->name, value->namelen / sizeof(WCHAR), fp, "\"\"");
		count += fprintf(fp, "\"=");
	}
	else
		count = fprintf(fp, "@=");

	switch (value->type) {
		case REG_SZ:
		case REG_EXPAND_SZ:
		case REG_MULTI_SZ:
			if (value->type != REG_SZ)
				fprintf(fp, "str(%d):", value->type);
			fputc('\"', fp);
			if (value->data)
				dump_strW((WCHAR *)value->data, value->len / sizeof(WCHAR), fp, "\"\"");
			fputc('\"', fp);
			break;
		case REG_DWORD:
			if (value->len == sizeof(DWORD)) {
				DWORD dw;
				memcpy(&dw, value->data, sizeof(DWORD));
				fprintf(fp, "dword:%08x", dw);
				break;
			}
			/* else fall through */
		default:
			if (value->type == REG_BINARY)
				count += fprintf(fp, "hex:");
			else
				count += fprintf(fp, "hex(%x):", value->type);
			for (i = 0; i < value->len; i++) {
				count += fprintf(fp, "%02x", *((unsigned char *)value->data + i));
				if (i < value->len-1) {
					fputc(',', fp);
					if (++count > 76) {
						fprintf(fp, "\\\n  ");
						count = 2;
					}
				}
			}
			break;
	}
	fputc('\n', fp);
}


/* save a registry and all its subkeys to a text file */
static void save_subkeys(const struct reg_key *key, const struct reg_key *base,struct LIBC_FILE *fp)
{
	int i, m, n;

	if (key->flags & KEY_VOLATILE)
		return;

	if ((key->last_value >= 0) || (key->last_subkey == -1)) {
		fprintf(fp, "\n[");
		if (key != base)
			dump_path(key, base, fp);
		fprintf(fp, "] %ld\n", (long)key->modif);
		for (i = 0; i <= key->last_value; i++) {
			m = i / VALUES_PER_BLOCK;
			n = i % VALUES_PER_BLOCK;
			dump_value(&key->values[m][n], fp);
		}
	}

	for (i = 0; i <= key->last_subkey; i++)
		save_subkeys(key->subkeys[i], base, fp);
}

unsigned int key_map_access(struct object *obj, unsigned int access)
{
	if (access & GENERIC_READ)
		access |= KEY_READ;
	if (access & GENERIC_WRITE)
		access |= KEY_WRITE;
	if (access & GENERIC_EXECUTE)
		access |= KEY_EXECUTE;
	if (access & GENERIC_ALL)
		access |= KEY_ALL_ACCESS;
	return access & ~(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);
}

/* close the notification associated with a handle */
int key_close_handle(struct object *obj, struct eprocess *process, obj_handle_t handle)
{
	struct reg_key *key = (struct reg_key *)obj;
	struct notify *notify = find_notify(key, process, handle);

	if (notify)
		do_notification(key, notify, 1);
	return 1;  /* ok to close */
}

void key_destroy(struct object *obj)
{
	int i;
	struct list_head  *ptr;
	struct reg_key *key = (struct reg_key *)obj;
	/*assert(obj->ops == &key_ops);*/

	free(key->name);
	free(key->class);
	for (i = 0; i <= key->last_value; i++) {
		int m = i / VALUES_PER_BLOCK, n = i % VALUES_PER_BLOCK;
		if (key->values[m][n].name)
			free(key->values[m][n].name);
		if (key->values[m][n].data)
			free(key->values[m][n].data);
	}
	if (key->values[3])
		free(key->values[3]);
	if (key->values[2])
		free(key->values[2]);
	if (key->values[1])
		free(key->values[1]);
	if (key->values[0])
		free(key->values[0]);
	for (i = 0; i <= key->last_subkey; i++) {
		key->subkeys[i]->parent = NULL;
		release_object(key->subkeys[i]);
	}
	free(key->subkeys);
	/* unconditionally notify everything waiting on this key */
	while ((ptr = (((&key->notify_list)->next == &key->notify_list) ? (&key->notify_list)->next : NULL))) {
		struct notify *notify = list_entry(ptr, struct notify, entry);

		do_notification(key, notify, 1);
	}
}

/* load a part of the registry from a file */
void load_registry(struct reg_key *key, obj_handle_t handle)
{
	struct file *filp;

	ktrace("\n");
	/* file handle replaced to name */   
	filp = fget(get_handle_fd(get_current_eprocess(), handle));
	if (filp) {
		struct LIBC_FILE *fp = libc_file_open(filp, "r");
		if (fp) {
			load_keys(key, NULL, fp, -1);
			fclose(fp);
		} else {
			fput(filp);
		}
	} else
		set_error(STATUS_INVALID_HANDLE);
}

/* save a registry branch to a file */
void save_all_subkeys(struct reg_key *key, struct LIBC_FILE *fp)
{
	fprintf(fp, "WINE REGISTRY Version 2\n");
	fprintf(fp, ";; All keys relative to ");
	dump_path(key, NULL, fp);
	fprintf(fp, "\n");
	save_subkeys(key, key, fp);
}

/* save a registry branch to a file handle */
void save_registry(struct reg_key *key, obj_handle_t handle)
{
	struct file *filp;

	if (key->flags & KEY_DELETED) {
		set_error(STATUS_KEY_DELETED);
		return;
	}

	/*FIXME*/
	filp = fget(get_handle_fd(get_current_eprocess(), handle));
	if (filp) {
		struct LIBC_FILE *fp = libc_file_open(filp, "w");
		if (fp) {
			save_all_subkeys(key, fp);
			fclose(fp);
		} else {
			fput(filp);
		}
	} else
		set_error(STATUS_INVALID_HANDLE);
}

/* save a registry branch to a file */
int save_branch(struct reg_key *key, const char *path)
{
	char *p, *tmp = NULL;
	int count = 0, ret = 0;
	struct LIBC_FILE *fp;
	struct file *filp;

	ktrace("reg_key %p, path %s\n", key, path);

	if (!(key->flags & KEY_DIRTY))
		return 1;

	/* create a temp file in the same directory */
	if (!(tmp = malloc(strlen(path) + 20)))
		return 0;
	strcpy(tmp, path);
	if ((p = strrchr(tmp, '/')))
		p++;
	else
		p = tmp;
	for (;;) {
		sprintf(p, "reg%lx%04x.tmp", (long)getpid(), count++);
		if (!IS_ERR(filp = filp_open(tmp, O_CREAT | O_EXCL | O_WRONLY, 0666)))
			break;
		if (PTR_ERR(filp) != -EEXIST)
			goto done;
	}

	if (!(fp = libc_file_open(filp, "w"))) {
		fput(filp);
		unlink(tmp);
		goto done;
	}
	save_all_subkeys(key, fp);
	ret = fclose(fp);
	/* if successfully written, rename to final name */
	if (!ret)
		ret = rename(tmp, path /* "./system_reg.new"*/);
	if (ret)
		unlink(tmp);
	else
		make_clean(key);

	ret = !ret;

done:
	free(tmp);
	return ret;
}

void flush_registry(void)
{
	int i;

	for (i = 0; i < save_branch_count; i++) {
		if (!save_branch(save_branch_info[i].key, save_branch_info[i].path)) {
			kdebug("could not save registry branch to %s\n", save_branch_info[i].path);
		}
	}
}

void write_registry(void)
{
	int i,j,dirty_count,k=1,write_num=200;
	unsigned int msecs,timeout;
	msecs = 10000;
	timeout = msecs_to_jiffies(msecs)+1;

	ktrace("\n");
	while (1) {
		dirty_count = 0;
		for (i=0;i < save_branch_count;i++){
			if (save_branch_info[i].key->flags & KEY_DIRTY)
				dirty_count++;
			for (j = 0; j < save_branch_info[i].key->last_subkey; j++)
				if ((*(save_branch_info[i].key->subkeys + j))->flags&KEY_DIRTY)
					dirty_count++;
		}

		if (kthread_should_stop()) {
			for (i = 0; i < save_branch_count; i++) {
				if (!save_branch(save_branch_info[i].key, save_branch_info[i].path)) {
					kdebug("could not save registry branch to %s\n", save_branch_info[i].path);
				}
			}
			return;
		}
		k = k*2;
		if (k > (2*write_num))
			k = k/2;
		if (dirty_count < write_num/k || dirty_count == 0) {
			goto sleep;
		}
		k = k/2;
		if(k == 0)
			k = 1;

		for (i = 0; i < save_branch_count; i++) {
			if (!save_branch(save_branch_info[i].key, save_branch_info[i].path)) {
				kdebug("could not save registry branch to %s\n", save_branch_info[i].path);
			}
		}
sleep:
		schedule_timeout_interruptible(timeout);
	}
}

void write_back_branches(void)
{
	save_branch(sys_key, "./system_reg.new"/*"/root/.wine/system_reg.new"*/);
	save_branch(user_key, "./user_reg.new"/*"/root/.wine/system_reg.new"*/);
	save_branch(udef_key, "./udef_reg.new"/*"/root/.wine/system_reg.new"*/);
}

DECL_HANDLER(load_init_registry)
{
	struct reg_key *key;
	struct unicode_str keyname;
	int dummy;
	char *filename;

	keyname.len = req->keylen;
	keyname.str = malloc(keyname.len);
	if (copy_from_user((void *)keyname.str, req->keyname, keyname.len))
		return;

	filename = malloc(MAX_PATH);
	if (!filename)
		goto out_free_keyname;
	if (copy_from_user((void *)filename, req->filename, req->filelen)) {
		set_error(STATUS_INVALID_ADDRESS);
		goto out_free_filename;
	}

	key = create_key(root_key, &keyname, NULL, 0, time(NULL), &dummy);

	load_init_registry_from_file(req->filename, key);

out_free_filename:
	free((void *)filename);

out_free_keyname:
	free((void *)keyname.str);
}

DECL_HANDLER(save_branch)
{
	ktrace("\n");

	save_branch(save_branch_info[req->branch_num].key,
			save_branch_info[req->branch_num].path);
}

DECL_HANDLER(create_key)
{
	struct reg_key *key = NULL, *parent;
	struct unicode_str name, class;
	unsigned int access = req->access;

	ktrace("\n");

	reply->hkey = NULL;

	if (req->namelen > get_req_data_size()) {
		set_error(STATUS_INVALID_PARAMETER);
		kdebug("fail, name to long\n");
		return;
	}

	class.str = (const WCHAR *)get_req_data() + req->namelen / sizeof(WCHAR);
	class.len = ((get_req_data_size() - req->namelen) / sizeof(WCHAR)) * sizeof(WCHAR);
	get_req_path(&name, !req->parent);

	if (name.str > class.str) {
		set_error(STATUS_INVALID_PARAMETER);
		kdebug("fail, name > class\n");
		return;
	}

	name.len = (class.str - name.str) * sizeof(WCHAR);

	/* NOTE: no access rights are required from the parent handle to create a key */
	if ((parent = get_parent_key_obj(req->parent))) {
		int flags = (req->options & REG_OPTION_VOLATILE) ? KEY_VOLATILE : KEY_DIRTY;

		if ((key = create_key(parent, &name, &class, flags, req->modif, &reply->created))) {
			reply->hkey = alloc_key_handle(key, access, req->attributes);
			release_object(key);
		}
		release_object(parent);
	}
	ktrace("done, status %x\n", get_error());
}

/* open a registry key */
DECL_HANDLER(open_key)
{
	struct reg_key *key, *parent;
	struct unicode_str name;
	unsigned int access = req->access;

	ktrace("\n");

	reply->hkey = 0;

	/* NOTE: no access rights are required to open the parent key, only the child key */
	if ((parent = get_parent_key_obj(req->parent))) {
		get_req_path(&name, !req->parent);

		if ((key = open_key(parent, &name))) {
			reply->hkey = alloc_key_handle(key, access, req->attributes);
			release_object(key);
		}
		release_object(parent);
	}
}

/* delete a registry key */
DECL_HANDLER(delete_key)
{
	struct reg_key *key;

	ktrace("\n");
	if ((key = get_key_obj(req->hkey, KEY_ALL_ACCESS))) {
		delete_key(key, 0);
		release_object(key);
	}
}

/* flush a registry key */
DECL_HANDLER(flush_key)
{
	struct reg_key *key = get_key_obj(req->hkey, KEY_WRITE);

	ktrace("\n");

	if (key) {
		/* FIXME we don't need to do anything here with the current implementation */
		release_object(key);
	}
}

/* enumerate registry subkeys */
DECL_HANDLER(enum_key)
{
	struct reg_key *key;
	int access = req->index == -1 ? KEY_QUERY_VALUE : KEY_ENUMERATE_SUB_KEYS;

	ktrace("\n");

	if ((key = get_key_obj(req->hkey, access))) {
		enum_key(key, req->index, req->info_class, reply);
		release_object(key);
	}
}


/* set a value of a registry key */
DECL_HANDLER(set_key_value)
{
	struct reg_key *key;
	struct unicode_str name;

	ktrace("\n");

	if (req->namelen > get_req_data_size()) {
		set_error(STATUS_INVALID_PARAMETER);
		return;
	}
	name.str = get_req_data();
	name.len = (req->namelen / sizeof(WCHAR)) * sizeof(WCHAR);

	if ((key = get_key_obj(req->hkey, KEY_SET_VALUE))) {
		data_size_t datalen = get_req_data_size() - req->namelen;
		const char *data = (const char *)get_req_data() + req->namelen;

		set_value(key, &name, req->type, data, datalen);
		release_object(key);
	}
}


/* retrieve the value of a registry key */
DECL_HANDLER(get_key_value)
{
	struct reg_key *key;
	struct unicode_str name;

	ktrace("\n");

	reply->total = 0;
	if ((key = get_key_obj(req->hkey, KEY_QUERY_VALUE))) {
		get_req_unicode_str(&name);
		get_value(key, &name, &reply->type, &reply->total);
		release_object(key);
	}
}

/* enumerate the value of a registry key */
DECL_HANDLER(enum_key_value)
{
	struct reg_key *key;

	ktrace("\n");

	if ((key = get_key_obj(req->hkey, KEY_QUERY_VALUE))) {
		enum_value(key, req->index, req->info_class, reply);
		release_object(key);
	}
}

/* delete a value of a registry key */
DECL_HANDLER(delete_key_value)
{
	struct reg_key *key;
	struct unicode_str name;

	ktrace("\n");

	if ((key = get_key_obj(req->hkey, KEY_SET_VALUE))) {
		get_req_unicode_str(&name);
		delete_value(key, &name);
		release_object(key);
	}
}

/* load a registry branch from a file */
DECL_HANDLER(load_registry)
{
	struct reg_key *key, *parent;
	struct unicode_str name;

	ktrace("\n");
	if ((parent = get_parent_key_obj(req->hkey))) {
		int dummy;

		get_req_path(&name, !req->hkey);
		if ((key = create_key(parent, &name, NULL, KEY_DIRTY, time(NULL), &dummy))) {
			load_registry(key, req->file);
			release_object(key);
		}
		release_object(parent);
	}
}


DECL_HANDLER(unload_registry)
{
	struct reg_key *key;

	ktrace("\n");
	if ((key = get_key_obj(req->hkey, 0))) {
		delete_key(key, 1);     /* FIXME */
		release_object(key);
	}
}


/* save a registry branch to a file */
DECL_HANDLER(save_registry)
{
	struct reg_key *key;

	ktrace("save_registry\n");

	if ((key = get_key_obj(req->hkey, 0))) {
		save_registry(key, req->file);
		release_object(key);
	}
}


/* add a registry key change notification */
DECL_HANDLER(set_registry_notification)
{
	struct reg_key *key;
	struct kevent *event;
	struct notify *notify;

	ktrace("\n");
	key = get_key_obj(req->hkey, KEY_NOTIFY);
	if (key) {
		event = get_event_obj(NULL, req->event, SYNCHRONIZE);
		if (event) {
			notify = find_notify(key, get_current_eprocess(), req->hkey);
			if (notify) {
				if (notify->event)
					release_object(notify->event);
				grab_object(event);
				notify->event = event;
			} else {
				notify = mem_alloc(sizeof(*notify));
				if (notify) {
					grab_object(event);
					notify->event   = event;
					notify->subtree = req->subtree;
					notify->filter  = req->filter;
					notify->hkey    = req->hkey;
					notify->process = get_current_eprocess();
					list_add_head(&key->notify_list, &notify->entry);
				}
			}
			release_object(event);
		}
		release_object(key);
	}
}
#endif /* CONFIG_UNIFIED_KERNEL */
