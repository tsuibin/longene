/*
 * reg.h
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
 * reg.h:
 * Refered to Wine code
 */
#ifndef _WINESERVER_REG_H
#define _WINESERVER_REG_H
#include "wineserver/lib.h"

#ifdef CONFIG_UNIFIED_KERNEL
#define REG_OPTION_RESERVED		0x00000000
#define REG_OPTION_NON_VOLATILE		0x00000000
#define REG_OPTION_VOLATILE		0x00000001
#define REG_OPTION_CREATE_LINK		0x00000002
#define REG_OPTION_BACKUP_RESTORE	0x00000004 /* FIXME */
#define REG_OPTION_OPEN_LINK		0x00000008
#define REG_LEGAL_OPTION	       (REG_OPTION_RESERVED|  \
		REG_OPTION_NON_VOLATILE|  \
		REG_OPTION_VOLATILE|  \
		REG_OPTION_CREATE_LINK|  \
		REG_OPTION_BACKUP_RESTORE|  \
		REG_OPTION_OPEN_LINK)


#define REG_CREATED_NEW_KEY	0x00000001
#define REG_OPENED_EXISTING_KEY	0x00000002

/* For RegNotifyChangeKeyValue */
#define REG_NOTIFY_CHANGE_NAME       0x01
#define REG_NOTIFY_CHANGE_ATTRIBUTES 0x02
#define REG_NOTIFY_CHANGE_LAST_SET   0x04
#define REG_NOTIFY_CHANGE_SECURITY   0x08

/* for RegKeyRestore flags */
#define REG_WHOLE_HIVE_VOLATILE 0x00000001
#define REG_REFRESH_HIVE        0x00000002
#define REG_NO_LAZY_FLUSH       0x00000004
#define REG_FORCE_RESTORE       0x00000008

/* key flags */
#define KEY_VOLATILE 0x0001  /* key is volatile (not saved to disk) */
#define KEY_DELETED  0x0002  /* key has been deleted */
#define KEY_DIRTY    0x0004  /* key has been modified */

#define MIN_SUBKEYS  8   /* min. number of allocated subkeys per key */
#define MIN_VALUES   8   /* min. number of allocated values per key */

#define MAX_NAME_LEN  MAX_PATH  /* max. length of a key name */
#define MAX_VALUE_LEN MAX_PATH  /* max. length of a value name */

#define REG_NONE                0       /* no type */
#define REG_SZ                  1       /* string type (ASCII) */
#define REG_EXPAND_SZ           2       /* string, includes %ENVVAR% (expanded by caller) (ASCII) */
#define REG_BINARY              3       /* binary format, callerspecific */
/* YES, REG_DWORD == REG_DWORD_LITTLE_ENDIAN */
#define REG_DWORD               4       /* DWORD in little endian format */
#define REG_DWORD_LITTLE_ENDIAN 4       /* DWORD in little endian format */
#define REG_DWORD_BIG_ENDIAN    5       /* DWORD in big endian format  */
#define REG_LINK                6       /* symbolic link (UNICODE) */
#define REG_MULTI_SZ            7       /* multiple strings, delimited by \0, terminated by \0\0 (ASCII) */
#define REG_RESOURCE_LIST       8       /* resource list? huh? */
#define REG_FULL_RESOURCE_DESCRIPTOR    9       /* full resource descriptor? huh? */
#define REG_RESOURCE_REQUIREMENTS_LIST  10
#define REG_QWORD               11      /* QWORD in little endian format */
#define REG_QWORD_LITTLE_ENDIAN 11      /* QWORD in little endian format */

/* security entities */
#define SECURITY_NULL_RID			(0x00000000L)
#define SECURITY_WORLD_RID			(0x00000000L)
#define SECURITY_LOCAL_RID			(0X00000000L)

#define SECURITY_NULL_SID_AUTHORITY		{0,0,0,0,0,0}

/* S-1-1 */
#define SECURITY_WORLD_SID_AUTHORITY		{0,0,0,0,0,1}

/* S-1-2 */
#define SECURITY_LOCAL_SID_AUTHORITY		{0,0,0,0,0,2}

/* S-1-3 */
#define SECURITY_CREATOR_SID_AUTHORITY		{0,0,0,0,0,3}
#define SECURITY_CREATOR_OWNER_RID		(0x00000000L)
#define SECURITY_CREATOR_GROUP_RID		(0x00000001L)
#define SECURITY_CREATOR_OWNER_SERVER_RID	(0x00000002L)
#define SECURITY_CREATOR_GROUP_SERVER_RID	(0x00000003L)

/* S-1-4 */
#define SECURITY_NON_UNIQUE_AUTHORITY		{0,0,0,0,0,4}

/* S-1-5 */
#define SECURITY_NT_AUTHORITY			{0,0,0,0,0,5}
#define SECURITY_DIALUP_RID                     0x00000001L
#define SECURITY_NETWORK_RID                    0x00000002L
#define SECURITY_BATCH_RID                      0x00000003L
#define SECURITY_INTERACTIVE_RID                0x00000004L
#define SECURITY_LOGON_IDS_RID                  0x00000005L
#define SECURITY_SERVICE_RID                    0x00000006L
#define SECURITY_ANONYMOUS_LOGON_RID            0x00000007L
#define SECURITY_PROXY_RID                      0x00000008L
#define SECURITY_ENTERPRISE_CONTROLLERS_RID     0x00000009L
#define SECURITY_SERVER_LOGON_RID               SECURITY_ENTERPRISE_CONTROLLERS_RID
#define SECURITY_PRINCIPAL_SELF_RID             0x0000000AL
#define SECURITY_AUTHENTICATED_USER_RID         0x0000000BL
#define SECURITY_RESTRICTED_CODE_RID            0x0000000CL
#define SECURITY_TERMINAL_SERVER_RID            0x0000000DL
#define SECURITY_REMOTE_LOGON_RID               0x0000000EL
#define SECURITY_THIS_ORGANIZATION_RID          0x0000000FL
#define SECURITY_LOCAL_SYSTEM_RID               0x00000012L
#define SECURITY_LOCAL_SERVICE_RID              0x00000013L
#define SECURITY_NETWORK_SERVICE_RID            0x00000014L
#define SECURITY_NT_NON_UNIQUE                  0x00000015L
#define SECURITY_BUILTIN_DOMAIN_RID             0x00000020L

#define SECURITY_PACKAGE_BASE_RID               0x00000040L
#define SECURITY_PACKAGE_NTLM_RID               0x0000000AL
#define SECURITY_PACKAGE_SCHANNEL_RID           0x0000000EL
#define SECURITY_PACKAGE_DIGEST_RID             0x00000015L
#define SECURITY_MAX_ALWAYS_FILTERED            0x000003E7L
#define SECURITY_MIN_NEVER_FILTERED             0x000003E8L
#define SECURITY_OTHER_ORGANIZATION_RID         0x000003E8L

#define	SID_REVISION			(1)	/* Current revision */
#define	SID_MAX_SUB_AUTHORITIES		(15)	/* current max subauths */
#define	SID_RECOMMENDED_SUB_AUTHORITIES	(1)	/* recommended subauths */

#define SECURITY_MAX_SID_SIZE (sizeof(SID) - sizeof(DWORD) + (SID_MAX_SUB_AUTHORITIES * sizeof(DWORD)))

#define KEY_QUERY_VALUE 1
#define KEY_SET_VALUE 2
#define KEY_CREATE_SUB_KEY 4
#define KEY_ENUMERATE_SUB_KEYS 8
#define KEY_NOTIFY 16
#define KEY_CREATE_LINK 32
#define KEY_WRITE 0x20006
#define KEY_EXECUTE 0x20019
#define KEY_READ 0x20019
#define KEY_ALL_ACCESS 0xf003f


#define MAKEWORD(low,high)     ((WORD)(((BYTE)((DWORD_PTR)(low) & 0xFF)) \
			| ((WORD)((BYTE)((DWORD_PTR)(high) & 0xFF))) << 8))
#define MAKELONG(low,high)     ((LONG)(((WORD)((DWORD_PTR)(low) & 0xFFFF)) \
			| ((DWORD)((WORD)((DWORD_PTR)(high) & 0xFFFF))) << 16))

struct notify
{
	struct list_head  entry;    /* entry in list of notifications */
	struct kevent    *event;    /* event to set when changing this key */
	int               subtree;  /* true if subtree notification */
	unsigned int      filter;   /* which events to notify on */
	obj_handle_t      hkey;     /* hkey associated with this notification */
	struct eprocess  *process;  /* process in which the hkey is valid */
};

/* information about a file being loaded */
struct file_load_info
{
	const char *filename; /* input file name */
	struct LIBC_FILE       *file;     /* input file */
	char       *buffer;   /* line buffer */
	int         len;      /* buffer length */
	int         line;     /* current input line */
	WCHAR      *tmp;      /* temp buffer to use while parsing input */
	size_t      tmplen;   /* length of temp buffer */
};

/* a key value */
struct key_value
{
	WCHAR            *name;    /* value name */
	unsigned short    namelen; /* length of value name */
	unsigned short    type;    /* value type */
	data_size_t       len;     /* value data length in bytes */
	void             *data;    /* pointer to value data */
};

#define VALUES_PER_BLOCK 0x1000

struct reg_key
{
	WCHAR            *name;        /* key name */
	WCHAR            *class;       /* key class */
	unsigned short    namelen;     /* length of key name */
	unsigned short    classlen;    /* length of class name */
	struct reg_key   *parent;      /* parent key */
	int               last_subkey; /* last in use subkey */
	int               nb_subkeys;  /* count of allocated subkeys */
	struct reg_key  **subkeys;     /* subkeys array */
	int               last_value;  /* last in use value */
	int               nb_values;   /* count of allocated values in array */
	struct key_value *values[4];   /* values array */
	unsigned int      flags;       /* flags */
	time_t            modif;       /* last modification time */
	struct list_head  notify_list; /* list of notifications */
};

#define MAX_SAVE_BRANCH_INFO 3

/* information about where to save a registry branch */
struct save_branch_info
{
	struct reg_key  *key;
	char        *path;
};

/* ch [0-9A-Fa-f] */
static inline char to_hex(char ch)
{
	return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

#endif /* CONFIG_UNIFIED_KERNEL */
#endif /* _WINESERVER_REG_H */
