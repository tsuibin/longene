/*
 * token.h
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
 *   May 2010 - Created.
 */

/* 
 * token.h:
 * Refered to Wine code
 */
#ifndef _WINESERVER_TOKEN_H
#define _WINESERVER_TOKEN_H

#ifdef CONFIG_UNIFIED_KERNEL
/* ACEs, directly starting after an ACL */
typedef struct _ACE_HEADER {
	BYTE	AceType;
	BYTE	AceFlags;
	WORD	AceSize;
} ACE_HEADER,*PACE_HEADER;

/* AceType */
#define	ACCESS_ALLOWED_ACE_TYPE		0
#define	ACCESS_DENIED_ACE_TYPE		1
#define	SYSTEM_AUDIT_ACE_TYPE		2
#define	SYSTEM_ALARM_ACE_TYPE		3

/* inherit AceFlags */
#define	OBJECT_INHERIT_ACE		0x01
#define	CONTAINER_INHERIT_ACE		0x02
#define	NO_PROPAGATE_INHERIT_ACE	0x04
#define	INHERIT_ONLY_ACE		0x08
#define	INHERITED_ACE		        0x10
#define	VALID_INHERIT_FLAGS		0x1F

/* AceFlags mask for what events we (should) audit */
#define	SUCCESSFUL_ACCESS_ACE_FLAG	0x40
#define	FAILED_ACCESS_ACE_FLAG		0x80

#define MAX_ACL_LEN 65535

typedef struct _ACCESS_DENIED_ACE {
	ACE_HEADER  Header;
	DWORD       Mask;
	DWORD       SidStart;
} ACCESS_DENIED_ACE,*PACCESS_DENIED_ACE;

typedef struct _ACCESS_ALLOWED_ACE {
	ACE_HEADER  Header;
	DWORD       Mask;
	DWORD       SidStart;
} ACCESS_ALLOWED_ACE,*PACCESS_ALLOWED_ACE;

typedef struct _SYSTEM_AUDIT_ACE {
	ACE_HEADER  Header;
	DWORD       Mask;
	DWORD       SidStart;
} SYSTEM_AUDIT_ACE,*PSYSTEM_AUDIT_ACE;

typedef struct _SYSTEM_ALARM_ACE {
	ACE_HEADER  Header;
	DWORD       Mask;
	DWORD       SidStart;
} SYSTEM_ALARM_ACE,*PSYSTEM_ALARM_ACE;

#define SE_GROUP_MANDATORY      0x00000001
#define SE_GROUP_ENABLED_BY_DEFAULT     0x00000002
#define SE_GROUP_ENABLED        0x00000004
#define SE_GROUP_OWNER          0x00000008
#define SE_GROUP_USE_FOR_DENY_ONLY  0x00000010
#define SE_GROUP_LOGON_ID       0xC0000000
#define SE_GROUP_RESOURCE       0x20000000

#define SE_PRIVILEGE_ENABLED_BY_DEFAULT 0x00000001
#define SE_PRIVILEGE_ENABLED        0x00000002
#define SE_PRIVILEGE_REMOVE     0x00000004
#define SE_PRIVILEGE_USED_FOR_ACCESS    0x80000000

#define PRIVILEGE_SET_ALL_NECESSARY     1

#define ACL_REVISION1 1
#define ACL_REVISION2 2
#define ACL_REVISION3 3
#define ACL_REVISION4 4

#define MIN_ACL_REVISION ACL_REVISION2
#define MAX_ACL_REVISION ACL_REVISION4

#define ACL_REVISION 2

#define FOREST_USER_RID_MAX                     0x000001F3L
#define DOMAIN_USER_RID_ADMIN                   0x000001F4L
#define DOMAIN_USER_RID_GUEST                   0x000001F5L
#define DOMAIN_USER_RID_KRBTGT                  0x000001F6L
#define DOMAIN_USER_RID_MAX                     0x000003E7L

#define DOMAIN_GROUP_RID_ADMINS                 0x00000200L
#define DOMAIN_GROUP_RID_USERS                  0x00000201L
#define DOMAIN_GROUP_RID_GUESTS                 0x00000202L
#define DOMAIN_GROUP_RID_COMPUTERS              0x00000203L
#define DOMAIN_GROUP_RID_CONTROLLERS            0x00000204L
#define DOMAIN_GROUP_RID_CERT_ADMINS            0x00000205L
#define DOMAIN_GROUP_RID_SCHEMA_ADMINS          0x00000206L
#define DOMAIN_GROUP_RID_ENTERPRISE_ADMINS      0x00000207L
#define DOMAIN_GROUP_RID_POLICY_ADMINS          0x00000208L

#define DOMAIN_ALIAS_RID_ADMINS                 0x00000220L
#define DOMAIN_ALIAS_RID_USERS                  0x00000221L
#define DOMAIN_ALIAS_RID_GUESTS                 0x00000222L
#define DOMAIN_ALIAS_RID_POWER_USERS            0x00000223L

#define DOMAIN_ALIAS_RID_ACCOUNT_OPS            0x00000224L
#define DOMAIN_ALIAS_RID_SYSTEM_OPS             0x00000225L
#define DOMAIN_ALIAS_RID_PRINT_OPS              0x00000226L
#define DOMAIN_ALIAS_RID_BACKUP_OPS             0x00000227L

#define DOMAIN_ALIAS_RID_REPLICATOR             0x00000228L
#define DOMAIN_ALIAS_RID_RAS_SERVERS            0x00000229L
#define DOMAIN_ALIAS_RID_PREW2KCOMPACCESS       0x0000022AL
#define DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS   0x0000022BL
#define DOMAIN_ALIAS_RID_NETWORK_CONFIGURATION_OPS 0x0000022CL
#define DOMAIN_ALIAS_RID_INCOMING_FOREST_TRUST_BUILDERS 0x0000022DL

#define DOMAIN_ALIAS_RID_MONITORING_USERS       0x0000022EL
#define DOMAIN_ALIAS_RID_LOGGING_USERS          0x0000022FL
#define DOMAIN_ALIAS_RID_AUTHORIZATIONACCESS    0x00000230L
#define DOMAIN_ALIAS_RID_TS_LICENSE_SERVERS     0x00000231L
#define DOMAIN_ALIAS_RID_DCOM_USERS             0x00000232L

#define SECURITY_SERVER_LOGON_RID       SECURITY_ENTERPRISE_CONTROLLERS_RID

#define SECURITY_PACKAGE_RID_COUNT              2L
#define SECURITY_LOGON_IDS_RID_COUNT        3L

#define OWNER_SECURITY_INFORMATION  0x00000001
#define GROUP_SECURITY_INFORMATION  0x00000002
#define DACL_SECURITY_INFORMATION   0x00000004
#define SACL_SECURITY_INFORMATION   0x00000008

#define OWNER_SECURITY_INFORMATION  0x00000001
#define GROUP_SECURITY_INFORMATION  0x00000002
#define DACL_SECURITY_INFORMATION   0x00000004
#define SACL_SECURITY_INFORMATION   0x00000008

#endif /* CONFIG_UNIFIED_KERNEL */
#endif /* _WINESERVER_TOKEN_H */
