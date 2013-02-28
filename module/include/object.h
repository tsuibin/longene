/*
 * object.h
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
 *   Jan 2007 - Created.
 */
 
/*
 * object.h: win32 object definition
 * Refered to ReactOS code
 */
#ifndef _OBJECT_H
#define _OBJECT_H

#include <asm/atomic.h>
#include <asm/uaccess.h>
#include "ntstatus.h"

#ifdef HAVE_SYS_POLL_H
#include <sys/poll.h>
#endif

#include "wineserver/list.h"
#include "wineserver/protocol.h"

#ifdef CONFIG_UNIFIED_KERNEL
#define POLL_NOTSIG	0
#define POLL_SIG	1

#define	OBJ_MAX_REPARSE_ATTEMPTS	16

#define		OBJ_NAME_PATH_SEPARATOR	((WCHAR)L'\\')

/* Values for DosDeviceDriveType */
#define DOSDEVICE_DRIVE_UNKNOWN		0
#define DOSDEVICE_DRIVE_CALCULATE	1
#define DOSDEVICE_DRIVE_REMOVABLE	2
#define DOSDEVICE_DRIVE_FIXED		3
#define DOSDEVICE_DRIVE_REMOTE		4
#define DOSDEVICE_DRIVE_CDROM		5
#define DOSDEVICE_DRIVE_RAMDISK		6

/* Object Flags */
#define OB_FLAG_CREATE_INFO    0x01
#define OB_FLAG_KERNEL_MODE    0x02
#define OB_FLAG_CREATOR_INFO   0x04
#define OB_FLAG_EXCLUSIVE      0x08
#define OB_FLAG_PERMANENT      0x10
#define OB_FLAG_SECURITY       0x20
#define OB_FLAG_SINGLE_PROCESS 0x40

#define TRANSLATE_NAME 0x01

struct wait_table_entry;

struct namespace;
struct object;
struct object_name;
struct w32thread;
struct w32process;
struct token;
struct file;
struct wait_queue_entry;
struct async;
struct async_queue;
struct winstation;
struct directory;

struct unicode_str
{
	const WCHAR *str;
	unsigned int  len;
};

struct object_type;
extern struct object_type *no_get_type(struct object *obj);

/* operations valid on all objects */
struct object_ops
{
	/* size of this object type */
	size_t size;
	/* dump the object (for debugging) */
	void (*dump)(struct object *,int);
	/* return the object type */
	struct object_type *(*get_type)(struct object *);
	/* return an fd object that can be used to read/write from the object */
	struct fd *(*get_fd)(struct object *);
	/* map access rights to the specific rights for this object */
	unsigned int (*map_access)(struct object *, unsigned int);
	/* lookup a name if an object has a namespace */
	struct object *(*lookup_name)(struct object *, struct unicode_str *,unsigned int);
	/* open a file object to access this object */
	struct object *(*open_file)(struct object *, unsigned int access, unsigned int sharing,
			unsigned int options);
	/* close a handle to this object */
	int (*close_handle)(struct object *,struct w32process *,obj_handle_t);
	/* destroy on refcount == 0 */
	void (*destroy)(struct object *);

	/* is object signaled? */
	int  (*signaled)(struct object *,struct w32thread *);
	/* wait satisfied; return 1 if abandoned */
	int  (*satisfied)(struct object *,struct w32thread *);
	/* signal an object */
	int  (*signal)(struct object *, unsigned int);
	/* returns the security descriptor of the object */
	struct security_descriptor *(*get_sd)(struct object *);
	/* sets the security descriptor of the object */
	int (*set_sd)(struct object *, const struct security_descriptor *, unsigned int);
};

struct wait_queue_entry
{
	struct list_head     entry;
	void  *obj;
	struct w32thread  *thread;
};

extern struct namespace *create_namespace(unsigned int hash_size);

extern void *create_named_object(HANDLE namespace, 
		const struct object_ops *ops,
		const struct unicode_str *name, unsigned int attributes);  /* D.M. TBD */
extern void unlink_named_object(struct object *obj);
extern void *alloc_wine_object(const struct object_ops *ops);
extern void make_object_static(struct object *obj);

extern struct object *find_object(HANDLE RootDirectory, const struct unicode_str *name,
				unsigned int attributes);
extern int no_satisfied(struct object *obj, struct w32thread *thread);
extern int no_signal(struct object *obj, unsigned int access);
extern struct fd *no_get_fd(struct object *obj);
extern unsigned int no_map_access(struct object *obj, unsigned int access);
extern struct object *no_lookup_name(struct object *obj, struct unicode_str *name, unsigned int attributes);
extern struct object *no_open_file(struct object *obj, unsigned int access, unsigned int sharing, unsigned int options);
extern int no_close_handle(struct object *obj, struct w32process *process, obj_handle_t handle);
extern void no_destroy(struct object *obj);

extern struct kevent *create_event(
		struct directory *root,
		const struct unicode_str *name,
		unsigned int attr,
		int manual_reset,
		int initial_state,
		const struct security_descriptor *sd
		);

/* atom functions */

extern atom_t add_global_atom(struct winstation *winstation, const WCHAR *str, data_size_t len);
extern atom_t find_global_atom(struct winstation *winstation, const WCHAR *str, data_size_t len);
extern int grab_global_atom(struct winstation *winstation, atom_t atom);
extern void release_global_atom(struct winstation *winstation, atom_t atom);
extern void *open_object_dir(HANDLE root, const struct unicode_str *name,
                              unsigned int attr, const struct object_ops *ops);
extern void *create_named_object_dir(HANDLE root, const struct unicode_str *name,
					unsigned int attr, const struct object_ops *ops);

extern struct object *find_object_dir(HANDLE root, const struct unicode_str *name,
				unsigned int attr, struct unicode_str *name_left);
extern obj_handle_t alloc_handle(struct w32process* proc, void* p, unsigned int access, int attr);

/* symbolic link functions */
extern struct symlink *create_symlink(struct directory *root, const struct unicode_str *name,
				unsigned int attr, const struct unicode_str *target);

/* devices */
extern void create_named_pipe_device(struct directory *root, const struct unicode_str *name);
extern void create_mailslot_device(struct directory *root, const struct unicode_str *name);

/* FIXME */
typedef PVOID	PACCESS_STATE;

/* System Initialization procedure for OB subcomponent */
BOOLEAN init_object(VOID);

VOID init_symbol_link(VOID);

/* Object Manager types */

typedef struct _OBJECT_HANDLE_INFORMATION {
	ULONG HandleAttributes;
	ACCESS_MASK GrantedAccess;
} OBJECT_HANDLE_INFORMATION, *POBJECT_HANDLE_INFORMATION;

typedef struct _OBJECT_DUMP_CONTROL {
	PVOID Stream;
	ULONG Detail;
} OB_DUMP_CONTROL, *POB_DUMP_CONTROL;

typedef VOID (*OB_DUMP_METHOD)(
		IN PVOID Object,
		IN POB_DUMP_CONTROL Control OPTIONAL
		);

typedef enum _OB_OPEN_REASON {
	ObCreateHandle,
	ObOpenHandle,
	ObDuplicateHandle,
	ObInheritHandle,
	ObMaxOpenReason
} OB_OPEN_REASON;

typedef VOID (*OB_CREATE_METHOD)(
		IN PVOID Object,
		IN PVOID Param
		);

typedef VOID (*OB_OPEN_METHOD)(
		IN OB_OPEN_REASON OpenReason,
		IN struct eprocess* Process OPTIONAL,
		IN PVOID Object,
		IN ACCESS_MASK GrantedAccess,
		IN ULONG HandleCount
		);

typedef BOOLEAN (*OB_OKAYTOCLOSE_METHOD)(
		IN struct eprocess* Process OPTIONAL,
		IN PVOID Object,
		IN HANDLE Handle
		);

typedef VOID (*OB_CLOSE_METHOD)(
		IN struct eprocess* Process OPTIONAL,
		IN PVOID Object,
		IN ACCESS_MASK GrantedAccess,
		IN ULONG ProcessHandleCount,
		IN ULONG SystemHandleCount
		);

typedef VOID (*OB_DELETE_METHOD)(
		IN PVOID Object
		);

typedef NTSTATUS (*OB_PARSE_METHOD)(
		IN PVOID ParseObject,
		IN PVOID ObjectType,
		IN OUT PACCESS_STATE AccessState,
		IN KPROCESSOR_MODE AccessMode,
		IN ULONG Attributes,
		IN OUT PUNICODE_STRING CompleteName,
		IN OUT PUNICODE_STRING RemainingName,
		IN OUT PVOID Context OPTIONAL,
		IN PSECURITY_QUALITY_OF_SERVICE SecurityQos OPTIONAL,
		OUT PVOID *Object
		);

typedef NTSTATUS (*OB_POLL_METHOD)(
		IN struct wait_table_entry *wte
		);

typedef NTSTATUS (*OB_SECURITY_METHOD)(
		IN PVOID Object,
		IN SECURITY_OPERATION_CODE OperationCode,
		IN PSECURITY_INFORMATION SecurityInformation,
		IN OUT PSECURITY_DESCRIPTOR SecurityDescriptor,
		IN OUT PULONG CapturedLength,
		IN OUT PSECURITY_DESCRIPTOR *ObjectsSecurityDescriptor,
		IN POOL_TYPE PoolType,
		IN PGENERIC_MAPPING GenericMapping
		);

typedef NTSTATUS (*OB_QUERYNAME_METHOD)(
		IN PVOID Object,
		OUT POBJECT_NAME_INFORMATION ObjectNameInfo,
		IN ULONG Length,
		OUT PULONG ReturnLength
		);

typedef struct object_type * (*OB_GETTYPE_METHOD)(
		IN void *obj
		);

typedef int (*OB_ADDQUEUE_METHOD)(
		IN void *obj,
		IN struct wait_queue_entry *entry
		);

typedef void (*OB_RMQUEUE_METHOD)(
		IN void *obj,
		IN struct wait_queue_entry *entry
		);

typedef int (*OB_SIGNALED_METHOD)(
		IN void *obj,
		IN struct w32thread *thread
		);

typedef int (*OB_SATISFIED_METHOD)(
		IN void *obj,
		IN struct w32thread *thread
		);

typedef int (*OB_SIGNAL_METHOD)(
		IN void *obj,
		IN unsigned int access
		);

typedef struct fd * (*OB_GETFD_METHOD)(
		IN void *obj
		);

typedef unsigned int (*OB_MAPACCESS_METHOD)(
		IN void *obj,
		IN unsigned int access
		);


/* Object Type Structure */

typedef struct _OBJECT_TYPE_INITIALIZER {
	USHORT Length;
	BOOLEAN UseDefaultObject;
	BOOLEAN Reserved;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	BOOLEAN MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
	OB_DUMP_METHOD DumpProcedure;
	OB_OPEN_METHOD OpenProcedure;
	OB_CLOSE_METHOD CloseProcedure;
	OB_CREATE_METHOD CreateProcedure;
	OB_DELETE_METHOD DeleteProcedure;
	OB_PARSE_METHOD ParseProcedure;
	OB_POLL_METHOD PollProcedure;
	OB_SECURITY_METHOD SecurityProcedure;
	OB_QUERYNAME_METHOD QueryNameProcedure;
	OB_OKAYTOCLOSE_METHOD OkayToCloseProcedure;
	OB_GETTYPE_METHOD GetTypeProcedure;
	OB_ADDQUEUE_METHOD AddQueueProcedure;
	OB_RMQUEUE_METHOD RemoveQueueProcedure;
	OB_SIGNALED_METHOD SignaledProcedure;
	OB_SATISFIED_METHOD SatisfiedProcedure;
	OB_SIGNAL_METHOD SignalProcedure;
	OB_GETFD_METHOD GetFdProcedure;
	OB_MAPACCESS_METHOD MapAccessProcedure;
} OBJECT_TYPE_INITIALIZER, *POBJECT_TYPE_INITIALIZER;

typedef struct _OBJECT_TYPE {
	ERESOURCE Mutex;
	LIST_ENTRY TypeList;
	UNICODE_STRING Name;            /* Copy from object header for convenience */
	PVOID DefaultObject;
	ULONG Index;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	OBJECT_TYPE_INITIALIZER TypeInfo;
} OBJECT_TYPE, *POBJECT_TYPE;


/* Object Directory Structure */

#define NUMBER_HASH_BUCKETS 37

typedef struct _OBJECT_DIRECTORY {
	struct object obj;
	struct _OBJECT_DIRECTORY_ENTRY *HashBuckets[NUMBER_HASH_BUCKETS];
	struct _OBJECT_DIRECTORY_ENTRY **LookupBucket;
	BOOLEAN LookupFound;
	USHORT SymbolicLinkUsageCount;
	struct _DEVICE_MAP *DeviceMap;
} OBJECT_DIRECTORY, *POBJECT_DIRECTORY;

/* Object Directory Entry Structure */

typedef struct _OBJECT_DIRECTORY_ENTRY {
	struct _OBJECT_DIRECTORY_ENTRY *ChainLink;
	PVOID Object;
} OBJECT_DIRECTORY_ENTRY, *POBJECT_DIRECTORY_ENTRY;

/* Object Directory */

typedef struct _OBJECT_DIRECTORY_INFORMATION {
	UNICODE_STRING ObjectName;
	UNICODE_STRING ObjectTypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

/* Symbolic Link Object Structure */

typedef struct _OBJECT_SYMBOLIC_LINK {
	LARGE_INTEGER CreationTime;
	UNICODE_STRING TargetName;
	UNICODE_STRING LinkTargetRemaining;
	PVOID LinkTargetObject;
	ULONG DosDeviceDriveIndex;  /* 1-based index into KUSER_SHARED_DATA.DosDeviceDriveType */
} OBJECT_SYMBOLIC_LINK, *POBJECT_SYMBOLIC_LINK;


/* Device Map Structure */

typedef struct _DEVICE_MAP {
	ULONG ReferenceCount;
	POBJECT_DIRECTORY DosDevicesDirectory;
	ULONG DriveMap;
	UCHAR DriveType[32];
} DEVICE_MAP, *PDEVICE_MAP;

extern PDEVICE_MAP ObSystemDeviceMap;

/* Object Handle Count Database */

typedef struct _OBJECT_HANDLE_COUNT_ENTRY {
	struct eprocess* Process;
	ULONG HandleCount;
} OBJECT_HANDLE_COUNT_ENTRY, *POBJECT_HANDLE_COUNT_ENTRY;

typedef struct _OBJECT_HANDLE_COUNT_DATABASE {
	ULONG CountEntries;
	OBJECT_HANDLE_COUNT_ENTRY HandleCountEntries[1];
} OBJECT_HANDLE_COUNT_DATABASE, *POBJECT_HANDLE_COUNT_DATABASE;

/* Object Header Structure */

typedef struct _OBJECT_CREATE_INFORMATION {
	ULONG Attributes;
	HANDLE RootDirectory;
	PVOID ParseContext;
	KPROCESSOR_MODE ProbeMode;
	ULONG PagedPoolCharge;
	ULONG NonPagedPoolCharge;
	ULONG SecurityDescriptorCharge;
	PSECURITY_DESCRIPTOR SecurityDescriptor;
	PSECURITY_QUALITY_OF_SERVICE SecurityQos;
	SECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;
} OBJECT_CREATE_INFORMATION, *POBJECT_CREATE_INFORMATION;

struct object_ops;
#define IS_WINE_OBJECT(obj_hdr) (obj_hdr->ops) 

typedef struct _OBJECT_HEADER {
	atomic_t PointerCount;
	union {
		atomic_t HandleCount;
		PSINGLE_LIST_ENTRY SEntry;
	};
	POBJECT_TYPE Type;  
	const struct object_ops *ops;   /* set to NULL if not a wine object */
	UCHAR NameInfoOffset;
	UCHAR HandleInfoOffset;
	UCHAR QuotaInfoOffset;
	UCHAR Flags;
	union {
		POBJECT_CREATE_INFORMATION ObjectCreateInfo;
		PVOID QuotaBlockCharged;
	};

	PSECURITY_DESCRIPTOR SecurityDescriptor;
	QUAD Body;
} OBJECT_HEADER, *POBJECT_HEADER;

typedef struct _OBJECT_HEADER_QUOTA_INFO {
	ULONG PagedPoolCharge;
	ULONG NonPagedPoolCharge;
	ULONG SecurityDescriptorCharge;
	struct eprocess* ExclusiveProcess;
} OBJECT_HEADER_QUOTA_INFO, *POBJECT_HEADER_QUOTA_INFO;

typedef struct _OBJECT_HEADER_HANDLE_INFO {
	union {
		POBJECT_HANDLE_COUNT_DATABASE HandleCountDataBase;
		OBJECT_HANDLE_COUNT_ENTRY SingleEntry;
	};
} OBJECT_HEADER_HANDLE_INFO, *POBJECT_HEADER_HANDLE_INFO;

typedef struct _OBJECT_HEADER_NAME_INFO {
	POBJECT_DIRECTORY Directory;
	UNICODE_STRING Name;
	ULONG Reserved;
} OBJECT_HEADER_NAME_INFO, *POBJECT_HEADER_NAME_INFO;

typedef struct _OBJECT_HEADER_CREATOR_INFO {
	LIST_ENTRY TypeList;
	HANDLE CreatorUniqueProcess;
	USHORT CreatorBackTraceIndex;
	USHORT Reserved;
} OBJECT_HEADER_CREATOR_INFO, *POBJECT_HEADER_CREATOR_INFO;

typedef struct _OBJECT_HANDLE_ATTRIBUTE_INFORMATION {
	BOOLEAN Inherit;
	BOOLEAN ProtectFromClose;
} OBJECT_HANDLE_ATTRIBUTE_INFORMATION, *POBJECT_HANDLE_ATTRIBUTE_INFORMATION;

typedef struct _OBJECT_BASIC_INFORMATION {
	ULONG Attributes;
	ACCESS_MASK GrantedAccess;
	atomic_t HandleCount;
	atomic_t PointerCount;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
	ULONG Reserved[3];
	ULONG NameInformationLength;
	ULONG TypeInformationLength;
	ULONG SecurityDescriptorLength;
	LARGE_INTEGER CreateTime;
} OBJECT_BASIC_INFORMATION, *POBJECT_BASIC_INFORMATION;

typedef struct _SYMLINK_OBJECT {
	CSHORT Type;
	CSHORT Size;
	UNICODE_STRING TargetName;
	LARGE_INTEGER CreateTime;
} SYMLINK_OBJECT, *PSYMLINK_OBJECT;

struct namespace
{
	unsigned int        hash_size;       /* size of hash table */
	struct list_head    names[1];        /* array of hash entry lists */
};

#define OB_FLAG_NEW_OBJECT              0x01
#define OB_FLAG_KERNEL_OBJECT           0x02
#define OB_FLAG_CREATOR_INFO            0x04
#define OB_FLAG_EXCLUSIVE_OBJECT        0x08
#define OB_FLAG_PERMANENT_OBJECT        0x10
#define OB_FLAG_DEFAULT_SECURITY_QUOTA  0x20
#define OB_FLAG_SINGLE_HANDLE_ENTRY     0x40

#define BODY_TO_HEADER(objbdy)                                                 \
	((OBJECT_HEADER *)((char *)objbdy - offsetof(OBJECT_HEADER, Body)))

#define HEADER_TO_WINE_OBJ(obj_header) \
    ((struct object*) ((char*)obj_header + offsetof(OBJECT_HEADER, Body)))

#define HEADER_TO_OBJECT_NAME(objhdr) ((POBJECT_HEADER_NAME_INFO)              \
		(!(objhdr)->NameInfoOffset ? NULL: ((PCHAR)(objhdr) - (objhdr)->NameInfoOffset)))

#define HEADER_TO_HANDLE_INFO(objhdr) ((POBJECT_HEADER_HANDLE_INFO)            \
		(!(objhdr)->HandleInfoOffset ? NULL: ((PCHAR)(objhdr) - (objhdr)->HandleInfoOffset)))

#define HEADER_TO_CREATOR_INFO(objhdr) ((POBJECT_HEADER_CREATOR_INFO)          \
		(!((objhdr)->Flags & OB_FLAG_CREATOR_INFO) ? NULL: ((PCHAR)(objhdr) - sizeof(OBJECT_HEADER_CREATOR_INFO))))

#define OBJECT_ALLOC_SIZE(ObjectSize) ((ObjectSize) + sizeof(OBJECT_HEADER))

#define HANDLE_TO_EX_HANDLE(handle) (LONG)(((LONG)(handle) >> 2) - 1)
#define EX_HANDLE_TO_HANDLE(exhandle) (HANDLE)(((exhandle) + 1) << 2)

#define ref_object(Object)	atomic_inc(&(BODY_TO_HEADER(Object))->PointerCount)

extern POBJECT_TYPE dir_object_type;
extern POBJECT_DIRECTORY name_space_root;

NTSTATUS
create_object(
		IN KPROCESSOR_MODE ProbeMode,
		IN POBJECT_TYPE ObjectType,
		IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
		IN KPROCESSOR_MODE OwnershipMode,
		IN OUT PVOID ParseContext OPTIONAL,
		IN ULONG ObjectBodySize,
		IN ULONG PagedPoolCharge,
		IN ULONG NonPagedPoolCharge,
		OUT PVOID *Object
	     );

NTSTATUS
insert_object(
		IN PVOID Object,
		IN PACCESS_STATE PassedAccessState OPTIONAL,
		IN ACCESS_MASK DesiredAccess OPTIONAL,
		IN ULONG ObjectPointerBias,
		OUT PVOID *NewObject OPTIONAL,
		OUT PHANDLE Handle
	     );

NTSTATUS
ref_object_by_handle(
		IN HANDLE Handle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_TYPE ObjectType OPTIONAL,
		IN KPROCESSOR_MODE AccessMode,
		OUT PVOID *Object,
		OUT POBJECT_HANDLE_INFORMATION HandleInformation OPTIONAL
		);

NTSTATUS
open_object_by_name(
		IN POBJECT_ATTRIBUTES ObjectAttributes,
		IN POBJECT_TYPE ObjectType,
		IN OUT PVOID ParseContext OPTIONAL,
		IN KPROCESSOR_MODE AccessMode,
		IN ACCESS_MASK DesiredAccess OPTIONAL,
		IN OUT PACCESS_STATE PassedAccessState OPTIONAL,
		OUT PHANDLE Handle
		);

NTSTATUS
open_object_by_pointer(
		IN PVOID Object,
		IN ULONG HandleAttributes,
		IN PACCESS_STATE PassedAccessState OPTIONAL,
		IN ACCESS_MASK DesiredAccess OPTIONAL,
		IN POBJECT_TYPE ObjectType OPTIONAL,
		IN KPROCESSOR_MODE AccessMode,
		OUT PHANDLE Handle
		);

NTSTATUS
ObReferenceObjectByName(
		IN PUNICODE_STRING ObjectName,
		IN ULONG Attributes,
		IN PACCESS_STATE PassedAccessState OPTIONAL,
		IN ACCESS_MASK DesiredAccess OPTIONAL,
		IN POBJECT_TYPE ObjectType,
		IN KPROCESSOR_MODE AccessMode,
		IN OUT PVOID ParseContext OPTIONAL,
		OUT PVOID *Object
		);

VOID
make_temp_object(
		IN PVOID Object
		);

BOOLEAN
ObFindHandleForObject(
		IN struct eprocess* Process,
		IN PVOID Object,
		IN POBJECT_TYPE ObjectType OPTIONAL,
		IN POBJECT_HANDLE_INFORMATION MatchCriteria OPTIONAL,
		OUT PHANDLE Handle
		);

BOOLEAN
insert_obdir_entry(
		IN POBJECT_DIRECTORY Directory,
		IN PVOID Object
		);

NTSTATUS
ref_object_by_pointer(
		IN PVOID Object,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_TYPE ObjectType,
		IN KPROCESSOR_MODE AccessMode
		);

VOID
ObfDereferenceObject(
		IN PVOID Object
		);

NTSTATUS
query_name_string(
		IN PVOID Object,
		OUT POBJECT_NAME_INFORMATION ObjectNameInfo,
		IN ULONG Length,
		OUT PULONG ReturnLength
		);

ULONG
ObGetObjectPointerCount(
		IN PVOID Object
		);

NTSTATUS
ObQueryTypeName(
		IN PVOID Object,
		PUNICODE_STRING ObjectTypeName,
		IN ULONG Length,
		OUT PULONG ReturnLength
	      );

NTSTATUS
ObDumpObjectByHandle(
		IN HANDLE Handle,
		IN POB_DUMP_CONTROL Control OPTIONAL
		);

NTSTATUS
ObDumpObjectByPointer(
		IN PVOID Object,
		IN POB_DUMP_CONTROL Control OPTIONAL
		);

NTSTATUS
ObSetDeviceMap(
		IN struct eprocess* TargetProcess,
		IN HANDLE DirectoryHandle
	     );

VOID
ObInheritDeviceMap(
		IN struct eprocess* NewProcess,
		IN struct eprocess* ParentProcess
		);

VOID
ObDereferenceDeviceMap(
		IN struct eprocess* Process
		);

NTSTATUS
ObQueryObjectAuditingByHandle(
		IN HANDLE Handle,
		OUT PBOOLEAN GenerateOnClose
		);

NTSTATUS
STDCALL
create_type_object(
		POBJECT_TYPE_INITIALIZER ObjectTypeInitializer,
		PUNICODE_STRING type_type_name,
		POBJECT_TYPE *ObjectType);

PVOID
lookup_obdir_entry(
		IN POBJECT_DIRECTORY Directory,
		IN PUNICODE_STRING Name,
		IN ULONG Attributes
		);

NTSTATUS
lookup_object_name(
		IN HANDLE RootDirectoryHandle OPTIONAL,
		IN PUNICODE_STRING ObjectName,
		IN ULONG Attributes,
		IN POBJECT_TYPE ObjectType,
		IN KPROCESSOR_MODE AccessMode,
		IN PVOID ParseContext OPTIONAL,
		IN PSECURITY_QUALITY_OF_SERVICE SecurityQos OPTIONAL,
		IN PVOID InsertObject OPTIONAL,
		IN OUT PACCESS_STATE AccessState,
		OUT PBOOLEAN DirectoryLocked,
		OUT PVOID *FoundObject
		);

VOID
deref_object(IN PVOID Object);

NTSTATUS
delete_object(POBJECT_HEADER Header);

int alloc_object(POBJECT_CREATE_INFORMATION ObjectCreateInfo,
                  PUNICODE_STRING ObjectName,
                  POBJECT_TYPE ObjectType,
                  ULONG ObjectSize,
                  POBJECT_HEADER *ObjectHeader);

BOOLEAN
delete_obdir_entry (IN POBJECT_DIRECTORY Directory);

NTSTATUS SERVICECALL
NtCreateDirectoryObject(OUT PHANDLE DirectoryHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes);

NTSTATUS
duplicate_object(struct eprocess *SourceProcess,
		struct eprocess *TargetProcess,
		HANDLE SourceHandle,
		PHANDLE TargetHandle,
		ACCESS_MASK DesiredAccess,
		BOOLEAN InheritHandle,
		ULONG Options);

NTSTATUS
set_handle_attr(HANDLE Handle,
		POBJECT_HANDLE_ATTRIBUTE_INFORMATION HandleInfo);

NTSTATUS
query_handle_attr(HANDLE Handle,
		POBJECT_HANDLE_ATTRIBUTE_INFORMATION HandleInfo);

VOID
set_permanent_object(IN PVOID ObjectBody, IN BOOLEAN Permanent);

NTSTATUS SERVICECALL
NtClose(IN HANDLE Handle);

LONG
copy_object_attr_from_user(
		POBJECT_ATTRIBUTES	UserObjectAttr,
		POBJECT_ATTRIBUTES	*KernelObjectAttr
		);

void *grab_object(void *obj);

void release_object(void *object);

void *create_wine_object(HANDLE namespace, const struct object_ops *ops,
		const struct unicode_str *name, struct object *parent);

struct security_descriptor *default_get_sd(struct object *obj);
int default_set_sd(struct object *obj, const struct security_descriptor *sd, unsigned int set_info);

static inline WCHAR *get_object_name(void *obj, data_size_t *len)
{
	POBJECT_HEADER_NAME_INFO name_info;

	name_info = HEADER_TO_OBJECT_NAME(BODY_TO_HEADER(obj));
	if (name_info) {
		*len = name_info->Name.Length;
		return name_info->Name.Buffer;
	} else {
		*len = 0;
		return NULL;
	}
}
#endif /* CONFIG_UNIFIED_KERNEL */
#endif /* _OBJECT_H */
