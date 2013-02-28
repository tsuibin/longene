/*
 * win32.h
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
 *   Jan 2006 - Created.
 */
 
/*
 * win32.h includes the type definitions of W32 syscall functions. 
 * Refered to ReactOS code
 */

#ifndef _WIN32_H
#define _WIN32_H

#include <linux/slab.h>
#include <linux/module.h>
#include <asm/byteorder.h>
#include "winternl.h"

#ifdef CONFIG_UNIFIED_KERNEL

#define EXE_SO

#ifndef CREATE_THREAD
#define CREATE_THREAD 2
#endif

#define IN
#define OUT
#define ANYSIZE_ARRAY 1
#define WINAPI __stdcall
#define NTAPI __stdcall
#define STDCALL __stdcall
#define DDKAPI /* TODO: that definition will be move to DDK header file */
#ifndef __stdcall
#define __stdcall __attribute__((stdcall))
#endif
#ifndef NULL
#define NULL 0
#endif

#if 0
#define KDEBUG 1
#define KTRACE 1
#endif

#ifdef KDEBUG
#define kdebug(FMT...) \
	do { \
		printk("UK: pid %x tid %x %s ", current->tgid, current->pid, __FUNCTION__); \
		printk(FMT); \
	} while (0)
#else
#define kdebug(FMT...) do { } while (0)
#endif

#ifdef KTRACE
#define ktrace(FMT...) \
	do { \
		printk("UK: pid %x tid %x %s ", current->tgid, current->pid, __FUNCTION__); \
		printk(FMT); \
	} while (0)
#else
#define ktrace(FMT...) do { } while (0)
#endif

#define _ANONYMOUS_UNION __extension__

#define	NOREGPARM	__attribute__((regparm(0)))
#define	SERVICECALL	STDCALL NOREGPARM

#define NT_SUCCESS(st)  ((st) == STATUS_SUCCESS)

#define OPTIONAL
#define OBJ_INHERIT          0x00000002L
#define OBJ_PERMANENT        0x00000010L
#define OBJ_EXCLUSIVE        0x00000020L
#define OBJ_CASE_INSENSITIVE 0x00000040L
#define OBJ_OPENIF           0x00000080L
#define OBJ_OPENLINK         0x00000100L
#define OBJ_KERNEL_HANDLE    0x00000200L
#define OBJ_VALID_ATTRIBUTES 0x000003F2L

#define DUPLICATE_CLOSE_SOURCE            0x00000001
#define DUPLICATE_SAME_ACCESS             0x00000002
#define DUPLICATE_SAME_ATTRIBUTES         0x00000004

#define IO_TYPE_FILE 0x0F5L /* Temp Hack */

#define MINLONG	0x80000000

#define __int64 long long
#define CONST const

typedef void 		VOID, *PVOID;
typedef void 		*LPVOID;
typedef void 		*PVOID64;
typedef void 		*HANDLE;
typedef const void 	*LPCVOID;

typedef char 		BOOLEAN, *PBOOLEAN;
typedef const char 	*LPCSTR;
typedef char CCHAR, *PCCHAR;
typedef signed char 	CHAR, *PCHAR, *LPSTR, *PSTR;
typedef unsigned short 	WORD, *LPWORD;
typedef unsigned char 	UCHAR, *PUCHAR;
typedef unsigned char 	BYTE;
typedef unsigned char	UINT8;

typedef unsigned short 		WCHAR;
typedef short SHORT, CSHORT;
typedef unsigned short 	USHORT, *PUSHORT;
typedef unsigned short	UINT16;

typedef signed int 	LONG, *PLONG;
typedef unsigned int 	UINT;
typedef unsigned int 	UINT32;
typedef unsigned int 	DWORD;
typedef unsigned int 	ULONG, *PULONG;;

typedef unsigned long 	ULONG_PTR, *PULONG_PTR;

typedef long long 		LONGLONG;
typedef unsigned long long 	ULONGLONG;

typedef unsigned __int64 ULONG64, *PULONG64;

typedef struct SECURITY_ATTRIBUTES 	*LPSECURITY_ATTRIBUTES;
typedef struct OFSTRUCT			*LPOFSTRUCT;

typedef int 	BOOL;
typedef BOOLEAN SECURITY_CONTEXT_TRACKING_MODE, *PSECURITY_CONTEXT_TRACKING_MODE;
typedef WORD 	*PSECURITY_DESCRIPTOR_CONTROL;
typedef DWORD 	*PDWORD, *LPDWORD;
typedef DWORD 	LCID;
typedef DWORD 	*PACCESS_MASK;
typedef DWORD 	SECURITY_INFORMATION, *PSECURITY_INFORMATION;
typedef PDWORD 	PLCID;

typedef USHORT 		RTL_ATOM, *PRTL_ATOM;
typedef USHORT 		LANGID, *PLANGID;
typedef LONG 		NTSTATUS, *PNTSTATUS;
typedef ULONG_PTR 	KAFFINITY;
typedef ULONG_PTR 	SIZE_T, *PSIZE_T;
typedef ULONG_PTR 	DWORD_PTR, *PDWORD_PTR;

typedef HANDLE 		*PHANDLE, *LPHANDLE;

typedef UCHAR 	SSPT, *PSSPT;
typedef WCHAR 	*PWCHAR, *LPWCH, *PWCH, *NWPSTR, *LPWSTR, *PWSTR;
typedef const WCHAR 	*LPCWSTR, *PCWSTR;
typedef PVOID 	PSID;
typedef PVOID 	(NTAPI * SSDT)(VOID);
typedef PVOID	PACCESS_TOKEN;
typedef SSDT 	*PSSDT;
typedef struct list_head LIST_ENTRY;

#define LPC_SIZE_T SIZE_T
#define LPC_PVOID PVOID
#define LPC_HANDLE HANDLE
#define LPC_CLIENT_ID CLIENT_ID
#define EXCEPTION_MAXIMUM_PARAMETERS 15
#define _ANONYMOUS_STRUCT

#define	FALSE	false
#define	false	(BOOLEAN)0
#define	TRUE	true
#define	true	(BOOLEAN)1

#define const_cpu_to_le16(x)	__constant_cpu_to_le16(x)

#define PROCESS_TERMINATE	1
#define PROCESS_CREATE_THREAD	2
#define PROCESS_SET_SESSIONID	4
#define PROCESS_VM_OPERATION	8
#define PROCESS_VM_READ	16
#define PROCESS_VM_WRITE	32
#define PROCESS_DUP_HANDLE	64
#define PROCESS_CREATE_PROCESS	128
#define PROCESS_SET_QUOTA	256
#define PROCESS_SET_INFORMATION	512
#define PROCESS_QUERY_INFORMATION	1024
#define PROCESS_SUSPEND_RESUME	2048
#define PROCESS_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0xFFF)
#define THREAD_TERMINATE	1
#define THREAD_SUSPEND_RESUME	2
#define THREAD_GET_CONTEXT	8
#define THREAD_SET_CONTEXT	16
#define THREAD_SET_INFORMATION	32
#define THREAD_QUERY_INFORMATION	64
#define THREAD_SET_THREAD_TOKEN	128
#define THREAD_IMPERSONATE	256
#define THREAD_DIRECT_IMPERSONATION	0x200
#define THREAD_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x3FF)
#define THREAD_BASE_PRIORITY_LOWRT	15
#define THREAD_BASE_PRIORITY_MAX	2
#define THREAD_BASE_PRIORITY_MIN	(-2)
#define THREAD_BASE_PRIORITY_IDLE	(-15)

#define TOKEN_ASSIGN_PRIMARY            (0x0001)
#define TOKEN_DUPLICATE                 (0x0002)
#define TOKEN_IMPERSONATE               (0x0004)
#define TOKEN_QUERY                     (0x0008)
#define TOKEN_QUERY_SOURCE              (0x0010)
#define TOKEN_ADJUST_PRIVILEGES         (0x0020)
#define TOKEN_ADJUST_GROUPS             (0x0040)
#define TOKEN_ADJUST_DEFAULT            (0x0080)
#define TOKEN_ADJUST_SESSIONID          (0x0100)
#define TOKEN_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED |\
			TOKEN_ASSIGN_PRIMARY     |\
			TOKEN_DUPLICATE          |\
			TOKEN_IMPERSONATE        |\
			TOKEN_QUERY              |\
			TOKEN_QUERY_SOURCE       |\
			TOKEN_ADJUST_PRIVILEGES  |\
			TOKEN_ADJUST_GROUPS      |\
			TOKEN_ADJUST_DEFAULT     |\
			TOKEN_ADJUST_SESSIONID)
#define TOKEN_READ       (STANDARD_RIGHTS_READ     |\
			TOKEN_QUERY)
#define TOKEN_WRITE      (STANDARD_RIGHTS_WRITE    |\
			TOKEN_ADJUST_PRIVILEGES  |\
			TOKEN_ADJUST_GROUPS      |\
			TOKEN_ADJUST_DEFAULT)

#define TOKEN_EXECUTE    (STANDARD_RIGHTS_EXECUTE)
#define TOKEN_SOURCE_LENGTH 8

typedef enum _MODE {
	KernelMode,
	UserMode,
	MaxiumMode
} MODE;

typedef enum _TIMER_TYPE
{
	NotificationTimer,
	SynchronizationTimer
} TIMER_TYPE;

typedef enum tagTOKEN_TYPE {
	TokenPrimary = 1,
	TokenImpersonation
} TOKEN_TYPE,*PTOKEN_TYPE;

typedef enum _KPROFILE_SOURCE
{
	ProfileTime,
	ProfileAlignmentFixup,
	ProfileTotalIssues,
	ProfilePipelineDry,
	ProfileLoadInstructions,
	ProfilePipelineFrozen,
	ProfileBranchInstructions,
	ProfileTotalNonissues,
	ProfileDcacheMisses,
	ProfileIcacheMisses,
	ProfileCacheMisses,
	ProfileBranchMispredictions,
	ProfileStoreInstructions,
	ProfileFpInstructions,
	ProfileIntegerInstructions,
	Profile2Issue,
	Profile3Issue,
	Profile4Issue,
	ProfileSpecialInstructions,
	ProfileTotalCycles,
	ProfileIcacheIssues,
	ProfileDcacheAccesses,
	ProfileMemoryBarrierCycles,
	ProfileLoadLinkedIssues,
	ProfileMaximum
} KPROFILE_SOURCE;

typedef enum _EVENT_TYPE
{
	SynchronizationEvent,
	NotificationEvent
} EVENT_TYPE;

typedef enum _PNP_VETO_TYPE {
  	PNP_VetoTypeUnknown,
  	PNP_VetoLegacyDevice,
  	PNP_VetoPendingClose,
  	PNP_VetoWindowsApp,
  	PNP_VetoWindowsService,
	PNP_VetoOutstandingOpen,
  	PNP_VetoDevice,
  	PNP_VetoDriver,
  	PNP_VetoIllegalDeviceRequest,
  	PNP_VetoInsufficientPower,
  	PNP_VetoNonDisableable,
  	PNP_VetoLegacyDriver
} PNP_VETO_TYPE, *PPNP_VETO_TYPE;

typedef enum _PLUGPLAY_EVENT_CATEGORY
{
	HardwareProfileChangeEvent,
	TargetDeviceChangeEvent,
	DeviceClassChangeEvent,
	CustomDeviceEvent,
	DeviceInstallEvent,
	DeviceArrivalEvent,
	PowerEvent,
	VetoEvent,
	BlockedDriverEvent,
	MaxPlugEventCategory
} PLUGPLAY_EVENT_CATEGORY;

typedef enum _SECURITY_IMPERSONATION_LEVEL {
	SecurityAnonymous,
	SecurityIdentification,
	SecurityImpersonation,
	SecurityDelegation
} SECURITY_IMPERSONATION_LEVEL,*PSECURITY_IMPERSONATION_LEVEL;


typedef enum {
	SE_OWNER_DEFAULTED		= const_cpu_to_le16(0x0001),
	SE_GROUP_DEFAULTED		= const_cpu_to_le16(0x0002),
	SE_DACL_PRESENT			= const_cpu_to_le16(0x0004),
	SE_DACL_DEFAULTED		= const_cpu_to_le16(0x0008),
	SE_SACL_PRESENT			= const_cpu_to_le16(0x0010),
	SE_SACL_DEFAULTED		= const_cpu_to_le16(0x0020),
	SE_DACL_AUTO_INHERIT_REQ	= const_cpu_to_le16(0x0100),
	SE_SACL_AUTO_INHERIT_REQ	= const_cpu_to_le16(0x0200),
	SE_DACL_AUTO_INHERITED		= const_cpu_to_le16(0x0400),
	SE_SACL_AUTO_INHERITED		= const_cpu_to_le16(0x0800),
	SE_DACL_PROTECTED		= const_cpu_to_le16(0x1000),
	SE_SACL_PROTECTED		= const_cpu_to_le16(0x2000),
	SE_RM_CONTROL_VALID		= const_cpu_to_le16(0x4000),
	SE_SELF_RELATIVE		= const_cpu_to_le16(0x8000),
} __attribute__ ((__packed__)) SECURITY_DESCRIPTOR_CONTROL;

#define const_cpu_to_le32(x)	__constant_cpu_to_le32(x)

typedef enum {
	/*
	 * The specific rights (bits 0 to 15). Depend on the type of the
	 * object being secured by the ACE.
	 */

	/* Specific rights for files and directories are as follows: */

	/* Right to read data from the file. (FILE) */
	FILE_READ_DATA			= const_cpu_to_le32(0x00000001),
	/* Right to list contents of a directory. (DIRECTORY) */
	FILE_LIST_DIRECTORY		= const_cpu_to_le32(0x00000001),

	/* Right to write data to the file. (FILE) */
	FILE_WRITE_DATA			= const_cpu_to_le32(0x00000002),
	/* Right to create a file in the directory. (DIRECTORY) */
	FILE_ADD_FILE			= const_cpu_to_le32(0x00000002),

	/* Right to append data to the file. (FILE) */
	FILE_APPEND_DATA		= const_cpu_to_le32(0x00000004),
	/* Right to create a subdirectory. (DIRECTORY) */
	FILE_ADD_SUBDIRECTORY		= const_cpu_to_le32(0x00000004),

	/* Right to read extended attributes. (FILE/DIRECTORY) */
	FILE_READ_EA			= const_cpu_to_le32(0x00000008),

	/* Right to write extended attributes. (FILE/DIRECTORY) */
	FILE_WRITE_EA			= const_cpu_to_le32(0x00000010),

	/* Right to execute a file. (FILE) */
	FILE_EXECUTE			= const_cpu_to_le32(0x00000020),
	/* Right to traverse the directory. (DIRECTORY) */
	FILE_TRAVERSE			= const_cpu_to_le32(0x00000020),

	/*
	 * Right to delete a directory and all the files it contains (its
	 * children), even if the files are read-only. (DIRECTORY)
	 */
	FILE_DELETE_CHILD		= const_cpu_to_le32(0x00000040),

	/* Right to read file attributes. (FILE/DIRECTORY) */
	FILE_READ_ATTRIBUTES		= const_cpu_to_le32(0x00000080),

	/* Right to change file attributes. (FILE/DIRECTORY) */
	FILE_WRITE_ATTRIBUTES		= const_cpu_to_le32(0x00000100),

	/*
	 * The standard rights (bits 16 to 23). Are independent of the type of
	 * object being secured.
	 */

	/* Right to delete the object. */
	DELETE				= const_cpu_to_le32(0x00010000),

	/*
	 * Right to read the information in the object's security descriptor,
	 * not including the information in the SACL. I.e. right to read the
	 * security descriptor and owner.
	 */
	READ_CONTROL			= const_cpu_to_le32(0x00020000),

	/* Right to modify the DACL in the object's security descriptor. */
	WRITE_DAC			= const_cpu_to_le32(0x00040000),

	/* Right to change the owner in the object's security descriptor. */
	WRITE_OWNER			= const_cpu_to_le32(0x00080000),

	/*
	 * Right to use the object for synchronization. Enables a process to
	 * wait until the object is in the signalled state. Some object types
	 * do not support this access right.
	 */
	SYNCHRONIZE			= const_cpu_to_le32(0x00100000),

	/*
	 * The following STANDARD_RIGHTS_* are combinations of the above for
	 * convenience and are defined by the Win32 API.
	 */

	/* These are currently defined to READ_CONTROL. */
	STANDARD_RIGHTS_READ		= const_cpu_to_le32(0x00020000),
	STANDARD_RIGHTS_WRITE		= const_cpu_to_le32(0x00020000),
	STANDARD_RIGHTS_EXECUTE		= const_cpu_to_le32(0x00020000),

	/* Combines DELETE, READ_CONTROL, WRITE_DAC, and WRITE_OWNER access. */
	STANDARD_RIGHTS_REQUIRED	= const_cpu_to_le32(0x000f0000),

	/*
	 * Combines DELETE, READ_CONTROL, WRITE_DAC, WRITE_OWNER, and
	 * SYNCHRONIZE access.
	 */
	STANDARD_RIGHTS_ALL		= const_cpu_to_le32(0x001f0000),

	/*
	 * The access system ACL and maximum allowed access types (bits 24 to
	 * 25, bits 26 to 27 are reserved).
	 */
	ACCESS_SYSTEM_SECURITY		= const_cpu_to_le32(0x01000000),
	MAXIMUM_ALLOWED			= const_cpu_to_le32(0x02000000),

	/*
	 * The generic rights (bits 28 to 31). These map onto the standard and
	 * specific rights.
	 */

	/* Read, write, and execute access. */
	GENERIC_ALL			= const_cpu_to_le32(0x10000000),

	/* Execute access. */
	GENERIC_EXECUTE			= const_cpu_to_le32(0x20000000),

	/*
	 * Write access. For files, this maps onto:
	 *	FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_DATA |
	 *	FILE_WRITE_EA | STANDARD_RIGHTS_WRITE | SYNCHRONIZE
	 * For directories, the mapping has the same numberical value. See
	 * above for the descriptions of the rights granted.
	 */
	GENERIC_WRITE			= const_cpu_to_le32(0x40000000),

	/*
	 * Read access. For files, this maps onto:
	 *	FILE_READ_ATTRIBUTES | FILE_READ_DATA | FILE_READ_EA |
	 *	STANDARD_RIGHTS_READ | SYNCHRONIZE
	 * For directories, the mapping has the same numberical value. See
	 * above for the descriptions of the rights granted.
	 */
	GENERIC_READ			= const_cpu_to_le32(0x80000000),
} ACCESS_MASK;

typedef enum _KEY_INFORMATION_CLASS
{
	KeyBasicInformation,
	KeyNodeInformation,
	KeyFullInformation,
	KeyNameInformation,
	KeyCachedInformation,
	KeyFlagsInformation
} KEY_INFORMATION_CLASS;

typedef enum _KEY_VALUE_INFORMATION_CLASS
{
	KeyValueBasicInformation,
	KeyValueFullInformation,
	KeyValuePartialInformation,
	KeyValueFullInformationAlign64,
	KeyValuePartialInformationAlign64
} KEY_VALUE_INFORMATION_CLASS;

typedef enum {
	PowerActionNone,
	PowerActionReserved,
	PowerActionSleep,
	PowerActionHibernate,
	PowerActionShutdown,
	PowerActionShutdownReset,
	PowerActionShutdownOff,
	PowerActionWarmEject
} POWER_ACTION, *PPOWER_ACTION;

typedef enum _SYSTEM_POWER_STATE {
	PowerSystemUnspecified,
	PowerSystemWorking,
	PowerSystemSleeping1,
	PowerSystemSleeping2,
	PowerSystemSleeping3,
	PowerSystemHibernate,
	PowerSystemShutdown,
	PowerSystemMaximum
} SYSTEM_POWER_STATE, *PSYSTEM_POWER_STATE;

typedef enum _SECTION_INHERIT
{
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT;

typedef enum _PLUGPLAY_CONTROL_CLASS
{
	PlugPlayControlUserResponse = 0x07,
	PlugPlayControlProperty = 0x0A,
	PlugPlayControlGetRelatedDevice = 0x0C,
	PlugPlayControlDeviceStatus = 0x0E,
	PlugPlayControlGetDeviceDepth,
	PlugPlayControlResetDevice = 0x14
} PLUGPLAY_CONTROL_CLASS;

typedef enum _POWER_INFORMATION_LEVEL {
	SystemPowerPolicyAc,
	SystemPowerPolicyDc,
	VerifySystemPolicyAc,
	VerifySystemPolicyDc,
	SystemPowerCapabilities,
	SystemBatteryState,
	SystemPowerStateHandler,
	ProcessorStateHandler,
	SystemPowerPolicyCurrent,
	AdministratorPowerPolicy,
	SystemReserveHiberFile,
	ProcessorInformation,
	SystemPowerInformation,
	ProcessorStateHandler2,
	LastWakeTime,
	LastSleepTime,
	SystemExecutionState,
	SystemPowerStateNotifyHandler,
	ProcessorPowerPolicyAc,
	ProcessorPowerPolicyDc,
	VerifyProcessorPowerPolicyAc,
	VerifyProcessorPowerPolicyDc,
	ProcessorPowerPolicyCurrent
} POWER_INFORMATION_LEVEL;

typedef enum _ATOM_INFORMATION_CLASS
{
	AtomBasicInformation,
	AtomTableInformation,
} ATOM_INFORMATION_CLASS;

typedef enum _FILE_INFORMATION_CLASS
{
	FileDirectoryInformation = 1,
	FileFullDirectoryInformation,
	FileBothDirectoryInformation,
	FileBasicInformation,
	FileStandardInformation,
	FileInternalInformation,
	FileEaInformation,
	FileAccessInformation,
	FileNameInformation,
	FileRenameInformation,
	FileLinkInformation,
	FileNamesInformation,
	FileDispositionInformation,
	FilePositionInformation,
	FileFullEaInformation,
	FileModeInformation,
	FileAlignmentInformation,
	FileAllInformation,
	FileAllocationInformation,
	FileEndOfFileInformation,
	FileAlternateNameInformation,
	FileStreamInformation,
	FilePipeInformation,
	FilePipeLocalInformation,
	FilePipeRemoteInformation,
	FileMailslotQueryInformation,
	FileMailslotSetInformation,
	FileCompressionInformation,
	FileObjectIdInformation,
	FileCompletionInformation,
	FileMoveClusterInformation,
	FileQuotaInformation,
	FileReparsePointInformation,
	FileNetworkOpenInformation,
	FileAttributeTagInformation,
	FileTrackingInformation,
	FileIdBothDirectoryInformation,
	FileIdFullDirectoryInformation,
	FileValidDataLengthInformation,
	FileShortNameInformation,
	FileMaximumInformation
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef enum _EVENT_INFORMATION_CLASS
{
	EventBasicInformation
} EVENT_INFORMATION_CLASS;

typedef enum _JOBOBJECTINFOCLASS
{
	JobObjectBasicAccountingInformation = 1,
	JobObjectBasicLimitInformation,
	JobObjectBasicProcessIdList,
	JobObjectBasicUIRestrictions,
	JobObjectSecurityLimitInformation,
	JobObjectEndOfJobTimeInformation,
	JobObjectAssociateCompletionPortInformation,
	JobObjectBasicAndIoAccountingInformation,
	JobObjectExtendedLimitInformation,
	JobObjectJobSetInformation,
	MaxJobObjectInfoClass
} JOBOBJECTINFOCLASS;

typedef enum _PORT_INFORMATION_CLASS
{
	PortNoInformation
} PORT_INFORMATION_CLASS;

typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation,
	ProcessQuotaLimits,
	ProcessIoCounters,
	ProcessVmCounters,
	ProcessTimes,
	ProcessBasePriority,
	ProcessRaisePriority,
	ProcessDebugPort,
	ProcessExceptionPort,
	ProcessAccessToken,
	ProcessLdtInformation,
	ProcessLdtSize,
	ProcessDefaultHardErrorMode,
	ProcessIoPortHandlers,
	ProcessPooledUsageAndLimits,
	ProcessWorkingSetWatch,
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup,
	ProcessPriorityClass,
	ProcessWx86Information,
	ProcessHandleCount,
	ProcessAffinityMask,
	ProcessPriorityBoost,
	ProcessDeviceMap,
	ProcessSessionInformation,
	ProcessForegroundInformation,
	ProcessWow64Information,
	ProcessImageFileName,
	ProcessLUIDDeviceMapsEnabled,
	ProcessBreakOnTermination,
	ProcessDebugObjectHandle,
	ProcessDebugFlags,
	ProcessHandleTracing,
	ProcessIoPriority,
	ProcessExecuteFlags,
	ProcessTlsInformation,
	ProcessCookie,
	ProcessImageInformation,
	ProcessCycleTime,
	ProcessPagePriority,
	ProcessInstrumentationCallback,
	MaxProcessInfoClass
} PROCESSINFOCLASS;

typedef enum _THREADINFOCLASS
{
	ThreadBasicInformation,
	ThreadTimes,
	ThreadPriority,
	ThreadBasePriority,
	ThreadAffinityMask,
	ThreadImpersonationToken,
	ThreadDescriptorTableEntry,
	ThreadEnableAlignmentFaultFixup,
	ThreadEventPair_Reusable,
	ThreadQuerySetWin32StartAddress,
	ThreadZeroTlsCell,
	ThreadPerformanceCount,
	ThreadAmILastThread,
	ThreadIdealProcessor,
	ThreadPriorityBoost,
	ThreadSetTlsArrayAddress,
	ThreadIsIoPending,
	ThreadHideFromDebugger,
	ThreadBreakOnTermination,
	ThreadSwitchLegacyState,
	ThreadIsTerminated,
	ThreadLastSystemCall,
	ThreadIoPriority,
	ThreadCycleTime,
	ThreadPagePriority,
	ThreadActualBasePriority,
	MaxThreadInfoClass
} THREADINFOCLASS;

typedef enum _TOKEN_INFORMATION_CLASS {
	TokenUser=1,TokenGroups,TokenPrivileges,TokenOwner,
	TokenPrimaryGroup,TokenDefaultDacl,TokenSource,TokenType,
	TokenImpersonationLevel,TokenStatistics,TokenRestrictedSids,
	TokenSessionId,TokenGroupsAndPrivileges,TokenSessionReference,
	TokenSandBoxInert,TokenAuditPolicy,TokenOrigin,
} TOKEN_INFORMATION_CLASS;

typedef enum _MUTANT_INFORMATION_CLASS
{
	MutantBasicInformation
} MUTANT_INFORMATION_CLASS;

typedef enum _OBJECT_INFORMATION_CLASS
{
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectAllTypesInformation,
	ObjectHandleInformation
} OBJECT_INFORMATION_CLASS;

typedef enum _IO_COMPLETION_INFORMATION_CLASS
{
	IoCompletionBasicInformation
} IO_COMPLETION_INFORMATION_CLASS;

typedef enum _SECTION_INFORMATION_CLASS
{
	SectionBasicInformation,
	SectionImageInformation,
} SECTION_INFORMATION_CLASS;

typedef enum _SEMAPHORE_INFORMATION_CLASS
{
	SemaphoreBasicInformation
} SEMAPHORE_INFORMATION_CLASS;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation, /* OBSOLETE: USE KUSER_SHARED_DATA */
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemNextEventIdInformation,
	SystemEventIdsInformation,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemPlugPlayBusInformation,
	SystemDockInformation,
	_SystemPowerInformation, /* FIXME */
	SystemProcessorSpeedInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation,
	SystemTimeSlipNotification,
	SystemSessionCreate,
	SystemSessionDetach,
	SystemSessionInformation,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemAddVerifier,
	SystemSessionProcessesInformation,
	SystemInformationClassMax
} SYSTEM_INFORMATION_CLASS;

typedef enum _TIMER_INFORMATION_CLASS
{
	TimerBasicInformation
} TIMER_INFORMATION_CLASS;

typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation,
	MemoryWorkingSetList,
	MemorySectionName,
	MemoryBasicVlmInformation
} MEMORY_INFORMATION_CLASS;

typedef enum _FSINFOCLASS
{
	FileFsVolumeInformation = 1,
	FileFsLabelInformation,
	FileFsSizeInformation,
	FileFsDeviceInformation,
	FileFsAttributeInformation,
	FileFsControlInformation,
	FileFsFullSizeInformation,
	FileFsObjectIdInformation,
	FileFsDriverPathInformation,
	FileFsMaximumInformation
} FS_INFORMATION_CLASS, *PFS_INFORMATION_CLASS;

typedef enum _KEY_SET_INFORMATION_CLASS
{
	KeyWriteTimeInformation,
	KeyUserFlagsInformation,
	MaxKeySetInfoClass
} KEY_SET_INFORMATION_CLASS;

typedef enum _SHUTDOWN_ACTION
{
	ShutdownNoReboot,
	ShutdownReboot,
	ShutdownPowerOff
} SHUTDOWN_ACTION;

typedef enum _DEBUG_CONTROL_CODE
{
	DebugGetTraceInformation = 1,
	DebugSetInternalBreakpoint,
	DebugSetSpecialCall,
	DebugClearSpecialCalls,
	DebugQuerySpecialCalls,
	DebugDbgBreakPoint,
	DebugDbgLoadSymbols
} DEBUG_CONTROL_CODE;

typedef enum _WAIT_TYPE
{
	WaitAny,
	WaitAll
} WAIT_TYPE;

typedef enum _KWAIT_REASON
{
	Executive,
	FreePage,
	PageIn,
	PoolAllocation,
	DelayExecution,
	Suspended,
	UserRequest,
	WrExecutive,
	WrFreePage,
	WrPageIn,
	WrPoolAllocation,
	WrDelayExecution,
	WrSuspended,
	WrUserRequest,
	WrEventPair,
	WrQueue,
	WrLpcReceive,
	WrLpcReply,
	WrVirtualMemory,
	WrPageOut,
	WrRendezvous,
	Spare2,
	WrGuardedMutex,
	Spare4,
	Spare5,
	Spare6,
	WrKernel,
	WrResource,
	WrPushLock,
	WrMutex,
	WrQuantumEnd,
	WrDispatchInt,
	WrPreempted,
	WrYieldExecution,
	MaximumWaitReason
} KWAIT_REASON;

typedef struct _LUID {
	DWORD LowPart;
	LONG HighPart;
} LUID, *PLUID;

typedef struct _EXCEPTION_RECORD {
	DWORD 			 ExceptionCode;
	DWORD 			 ExceptionFlags;
	struct _EXCEPTION_RECORD *ExceptionRecord;
	PVOID 			 ExceptionAddress;
	DWORD			 NumberParameters;
	DWORD			 ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD,*PEXCEPTION_RECORD,*LPEXCEPTION_RECORD;

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		NTSTATUS  Status;
		PVOID     Pointer;
	};
	ULONG_PTR  Information;
	NTSTATUS  async_status;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;



typedef union _LARGE_INTEGER {
	struct {
		DWORD LowPart;
		LONG  HighPart;
  	} u;
#if ! defined(NONAMELESSUNION) || defined(__cplusplus)
  	_ANONYMOUS_STRUCT struct {
		DWORD LowPart;
		LONG  HighPart;
  	};
#endif /* NONAMELESSUNION */
  	LONGLONG QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;

typedef struct {
	unsigned int   data1;	/* The first eight hexadecimal digits of the GUID. */
	unsigned short data2;	/* The first group of four hexadecimal digits. */
	unsigned short data3;	/* The second group of four hexadecimal digits. */
	unsigned char  data4[8];/* The first two bytes are the third group of four
			   	hexadecimal digits. The remaining six bytes are the
			   	final 12 hexadecimal digits. */
} __attribute__ ((__packed__)) GUID;

#define MAXIMUM_SUPPORTED_EXTENSION  512
typedef struct _FLOATING_SAVE_AREA {
	DWORD	ControlWord;
	DWORD	StatusWord;
	DWORD	TagWord;
	DWORD	ErrorOffset;
	DWORD	ErrorSelector;
	DWORD	DataOffset;
	DWORD	DataSelector;
	BYTE	RegisterArea[80];
	DWORD	Cr0NpxState;
} FLOATING_SAVE_AREA;
typedef struct _CONTEXT {
	DWORD		   ContextFlags;
	DWORD	  	   Dr0;
	DWORD		   Dr1;
	DWORD		   Dr2;
	DWORD		   Dr3;
	DWORD		   Dr6;
	DWORD		   Dr7;
	FLOATING_SAVE_AREA FloatSave;
	DWORD		   SegGs;
	DWORD		   SegFs;
	DWORD		   SegEs;
	DWORD		   SegDs;
	DWORD		   Edi;
	DWORD		   Esi;
	DWORD		   Ebx;
	DWORD		   Edx;
	DWORD		   Ecx;
	DWORD		   Eax;
	DWORD		   Ebp;
	DWORD		   Eip;
	DWORD		   SegCs;
	DWORD		   EFlags;
	DWORD		   Esp;
	DWORD		   SegSs;
	BYTE		   ExtendedRegisters[MAXIMUM_SUPPORTED_EXTENSION];
} CONTEXT;

typedef struct _GET_SET_CTX_CONTEXT {
	struct kapc apc;
	struct kevent event;
	CONTEXT context;
} GET_SET_CTX_CONTEXT, *PGET_SET_CTX_CONTEXT;

typedef struct pt_regs Context;
typedef Context *PContext,*LPContext;
typedef CONTEXT *PCONTEXT,*LPCONTEXT;

typedef struct _LUID_AND_ATTRIBUTES {
	LUID   Luid;
	DWORD  Attributes;
} LUID_AND_ATTRIBUTES, *PLUID_AND_ATTRIBUTES;

typedef struct _ACL {
	BYTE AclRevision;
	BYTE Sbz1;
	WORD AclSize;
	WORD AceCount;
	WORD Sbz2;
} ACL,*PACL;
typedef struct _SID_AND_ATTRIBUTES {
	PSID  Sid;
	DWORD Attributes;
} SID_AND_ATTRIBUTES, *PSID_AND_ATTRIBUTES;

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _SECURITY_DESCRIPTOR {
	BYTE 			    Revision;
	BYTE 			    Sbz1;
	SECURITY_DESCRIPTOR_CONTROL Control;
	PSID			    Owner;
	PSID			    Group;
	PACL			    Sacl;
	PACL			    Dacl;
} SECURITY_DESCRIPTOR, *PSECURITY_DESCRIPTOR, *PISECURITY_DESCRIPTOR;


typedef struct _GENERIC_MAPPING {
	ACCESS_MASK GenericRead;
	ACCESS_MASK GenericWrite;
	ACCESS_MASK GenericExecute;
	ACCESS_MASK GenericAll;
} GENERIC_MAPPING, *PGENERIC_MAPPING;


typedef union _ULARGE_INTEGER {
	struct {
		DWORD LowPart;
		DWORD HighPart;
	} u;
#if ! defined(NONAMELESSUNION) || defined(__cplusplus)
  	_ANONYMOUS_STRUCT struct {
		DWORD LowPart;
		DWORD HighPart;
  	};
#endif /* NONAMELESSUNION */
  	ULONGLONG QuadPart;
} ULARGE_INTEGER, *PULARGE_INTEGER;


typedef struct _SECURITY_QUALITY_OF_SERVICE {
	DWORD 				Length;
	SECURITY_IMPERSONATION_LEVEL	ImpersonationLevel;
	SECURITY_CONTEXT_TRACKING_MODE 	ContextTrackingMode;
	BOOLEAN 			EffectiveOnly;
} SECURITY_QUALITY_OF_SERVICE,*PSECURITY_QUALITY_OF_SERVICE;

typedef struct _PORT_VIEW
{
	ULONG 		Length;
	LPC_HANDLE	SectionHandle;
	ULONG 		SectionOffset;
	LPC_SIZE_T 	ViewSize;
	LPC_PVOID 	ViewBase;
	LPC_PVOID 	ViewRemoteBase;
} PORT_VIEW, *PPORT_VIEW;

typedef struct _REMOTE_PORT_VIEW
{
	ULONG 		Length;
	LPC_SIZE_T 	ViewSize;
	LPC_PVOID 	ViewBase;
} REMOTE_PORT_VIEW, *PREMOTE_PORT_VIEW;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG 		Length;
	HANDLE 		RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG 		Attributes;
	PVOID 		SecurityDescriptor;
	PVOID 		SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _INITIAL_TEB
{
    PVOID StackBase;
    PVOID StackLimit;
    PVOID StackCommit;
    PVOID StackCommitMax;
    PVOID StackReserved;
} INITIAL_TEB, *PINITIAL_TEB;

typedef struct _TOKEN_USER {
	SID_AND_ATTRIBUTES User;
} TOKEN_USER, *PTOKEN_USER;

typedef struct _TOKEN_GROUPS {
	DWORD 		   GroupCount;
	SID_AND_ATTRIBUTES Groups[ANYSIZE_ARRAY];
} TOKEN_GROUPS,*PTOKEN_GROUPS,*LPTOKEN_GROUPS;

typedef struct _TOKEN_PRIVILEGES {
	DWORD 		    PrivilegeCount;
	LUID_AND_ATTRIBUTES Privileges[ANYSIZE_ARRAY];
} TOKEN_PRIVILEGES,*PTOKEN_PRIVILEGES,*LPTOKEN_PRIVILEGES;

typedef struct _TOKEN_OWNER {
	PSID Owner;
} TOKEN_OWNER,*PTOKEN_OWNER;

typedef struct _TOKEN_PRIMARY_GROUP {
	PSID PrimaryGroup;
} TOKEN_PRIMARY_GROUP,*PTOKEN_PRIMARY_GROUP;


typedef struct _TOKEN_DEFAULT_DACL {
	PACL DefaultDacl;
} TOKEN_DEFAULT_DACL,*PTOKEN_DEFAULT_DACL;
#define TOKEN_SOURCE_LENGTH 8
typedef struct _TOKEN_SOURCE {
	CHAR SourceName[TOKEN_SOURCE_LENGTH];
	LUID SourceIdentifier;
} TOKEN_SOURCE,*PTOKEN_SOURCE;

typedef struct _PLUGPLAY_EVENT_BLOCK
{
	GUID 			EventGuid;
	PLUGPLAY_EVENT_CATEGORY EventCategory;
	PULONG 			Result;
	ULONG 			Flags;
	ULONG 			TotalSize;
	PVOID 			DeviceObject;
	union
	{
		struct
		{
	        	GUID  ClassGuid;
	        	WCHAR SymbolicLinkName[ANYSIZE_ARRAY];
	    	} DeviceClass;
	    	struct
	    	{
	        	WCHAR DeviceIds[ANYSIZE_ARRAY];
	    	} TargetDevice;
	    	struct
	    	{
	        	WCHAR DeviceId[ANYSIZE_ARRAY];
	    	} InstallDevice;
	    	struct
	    	{
	        	PVOID NotificationStructure;
	        	WCHAR DeviceIds[ANYSIZE_ARRAY];
	    	} CustomNotification;
	    	struct
	    	{
	        	PVOID Notification;
	    	} ProfileNotification;
	   	struct
	    	{
	        	ULONG NotificationCode;
	        	ULONG NotificationData;
	    	} PowerNotification;
	    	struct
	    	{
	        	PNP_VETO_TYPE 	VetoType;
	        	WCHAR 		DeviceIdVetoNameBuffer[ANYSIZE_ARRAY];
	    	} VetoNotification;
	    	struct
	    	{
	        	GUID BlockedDriverGuid;
	    	} BlockedDriverNotification;
	};
} PLUGPLAY_EVENT_BLOCK, *PPLUGPLAY_EVENT_BLOCK;

typedef struct _PORT_MESSAGE
{
	union
	{
	    	struct
	    	{
	        	CSHORT DataLength;
	        	CSHORT TotalLength;
	    	} s1;
	    	ULONG Length;
	} u1;
	union
	{
	    	struct
	    	{
	        	CSHORT Type;
	        	CSHORT DataInfoOffset;
	    	} s2;
	    	ULONG ZeroInit;
	} u2;
	union
	{
	    	LPC_CLIENT_ID 	ClientId;
	    	double 		DoNotUseThisField;
	};
	ULONG MessageId;
	union
	{
	    	LPC_SIZE_T ClientViewSize;
	    	ULONG 	   CallbackId;
	};
} PORT_MESSAGE, *PPORT_MESSAGE;

typedef struct _PRIVILEGE_SET {
	DWORD 			PrivilegeCount;
	DWORD 			Control;
	LUID_AND_ATTRIBUTES 	Privilege[ANYSIZE_ARRAY];
} PRIVILEGE_SET,*PPRIVILEGE_SET;

typedef struct _FILE_BASIC_INFORMATION
{
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	ULONG 	      FileAttributes;
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;


typedef struct _FILE_DIRECTORY_INFORMATION {
	ULONG           NextEntryOffset;
	ULONG           FileIndex;
	LARGE_INTEGER   CreationTime;
	LARGE_INTEGER   LastAccessTime;
	LARGE_INTEGER   LastWriteTime;
	LARGE_INTEGER   ChangeTime;
	LARGE_INTEGER   EndOfFile;
	LARGE_INTEGER   AllocationSize;
	ULONG           FileAttributes;
	ULONG           FileNameLength;
	WCHAR           FileName[1];
} FILE_DIRECTORY_INFORMATION, *PFILE_DIRECTORY_INFORMATION;

typedef struct _FILE_FULL_DIRECTORY_INFORMATION {
	ULONG           NextEntryOffset;
	ULONG           FileIndex;
	LARGE_INTEGER   CreationTime;
	LARGE_INTEGER   LastAccessTime;
	LARGE_INTEGER   LastWriteTime;
	LARGE_INTEGER   ChangeTime;
	LARGE_INTEGER   EndOfFile;
	LARGE_INTEGER   AllocationSize;
	ULONG           FileAttributes;
	ULONG           FileNameLength;
	ULONG           EaSize;
	WCHAR           FileName[0];
} FILE_FULL_DIRECTORY_INFORMATION, *PFILE_FULL_DIRECTORY_INFORMATION;

typedef struct _FILE_BOTH_DIRECTORY_INFORMATION {
	ULONG         NextEntryOffset;
	ULONG         FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG         FileAttributes;
	ULONG         FileNameLength;
	ULONG         EaSize;
	CHAR          ShortNameLength;
	WCHAR         ShortName[12];
	WCHAR         FileName[0];
} FILE_BOTH_DIRECTORY_INFORMATION, *PFILE_BOTH_DIRECTORY_INFORMATION;


typedef struct _FILE_INTERNAL_INFORMATION {
	LARGE_INTEGER IndexNumber;
} FILE_INTERNAL_INFORMATION, *PFILE_INTERNAL_INFORMATION;

typedef struct _FILE_EA_INFORMATION {
	ULONG EaSize;
} FILE_EA_INFORMATION, *PFILE_EA_INFORMATION;

typedef struct _FILE_ACCESS_INFORMATION {
	ACCESS_MASK AccessFlags;
} FILE_ACCESS_INFORMATION, *PFILE_ACCESS_INFORMATION;

typedef struct _FILE_NAME_INFORMATION {
	ULONG  FileNameLength;
	WCHAR  FileName[1];
} FILE_NAME_INFORMATION, *PFILE_NAME_INFORMATION;


typedef struct _FILE_RENAME_INFORMATION {
	BOOLEAN ReplaceIfExists;
	HANDLE  RootDirectory;
	ULONG   FileNameLength;
	WCHAR   FileName[1];
} FILE_RENAME_INFORMATION, *PFILE_RENAME_INFORMATION;

typedef struct _FILE_NAMES_INFORMATION {
	ULONG NextEntryOffset;
	ULONG FileIndex;
	ULONG FileNameLength;
	WCHAR FileName[1];
} FILE_NAMES_INFORMATION, *PFILE_NAMES_INFORMATION;


typedef struct _FILE_DISPOSITION_INFORMATION {
	BOOLEAN  DeleteFile;
} FILE_DISPOSITION_INFORMATION, *PFILE_DISPOSITION_INFORMATION;

typedef struct _FILE_FULL_EA_INFORMATION {
	ULONG  NextEntryOffset;
	UCHAR  Flags;
	UCHAR  EaNameLength;
	USHORT  EaValueLength;
	CHAR  EaName[1];
} FILE_FULL_EA_INFORMATION, *PFILE_FULL_EA_INFORMATION;


typedef struct _FILE_MODE_INFORMATION {
	ULONG Mode;
} FILE_MODE_INFORMATION, *PFILE_MODE_INFORMATION;

typedef struct _FILE_POSITION_INFORMATION {
	LARGE_INTEGER CurrentByteOffset;
} FILE_POSITION_INFORMATION, *PFILE_POSITION_INFORMATION;	   


typedef struct _FILE_ALLOCATION_INFORMATION {
	LARGE_INTEGER AllocationSize;
} FILE_ALLOCATION_INFORMATION, *PFILE_ALLOCATION_INFORMATION;


typedef struct _FILE_ALIGNMENT_INFORMATION {
	ULONG  AlignmentRequirement;
} FILE_ALIGNMENT_INFORMATION, *PFILE_ALIGNMENT_INFORMATION;


typedef struct _FILE_END_OF_FILE_INFORMATION {
	LARGE_INTEGER  EndOfFile;
} FILE_END_OF_FILE_INFORMATION, *PFILE_END_OF_FILE_INFORMATION;


typedef struct _FILE_STANDARD_INFORMATION {
  LARGE_INTEGER  AllocationSize;
  LARGE_INTEGER  EndOfFile;
  ULONG  NumberOfLinks;
  BOOLEAN  DeletePending;
  BOOLEAN  Directory;
} FILE_STANDARD_INFORMATION, *PFILE_STANDARD_INFORMATION;

typedef struct _FILE_STREAM_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG StreamNameLength;
	LARGE_INTEGER StreamSize;
	LARGE_INTEGER StreamAllocationSize;
	WCHAR StreamName[1];
} FILE_STREAM_INFORMATION, *PFILE_STREAM_INFORMATION;

typedef struct _FILE_MAILSLOT_QUERY_INFORMATION {
	ULONG           MaximumMessageSize;
	ULONG           MailslotQuota;
	ULONG           NextMessageSize;
	ULONG           MessagesAvailable;
	LARGE_INTEGER   ReadTimeout;
} FILE_MAILSLOT_QUERY_INFORMATION, *PFILE_MAILSLOT_QUERY_INFORMATION;

typedef struct _FILE_ALL_INFORMATION {
	FILE_BASIC_INFORMATION      BasicInformation;
	FILE_STANDARD_INFORMATION   StandardInformation;
	FILE_INTERNAL_INFORMATION   InternalInformation;
	FILE_EA_INFORMATION         EaInformation;
	FILE_ACCESS_INFORMATION     AccessInformation;
	FILE_POSITION_INFORMATION   PositionInformation;
	FILE_MODE_INFORMATION       ModeInformation;
	FILE_ALIGNMENT_INFORMATION  AlignmentInformation;
	FILE_NAME_INFORMATION       NameInformation;
} FILE_ALL_INFORMATION, *PFILE_ALL_INFORMATION;


typedef struct _FILE_NETWORK_OPEN_INFORMATION
{
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER AllocationSize;
	LARGE_INTEGER EndOfFile;
	ULONG 	      FileAttributes;
} FILE_NETWORK_OPEN_INFORMATION, *PFILE_NETWORK_OPEN_INFORMATION;

typedef struct _KEY_VALUE_ENTRY
{
	PUNICODE_STRING ValueName;
	ULONG 		DataLength;
	ULONG 		DataOffset;
	ULONG 		Type;
} KEY_VALUE_ENTRY, *PKEY_VALUE_ENTRY;

typedef union _FILE_SEGMENT_ELEMENT {
	PVOID64   Buffer;
	ULONGLONG Alignment;
}FILE_SEGMENT_ELEMENT, *PFILE_SEGMENT_ELEMENT;

typedef struct _LDT_ENTRY
{
	USHORT LimitLow;
	USHORT BaseLow;
	union
	{
	    	struct
	    	{
	        	UCHAR BaseMid;
	        	UCHAR Flags1;
	        	UCHAR Flags2;
	        	UCHAR BaseHi;
	    	} Bytes;
	    	struct
	    	{
	        	ULONG BaseMid : 8;
	        	ULONG Type : 5;
	        	ULONG Dpl : 2;
	        	ULONG Pres : 1;
	        	ULONG LimitHi : 4;
	        	ULONG Sys : 1;
	        	ULONG Reserved_0 : 1;
	        	ULONG Default_Big : 1;
	        	ULONG Granularity : 1;
	        	ULONG BaseHi : 8;
	    	} Bits;
	} HighWord;
} LDT_ENTRY, *PLDT_ENTRY;

typedef struct _EVENT_TRACE_HEADER
{
	USHORT  Size;
	union {
		USHORT  FieldTypeFlags;
		struct {
			UCHAR  HeaderType;
			UCHAR  MarkerFlags;
		};
	};
	union {
		ULONG  Version;
		struct {
			UCHAR  Type;
			UCHAR  Level;
			USHORT  Version;
		} Class;
	};
	ULONG  ThreadId;
	ULONG  ProcessId;
	LARGE_INTEGER  TimeStamp;
	union {
		GUID  Guid;
		ULONGLONG  GuidPtr;
	};
	union {
		struct {
			ULONG  ClientContext;
			ULONG  Flags;
		};
		struct {
			ULONG  KernelTime;
			ULONG  UserTime;
		};
		ULONG64  ProcessorTime;
	};
} EVENT_TRACE_HEADER, *PEVENT_TRACE_HEADER;

typedef VOID
(NTAPI *PIO_APC_ROUTINE)(
	IN PVOID ApcContext,
	IN PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG Reserved);

typedef VOID
(NTAPI *PKNORMAL_ROUTINE)(
	IN PVOID  NormalContext,
	IN PVOID  SystemArgument1,
	IN PVOID  SystemArgument2);

typedef VOID
(NTAPI *PTIMER_APC_ROUTINE)(
	IN PVOID  TimerContext,
	IN ULONG  TimerLowValue,
	IN LONG  TimerHighValue);

typedef struct _LPC_MESSAGE
{
	USHORT  	DataSize;
	USHORT  	MessageSize;
	USHORT  	MessageType;
	USHORT 	 	VirtualRangesOffset;
	CLIENT_ID  	ClientId;
	ULONG  		MessageId;
	ULONG  		SectionSize;
} LPC_MESSAGE, *PLPC_MESSAGE;

typedef struct _LPC_SECTION_WRITE
{
	ULONG   Length;
	HANDLE  SectionHandle;
	ULONG   SectionOffset;
	ULONG   ViewSize;
	PVOID   ViewBase;
	PVOID   TargetViewBase;
} LPC_SECTION_WRITE, *PLPC_SECTION_WRITE;

typedef struct _LPC_SECTION_READ
{
	ULONG  Length;
	ULONG  ViewSize;
	PVOID  ViewBase;
} LPC_SECTION_READ, *PLPC_SECTION_READ;

typedef struct OVERLAPPED{
	DWORD	Internal;
	DWORD	InternalHigh;
	DWORD	Offset;
	DWORD	OffsetHigh;
	HANDLE	hEvent;
}OVERLAPPED,*LPOVERLAPPED;

/* From ReactOS, don't touch. */

typedef struct _SSDT_ENTRY {
	PSSDT   SSDT;
	PULONG  ServiceCounterTable;
	ULONG   NumberOfServices;
	PSSPT   SSPT;
} SSDT_ENTRY;

extern HANDLE hBaseDir;

/* for kernel */
/* These are not exposed to drivers normally */
#ifndef _NTOS_MODE_USER
    #define JOB_OBJECT_ASSIGN_PROCESS    (1)
    #define JOB_OBJECT_SET_ATTRIBUTES    (2)
    #define JOB_OBJECT_QUERY    (4)
    #define JOB_OBJECT_TERMINATE    (8)
    #define JOB_OBJECT_SET_SECURITY_ATTRIBUTES    (16)
    #define JOB_OBJECT_ALL_ACCESS    (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|31)
#endif

struct ps_impersonation_information
{
	void*					token;
	unsigned char                         	copy_on_open;
	unsigned char                         	effective_only;
	enum security_impersonation_level    	impersonation_level;
};


struct termination_port {
    struct termination_port*	next;
    void*			port;
};

struct sid_and_attributes {
	void*		sid;
	unsigned long 	attributes;
};

struct ps_job_token_filter
{
    unsigned int 		captured_sid_count;
    struct sid_and_attributes 	captured_sids;
    unsigned int 		captured_sids_length;
    unsigned int 		captured_group_count;
    struct sid_and_attributes 	captured_groups;
    unsigned int 		captured_groups_length;
    unsigned int 		captured_privilege_count;
    struct sid_and_attributes 	captured_privileges;
    unsigned int 		captured_privileges_length;
};

struct io_counters {
	unsigned long long  	read_op_count;
	unsigned long long  	write_opcount;
	unsigned long long  	other_op_count;
	unsigned long long 	read_transfer_count;
	unsigned long long 	write_transfer_count;
	unsigned long long 	other_transfer_count;
};

struct ejob
{
    struct kevent 		event;
    struct list_head 		job_links;
    struct list_head 		process_list_head;
    struct eresource 		job_lock;
    large_integer_t 		total_utime;
    large_integer_t 		total_ktime;
    large_integer_t 		this_period_total_utime;
    large_integer_t 		this_period_total_ktime;
    unsigned int 		total_page_fault_count;
    unsigned int 		total_processes;
    unsigned int 		active_processes;
    unsigned int 		total_terminated_processes;
    large_integer_t 		per_process_utime_limit;
    large_integer_t 		per_job_utime_limit;
    unsigned int 		limit_flags;
    unsigned int 		min_workingset_size;
    unsigned int 		max_workingset_size;
    unsigned int 		active_process_limit;
    unsigned int 		affinity;
    unsigned char 		priority_class;
    unsigned int 		ui_restrictions_class;
    unsigned int 		security_limit_flags;
    void* 			token;
    struct ps_job_token_filter* filter;
    unsigned int 		end_of_job_time_action;
    void* 			completion_port;
    void* 			completion_key;
    unsigned int 		session_id;
    unsigned int 		scheduling_class;
    unsigned long long 		read_op_count;
    unsigned long long 		write_op_count;
    unsigned long long 		other_op_count;
    unsigned long long 		read_transfer_count;
    unsigned long long 		write_transfer_count;
    unsigned long long 		other_transfer_count;
    struct io_counters 		io_info;
    unsigned int 		process_memory_limit;
    unsigned int 		job_memory_limit;
    unsigned int 		peak_proc_mem_used;
    unsigned int 		peak_job_memused;
    unsigned int 		current_job_mem_used;
    struct kguarded_mutex 	memory_limits_lock;
    unsigned long 		member_level;
    unsigned long 		job_flags;
};

typedef struct _PROCESS_BASIC_INFORMATION {
    DWORD ExitStatus;
    DWORD PebBaseAddress;
    DWORD AffinityMask;
    DWORD BasePriority;
    ULONG UniqueProcessId;
    ULONG InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

typedef struct _KERNEL_USER_TIMES
{
    large_integer_t CreateTime;
    large_integer_t ExitTime;
    large_integer_t KernelTime;
    large_integer_t UserTime;
} KERNEL_USER_TIMES, *PKERNEL_USER_TIMES;

typedef struct _PROCESS_SESSION_INFORMATION
{
    ULONG SessionId;
} PROCESS_SESSION_INFORMATION, *PPROCESS_SESSION_INFORMATION;

typedef struct _VM_COUNTERS
{
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
} VM_COUNTERS, *PVM_COUNTERS;

typedef struct _PROCESS_PRIORITY_CLASS {
    BOOLEAN     Foreground;
    UCHAR       PriorityClass;
} PROCESS_PRIORITY_CLASS, *PPROCESS_PRIORITY_CLASS;

typedef kprocessor_mode_t	KPROCESSOR_MODE;

typedef enum _SECURITY_OPERATION_CODE
{
	SetSecurityDescriptor,
	QuerySecurityDescriptor,
	DeleteSecurityDescriptor,
	AssignSecurityDescriptor
} SECURITY_OPERATION_CODE;

typedef enum _POOL_TYPE
{
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS,
	MaxPoolType,
	NonPagedPoolSession = 32,
	PagedPoolSession,
	NonPagedPoolMustSucceedSession,
	DontUseThisTypeSession,
	NonPagedPoolCacheAlignedSession,
	PagedPoolCacheAlignedSession,
	NonPagedPoolCacheAlignedMustSSession
} POOL_TYPE;

typedef struct _OBJECT_NAME_INFORMATION
{
	UNICODE_STRING	Name;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

typedef struct _SINGLE_LIST_ENTRY
{
	struct _SINGLE_LIST_ENTRY	*Next;
} SINGLE_LIST_ENTRY, *PSINGLE_LIST_ENTRY;

typedef long long	QUAD;

typedef struct eresource	ERESOURCE, *PERESOURCE;

#define INIT_OBJECT_ATTR(p,n,a,r,s) { \
	(p)->Length = sizeof(OBJECT_ATTRIBUTES); \
	(p)->RootDirectory = (r); \
	(p)->Attributes = (a); \
	(p)->ObjectName = (n); \
	(p)->SecurityDescriptor = (s); \
	(p)->SecurityQualityOfService = NULL; \
}

typedef struct _SEP_AUDIT_POLICY_CATEGORIES
{
	UCHAR System:4;
	UCHAR Logon:4;
	UCHAR ObjectAccess:4;
	UCHAR PrivilegeUse:4;
	UCHAR DetailedTracking:4;
	UCHAR PolicyChange:4;
	UCHAR AccountManagement:4;
	UCHAR DirectoryServiceAccess:4;
	UCHAR AccountLogon:4;
} SEP_AUDIT_POLICY_CATEGORIES, *PSEP_AUDIT_POLICY_CATEGORIES;

typedef struct _SEP_AUDIT_POLICY_OVERLAY
{
	ULONGLONG PolicyBits:36;
	UCHAR SetBit:1;
} SEP_AUDIT_POLICY_OVERLAY, *PSEP_AUDIT_POLICY_OVERLAY;

typedef struct _SEP_AUDIT_POLICY
{
	union
	{
		SEP_AUDIT_POLICY_CATEGORIES PolicyElements;
		SEP_AUDIT_POLICY_OVERLAY PolicyOverlay;
		ULONGLONG Overlay;
	};
} SEP_AUDIT_POLICY, *PSEP_AUDIT_POLICY;

typedef struct _TOKEN
{
	TOKEN_SOURCE TokenSource;                         /* 0x00 */
	LUID TokenId;                                     /* 0x10 */
	LUID AuthenticationId;                            /* 0x18 */
	LUID ParentTokenId;                               /* 0x20 */
	LARGE_INTEGER ExpirationTime;                     /* 0x28 */
	ERESOURCE 	      *TokenLock;                     /* 0x30 */
	SEP_AUDIT_POLICY  AuditPolicy;                    /* 0x38 */
	LUID ModifiedId;                                  /* 0x40 */
	ULONG SessionId;                                  /* 0x48 */
	ULONG UserAndGroupCount;                          /* 0x4C */
	ULONG RestrictedSidCount;                         /* 0x50 */
	ULONG PrivilegeCount;                             /* 0x54 */
	ULONG VariableLength;                             /* 0x58 */
	ULONG DynamicCharged;                             /* 0x5C */
	ULONG DynamicAvailable;                           /* 0x60 */
	ULONG DefaultOwnerIndex;                          /* 0x64 */
	PSID_AND_ATTRIBUTES UserAndGroups;                /* 0x68 */
	PSID_AND_ATTRIBUTES RestrictedSids;               /* 0x6C */
	PSID PrimaryGroup;                                /* 0x70 */
	PLUID_AND_ATTRIBUTES Privileges;                  /* 0x74 */
	PULONG DynamicPart;                               /* 0x78 */
	PACL DefaultDacl;                                 /* 0x7C */
	TOKEN_TYPE TokenType;                             /* 0x80 */
	SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;  /* 0x84 */
	ULONG TokenFlags;                                 /* 0x88 */
	BOOLEAN TokenInUse;                               /* 0x8C */
	PVOID ProxyData;                                  /* 0x90 */
	PVOID AuditData;                                  /* 0x94 */
	LUID OriginatingLogonSession;                     /* 0x98 */
	ULONG VariablePart;                               /* 0xA0 */
} TOKEN, *PTOKEN;

typedef struct _FAST_MUTEX {
	LONG Count;
	struct kthread *Owner;
	atomic_t Contention;
	struct kevent Event;
	ULONG OldIrql;
} FAST_MUTEX, *PFAST_MUTEX;

typedef struct kthread *PKTHREAD;

/* Refer to ReactOS include/ndk/extypes.h */

/* Class 0 */
typedef struct _SYSTEM_BASIC_INFORMATION
{
	ULONG Reserved;
	ULONG TimerResolution;
	ULONG PageSize;
	ULONG NumberOfPhysicalPages;
	ULONG LowestPhysicalPageNumber;
	ULONG HighestPhysicalPageNumber;
	ULONG AllocationGranularity;
	ULONG MinimumUserModeAddress;
	ULONG MaximumUserModeAddress;
	KAFFINITY ActiveProcessorsAffinityMask;
	CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;

/* Class 1 */
typedef struct _SYSTEM_PROCESSOR_INFORMATION
{
	USHORT ProcessorArchitecture;
	USHORT ProcessorLevel;
	USHORT ProcessorRevision;
	USHORT Reserved;
	ULONG ProcessorFeatureBits;
} SYSTEM_PROCESSOR_INFORMATION, *PSYSTEM_PROCESSOR_INFORMATION;

/* Class 2 */
typedef struct _SYSTEM_PERFORMANCE_INFORMATION
{
	LARGE_INTEGER IdleProcessTime;
	LARGE_INTEGER IoReadTransferCount;
	LARGE_INTEGER IoWriteTransferCount;
	LARGE_INTEGER IoOtherTransferCount;
	ULONG IoReadOperationCount;
	ULONG IoWriteOperationCount;
	ULONG IoOtherOperationCount;
	ULONG AvailablePages;
	ULONG CommittedPages;
	ULONG CommitLimit;
	ULONG PeakCommitment;
	ULONG PageFaultCount;
	ULONG CopyOnWriteCount;
	ULONG TransitionCount;
	ULONG CacheTransitionCount;
	ULONG DemandZeroCount;
	ULONG PageReadCount;
	ULONG PageReadIoCount;
	ULONG CacheReadCount;
	ULONG CacheIoCount;
	ULONG DirtyPagesWriteCount;
	ULONG DirtyWriteIoCount;
	ULONG MappedPagesWriteCount;
	ULONG MappedWriteIoCount;
	ULONG PagedPoolPages;
	ULONG NonPagedPoolPages;
	ULONG PagedPoolAllocs;
	ULONG PagedPoolFrees;
	ULONG NonPagedPoolAllocs;
	ULONG NonPagedPoolFrees;
	ULONG FreeSystemPtes;
	ULONG ResidentSystemCodePage;
	ULONG TotalSystemDriverPages;
	ULONG TotalSystemCodePages;
	ULONG NonPagedPoolLookasideHits;
	ULONG PagedPoolLookasideHits;
	ULONG Spare3Count;
	ULONG ResidentSystemCachePage;
	ULONG ResidentPagedPoolPage;
	ULONG ResidentSystemDriverPage;
	ULONG CcFastReadNoWait;
	ULONG CcFastReadWait;
	ULONG CcFastReadResourceMiss;
	ULONG CcFastReadNotPossible;
	ULONG CcFastMdlReadNoWait;
	ULONG CcFastMdlReadWait;
	ULONG CcFastMdlReadResourceMiss;
	ULONG CcFastMdlReadNotPossible;
	ULONG CcMapDataNoWait;
	ULONG CcMapDataWait;
	ULONG CcMapDataNoWaitMiss;
	ULONG CcMapDataWaitMiss;
	ULONG CcPinMappedDataCount;
	ULONG CcPinReadNoWait;
	ULONG CcPinReadWait;
	ULONG CcPinReadNoWaitMiss;
	ULONG CcPinReadWaitMiss;
	ULONG CcCopyReadNoWait;
	ULONG CcCopyReadWait;
	ULONG CcCopyReadNoWaitMiss;
	ULONG CcCopyReadWaitMiss;
	ULONG CcMdlReadNoWait;
	ULONG CcMdlReadWait;
	ULONG CcMdlReadNoWaitMiss;
	ULONG CcMdlReadWaitMiss;
	ULONG CcReadAheadIos;
	ULONG CcLazyWriteIos;
	ULONG CcLazyWritePages;
	ULONG CcDataFlushes;
	ULONG CcDataPages;
	ULONG ContextSwitches;
	ULONG FirstLevelTbFills;
	ULONG SecondLevelTbFills;
	ULONG SystemCalls;
} SYSTEM_PERFORMANCE_INFORMATION, *PSYSTEM_PERFORMANCE_INFORMATION;

/* Class 3 */
typedef struct _SYSTEM_TIMEOFDAY_INFORMATION {
	LARGE_INTEGER BootTime;
	LARGE_INTEGER CurrentTime;
	LARGE_INTEGER TimeZoneBias;
	ULONG TimeZoneId;
	ULONG Reserved;
} SYSTEM_TIMEOFDAY_INFORMATION, *PSYSTEM_TIMEOFDAY_INFORMATION;

/* Class 4 */

/* Class 5 */
typedef struct _SYSTEM_PROCESS_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	LONG BasePriority; 	/* FIXME: KPRIORITY BasePriority */
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG UniqueProcessKey;

	/*
	 * This part corresponds to VM_COUNTERS_EX.
	 * NOTE: *NOT* THE SAME AS VM_COUNTERS!
	 */
	ULONG PeakVirtualSize;
	ULONG VirtualSize;
	ULONG PageFaultCount;
	ULONG PeakWorkingSetSize;
	ULONG WorkingSetSize;
	ULONG QuotaPeakPagedPoolUsage;
	ULONG QuotaPagedPoolUsage;
	ULONG QuotaPeakNonPagedPoolUsage;
	ULONG QuotaNonPagedPoolUsage;
	ULONG PagefileUsage;
	ULONG PeakPagefileUsage;
	ULONG PrivatePageCount;

	/*
	 * This part corresponds to IO_COUNTERS
	 */
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;

	/* SYSTEM_THREAD_INFORMATION TH[1]; */
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

/* Class 6~7 */

/* Class 8 */
typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
{
	LARGE_INTEGER IdleTime;
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER DpcTime;
	LARGE_INTEGER InterruptTime;
	ULONG InterruptCount;
} SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION, *PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION;

/* Class 16 */
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

/* Class 17~20 */

/* Class 21 */
typedef struct _SYSTEM_FILECACHE_INFORMATION
{
	ULONG CurrentSize;
	ULONG PeakSize;
	ULONG PageFaultCount;
	ULONG MinimumWorkingSet;
	ULONG MaximumWorkingSet;
	ULONG CurrentSizeIncludingTransitionInPages;
	ULONG PeakSizeIncludingTransitionInPages;
	ULONG TransitionRePurposeCount;
	ULONG Flags;
} SYSTEM_FILECACHE_INFORMATION, *PSYSTEM_FILECACHE_INFORMATION;

/* Class 22 */

/* Class 23 */
typedef struct _SYSTEM_INTERRUPT_INFORMATION
{
	ULONG ContextSwitches;
	ULONG DpcCount;
	ULONG DpcRate;
	ULONG TimeIncrement;
	ULONG DpcBypassCount;
	ULONG ApcBypassCount;
} SYSTEM_INTERRUPT_INFORMATION, *PSYSTEM_INTERRUPT_INFORMATION;

/* Class 24~34 */

/* Class 35 */
typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
{
	BOOLEAN KernelDebuggerEnabled;
	BOOLEAN KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

/* Class 36 */

/* Class 37 */
typedef struct _SYSTEM_REGISTRY_QUOTA_INFORMATION
{
	ULONG RegistryQuotaAllowed;
	ULONG RegistryQuotaUsed;
	ULONG PagedPoolSize;
} SYSTEM_REGISTRY_QUOTA_INFORMATION, *PSYSTEM_REGISTRY_QUOTA_INFORMATION;
#endif /* CONFIG_UNIFIED_KERNEL */
#endif /* _WIN32_H */
