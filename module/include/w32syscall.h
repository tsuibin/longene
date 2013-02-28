/*
 * w32syscall.h
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
 * w32syscall.h:
 * Refered to ReactOS code
 */

#ifndef _W32SYSCALL_H
#define _W32SYSCALL_H

#include <linux/module.h>
#include "win32.h"
#include "wineserver/server.h"

#ifdef CONFIG_UNIFIED_KERNEL
/* 0 */
NTSTATUS SERVICECALL
NtAcceptConnectPort (PHANDLE		ServerPortHandle,
		HANDLE		NamedPortHandle,
		PPORT_MESSAGE	LpcMessage,
		BOOLEAN		AcceptIt,
		PPORT_VIEW		WriteMap,
		PREMOTE_PORT_VIEW	ReadMap);

NTSTATUS SERVICECALL
NtAccessCheck(IN  PSECURITY_DESCRIPTOR	SecurityDescriptor,
		IN  HANDLE 		TokenHandle,
		IN  ACCESS_MASK 		DesiredAccess,
		IN  PGENERIC_MAPPING 	GenericMapping,
		OUT PPRIVILEGE_SET 	PrivilegeSet,
		OUT PULONG 		ReturnLength,
		OUT PACCESS_MASK 		GrantedAccess,
		OUT PNTSTATUS 		AccessStatus);

NTSTATUS SERVICECALL
NtAccessCheckAndAuditAlarm(IN  PUNICODE_STRING		SubsystemName,
		IN  PVOID			HandleId,
		IN  PUNICODE_STRING		ObjectTypeName,
		IN  PUNICODE_STRING		ObjectName,
		IN  PSECURITY_DESCRIPTOR	SecurityDescriptor,
		IN  ACCESS_MASK		DesiredAccess,
		IN  PGENERIC_MAPPING		GenericMapping,
		IN  BOOLEAN			ObjectCreation,
		OUT PACCESS_MASK		GrantedAccess,
		OUT PNTSTATUS		AccessStatus,
		OUT PBOOLEAN			GenerateOnClose);

NTSTATUS SERVICECALL
NtAddAtom(IN  PWSTR	AtomName,
		IN  ULONG	AtomNameLength,
		OUT PRTL_ATOM	Atom);

NTSTATUS SERVICECALL
NtAddBootEntry(IN PUNICODE_STRING EntryName,
		IN PUNICODE_STRING EntryValue);

/* 5 */
NTSTATUS SERVICECALL
NtAdjustGroupsToken(IN  HANDLE		TokenHandle,
		IN  BOOLEAN		ResetToDefault,
		IN  PTOKEN_GROUPS	NewState,
		IN  ULONG		BufferLength,
		OUT PTOKEN_GROUPS	PreviousState OPTIONAL,
		OUT PULONG		ReturnLength);

NTSTATUS SERVICECALL
NtAdjustPrivilegesToken (IN  HANDLE		TokenHandle,
		IN  BOOLEAN		DisableAllPrivileges,
		IN  PTOKEN_PRIVILEGES	NewState,
		IN  ULONG		BufferLength,
		OUT PTOKEN_PRIVILEGES	PreviousState OPTIONAL,
		OUT PULONG		ReturnLength OPTIONAL);

NTSTATUS SERVICECALL
NtAlertResumeThread(IN  HANDLE	ThreadHandle,
		OUT PULONG	SuspendCount);

NTSTATUS SERVICECALL
NtAlertThread (IN HANDLE ThreadHandle);

NTSTATUS SERVICECALL
NtAllocateLocallyUniqueId(OUT LUID *LocallyUniqueId);

/* 10 */
NTSTATUS SERVICECALL
NtAllocateUuids(OUT PULARGE_INTEGER	Time,
		OUT PULONG		Range,
		OUT PULONG		Sequence,
		OUT PUCHAR		Seed);

NTSTATUS SERVICECALL
NtAllocateVirtualMemory(IN     HANDLE	ProcessHandle,
		IN OUT PVOID*	UBaseAddress,
		IN     ULONG	ZeroBits,
		IN OUT PULONG	URegionSize,
		IN     ULONG	AllocationType,
		IN     ULONG	Protect);

NTSTATUS SERVICECALL
NtAssignProcessToJobObject(HANDLE JobHandle,
		HANDLE ProcessHandle);

NTSTATUS SERVICECALL
NtCallbackReturn (PVOID		Result,
		ULONG		ResultLength,
		NTSTATUS	Status);

NTSTATUS SERVICECALL
NtCancelIoFile(IN  HANDLE		FileHandle,
		OUT PIO_STATUS_BLOCK	IoStatusBlock);

/* 15 */
NTSTATUS SERVICECALL
NtCancelTimer(IN  HANDLE	TimerHandle,
		OUT PBOOLEAN	CurrentState OPTIONAL);

NTSTATUS SERVICECALL
NtClearEvent(IN HANDLE EventHandle);

NTSTATUS SERVICECALL
NtCloseObjectAuditAlarm(IN PUNICODE_STRING	SubsystemName,
		IN PVOID		HandleId,
		IN BOOLEAN		GenerateOnClose);

NTSTATUS SERVICECALL
NtCompleteConnectPort (HANDLE hServerSideCommPort);

/* 20 */
NTSTATUS SERVICECALL
NtConnectPort (PHANDLE				UnsafeConnectedPortHandle,
		PUNICODE_STRING			PortName,
		PSECURITY_QUALITY_OF_SERVICE	Qos,
		PPORT_VIEW			UnsafeWriteMap,
		PREMOTE_PORT_VIEW		UnsafeReadMap,
		PULONG				UnsafeMaximumMessageSize,
		PVOID				UnsafeConnectData,
		PULONG				UnsafeConnectDataLength);

NTSTATUS SERVICECALL
NtContinue(IN PContext	Context,
		IN BOOLEAN	TestAlert);

NTSTATUS SERVICECALL
NtCreateDirectoryObject (OUT PHANDLE		DirectoryHandle,
		IN ACCESS_MASK		DesiredAccess,
		IN POBJECT_ATTRIBUTES	ObjectAttributes);

#if 0
NTSTATUS SERVICECALL
NtCreateEvent(OUT PHANDLE		EventHandle,
		IN  ACCESS_MASK		DesiredAccess,
		IN  POBJECT_ATTRIBUTES	ObjectAttributes  OPTIONAL,
		IN  EVENT_TYPE		EventType,
		IN  BOOLEAN		InitialState);
#endif

NTSTATUS SERVICECALL
NtCreateEventPair(OUT PHANDLE			EventPairHandle,
		IN  ACCESS_MASK		DesiredAccess,
		IN  POBJECT_ATTRIBUTES	ObjectAttributes);

/* 25 */
#if 0
NTSTATUS SERVICECALL
NtCreateFile(PHANDLE		FileHandle,
		ACCESS_MASK	DesiredAccess,
		POBJECT_ATTRIBUTES	ObjectAttributes,
		PIO_STATUS_BLOCK	IoStatusBlock,
		PLARGE_INTEGER	AllocateSize,
		ULONG		FileAttributes,
		ULONG		ShareAccess,
		ULONG		CreateDisposition,
		ULONG		CreateOptions,
		PVOID		EaBuffer,
		ULONG		EaLength);
#endif

NTSTATUS SERVICECALL
NtCreateIoCompletion(OUT PHANDLE		IoCompletionHandle,
		IN  ACCESS_MASK		DesiredAccess,
		IN  POBJECT_ATTRIBUTES	ObjectAttributes,
		IN  ULONG			NumberOfConcurrentThreads);

NTSTATUS SERVICECALL
NtCreateJobObject(PHANDLE		JobHandle,
		ACCESS_MASK		DesiredAccess,
		POBJECT_ATTRIBUTES	ObjectAttributes);

NTSTATUS SERVICECALL
NtCreateKey(OUT PHANDLE			KeyHandle,
		IN  ACCESS_MASK		DesiredAccess,
		IN  POBJECT_ATTRIBUTES	ObjectAttributes,
		IN  ULONG			TitleIndex,
		IN  PUNICODE_STRING		Class,
		IN  ULONG			CreateOptions,
		OUT PULONG			Disposition);

NTSTATUS SERVICECALL
NtCreateMailslotFile(OUT PHANDLE		FileHandle,
		IN  ACCESS_MASK		DesiredAccess,
		IN  POBJECT_ATTRIBUTES	ObjectAttributes,
		OUT PIO_STATUS_BLOCK	IoStatusBlock,
		IN  ULONG			CreateOptions,
		IN  ULONG			MailslotQuota,
		IN  ULONG			MaxMessageSize,
		IN  PLARGE_INTEGER		TimeOut);

/* 30 */
#if 0
NTSTATUS SERVICECALL
NtCreateMutant(OUT PHANDLE MutantHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes  OPTIONAL,
		IN BOOLEAN InitialOwner);
#endif

NTSTATUS SERVICECALL
NtCreateNamedPipeFile(PHANDLE 			FileHandle,
		ACCESS_MASK 		DesiredAccess,
		POBJECT_ATTRIBUTES 	ObjectAttributes,
		PIO_STATUS_BLOCK 		IoStatusBlock,
		ULONG 			ShareAccess,
		ULONG 			CreateDisposition,
		ULONG 			CreateOptions,
		ULONG 			NamedPipeType,
		ULONG 			ReadMode,
		ULONG 			CompletionMode,
		ULONG 			MaximumInstances,
		ULONG 			InboundQuota,
		ULONG 			OutboundQuota,
		PLARGE_INTEGER 		DefaultTimeout);

NTSTATUS SERVICECALL
NtCreatePagingFile(IN PUNICODE_STRING 	FileName,
		IN PLARGE_INTEGER 	InitialSize,
		IN PLARGE_INTEGER 	MaximumSize,
		IN ULONG 	Reserved);

NTSTATUS SERVICECALL
NtCreatePort (PHANDLE			PortHandle,
		POBJECT_ATTRIBUTES	ObjectAttributes,
		ULONG			MaxConnectInfoLength,
		ULONG			MaxDataLength,
		ULONG			MaxPoolUsage);

NTSTATUS SERVICECALL
NtCreateProcess(OUT PHANDLE 		ProcessHandle,
		IN  ACCESS_MASK 	DesiredAccess,
		IN  POBJECT_ATTRIBUTES 	ObjectAttributes  OPTIONAL,
		IN  HANDLE 		ParentProcess,
		IN  BOOLEAN 		InheritObjectTable,
		IN  HANDLE 		SectionHandle  OPTIONAL,
		IN  HANDLE 		DebugPort  OPTIONAL,
		IN  HANDLE 		ExceptionPort  OPTIONAL);

/* 35 */
NTSTATUS SERVICECALL
NtCreateProfile(OUT PHANDLE 		ProfileHandle,
		IN  HANDLE 		Process OPTIONAL,
		IN  PVOID 		ImageBase,
		IN  ULONG 		ImageSize,
		IN  ULONG 		BucketSize,
		IN  PVOID 		Buffer,
		IN  ULONG 		BufferSize,
		IN  KPROFILE_SOURCE 	ProfileSource,
		IN  KAFFINITY 		Affinity);

#if 0
NTSTATUS SERVICECALL
NtCreateSection (OUT PHANDLE 		SectionHandle,
		IN  ACCESS_MASK 	DesiredAccess,
		IN  POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
		IN  PLARGE_INTEGER 	MaximumSize OPTIONAL,
		IN  ULONG 		SectionPageProtection OPTIONAL,
		IN  ULONG 		AllocationAttributes,
		IN  HANDLE 		FileHandle OPTIONAL);

NTSTATUS SERVICECALL
NtCreateSemaphore(OUT PHANDLE 			SemaphoreHandle,
		IN  ACCESS_MASK 		DesiredAccess,
		IN  POBJECT_ATTRIBUTES 	ObjectAttributes  OPTIONAL,
		IN  LONG 			InitialCount,
		IN  LONG			MaximumCount);
#endif

NTSTATUS SERVICECALL
NtCreateSymbolicLinkObject(OUT PHANDLE 			LinkHandle,
		IN  ACCESS_MASK 		DesiredAccess,
		IN  POBJECT_ATTRIBUTES 	ObjectAttributes,
		IN  PUNICODE_STRING 		LinkTarget);

NTSTATUS SERVICECALL
NtCreateThread(OUT PHANDLE 		ThreadHandle,
		IN  ACCESS_MASK 		DesiredAccess,
		IN  POBJECT_ATTRIBUTES 	ObjectAttributes  OPTIONAL,
		IN  HANDLE 		ProcessHandle,
		OUT PCLIENT_ID 		ClientId,
		IN  PCONTEXT 		ThreadContext,
		IN  PINITIAL_TEB 	InitialTeb,
		IN  BOOLEAN 		CreateSuspended);

/* 40 */
NTSTATUS SERVICECALL
NtCreateTimer(OUT PHANDLE 		TimerHandle,
		IN  ACCESS_MASK 		DesiredAccess,
		IN  POBJECT_ATTRIBUTES 	ObjectAttributes OPTIONAL,
		IN  TIMER_TYPE 		TimerType);

NTSTATUS SERVICECALL
NtCreateToken(OUT PHANDLE 		TokenHandle,
		IN  ACCESS_MASK 		DesiredAccess,
		IN  POBJECT_ATTRIBUTES 	ObjectAttributes,
		IN  TOKEN_TYPE 		TokenType,
		IN  PLUID 		AuthenticationId,
		IN  PLARGE_INTEGER 	ExpirationTime,
		IN  PTOKEN_USER 		TokenUser,
		IN  PTOKEN_GROUPS 	TokenGroups,
		IN  PTOKEN_PRIVILEGES 	TokenPrivileges,
		IN  PTOKEN_OWNER 		TokenOwner,
		IN  PTOKEN_PRIMARY_GROUP 	TokenPrimaryGroup,
		IN  PTOKEN_DEFAULT_DACL 	TokenDefaultDacl,
		IN  PTOKEN_SOURCE 	TokenSource);

NTSTATUS SERVICECALL
NtCreateWaitablePort (OUT PHANDLE		PortHandle,
		IN  POBJECT_ATTRIBUTES	ObjectAttributes,
		IN  ULONG			MaxConnectInfoLength,
		IN  ULONG			MaxDataLength,
		IN  ULONG			MaxPoolUsage);

NTSTATUS SERVICECALL
NtDelayExecution(IN BOOLEAN Alertable,
		IN PLARGE_INTEGER DelayInterval);

NTSTATUS SERVICECALL
NtDeleteAtom(IN RTL_ATOM Atom);

/* 45 */
NTSTATUS SERVICECALL
NtDeleteBootEntry(IN PUNICODE_STRING EntryName,
		IN PUNICODE_STRING EntryValue);

NTSTATUS SERVICECALL
NtDeleteFile(IN POBJECT_ATTRIBUTES ObjectAttributes);

NTSTATUS SERVICECALL
NtDeleteKey(IN HANDLE KeyHandle);

NTSTATUS SERVICECALL
NtDeleteObjectAuditAlarm(IN PUNICODE_STRING 	SubsystemName,
		IN PVOID 		HandleId,
		IN BOOLEAN 		GenerateOnClose);

NTSTATUS SERVICECALL
NtDeleteValueKey (IN HANDLE 		KeyHandle,
		IN PUNICODE_STRING 	ValueName);

/* 50 */
NTSTATUS SERVICECALL
NtDeviceIoControlFile(IN  HANDLE 		DeviceHandle,
		IN  HANDLE 		Event OPTIONAL,
		IN  PIO_APC_ROUTINE 	UserApcRoutine OPTIONAL,
		IN  PVOID 		UserApcContext OPTIONAL,
		OUT PIO_STATUS_BLOCK 	IoStatusBlock,
		IN  ULONG 		IoControlCode,
		IN  PVOID 		InputBuffer,
		IN  ULONG 		InputBufferLength OPTIONAL,
		OUT PVOID 		OutputBuffer,
		IN  ULONG 		OutputBufferLength OPTIONAL);

NTSTATUS SERVICECALL
NtDisplayString(IN PUNICODE_STRING DisplayString);

NTSTATUS SERVICECALL
NtDuplicateObject (IN  HANDLE		SourceProcessHandle,
		IN  HANDLE		SourceHandle,
		IN  HANDLE		TargetProcessHandle,
		OUT PHANDLE		TargetHandle  OPTIONAL,
		IN  ACCESS_MASK	DesiredAccess,
		IN  ULONG		InheritHandle,
		IN  ULONG		Options);

NTSTATUS SERVICECALL
NtDuplicateToken(IN  HANDLE 		ExistingTokenHandle,
		IN  ACCESS_MASK 	DesiredAccess,
		IN  POBJECT_ATTRIBUTES ObjectAttributes  OPTIONAL,
		IN  BOOLEAN 		EffectiveOnly,
		IN  TOKEN_TYPE 	TokenType,
		OUT PHANDLE 		NewTokenHandle);

NTSTATUS SERVICECALL
NtEnumerateBootEntries(IN ULONG Unknown1,
		IN ULONG Unknown2);

/* 55 */
NTSTATUS SERVICECALL
NtEnumerateKey(IN  HANDLE 			KeyHandle,
		IN  ULONG 			Index,
		IN  KEY_INFORMATION_CLASS 	KeyInformationClass,
		OUT PVOID 			KeyInformation,
		IN  ULONG 			Length,
		OUT PULONG 			ResultLength);

NTSTATUS SERVICECALL
NtEnumerateValueKey(IN  HANDLE 				KeyHandle,
		IN  ULONG 				Index,
		IN  KEY_VALUE_INFORMATION_CLASS 	KeyValueInformationClass,
		OUT PVOID 				KeyValueInformation,
		IN  ULONG 				Length,
		OUT PULONG 				ResultLength);

NTSTATUS SERVICECALL
NtExtendSection(IN HANDLE 		SectionHandle,
		IN PLARGE_INTEGER 	NewMaximumSize);

NTSTATUS SERVICECALL
NtFindAtom(IN  PWSTR		AtomName,
		IN  ULONG		AtomNameLength,
		OUT PRTL_ATOM	Atom);

#if 0
NTSTATUS SERVICECALL
NtFlushBuffersFile(IN  HANDLE 		FileHandle,
		OUT PIO_STATUS_BLOCK IoStatusBlock);
#endif

/* 60 */
NTSTATUS SERVICECALL
NtFlushInstructionCache (IN HANDLE	ProcessHandle,
		IN PVOID	BaseAddress,
		IN ULONG	NumberOfBytesToFlush);

NTSTATUS SERVICECALL
NtFlushKey(IN HANDLE KeyHandle);

NTSTATUS SERVICECALL
NtFlushVirtualMemory(IN  HANDLE ProcessHandle,
		IN OUT  PVOID *BaseAddress,
		IN OUT PSIZE_T RegionSize,
		OUT PIO_STATUS_BLOCK IoStatus);

NTSTATUS SERVICECALL
NtFlushWriteBuffer(VOID);

NTSTATUS SERVICECALL
NtFreeVirtualMemory(IN HANDLE ProcessHandle,
		IN PVOID* PBaseAddress,
		IN PULONG PRegionSize,
		IN ULONG  FreeType);

/* 65 */
NTSTATUS SERVICECALL
NtFsControlFile(IN  HANDLE		 DeviceHandle,
		IN  HANDLE Event	 OPTIONAL,
		IN  PIO_APC_ROUTINE 	 UserApcRoutine OPTIONAL,
		IN  PVOID UserApcContext OPTIONAL,
		OUT PIO_STATUS_BLOCK 	 IoStatusBlock,
		IN  ULONG 		 IoControlCode,
		IN  PVOID 		 InputBuffer,
		IN  ULONG 		 InputBufferLength OPTIONAL,
		OUT PVOID 		 OutputBuffer,
		IN  ULONG 		 OutputBufferLength OPTIONAL);

NTSTATUS SERVICECALL
NtGetContextThread(IN  HANDLE   ThreadHandle,
		OUT PCONTEXT ThreadContext);

NTSTATUS SERVICECALL
NtGetPlugPlayEvent(IN  ULONG 			Reserved1,
		IN  ULONG 			Reserved2,
		OUT PPLUGPLAY_EVENT_BLOCK 	Buffer,
		IN  ULONG 			BufferSize);

NTSTATUS SERVICECALL
NtGetTickCount(VOID);

NTSTATUS SERVICECALL
NtImpersonateClientOfPort (HANDLE		PortHandle,
		PPORT_MESSAGE	ClientMessage);

/* 70 */
NTSTATUS SERVICECALL
NtImpersonateThread(IN HANDLE 				ThreadHandle,
		IN HANDLE 				ThreadToImpersonateHandle,
		IN PSECURITY_QUALITY_OF_SERVICE 	SecurityQualityOfService);

NTSTATUS SERVICECALL
NtInitializeRegistry (IN BOOLEAN SetUpBoot);

NTSTATUS SERVICECALL
NtInitiatePowerAction (IN POWER_ACTION 		SystemAction,
		IN SYSTEM_POWER_STATE 	MinSystemState,
		IN ULONG 		Flags,
		IN BOOLEAN 		Asynchronous);

NTSTATUS SERVICECALL
NtIsProcessInJob (IN HANDLE ProcessHandle,
		IN HANDLE JobHandle OPTIONAL);

NTSTATUS SERVICECALL
NtListenPort (IN HANDLE		PortHandle,
		IN PPORT_MESSAGE	ConnectMsg);

/* 75 */
NTSTATUS SERVICECALL
NtLoadDriver(IN PUNICODE_STRING DriverServiceName);

NTSTATUS SERVICECALL
NtLoadKey (IN POBJECT_ATTRIBUTES KeyObjectAttributes,
		IN POBJECT_ATTRIBUTES FileObjectAttributes);

NTSTATUS SERVICECALL
NtLoadKey2 (IN POBJECT_ATTRIBUTES KeyObjectAttributes,
		IN POBJECT_ATTRIBUTES FileObjectAttributes,
		IN ULONG 		  Flags);

NTSTATUS SERVICECALL
NtLockFile(IN  HANDLE 		FileHandle,
		IN  HANDLE 		EventHandle OPTIONAL,
		IN  PIO_APC_ROUTINE 	ApcRoutine OPTIONAL,
		IN  PVOID ApcContext OPTIONAL,
		OUT PIO_STATUS_BLOCK IoStatusBlock,
		IN  PLARGE_INTEGER 	ByteOffset,
		IN  PLARGE_INTEGER 	Length,
		IN  ULONG  		Key,
		IN  BOOLEAN		FailImmediately,
		IN  BOOLEAN		ExclusiveLock);

NTSTATUS SERVICECALL
NtLockVirtualMemory(HANDLE ProcessHandle,
		PVOID  *BaseAddress,
		PSIZE_T NumberOfBytesToLock,
		ULONG  MapType);

/* 80 */
NTSTATUS SERVICECALL
NtMakePermanentObject(IN HANDLE ObjectHandle);

NTSTATUS SERVICECALL
NtMakeTemporaryObject(IN HANDLE ObjectHandle);

#if 0
NTSTATUS SERVICECALL
NtMapViewOfSection(IN     HANDLE 		SectionHandle,
		IN     HANDLE 		ProcessHandle,
		IN OUT PVOID* 		BaseAddress  OPTIONAL,
		IN     ULONG 		ZeroBits  OPTIONAL,
		IN     ULONG 		CommitSize,
		IN OUT PLARGE_INTEGER	SectionOffset  OPTIONAL,
		IN OUT PULONG 		ViewSize,
		IN     SECTION_INHERIT 	InheritDisposition,
		IN     ULONG 		AllocationType  OPTIONAL,
		IN     ULONG 		Protect);
#endif

NTSTATUS SERVICECALL
NtNotifyChangeDirectoryFile(IN  HANDLE 			FileHandle,
		IN  HANDLE 			Event OPTIONAL,
		IN  PIO_APC_ROUTINE 	ApcRoutine OPTIONAL,
		IN  PVOID 			ApcContext OPTIONAL,
		OUT PIO_STATUS_BLOCK 	IoStatusBlock,
		OUT PVOID 			Buffer,
		IN  ULONG 			BufferSize,
		IN  ULONG 			CompletionFilter,
		IN  BOOLEAN 		WatchTree);

NTSTATUS SERVICECALL
NtNotifyChangeKey (IN  HANDLE 		KeyHandle,
		IN  HANDLE 		Event,
		IN  PIO_APC_ROUTINE  ApcRoutine OPTIONAL,
		IN  PVOID ApcContext OPTIONAL,
		OUT PIO_STATUS_BLOCK IoStatusBlock,
		IN  ULONG 		CompletionFilter,
		IN  BOOLEAN 		WatchSubtree,
		OUT PVOID 		Buffer,
		IN  ULONG 		Length,
		IN  BOOLEAN 		Asynchronous);

/* 85 */
NTSTATUS SERVICECALL
NtOpenDirectoryObject (OUT PHANDLE 		DirectoryHandle,
		IN  ACCESS_MASK 		DesiredAccess,
		IN  POBJECT_ATTRIBUTES 	ObjectAttributes);

#if 0
NTSTATUS SERVICECALL
NtOpenEvent(OUT PHANDLE 		EventHandle,
		IN  ACCESS_MASK 		DesiredAccess,
		IN  POBJECT_ATTRIBUTES 	ObjectAttributes);
#endif

NTSTATUS SERVICECALL
NtOpenEventPair(OUT PHANDLE 		EventPairHandle,
		IN  ACCESS_MASK 	DesiredAccess,
		IN  POBJECT_ATTRIBUTES 	ObjectAttributes);

#if 0
NTSTATUS SERVICECALL
NtOpenFile(PHANDLE 		FileHandle,
		ACCESS_MASK 		DesiredAccess,
		POBJECT_ATTRIBUTES 	ObjectAttributes,
		PIO_STATUS_BLOCK 	IoStatusBlock,
		ULONG 		ShareAccess,
		ULONG 		OpenOptions);
#endif

NTSTATUS SERVICECALL
NtOpenIoCompletion(OUT PHANDLE 			IoCompletionHandle,
		IN  ACCESS_MASK 		DesiredAccess,
		IN  POBJECT_ATTRIBUTES 	ObjectAttributes);

/* 90 */
NTSTATUS SERVICECALL
NtOpenJobObject (PHANDLE 		JobHandle,
		ACCESS_MASK 		DesiredAccess,
		POBJECT_ATTRIBUTES 	ObjectAttributes);

NTSTATUS SERVICECALL
NtOpenKey(OUT PHANDLE 		 KeyHandle,
		IN  ACCESS_MASK 	 DesiredAccess,
		IN  POBJECT_ATTRIBUTES ObjectAttributes);

#if 0
NTSTATUS SERVICECALL
NtOpenMutant(OUT PHANDLE 		MutantHandle,
		IN  ACCESS_MASK 		DesiredAccess,
		IN  POBJECT_ATTRIBUTES 	ObjectAttributes);
#endif

NTSTATUS SERVICECALL
NtOpenObjectAuditAlarm(IN  PUNICODE_STRING 	SubsystemName,
		IN  PVOID 		HandleId,
		IN  PUNICODE_STRING 	ObjectTypeName,
		IN  PUNICODE_STRING 	ObjectName,
		IN  PSECURITY_DESCRIPTOR SecurityDescriptor,
		IN  HANDLE 		ClientToken,
		IN  ULONG 		DesiredAccess,
		IN  ULONG 		GrantedAccess,
		IN  PPRIVILEGE_SET 	Privileges,
		IN  BOOLEAN 		ObjectCreation,
		IN  BOOLEAN 		AccessGranted,
		OUT PBOOLEAN 		GenerateOnClose);

NTSTATUS SERVICECALL
NtOpenProcess(OUT PHANDLE 		ProcessHandle,
		IN  ACCESS_MASK 		DesiredAccess,
		IN  POBJECT_ATTRIBUTES 	ObjectAttributes,
		IN  PCLIENT_ID 		ClientId);

/* 95 */
NTSTATUS SERVICECALL
NtOpenProcessToken(IN  HANDLE	   ProcessHandle,
		IN  ACCESS_MASK DesiredAccess,
		OUT PHANDLE     TokenHandle);

NTSTATUS SERVICECALL
NtOpenProcessTokenEx(IN  HANDLE 	ProcessHandle,
		IN  ACCESS_MASK 	DesiredAccess,
		IN  ULONG 		HandleAttributes,
		OUT PHANDLE 	TokenHandle);

NTSTATUS SERVICECALL
NtOpenSection(PHANDLE 		 SectionHandle,
		ACCESS_MASK  	 DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes);

#if 0
NTSTATUS SERVICECALL
NtOpenSemaphore(OUT PHANDLE 		SemaphoreHandle,
		IN  ACCESS_MASK 	DesiredAccess,
		IN  POBJECT_ATTRIBUTES  ObjectAttributes);
#endif

NTSTATUS SERVICECALL
NtOpenSymbolicLinkObject(OUT PHANDLE		 LinkHandle,
		IN  ACCESS_MASK	 DesiredAccess,
		IN  POBJECT_ATTRIBUTES  ObjectAttributes);

/* 100 */
NTSTATUS SERVICECALL
NtOpenThread(OUT PHANDLE 		ThreadHandle,
		IN  ACCESS_MASK 		DesiredAccess,
		IN  POBJECT_ATTRIBUTES 	ObjectAttributes  OPTIONAL,
		IN  PCLIENT_ID		ClientId  OPTIONAL);

NTSTATUS SERVICECALL
NtOpenThreadToken(IN  HANDLE 		ThreadHandle,
		IN  ACCESS_MASK 	DesiredAccess,
		IN  BOOLEAN 		OpenAsSelf,
		OUT PHANDLE 		TokenHandle);

NTSTATUS SERVICECALL
NtOpenThreadTokenEx(IN  HANDLE 		ThreadHandle,
		IN  ACCESS_MASK 	DesiredAccess,
		IN  BOOLEAN 	OpenAsSelf,
		IN  ULONG 		HandleAttributes,
		OUT PHANDLE 	TokenHandle);

NTSTATUS SERVICECALL
NtOpenTimer(OUT PHANDLE 		TimerHandle,
		IN  ACCESS_MASK 		DesiredAccess,
		IN  POBJECT_ATTRIBUTES 	ObjectAttributes);

NTSTATUS SERVICECALL
NtPlugPlayControl(IN     PLUGPLAY_CONTROL_CLASS PlugPlayControlClass,
		IN OUT PVOID 			Buffer,
		IN     ULONG 			BufferLength);

/* 105 */
NTSTATUS SERVICECALL
NtPowerInformation(IN  POWER_INFORMATION_LEVEL  PowerInformationLevel,
		IN  PVOID 			InputBuffer  OPTIONAL,
		IN  ULONG 			InputBufferLength,
		OUT PVOID 			OutputBuffer  OPTIONAL,
		IN  ULONG 			OutputBufferLength);

NTSTATUS SERVICECALL
NtPrivilegeCheck (IN HANDLE 		ClientToken,
		IN PPRIVILEGE_SET 	RequiredPrivileges,
		IN 			PBOOLEAN Result);

NTSTATUS SERVICECALL
NtPrivilegedServiceAuditAlarm(IN PUNICODE_STRING SubsystemName,
		IN PUNICODE_STRING ServiceName,
		IN HANDLE 	 ClientToken,
		IN PPRIVILEGE_SET  Privileges,
		IN BOOLEAN 	 AccessGranted);

NTSTATUS SERVICECALL
NtPrivilegeObjectAuditAlarm(IN PUNICODE_STRING  SubsystemName,
		IN PVOID 		HandleId,
		IN HANDLE 		ClientToken,
		IN ULONG 		DesiredAccess,
		IN PPRIVILEGE_SET 	Privileges,
		IN BOOLEAN 		AccessGranted);

NTSTATUS SERVICECALL
NtProtectVirtualMemory(IN     HANDLE ProcessHandle,
		IN OUT PVOID  *UnsafeBaseAddress,
		IN OUT ULONG  *UnsafeNumberOfBytesToProtect,
		IN     ULONG  NewAccessProtection,
		OUT    PULONG UnsafeOldAccessProtection);

/* 110 */
#if 0
NTSTATUS SERVICECALL
NtPulseEvent(IN  HANDLE EventHandle,
		OUT PLONG  PreviousState OPTIONAL);
#endif

NTSTATUS SERVICECALL
NtQueryInformationAtom(RTL_ATOM 		Atom,
		ATOM_INFORMATION_CLASS   AtomInformationClass,
		PVOID 			AtomInformation,
		ULONG 			AtomInformationLength,
		PULONG 			ReturnLength);

NTSTATUS SERVICECALL
NtQueryAttributesFile(IN  POBJECT_ATTRIBUTES 	  ObjectAttributes,
		OUT PFILE_BASIC_INFORMATION FileInformation);

NTSTATUS SERVICECALL
NtQueryBootEntryOrder(IN ULONG Unknown1,
		IN ULONG Unknown2);

NTSTATUS SERVICECALL
NtQueryBootOptions(IN ULONG Unknown1,
		IN ULONG Unknown2);

/* 115 */
NTSTATUS SERVICECALL
NtQueryDefaultLocale(IN  BOOLEAN UserProfile,
		OUT PLCID   DefaultLocaleId);

NTSTATUS SERVICECALL
NtQueryDefaultUILanguage(OUT PLANGID LanguageId);

NTSTATUS SERVICECALL
NtQueryDirectoryFile(IN  HANDLE 		FileHandle,
		IN  HANDLE 		PEvent OPTIONAL,
		IN  PIO_APC_ROUTINE 	ApcRoutine OPTIONAL,
		IN  PVOID 			ApcContext OPTIONAL,
		OUT PIO_STATUS_BLOCK 	IoStatusBlock,
		OUT PVOID 			FileInformation,
		IN  ULONG 			Length,
		IN  FILE_INFORMATION_CLASS FileInformationClass,
		IN  BOOLEAN 		ReturnSingleEntry,
		IN  PUNICODE_STRING 	FileName OPTIONAL,
		IN  BOOLEAN 		RestartScan);

NTSTATUS SERVICECALL
NtQueryDirectoryObject (IN     HANDLE  DirectoryHandle,
		OUT    PVOID   Buffer,
		IN     ULONG   BufferLength,
		IN     BOOLEAN ReturnSingleEntry,
		IN     BOOLEAN RestartScan,
		IN OUT PULONG  Context,
		OUT    PULONG  ReturnLength OPTIONAL);

NTSTATUS SERVICECALL
NtQueryEaFile(IN  HANDLE 		FileHandle,
		OUT PIO_STATUS_BLOCK	IoStatusBlock,
		OUT PVOID 		Buffer,
		IN  ULONG 		Length,
		IN  BOOLEAN 		ReturnSingleEntry,
		IN  PVOID 		EaList OPTIONAL,
		IN  ULONG 		EaListLength,
		IN  PULONG 		EaIndex OPTIONAL,
		IN  BOOLEAN 		RestartScan);

/* 120 */
NTSTATUS SERVICECALL
NtQueryEvent(IN  HANDLE 		 EventHandle,
		IN  EVENT_INFORMATION_CLASS EventInformationClass,
		OUT PVOID 			 EventInformation,
		IN  ULONG 			 EventInformationLength,
		OUT PULONG 		 ReturnLength  OPTIONAL);

NTSTATUS SERVICECALL
NtQueryFullAttributesFile(IN  POBJECT_ATTRIBUTES 		ObjectAttributes,
		OUT PFILE_NETWORK_OPEN_INFORMATION 	FileInformation);

#if 0
NTSTATUS SERVICECALL
NtQueryInformationFile(HANDLE 			FileHandle,
		PIO_STATUS_BLOCK 	IoStatusBlock,
		PVOID 			FileInformation,
		ULONG 			Length,
		FILE_INFORMATION_CLASS 	FileInformationClass);
#endif

NTSTATUS SERVICECALL
NtQueryInformationJobObject (HANDLE 		JobHandle,
		JOBOBJECTINFOCLASS JobInformationClass,
		PVOID 		JobInformation,
		ULONG 		JobInformationLength,
		PULONG 		ReturnLength);

NTSTATUS SERVICECALL
NtQueryInformationPort (IN  HANDLE			PortHandle,
		IN  PORT_INFORMATION_CLASS	PortInformationClass,
		OUT PVOID			PortInformation,
		IN  ULONG			PortInformationLength,
		OUT PULONG			ReturnLength);

/* 125 */
NTSTATUS SERVICECALL
NtQueryInformationProcess(IN  HANDLE 		ProcessHandle,
		IN  PROCESSINFOCLASS  ProcessInformationClass,
		OUT PVOID 		ProcessInformation,
		IN  ULONG 		ProcessInformationLength,
		OUT PULONG 		ReturnLength  OPTIONAL);

NTSTATUS SERVICECALL
NtQueryInformationThread (IN  HANDLE		ThreadHandle,
		IN  THREADINFOCLASS	ThreadInformationClass,
		OUT PVOID		ThreadInformation,
		IN  ULONG		ThreadInformationLength,
		OUT PULONG		ReturnLength  OPTIONAL);

NTSTATUS SERVICECALL
NtQueryInformationToken(IN  HANDLE 			TokenHandle,
		IN  TOKEN_INFORMATION_CLASS 	TokenInformationClass,
		OUT PVOID 			TokenInformation,
		IN  ULONG 			TokenInformationLength,
		OUT PULONG 			ReturnLength);

NTSTATUS SERVICECALL
NtQueryInstallUILanguage(OUT PLANGID LanguageId);

NTSTATUS SERVICECALL
NtQueryIntervalProfile(IN  KPROFILE_SOURCE ProfileSource,
		OUT PULONG 	   Interval);

/* 130 */
NTSTATUS SERVICECALL
NtQueryIoCompletion(IN  HANDLE 				IoCompletionHandle,
		IN  IO_COMPLETION_INFORMATION_CLASS IoCompletionInformationClass,
		OUT PVOID 				IoCompletionInformation,
		IN  ULONG 				IoCompletionInformationLength,
		OUT PULONG 				ResultLength OPTIONAL);

NTSTATUS SERVICECALL
NtQueryKey(IN  HANDLE 			KeyHandle,
		IN  KEY_INFORMATION_CLASS 	KeyInformationClass,
		OUT PVOID 			KeyInformation,
		IN  ULONG 			Length,
		OUT PULONG 			ResultLength);

NTSTATUS SERVICECALL
NtQueryMultipleValueKey (IN      HANDLE 		KeyHandle,
		IN  OUT PKEY_VALUE_ENTRY 	ValueList,
		IN      ULONG 			NumberOfValues,
		OUT     PVOID 			Buffer,
		IN  OUT PULONG 		Length,
		OUT     PULONG 		ReturnLength);

NTSTATUS SERVICECALL
NtQueryMutant(IN  HANDLE 			MutantHandle,
		IN  MUTANT_INFORMATION_CLASS 	MutantInformationClass,
		OUT PVOID 			MutantInformation,
		IN  ULONG 			MutantInformationLength,
		OUT PULONG			ResultLength  OPTIONAL);

NTSTATUS SERVICECALL
NtQueryObject (IN  HANDLE 			ObjectHandle,
		IN  OBJECT_INFORMATION_CLASS 	ObjectInformationClass,
		OUT PVOID 			ObjectInformation,
		IN  ULONG 			Length,
		OUT PULONG 			ResultLength  OPTIONAL);

/* 135 */
NTSTATUS SERVICECALL
NtQueryPerformanceCounter(OUT PLARGE_INTEGER PerformanceCounter,
		OUT PLARGE_INTEGER PerformanceFrequency OPTIONAL);

NTSTATUS SERVICECALL
NtQueryQuotaInformationFile(IN  HANDLE		 FileHandle,
		OUT PIO_STATUS_BLOCK IoStatusBlock,
		OUT PVOID		 Buffer,
		IN  ULONG		 Length,
		IN  BOOLEAN		 ReturnSingleEntry,
		IN  PVOID	 SidList OPTIONAL,
		IN  ULONG		 SidListLength,
		IN  PSID 		 StartSid OPTIONAL,
		IN  BOOLEAN 	 RestartScan);

NTSTATUS SERVICECALL
NtQuerySection(IN  HANDLE			SectionHandle,
		IN  SECTION_INFORMATION_CLASS 	SectionInformationClass,
		OUT PVOID 			SectionInformation,
		IN  ULONG 			SectionInformationLength,
		OUT PULONG 			ResultLength  OPTIONAL);

NTSTATUS SERVICECALL
NtQuerySecurityObject(IN  HANDLE 		Handle,
		IN  SECURITY_INFORMATION  SecurityInformation,
		OUT PSECURITY_DESCRIPTOR  SecurityDescriptor,
		IN  ULONG 		Length,
		OUT PULONG 		ResultLength);

NTSTATUS SERVICECALL
NtQuerySemaphore(IN  HANDLE 			 SemaphoreHandle,
		IN  SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass,
		OUT PVOID			 SemaphoreInformation,
		IN  ULONG			 SemaphoreInformationLength,
		OUT PULONG			 ReturnLength  OPTIONAL);

/* 140 */
NTSTATUS SERVICECALL
NtQuerySymbolicLinkObject(IN  HANDLE		LinkHandle,
		OUT PUNICODE_STRING	LinkTarget,
		OUT PULONG 		ResultLength  OPTIONAL);

NTSTATUS SERVICECALL
NtQuerySystemEnvironmentValue (IN     PUNICODE_STRING	VariableName,
		OUT    PWSTR		ValueBuffer,
		IN     ULONG		ValueBufferLength,
		IN OUT PULONG		ReturnLength  OPTIONAL);

NTSTATUS SERVICECALL
NtQuerySystemInformation (IN  SYSTEM_INFORMATION_CLASS  SystemInformationClass,
		OUT PVOID 			SystemInformation,
		IN  ULONG 			Length,
		OUT PULONG 			UnsafeResultLength);

NTSTATUS SERVICECALL
NtQuerySystemTime(OUT PLARGE_INTEGER SystemTime);

NTSTATUS SERVICECALL
NtQueryTimer(IN  HANDLE 		 TimerHandle,
		IN  TIMER_INFORMATION_CLASS TimerInformationClass,
		OUT PVOID			 TimerInformation,
		IN  ULONG			 TimerInformationLength,
		OUT PULONG			 ReturnLength  OPTIONAL);

/* 145 */
NTSTATUS SERVICECALL
NtQueryTimerResolution(OUT PULONG MinimumResolution,
		OUT PULONG MaximumResolution,
		OUT PULONG ActualResolution);

NTSTATUS SERVICECALL
NtQueryValueKey(IN  HANDLE			KeyHandle,
		IN  PUNICODE_STRING 		ValueName,
		IN  KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
		OUT PVOID 			KeyValueInformation,
		IN  ULONG 			Length,
		OUT PULONG 			ResultLength);

NTSTATUS SERVICECALL
NtQueryVirtualMemory (IN  HANDLE		   ProcessHandle,
		IN  PVOID			   Address,
		IN  LONG             VirtualMemoryInformationClass,
		OUT PVOID			   VirtualMemoryInformation,
		IN  ULONG			   Length,
		OUT PULONG		   UnsafeResultLength);

NTSTATUS SERVICECALL
NtQueryVolumeInformationFile(IN  HANDLE 		FileHandle,
		OUT PIO_STATUS_BLOCK 	IoStatusBlock,
		OUT PVOID 			FsInformation,
		IN  ULONG 			Length,
		IN  FS_INFORMATION_CLASS 	FsInformationClass);

NTSTATUS SERVICECALL
NtQueueApcThread(HANDLE 	  ThreadHandle,
		PKNORMAL_ROUTINE ApcRoutine,
		PVOID		  NormalContext,
		PVOID		  SystemArgument1,
		PVOID		  SystemArgument2);

/* 150 */
NTSTATUS SERVICECALL
NtRaiseException(IN PEXCEPTION_RECORD 	ExceptionRecord,
		IN PCONTEXT		Context,
		IN BOOLEAN 		SearchFrames);

NTSTATUS SERVICECALL
NtRaiseHardError(IN  NTSTATUS 	ErrorStatus,
		IN  ULONG 	NumberOfParameters,
		IN  ULONG 	UnicodeStringParameterMask,
		IN  PULONG_PTR Parameters,
		IN  ULONG 	ValidResponseOptions,
		OUT PULONG 	Response);

#if 0
NTSTATUS SERVICECALL
NtReadFile(IN  HANDLE		 FileHandle,
		IN  HANDLE		 Event OPTIONAL,
		IN  PIO_APC_ROUTINE	 ApcRoutine OPTIONAL,
		IN  PVOID 		 ApcContext OPTIONAL,
		OUT			 PIO_STATUS_BLOCK IoStatusBlock,
		OUT			 PVOID Buffer,
		IN 			 ULONG Length,
		IN 			 PLARGE_INTEGER ByteOffset OPTIONAL, 
		IN 			 PULONG Key OPTIONAL);
#endif

NTSTATUS SERVICECALL
NtReadFileScatter(IN  HANDLE			FileHandle,
		IN  HANDLE			Event OPTIONAL,
		IN  PIO_APC_ROUTINE 		UserApcRoutine OPTIONAL,
		IN  PVOID			UserApcContext OPTIONAL,
		OUT PIO_STATUS_BLOCK 		UserIoStatusBlock,
		IN  FILE_SEGMENT_ELEMENT 	BufferDescription [],
		IN  ULONG 			BufferLength,
		IN  PLARGE_INTEGER  		ByteOffset,
		IN  PULONG 			Key OPTIONAL);

NTSTATUS SERVICECALL
NtReadRequestData (HANDLE		PortHandle,
		PPORT_MESSAGE	Message,
		ULONG		Index,
		PVOID		Buffer,
		ULONG		BufferLength,
		PULONG		Returnlength);

/* 155 */
NTSTATUS SERVICECALL
NtReadVirtualMemory(IN  HANDLE ProcessHandle,
		IN  PVOID  BaseAddress,
		OUT PVOID  Buffer,
		IN  ULONG  NumberOfBytesToRead,
		OUT PULONG NumberOfBytesRead OPTIONAL);

NTSTATUS SERVICECALL
NtRegisterThreadTerminatePort(HANDLE PortHandle);

#if 0
NTSTATUS SERVICECALL
NtReleaseMutant(IN HANDLE MutantHandle,
		IN PLONG  PreviousCount  OPTIONAL);

NTSTATUS SERVICECALL
NtReleaseSemaphore(IN  HANDLE SemaphoreHandle,
		IN  LONG   ReleaseCount,
		OUT PLONG  PreviousCount  OPTIONAL);
#endif

NTSTATUS SERVICECALL
NtRemoveIoCompletion(IN  HANDLE		  IoCompletionHandle,
		OUT PVOID 		  *CompletionKey,
		OUT PVOID 		  *CompletionContext,
		OUT PIO_STATUS_BLOCK IoStatusBlock,
		IN  PLARGE_INTEGER   Timeout OPTIONAL);

/* 160  */
NTSTATUS SERVICECALL
NtReplaceKey (IN POBJECT_ATTRIBUTES ObjectAttributes,
		IN HANDLE 	    Key,
		IN POBJECT_ATTRIBUTES ReplacedObjectAttributes);

NTSTATUS SERVICECALL
NtReplyPort (IN	HANDLE		PortHandle,
		IN	PPORT_MESSAGE	LpcReply);

NTSTATUS SERVICECALL
NtReplyWaitReceivePort(IN  HANDLE	 PortHandle,
		OUT PVOID 	 *PortContext OPTIONAL,
		IN  PPORT_MESSAGE ReplyMessage OPTIONAL,
		OUT PPORT_MESSAGE ReceiveMessage);

NTSTATUS SERVICECALL
NtReplyWaitReplyPort (HANDLE		PortHandle,
		PPORT_MESSAGE	ReplyMessage);

NTSTATUS SERVICECALL 
NtRequestPort (IN HANDLE	PortHandle,
		IN PPORT_MESSAGE	LpcMessage);

/* 165 */
NTSTATUS SERVICECALL
NtRequestWaitReplyPort (IN HANDLE        PortHandle,
		PPORT_MESSAGE UnsafeLpcRequest,
		PPORT_MESSAGE UnsafeLpcReply);

#if 0
NTSTATUS SERVICECALL
NtResetEvent(IN  HANDLE EventHandle,
		OUT PLONG  PreviousState OPTIONAL);
#endif

NTSTATUS SERVICECALL
NtRestoreKey (IN HANDLE KeyHandle,
		IN HANDLE FileHandle,
		IN ULONG  RestoreFlags);

NTSTATUS SERVICECALL
NtResumeThread(IN HANDLE ThreadHandle,
		IN PULONG SuspendCount  OPTIONAL);

NTSTATUS SERVICECALL
NtSaveKey (IN HANDLE KeyHandle,
		IN HANDLE FileHandle);

/* 170 */
NTSTATUS SERVICECALL
NtSaveKeyEx(IN HANDLE KeyHandle,
		IN HANDLE FileHandle,
		IN ULONG  Flags); /* REG_STANDARD_FORMAT, etc.. */

NTSTATUS SERVICECALL
NtSetBootEntryOrder(IN ULONG Unknown1,
		IN ULONG Unknown2);

NTSTATUS SERVICECALL
NtSetBootOptions(ULONG Unknown1,
		ULONG Unknown2);

NTSTATUS SERVICECALL
NtSetIoCompletion(IN HANDLE   IoCompletionPortHandle,
		IN PVOID    CompletionKey,
		IN PVOID    CompletionContext,
		IN NTSTATUS CompletionStatus,
		IN ULONG    CompletionInformation);

NTSTATUS SERVICECALL
NtSetContextThread(IN HANDLE   ThreadHandle,
		IN PCONTEXT ThreadContext);

/* 175 */
NTSTATUS SERVICECALL
NtSetDefaultHardErrorPort(IN HANDLE PortHandle);

NTSTATUS SERVICECALL
NtSetDefaultLocale(IN BOOLEAN UserProfile,
		IN LCID    DefaultLocaleId);

NTSTATUS SERVICECALL
NtSetDefaultUILanguage(IN LANGID LanguageId);

NTSTATUS SERVICECALL
NtSetEaFile(IN HANDLE 		FileHandle,
		IN PIO_STATUS_BLOCK IoStatusBlock,
		IN PVOID 		EaBuffer,
		IN ULONG 		EaBufferSize);

#if 0
NTSTATUS SERVICECALL
NtSetEvent(IN  HANDLE EventHandle,
		OUT PLONG  PreviousState  OPTIONAL);
#endif

/* 180 */
NTSTATUS SERVICECALL
NtSetHighEventPair(IN HANDLE EventPairHandle);

NTSTATUS SERVICECALL
NtSetHighWaitLowEventPair(IN HANDLE EventPairHandle);

#if 0
NTSTATUS SERVICECALL
NtSetInformationFile(HANDLE			FileHandle,
		PIO_STATUS_BLOCK		IoStatusBlock,
		PVOID			FileInformation,
		ULONG 			Length,
		FILE_INFORMATION_CLASS 	FileInformationClass);
#endif

NTSTATUS SERVICECALL
NtSetInformationKey (IN HANDLE 			  KeyHandle,
		IN KEY_SET_INFORMATION_CLASS KeyInformationClass,
		IN PVOID			  KeyInformation,
		IN ULONG			  KeyInformationLength);

NTSTATUS SERVICECALL
NtSetInformationJobObject (HANDLE 		JobHandle,
		JOBOBJECTINFOCLASS 	JobInformationClass,
		PVOID 		JobInformation,
		ULONG 		JobInformationLength);

/* 185 */
NTSTATUS SERVICECALL
NtSetInformationObject (IN HANDLE 			ObjectHandle,
		IN OBJECT_INFORMATION_CLASS 	ObjectInformationClass,
		IN PVOID 			ObjectInformation,
		IN ULONG 			Length);

NTSTATUS SERVICECALL
NtSetInformationProcess(IN HANDLE 		ProcessHandle,
		IN PROCESSINFOCLASS 	ProcessInformationClass,
		IN PVOID 		ProcessInformation,
		IN ULONG 		ProcessInformationLength);

NTSTATUS SERVICECALL
NtSetInformationThread (IN HANDLE 		ThreadHandle,
		IN THREADINFOCLASS 	ThreadInformationClass,
		IN PVOID 		ThreadInformation,
		IN ULONG 		ThreadInformationLength);

NTSTATUS SERVICECALL
NtSetInformationToken(IN  HANDLE 		  TokenHandle,
		IN  TOKEN_INFORMATION_CLASS TokenInformationClass,
		OUT PVOID			  TokenInformation,
		IN  ULONG			  TokenInformationLength);

NTSTATUS SERVICECALL
NtSetIntervalProfile(IN ULONG 		Interval,
		IN KPROFILE_SOURCE Source);

/* 190 */
NTSTATUS SERVICECALL
NtSetLdtEntries (ULONG 		Selector1,
		LDT_ENTRY 	LdtEntry1,
		ULONG 		Selector2,
		LDT_ENTRY 	LdtEntry2);

NTSTATUS SERVICECALL
NtSetLowEventPair(IN HANDLE EventPairHandle);

NTSTATUS SERVICECALL
NtSetLowWaitHighEventPair(IN HANDLE EventPairHandle);

NTSTATUS SERVICECALL
NtSetQuotaInformationFile(HANDLE 		FileHandle,
		PIO_STATUS_BLOCK 	IoStatusBlock,
		PVOID 		Buffer,
		ULONG 		BufferLength);

NTSTATUS SERVICECALL
NtSetSecurityObject(IN HANDLE 		    Handle,
		IN SECURITY_INFORMATION SecurityInformation,
		IN PSECURITY_DESCRIPTOR SecurityDescriptor);

/* 195 */
NTSTATUS SERVICECALL
NtSetSystemEnvironmentValue (IN	PUNICODE_STRING	VariableName,
		IN	PUNICODE_STRING	Value);

NTSTATUS SERVICECALL
NtSetSystemInformation (IN SYSTEM_INFORMATION_CLASS	SystemInformationClass,
		IN PVOID			SystemInformation,
		IN ULONG			SystemInformationLength);

NTSTATUS SERVICECALL
NtSetSystemPowerState(IN POWER_ACTION 		SystemAction,
		IN SYSTEM_POWER_STATE 	MinSystemState,
		IN ULONG 			Flags);

NTSTATUS SERVICECALL
NtSetSystemTime(IN  PLARGE_INTEGER SystemTime,
		OUT PLARGE_INTEGER PreviousTime OPTIONAL);

NTSTATUS SERVICECALL
NtSetTimer(IN  HANDLE 			TimerHandle,
		IN  PLARGE_INTEGER 		DueTime,
		IN  PTIMER_APC_ROUTINE 	TimerApcRoutine OPTIONAL,
		IN  PVOID 			TimerContext OPTIONAL,
		IN  BOOLEAN 			WakeTimer,
		IN  LONG 			Period OPTIONAL,
		OUT PBOOLEAN 		PreviousState OPTIONAL);

/* 200 */
NTSTATUS SERVICECALL
NtSetTimerResolution(IN  ULONG   DesiredResolution,
		IN  BOOLEAN SetResolution,
		OUT PULONG  CurrentResolution);

NTSTATUS SERVICECALL
NtSetUuidSeed(IN PUCHAR Seed);

NTSTATUS SERVICECALL
NtSetValueKey(IN HANDLE 	 KeyHandle,
		IN PUNICODE_STRING ValueName,
		IN ULONG		 TitleIndex,
		IN ULONG		 Type,
		IN PVOID		 Data,
		IN ULONG		 DataSize);

NTSTATUS SERVICECALL
NtSetVolumeInformationFile(IN  HANDLE 			FileHandle,
		OUT PIO_STATUS_BLOCK 	IoStatusBlock,
		IN  PVOID 			FsInformation,
		IN  ULONG 			Length,
		IN  FS_INFORMATION_CLASS 	FsInformationClass);

NTSTATUS SERVICECALL
NtShutdownSystem(IN SHUTDOWN_ACTION Action);

/* 205*/
NTSTATUS SERVICECALL
NtSignalAndWaitForSingleObject(IN HANDLE 	 ObjectHandleToSignal,
		IN HANDLE 	 WaitableObjectHandle,
		IN BOOLEAN	  Alertable,
		IN PLARGE_INTEGER TimeOut  OPTIONAL);

NTSTATUS SERVICECALL
NtStartProfile(IN HANDLE ProfileHandle);

NTSTATUS SERVICECALL
NtStopProfile(IN HANDLE ProfileHandle);

NTSTATUS SERVICECALL
NtSuspendThread(IN HANDLE ThreadHandle,
		IN PULONG PreviousSuspendCount  OPTIONAL);

NTSTATUS SERVICECALL
NtSystemDebugControl(DEBUG_CONTROL_CODE ControlCode,
		PVOID 		InputBuffer,
		ULONG 		InputBufferLength,
		PVOID 		OutputBuffer,
		ULONG 		OutputBufferLength,
		PULONG 		ReturnLength);

/* 210 */
NTSTATUS SERVICECALL
NtTerminateJobObject(HANDLE   JobHandle,
		NTSTATUS ExitStatus);

NTSTATUS SERVICECALL
NtTerminateProcess(IN HANDLE   ProcessHandle  OPTIONAL,
		IN NTSTATUS ExitStatus);

NTSTATUS SERVICECALL
NtTerminateThread(IN HANDLE   ThreadHandle,
		IN NTSTATUS ExitStatus);

NTSTATUS SERVICECALL
NtTestAlert(VOID);

NTSTATUS SERVICECALL
NtTraceEvent(IN ULONG 				TraceHandle,
		IN ULONG 				Flags,
		IN ULONG 				TraceHeaderLength,
		IN struct _EVENT_TRACE_HEADER* 	TraceHeader);

/* 215 */
NTSTATUS SERVICECALL
NtTranslateFilePath(ULONG Unknown1,
		ULONG Unknown2,
		ULONG Unknown3);

NTSTATUS SERVICECALL
NtUnloadDriver(IN PUNICODE_STRING DriverServiceName);

NTSTATUS SERVICECALL
NtUnloadKey (IN POBJECT_ATTRIBUTES KeyObjectAttributes);

NTSTATUS SERVICECALL
NtUnlockFile(IN  HANDLE 	  FileHandle,
		OUT PIO_STATUS_BLOCK IoStatusBlock,
		IN  PLARGE_INTEGER	  ByteOffset,
		IN  PLARGE_INTEGER	  Length,
		OUT ULONG 		  Key OPTIONAL);

NTSTATUS SERVICECALL
NtUnlockVirtualMemory(HANDLE ProcessHandle,
		PVOID  *BaseAddress,
		PSIZE_T NumberOfBytesToUnlock,
		ULONG NumberOfBytesUnlocked OPTIONAL);

/* 220 */
#if 0
NTSTATUS SERVICECALL
NtUnmapViewOfSection (HANDLE ProcessHandle,
		PVOID  BaseAddress);
#endif

NTSTATUS SERVICECALL 
NtVdmControl(ULONG ControlCode,PVOID ControlData);

#if 0
NTSTATUS SERVICECALL
NtWaitForMultipleObjects(IN ULONG 	   ObjectCount,
		IN PHANDLE	   HandleArray,
		IN WAIT_TYPE	   WaitType,
		IN BOOLEAN	   Alertable,
		IN PLARGE_INTEGER TimeOut  OPTIONAL);
#endif

NTSTATUS SERVICECALL
NtWaitForSingleObject(IN HANDLE 	ObjectHandle,
		IN BOOLEAN 	Alertable,
		IN PLARGE_INTEGER TimeOut  OPTIONAL);

NTSTATUS SERVICECALL
NtWaitHighEventPair(IN HANDLE EventPairHandle);

/* 225 */
NTSTATUS SERVICECALL
NtWaitLowEventPair(IN HANDLE EventPairHandle);

#if 0
NTSTATUS SERVICECALL
NtWriteFile (IN  HANDLE 	  FileHandle,
		IN  HANDLE 	  Event OPTIONAL,
		IN  PIO_APC_ROUTINE  ApcRoutine OPTIONAL,
		IN  PVOID 		  ApcContext OPTIONAL,
		OUT PIO_STATUS_BLOCK IoStatusBlock,
		IN  PVOID		  Buffer,
		IN  ULONG		  Length,
		IN  PLARGE_INTEGER   ByteOffset OPTIONAL, 
		IN  PULONG 	  Key OPTIONAL);
#endif

NTSTATUS SERVICECALL
NtWriteFileGather(IN  HANDLE		   FileHandle,
		IN  HANDLE		   Event OPTIONAL,
		IN  PIO_APC_ROUTINE	   UserApcRoutine OPTIONAL,
		IN  PVOID		   UserApcContext OPTIONAL,
		OUT PIO_STATUS_BLOCK	   UserIoStatusBlock,
		IN  FILE_SEGMENT_ELEMENT BufferDescription [],
		IN  ULONG		   BufferLength,
		IN  PLARGE_INTEGER	   ByteOffset,
		IN  PULONG 		   Key OPTIONAL);

NTSTATUS SERVICECALL 
NtWriteRequestData (HANDLE		PortHandle,
		PPORT_MESSAGE	Message,
		ULONG		Index,
		PVOID		Buffer,
		ULONG		BufferLength,
		PULONG		ReturnLength);

NTSTATUS SERVICECALL
NtWriteVirtualMemory(IN  HANDLE ProcessHandle,
		IN  PVOID  BaseAddress,
		IN  PVOID  Buffer,
		IN  ULONG  NumberOfBytesToWrite,
		OUT PULONG NumberOfBytesWritten  OPTIONAL);

/* 230 */
NTSTATUS SERVICECALL
NtW32Call(IN  ULONG  RoutineIndex,
		IN  PVOID  Argument,
		IN  ULONG  ArgumentLength,
		OUT PVOID* Result OPTIONAL,
		OUT PULONG ResultLength OPTIONAL);

NTSTATUS SERVICECALL
NtYieldExecution(VOID);

NTSTATUS SERVICECALL
NtWineService(PSERVER_REQUEST_INFO ReqMsg);

NTSTATUS SERVICECALL
NtCatchApc(int param);

#endif /* CONFIG_UNIFIED_KERNEL */
#endif /* _W32SYSCALL_H */
