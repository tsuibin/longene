/*
 * w32syscall.c
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
 * w32syscall.c: win32 syscall definition	
 * It also includes the W32 syscall function table and other data structures 
 * (from ReactOS)
 * Refered to ReactOS code
 */

#include "w32syscall.h"
#include "file.h"
#include "mutex.h"
#include "section.h"
#include "semaphore.h"
#include "wineserver/lib.h"

#ifdef CONFIG_UNIFIED_KERNEL

extern void debug_gdt(void);

/* 0 */
NTSTATUS SERVICECALL
NtAcceptConnectPort (PHANDLE		ServerPortHandle,
		HANDLE		NamedPortHandle,
		PPORT_MESSAGE	LpcMessage,
		BOOLEAN		AcceptIt,
		PPORT_VIEW		WriteMap,
		PREMOTE_PORT_VIEW	ReadMap)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtAcceptConnectPort);

NTSTATUS SERVICECALL
NtAccessCheck(IN  PSECURITY_DESCRIPTOR	SecurityDescriptor,
		IN  HANDLE 		TokenHandle,
		IN  ACCESS_MASK 		DesiredAccess,
		IN  PGENERIC_MAPPING 	GenericMapping,
		OUT PPRIVILEGE_SET 	PrivilegeSet,
		OUT PULONG 		ReturnLength,
		OUT PACCESS_MASK 		GrantedAccess,
		OUT PNTSTATUS 		AccessStatus)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtAccessCheck);

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
		OUT PBOOLEAN			GenerateOnClose)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtAccessCheckAndAuditAlarm);

NTSTATUS SERVICECALL
NtAddAtom(IN  PWSTR	AtomName,
		IN  ULONG	AtomNameLength,
		OUT PRTL_ATOM	Atom)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtAddAtom);

NTSTATUS SERVICECALL
NtAddBootEntry(IN PUNICODE_STRING EntryName,
		IN PUNICODE_STRING EntryValue)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtAddBootEntry);

/* 5 */
NTSTATUS SERVICECALL
NtAdjustGroupsToken(IN  HANDLE		TokenHandle,
		IN  BOOLEAN		ResetToDefault,
		IN  PTOKEN_GROUPS	NewState,
		IN  ULONG		BufferLength,
		OUT PTOKEN_GROUPS	PreviousState OPTIONAL,
		OUT PULONG		ReturnLength)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtAdjustGroupsToken);

NTSTATUS SERVICECALL
NtAdjustPrivilegesToken (IN  HANDLE		TokenHandle,
		IN  BOOLEAN		DisableAllPrivileges,
		IN  PTOKEN_PRIVILEGES	NewState,
		IN  ULONG		BufferLength,
		OUT PTOKEN_PRIVILEGES	PreviousState OPTIONAL,
		OUT PULONG		ReturnLength OPTIONAL)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtAdjustPrivilegesToken);

#if 0
NTSTATUS SERVICECALL
NtAlertResumeThread(IN  HANDLE	ThreadHandle,
		OUT PULONG	SuspendCount)
{
	return -ENOSYS;
}

NTSTATUS SERVICECALL
NtAlertThread (IN HANDLE ThreadHandle)
{
	return -ENOSYS;
}
#endif

NTSTATUS SERVICECALL
NtAllocateLocallyUniqueId(OUT LUID *LocallyUniqueId)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtAllocateLocallyUniqueId);

/* 10 */
NTSTATUS SERVICECALL
NtAllocateUuids(OUT PULARGE_INTEGER	Time,
		OUT PULONG		Range,
		OUT PULONG		Sequence,
		OUT PUCHAR		Seed)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtAllocateUuids);

#if 0
NTSTATUS SERVICECALL
NtAllocateVirtualMemory(IN     HANDLE	ProcessHandle,
		IN OUT PVOID*	UBaseAddress,
		IN     ULONG	ZeroBits,
		IN OUT PULONG	URegionSize,
		IN     ULONG	AllocationType,
		IN     ULONG	Protect)
{	
	return -ENOSYS;
}
#endif

NTSTATUS SERVICECALL
NtAssignProcessToJobObject(HANDLE JobHandle,
		HANDLE ProcessHandle)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtAssignProcessToJobObject);

NTSTATUS SERVICECALL
NtCallbackReturn (PVOID		Result,
		ULONG		ResultLength,
		NTSTATUS	Status)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtCallbackReturn);

NTSTATUS SERVICECALL
NtCancelIoFile(IN  HANDLE		FileHandle,
		OUT PIO_STATUS_BLOCK	IoStatusBlock)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtCancelIoFile);

/* 15 */
NTSTATUS SERVICECALL
NtCancelTimer(IN  HANDLE	TimerHandle,
		OUT PBOOLEAN	CurrentState OPTIONAL)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtCancelTimer);

#if 0
NTSTATUS SERVICECALL
NtClearEvent(IN HANDLE EventHandle)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtClearEvent);

NTSTATUS SERVICECALL
NtClose(IN HANDLE Handle)
{
	return -ENOSYS;
}
#endif

NTSTATUS SERVICECALL
NtCloseObjectAuditAlarm(IN PUNICODE_STRING	SubsystemName,
		IN PVOID		HandleId,
		IN BOOLEAN		GenerateOnClose)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtCloseObjectAuditAlarm);

NTSTATUS SERVICECALL
NtCompleteConnectPort (HANDLE hServerSideCommPort)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtCompleteConnectPort);

/* 20 */
NTSTATUS SERVICECALL
NtConnectPort (PHANDLE				UnsafeConnectedPortHandle,
		PUNICODE_STRING			PortName,
		PSECURITY_QUALITY_OF_SERVICE	Qos,
		PPORT_VIEW			UnsafeWriteMap,
		PREMOTE_PORT_VIEW		UnsafeReadMap,
		PULONG				UnsafeMaximumMessageSize,
		PVOID				UnsafeConnectData,
		PULONG				UnsafeConnectDataLength)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtConnectPort);

#if 0
NTSTATUS SERVICECALL
NtContinue(IN Pcontext	Context,
		IN BOOLEAN	TestAlert)
{
	return -ENOSYS;
}

NTSTATUS SERVICECALL
NtCreateDirectoryObject (OUT PHANDLE		DirectoryHandle,
		IN ACCESS_MASK		DesiredAccess,
		IN POBJECT_ATTRIBUTES	ObjectAttributes)
{	
	return -ENOSYS;
}

NTSTATUS SERVICECALL
NtCreateEvent(OUT PHANDLE		EventHandle,
		IN  ACCESS_MASK		DesiredAccess,
		IN  POBJECT_ATTRIBUTES	ObjectAttributes  OPTIONAL,
		IN  EVENT_TYPE		EventType,
		IN  BOOLEAN		InitialState)
{
	return -ENOSYS;
}
#endif

NTSTATUS SERVICECALL
NtCreateEventPair(OUT PHANDLE			EventPairHandle,
		IN  ACCESS_MASK		DesiredAccess,
		IN  POBJECT_ATTRIBUTES	ObjectAttributes)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtCreateEventPair);

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
		ULONG		EaLength)
{
	return -ENOSYS;
}
#endif

NTSTATUS SERVICECALL
NtCreateIoCompletion(OUT PHANDLE		IoCompletionHandle,
		IN  ACCESS_MASK		DesiredAccess,
		IN  POBJECT_ATTRIBUTES	ObjectAttributes,
		IN  ULONG			NumberOfConcurrentThreads)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtCreateIoCompletion);

NTSTATUS SERVICECALL
NtCreateJobObject(PHANDLE		JobHandle,
		ACCESS_MASK		DesiredAccess,
		POBJECT_ATTRIBUTES	ObjectAttributes)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtCreateJobObject);

NTSTATUS SERVICECALL
NtCreateKey(OUT PHANDLE			KeyHandle,
		IN  ACCESS_MASK		DesiredAccess,
		IN  POBJECT_ATTRIBUTES	ObjectAttributes,
		IN  ULONG			TitleIndex,
		IN  PUNICODE_STRING		Class,
		IN  ULONG			CreateOptions,
		OUT PULONG			Disposition)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtCreateKey);

NTSTATUS SERVICECALL
NtCreateMailslotFile(OUT PHANDLE		FileHandle,
		IN  ACCESS_MASK		DesiredAccess,
		IN  POBJECT_ATTRIBUTES	ObjectAttributes,
		OUT PIO_STATUS_BLOCK	IoStatusBlock,
		IN  ULONG			CreateOptions,
		IN  ULONG			MailslotQuota,
		IN  ULONG			MaxMessageSize,
		IN  PLARGE_INTEGER		TimeOut)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtCreateMailslotFile);

/* 30 */
#if 0
NTSTATUS SERVICECALL
NtCreateMutant(OUT PHANDLE MutantHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes  OPTIONAL,
		IN BOOLEAN InitialOwner)
{
	return -ENOSYS;
}
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
		PLARGE_INTEGER 		DefaultTimeout)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtCreateNamedPipeFile);

NTSTATUS SERVICECALL
NtCreatePagingFile(IN PUNICODE_STRING 	FileName,
		IN PLARGE_INTEGER 	InitialSize,
		IN PLARGE_INTEGER 	MaximumSize,
		IN ULONG 	Reserved)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtCreatePagingFile);

NTSTATUS SERVICECALL
NtCreatePort (PHANDLE			PortHandle,
		POBJECT_ATTRIBUTES	ObjectAttributes,
		ULONG			MaxConnectInfoLength,
		ULONG			MaxDataLength,
		ULONG			MaxPoolUsage)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtCreatePort);

#if 0
NTSTATUS SERVICECALL
NtCreateProcess(OUT PHANDLE 		ProcessHandle,
		IN  ACCESS_MASK 	DesiredAccess,
		IN  POBJECT_ATTRIBUTES 	ObjectAttributes  OPTIONAL,
		IN  HANDLE 		ParentProcess,
		IN  BOOLEAN 		InheritObjectTable,
		IN  HANDLE 		SectionHandle  OPTIONAL,
		IN  HANDLE 		DebugPort  OPTIONAL,
		IN  HANDLE 		ExceptionPort  OPTIONAL)
{
	return -ENOSYS;
}
#endif

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
		IN  KAFFINITY 		Affinity)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtCreateProfile);

#if 0
NTSTATUS SERVICECALL
NtCreateSection (OUT PHANDLE 		SectionHandle,
		IN  ACCESS_MASK 	DesiredAccess,
		IN  POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
		IN  PLARGE_INTEGER 	MaximumSize OPTIONAL,
		IN  ULONG 		SectionPageProtection OPTIONAL,
		IN  ULONG 		AllocationAttributes,
		IN  HANDLE 		FileHandle OPTIONAL)
{	
	return -ENOSYS;
}

NTSTATUS SERVICECALL
NtCreateSemaphore(OUT PHANDLE 			SemaphoreHandle,
		IN  ACCESS_MASK 		DesiredAccess,
		IN  POBJECT_ATTRIBUTES 	ObjectAttributes  OPTIONAL,
		IN  LONG 			InitialCount,
		IN  LONG			MaximumCount)
{	
	return -ENOSYS;
}

NTSTATUS SERVICECALL
NtCreateSymbolicLinkObject(OUT PHANDLE 			LinkHandle,
		IN  ACCESS_MASK 		DesiredAccess,
		IN  POBJECT_ATTRIBUTES 	ObjectAttributes,
		IN  PUNICODE_STRING 		LinkTarget)
{	
	return -ENOSYS;
}

NTSTATUS SERVICECALL
NtCreateThread(OUT PHANDLE 		ThreadHandle,
		IN  ACCESS_MASK 		DesiredAccess,
		IN  POBJECT_ATTRIBUTES 	ObjectAttributes  OPTIONAL,
		IN  HANDLE 		ProcessHandle,
		OUT PCLIENT_ID 		ClientId,
		IN  PCONTEXT 		ThreadContext,
		IN  PINITIAL_TEB 	InitialTeb,
		IN  BOOLEAN 		CreateSuspended)
{	
	return -ENOSYS;
}
#endif

/* 40 */
NTSTATUS SERVICECALL
NtCreateTimer(OUT PHANDLE 		TimerHandle,
		IN  ACCESS_MASK 		DesiredAccess,
		IN  POBJECT_ATTRIBUTES 	ObjectAttributes OPTIONAL,
		IN  TIMER_TYPE 		TimerType)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtCreateTimer);

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
		IN  PTOKEN_SOURCE 	TokenSource)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtCreateToken);


NTSTATUS SERVICECALL
NtCreateWaitablePort (OUT PHANDLE		PortHandle,
		IN  POBJECT_ATTRIBUTES	ObjectAttributes,
		IN  ULONG			MaxConnectInfoLength,
		IN  ULONG			MaxDataLength,
		IN  ULONG			MaxPoolUsage)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtCreateWaitablePort);

#if 0
NTSTATUS SERVICECALL
NtDelayExecution(IN BOOLEAN Alertable,
		IN PLARGE_INTEGER DelayInterval)
{
	return -ENOSYS;
}
#endif

NTSTATUS SERVICECALL
NtDeleteAtom(IN RTL_ATOM Atom)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtDeleteAtom);

/* 45 */
NTSTATUS SERVICECALL
NtDeleteBootEntry(IN PUNICODE_STRING EntryName,
		IN PUNICODE_STRING EntryValue)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtDeleteBootEntry);


NTSTATUS SERVICECALL
NtDeleteFile(IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtDeleteFile);

NTSTATUS SERVICECALL
NtDeleteKey(IN HANDLE KeyHandle)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtDeleteKey);

NTSTATUS SERVICECALL
NtDeleteObjectAuditAlarm(IN PUNICODE_STRING 	SubsystemName,
		IN PVOID 		HandleId,
		IN BOOLEAN 		GenerateOnClose)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtDeleteObjectAuditAlarm);

NTSTATUS SERVICECALL
NtDeleteValueKey (IN HANDLE 		KeyHandle,
		IN PUNICODE_STRING 	ValueName)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtDeleteValueKey);

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
		IN  ULONG 		OutputBufferLength OPTIONAL)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtDeviceIoControlFile);

NTSTATUS SERVICECALL
NtDisplayString(IN PUNICODE_STRING DisplayString)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtDisplayString);

#if 0
NTSTATUS SERVICECALL
NtDuplicateObject (IN  HANDLE		SourceProcessHandle,
		IN  HANDLE		SourceHandle,
		IN  HANDLE		TargetProcessHandle,
		OUT PHANDLE		TargetHandle  OPTIONAL,
		IN  ACCESS_MASK	DesiredAccess,
		IN  ULONG		InheritHandle,
		IN  ULONG		Options)
{	
	return -ENOSYS;
}
#endif

NTSTATUS SERVICECALL
NtDuplicateToken(IN  HANDLE 		ExistingTokenHandle,
		IN  ACCESS_MASK 	DesiredAccess,
		IN  POBJECT_ATTRIBUTES ObjectAttributes  OPTIONAL,
		IN  BOOLEAN 		EffectiveOnly,
		IN  TOKEN_TYPE 	TokenType,
		OUT PHANDLE 		NewTokenHandle)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtDuplicateToken);

NTSTATUS SERVICECALL
NtEnumerateBootEntries(IN ULONG Unknown1,
		IN ULONG Unknown2)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtEnumerateBootEntries);

/* 55 */
NTSTATUS SERVICECALL
NtEnumerateKey(IN  HANDLE 			KeyHandle,
		IN  ULONG 			Index,
		IN  KEY_INFORMATION_CLASS 	KeyInformationClass,
		OUT PVOID 			KeyInformation,
		IN  ULONG 			Length,
		OUT PULONG 			ResultLength)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtEnumerateKey);

NTSTATUS SERVICECALL
NtEnumerateValueKey(IN  HANDLE 				KeyHandle,
		IN  ULONG 				Index,
		IN  KEY_VALUE_INFORMATION_CLASS 	KeyValueInformationClass,
		OUT PVOID 				KeyValueInformation,
		IN  ULONG 				Length,
		OUT PULONG 				ResultLength)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtEnumerateValueKey);

#if 0
NTSTATUS SERVICECALL
NtExtendSection(IN HANDLE 		SectionHandle,
		IN PLARGE_INTEGER 	NewMaximumSize)
{	
	return -ENOSYS;
}
#endif

NTSTATUS SERVICECALL
NtFindAtom(IN  PWSTR		AtomName,
		IN  ULONG		AtomNameLength,
		OUT PRTL_ATOM	Atom)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtFindAtom);

#if 0
NTSTATUS SERVICECALL
NtFlushBuffersFile(IN  HANDLE 		FileHandle,
		OUT PIO_STATUS_BLOCK IoStatusBlock)
{
	return -ENOSYS;
}
#endif

/* 60 */
NTSTATUS SERVICECALL
NtFlushInstructionCache (IN HANDLE	ProcessHandle,
		IN PVOID	BaseAddress,
		IN ULONG	NumberOfBytesToFlush)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtFlushInstructionCache);

NTSTATUS SERVICECALL
NtFlushKey(IN HANDLE KeyHandle)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtFlushKey);

#if 0
NTSTATUS SERVICECALL
NtFlushVirtualMemory(IN  HANDLE ProcessHandle,
		IN  PVOID  BaseAddress,
		IN  ULONG  NumberOfBytesToFlush,
		OUT PULONG NumberOfBytesFlushed OPTIONAL)
{
	return -ENOSYS;
}
#endif

NTSTATUS SERVICECALL
NtFlushWriteBuffer(VOID)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtFlushWriteBuffer);

#if 0
NTSTATUS SERVICECALL
NtFreeVirtualMemory(IN HANDLE ProcessHandle,
		IN PVOID* PBaseAddress,
		IN PULONG PRegionSize,
		IN ULONG  FreeType)
{	
	return -ENOSYS;
}
#endif

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
		IN  ULONG 		 OutputBufferLength OPTIONAL)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtFsControlFile);

#if 0
NTSTATUS SERVICECALL
NtGetContextThread(IN  HANDLE   ThreadHandle,
		OUT PCONTEXT ThreadContext)
{
	return -ENOSYS;
}
#endif

NTSTATUS SERVICECALL
NtGetPlugPlayEvent(IN  ULONG 			Reserved1,
		IN  ULONG 			Reserved2,
		OUT PPLUGPLAY_EVENT_BLOCK 	Buffer,
		IN  ULONG 			BufferSize)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtGetPlugPlayEvent);

NTSTATUS SERVICECALL
NtGetTickCount(VOID)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtGetTickCount);

NTSTATUS SERVICECALL
NtImpersonateClientOfPort (HANDLE		PortHandle,
		PPORT_MESSAGE	ClientMessage)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtImpersonateClientOfPort);

/* 70 */
NTSTATUS SERVICECALL
NtImpersonateThread(IN HANDLE 				ThreadHandle,
		IN HANDLE 				ThreadToImpersonateHandle,
		IN PSECURITY_QUALITY_OF_SERVICE 	SecurityQualityOfService)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtImpersonateThread);

NTSTATUS SERVICECALL
NtInitializeRegistry (IN BOOLEAN SetUpBoot)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtInitializeRegistry);

NTSTATUS SERVICECALL
NtInitiatePowerAction (IN POWER_ACTION 		SystemAction,
		IN SYSTEM_POWER_STATE 	MinSystemState,
		IN ULONG 		Flags,
		IN BOOLEAN 		Asynchronous)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtInitiatePowerAction);

NTSTATUS SERVICECALL
NtIsProcessInJob (IN HANDLE ProcessHandle,
		IN HANDLE JobHandle OPTIONAL)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtIsProcessInJob);

NTSTATUS SERVICECALL
NtListenPort (IN HANDLE		PortHandle,
		IN PPORT_MESSAGE	ConnectMsg)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtListenPort);

/* 75 */
NTSTATUS SERVICECALL
NtLoadDriver(IN PUNICODE_STRING DriverServiceName)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtLoadDriver);

NTSTATUS SERVICECALL
NtLoadKey (IN POBJECT_ATTRIBUTES KeyObjectAttributes,
		IN POBJECT_ATTRIBUTES FileObjectAttributes)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtLoadKey);


NTSTATUS SERVICECALL
NtLoadKey2 (IN POBJECT_ATTRIBUTES KeyObjectAttributes,
		IN POBJECT_ATTRIBUTES FileObjectAttributes,
		IN ULONG 		  Flags)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtLoadKey2);

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
		IN  BOOLEAN		ExclusiveLock)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtLockFile);

#if 0
NTSTATUS SERVICECALL
NtLockVirtualMemory(HANDLE ProcessHandle,
		PVOID  BaseAddress,
		ULONG  NumberOfBytesToLock,
		PULONG NumberOfBytesLocked)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtLockVirtualMemory);

/* 80 */
NTSTATUS SERVICECALL
NtMakePermanentObject(IN HANDLE ObjectHandle)
{	
	return -ENOSYS;
}

NTSTATUS SERVICECALL
NtMakeTemporaryObject(IN HANDLE ObjectHandle)
{	
	return -ENOSYS;
}

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
		IN     ULONG 		Protect)
{	
	return -ENOSYS;
}
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
		IN  BOOLEAN 		WatchTree)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtNotifyChangeDirectoryFile);

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
		IN  BOOLEAN 		Asynchronous)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtNotifyChangeKey);

/* 85 */
#if 0
NTSTATUS SERVICECALL
NtOpenDirectoryObject (OUT PHANDLE 		DirectoryHandle,
		IN  ACCESS_MASK 		DesiredAccess,
		IN  POBJECT_ATTRIBUTES 	ObjectAttributes)
{	
	return -ENOSYS;
}

NTSTATUS SERVICECALL
NtOpenEvent(OUT PHANDLE 		EventHandle,
		IN  ACCESS_MASK 		DesiredAccess,
		IN  POBJECT_ATTRIBUTES 	ObjectAttributes)
{
	return -ENOSYS;
}
#endif

NTSTATUS SERVICECALL
NtOpenEventPair(OUT PHANDLE 		EventPairHandle,
		IN  ACCESS_MASK 	DesiredAccess,
		IN  POBJECT_ATTRIBUTES 	ObjectAttributes)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtOpenEventPair);

#if 0
NTSTATUS SERVICECALL
NtOpenFile(PHANDLE 		FileHandle,
		ACCESS_MASK 		DesiredAccess,
		POBJECT_ATTRIBUTES 	ObjectAttributes,
		PIO_STATUS_BLOCK 	IoStatusBlock,
		ULONG 		ShareAccess,
		ULONG 		OpenOptions)
{
	return -ENOSYS;
}
#endif

NTSTATUS SERVICECALL
NtOpenIoCompletion(OUT PHANDLE 			IoCompletionHandle,
		IN  ACCESS_MASK 		DesiredAccess,
		IN  POBJECT_ATTRIBUTES 	ObjectAttributes)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtOpenIoCompletion);

/* 90 */
NTSTATUS SERVICECALL
NtOpenJobObject (PHANDLE 		JobHandle,
		ACCESS_MASK 		DesiredAccess,
		POBJECT_ATTRIBUTES 	ObjectAttributes)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtOpenJobObject);

NTSTATUS SERVICECALL
NtOpenKey(OUT PHANDLE 		 KeyHandle,
		IN  ACCESS_MASK 	 DesiredAccess,
		IN  POBJECT_ATTRIBUTES ObjectAttributes)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtOpenKey);

#if 0
NTSTATUS SERVICECALL
NtOpenMutant(OUT PHANDLE 		MutantHandle,
		IN  ACCESS_MASK 		DesiredAccess,
		IN  POBJECT_ATTRIBUTES 	ObjectAttributes)
{
	return -ENOSYS;
}
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
		OUT PBOOLEAN 		GenerateOnClose)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtOpenObjectAuditAlarm);

#if 0
NTSTATUS SERVICECALL
NtOpenProcess(OUT PHANDLE 		ProcessHandle,
		IN  ACCESS_MASK 		DesiredAccess,
		IN  POBJECT_ATTRIBUTES 	ObjectAttributes,
		IN  PCLIENT_ID 		ClientId)
{
	return -ENOSYS;
}

/* 95 */
NTSTATUS SERVICECALL
NtOpenProcessToken(IN  HANDLE	   ProcessHandle,
		IN  ACCESS_MASK DesiredAccess,
		OUT PHANDLE     TokenHandle)
{
	return -ENOSYS;
}

NTSTATUS SERVICECALL
NtOpenProcessTokenEx(IN  HANDLE 	ProcessHandle,
		IN  ACCESS_MASK 	DesiredAccess,
		IN  ULONG 		HandleAttributes,
		OUT PHANDLE 	TokenHandle)
{
	return -ENOSYS;
}

NTSTATUS SERVICECALL
NtOpenSection(PHANDLE 		 SectionHandle,
		ACCESS_MASK  	 DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes)
{	
	return -ENOSYS;
}

NTSTATUS SERVICECALL
NtOpenSemaphore(OUT PHANDLE 		SemaphoreHandle,
		IN  ACCESS_MASK 	DesiredAccess,
		IN  POBJECT_ATTRIBUTES  ObjectAttributes)
{	
	return -ENOSYS;
}

NTSTATUS SERVICECALL
NtOpenSymbolicLinkObject(OUT PHANDLE		 LinkHandle,
		IN  ACCESS_MASK	 DesiredAccess,
		IN  POBJECT_ATTRIBUTES  ObjectAttributes)
{	
	return -ENOSYS;
}

/* 100 */
NTSTATUS SERVICECALL
NtOpenThread(OUT PHANDLE 		ThreadHandle,
		IN  ACCESS_MASK 		DesiredAccess,
		IN  POBJECT_ATTRIBUTES 	ObjectAttributes  OPTIONAL,
		IN  PCLIENT_ID		ClientId  OPTIONAL)
{
	return -ENOSYS;
}

NTSTATUS SERVICECALL
NtOpenThreadToken(IN  HANDLE 		ThreadHandle,
		IN  ACCESS_MASK 	DesiredAccess,
		IN  BOOLEAN 		OpenAsSelf,
		OUT PHANDLE 		TokenHandle)
{	
	return -ENOSYS;
}

NTSTATUS SERVICECALL
NtOpenThreadTokenEx(IN  HANDLE 		ThreadHandle,
		IN  ACCESS_MASK 	DesiredAccess,
		IN  BOOLEAN 	OpenAsSelf,
		IN  ULONG 		HandleAttributes,
		OUT PHANDLE 	TokenHandle)
{
	return -ENOSYS;
}
#endif

NTSTATUS SERVICECALL
NtOpenTimer(OUT PHANDLE 		TimerHandle,
		IN  ACCESS_MASK 		DesiredAccess,
		IN  POBJECT_ATTRIBUTES 	ObjectAttributes)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtOpenTimer);

NTSTATUS SERVICECALL
NtPlugPlayControl(IN     PLUGPLAY_CONTROL_CLASS PlugPlayControlClass,
		IN OUT PVOID 			Buffer,
		IN     ULONG 			BufferLength)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtPlugPlayControl);

/* 105 */
NTSTATUS SERVICECALL
NtPowerInformation(IN  POWER_INFORMATION_LEVEL  PowerInformationLevel,
		IN  PVOID 			InputBuffer  OPTIONAL,
		IN  ULONG 			InputBufferLength,
		OUT PVOID 			OutputBuffer  OPTIONAL,
		IN  ULONG 			OutputBufferLength)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtPowerInformation);

NTSTATUS SERVICECALL
NtPrivilegeCheck (IN HANDLE 		ClientToken,
		IN PPRIVILEGE_SET 	RequiredPrivileges,
		IN 			PBOOLEAN Result)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtPrivilegeCheck);

NTSTATUS SERVICECALL
NtPrivilegedServiceAuditAlarm(IN PUNICODE_STRING SubsystemName,
		IN PUNICODE_STRING ServiceName,
		IN HANDLE 	 ClientToken,
		IN PPRIVILEGE_SET  Privileges,
		IN BOOLEAN 	 AccessGranted)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtPrivilegedServiceAuditAlarm);

NTSTATUS SERVICECALL
NtPrivilegeObjectAuditAlarm(IN PUNICODE_STRING  SubsystemName,
		IN PVOID 		HandleId,
		IN HANDLE 		ClientToken,
		IN ULONG 		DesiredAccess,
		IN PPRIVILEGE_SET 	Privileges,
		IN BOOLEAN 		AccessGranted)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtPrivilegeObjectAuditAlarm);

#if 0
NTSTATUS SERVICECALL
NtProtectVirtualMemory(IN     HANDLE ProcessHandle,
		IN OUT PVOID  *UnsafeBaseAddress,
		IN OUT ULONG  *UnsafeNumberOfBytesToProtect,
		IN     ULONG  NewAccessProtection,
		OUT    PULONG UnsafeOldAccessProtection)
{	
	return -ENOSYS;
}

/* 110 */
NTSTATUS SERVICECALL
NtPulseEvent(IN  HANDLE EventHandle,
		OUT PLONG  PreviousState OPTIONAL)
{	
	return -ENOSYS;
}
#endif

NTSTATUS SERVICECALL
NtQueryInformationAtom(RTL_ATOM 		Atom,
		ATOM_INFORMATION_CLASS   AtomInformationClass,
		PVOID 			AtomInformation,
		ULONG 			AtomInformationLength,
		PULONG 			ReturnLength)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtQueryInformationAtom);

NTSTATUS SERVICECALL
NtQueryAttributesFile(IN  POBJECT_ATTRIBUTES 	  ObjectAttributes,
		OUT PFILE_BASIC_INFORMATION FileInformation)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtQueryAttributesFile);

NTSTATUS SERVICECALL
NtQueryBootEntryOrder(IN ULONG Unknown1,
		IN ULONG Unknown2)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtQueryBootEntryOrder);

NTSTATUS SERVICECALL
NtQueryBootOptions(IN ULONG Unknown1,
		IN ULONG Unknown2)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtQueryBootOptions);

/* 115 */
NTSTATUS SERVICECALL
NtQueryDefaultLocale(IN  BOOLEAN UserProfile,
		OUT PLCID   DefaultLocaleId)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtQueryDefaultLocale);

NTSTATUS SERVICECALL
NtQueryDefaultUILanguage(OUT PLANGID LanguageId)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtQueryDefaultUILanguage);

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
		IN  BOOLEAN 		RestartScan)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtQueryDirectoryFile);

#if 0
NTSTATUS SERVICECALL
NtQueryDirectoryObject (IN     HANDLE  DirectoryHandle,
		OUT    PVOID   Buffer,
		IN     ULONG   BufferLength,
		IN     BOOLEAN ReturnSingleEntry,
		IN     BOOLEAN RestartScan,
		IN OUT PULONG  Context,
		OUT    PULONG  ReturnLength OPTIONAL)
{	
	return -ENOSYS;
}
#endif

NTSTATUS SERVICECALL
NtQueryEaFile(IN  HANDLE 		FileHandle,
		OUT PIO_STATUS_BLOCK	IoStatusBlock,
		OUT PVOID 		Buffer,
		IN  ULONG 		Length,
		IN  BOOLEAN 		ReturnSingleEntry,
		IN  PVOID 		EaList OPTIONAL,
		IN  ULONG 		EaListLength,
		IN  PULONG 		EaIndex OPTIONAL,
		IN  BOOLEAN 		RestartScan)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtQueryEaFile);

/* 120 */
#if 0
NTSTATUS SERVICECALL
NtQueryEvent(IN  HANDLE 		 EventHandle,
		IN  EVENT_INFORMATION_CLASS EventInformationClass,
		OUT PVOID 			 EventInformation,
		IN  ULONG 			 EventInformationLength,
		OUT PULONG 		 ReturnLength  OPTIONAL)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtQueryEvent);
#endif

NTSTATUS SERVICECALL
NtQueryFullAttributesFile(IN  POBJECT_ATTRIBUTES 		ObjectAttributes,
		OUT PFILE_NETWORK_OPEN_INFORMATION 	FileInformation)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtQueryFullAttributesFile);

#if 0
NTSTATUS SERVICECALL
NtQueryInformationFile(HANDLE 			FileHandle,
		PIO_STATUS_BLOCK 	IoStatusBlock,
		PVOID 			FileInformation,
		ULONG 			Length,
		FILE_INFORMATION_CLASS 	FileInformationClass)
{	
	return -ENOSYS;
}
#endif

NTSTATUS SERVICECALL
NtQueryInformationJobObject (HANDLE 		JobHandle,
		JOBOBJECTINFOCLASS JobInformationClass,
		PVOID 		JobInformation,
		ULONG 		JobInformationLength,
		PULONG 		ReturnLength)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtQueryInformationJobObject);

NTSTATUS SERVICECALL
NtQueryInformationPort (IN  HANDLE			PortHandle,
		IN  PORT_INFORMATION_CLASS	PortInformationClass,
		OUT PVOID			PortInformation,
		IN  ULONG			PortInformationLength,
		OUT PULONG			ReturnLength)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtQueryInformationPort);

/* 125 */
#if 0
NTSTATUS SERVICECALL
NtQueryInformationProcess(IN  HANDLE 		ProcessHandle,
		IN  PROCESSINFOCLASS  ProcessInformationClass,
		OUT PVOID 		ProcessInformation,
		IN  ULONG 		ProcessInformationLength,
		OUT PULONG 		ReturnLength  OPTIONAL)
{	
	return -ENOSYS;
}

NTSTATUS SERVICECALL
NtQueryInformationThread (IN  HANDLE		ThreadHandle,
		IN  THREADINFOCLASS	ThreadInformationClass,
		OUT PVOID		ThreadInformation,
		IN  ULONG		ThreadInformationLength,
		OUT PULONG		ReturnLength  OPTIONAL)
{	
	return -ENOSYS;
}
#endif

NTSTATUS SERVICECALL
NtQueryInformationToken(IN  HANDLE 			TokenHandle,
		IN  TOKEN_INFORMATION_CLASS 	TokenInformationClass,
		OUT PVOID 			TokenInformation,
		IN  ULONG 			TokenInformationLength,
		OUT PULONG 			ReturnLength)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtQueryInformationToken);

NTSTATUS SERVICECALL
NtQueryInstallUILanguage(OUT PLANGID LanguageId)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtQueryInstallUILanguage);

NTSTATUS SERVICECALL
NtQueryIntervalProfile(IN  KPROFILE_SOURCE ProfileSource,
		OUT PULONG 	   Interval)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtQueryIntervalProfile);

/* 130 */
NTSTATUS SERVICECALL
NtQueryIoCompletion(IN  HANDLE 				IoCompletionHandle,
		IN  IO_COMPLETION_INFORMATION_CLASS IoCompletionInformationClass,
		OUT PVOID 				IoCompletionInformation,
		IN  ULONG 				IoCompletionInformationLength,
		OUT PULONG 				ResultLength OPTIONAL)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtQueryIoCompletion);

NTSTATUS SERVICECALL
NtQueryKey(IN  HANDLE 			KeyHandle,
		IN  KEY_INFORMATION_CLASS 	KeyInformationClass,
		OUT PVOID 			KeyInformation,
		IN  ULONG 			Length,
		OUT PULONG 			ResultLength)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtQueryKey);

NTSTATUS SERVICECALL
NtQueryMultipleValueKey (IN      HANDLE 		KeyHandle,
		IN  OUT PKEY_VALUE_ENTRY 	ValueList,
		IN      ULONG 			NumberOfValues,
		OUT     PVOID 			Buffer,
		IN  OUT PULONG 		Length,
		OUT     PULONG 		ReturnLength)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtQueryMultipleValueKey);

NTSTATUS SERVICECALL
NtQueryMutant(IN  HANDLE 			MutantHandle,
		IN  MUTANT_INFORMATION_CLASS 	MutantInformationClass,
		OUT PVOID 			MutantInformation,
		IN  ULONG 			MutantInformationLength,
		OUT PULONG			ResultLength  OPTIONAL)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtQueryMutant);

#if 0
NTSTATUS SERVICECALL
NtQueryObject (IN  HANDLE 			ObjectHandle,
		IN  OBJECT_INFORMATION_CLASS 	ObjectInformationClass,
		OUT PVOID 			ObjectInformation,
		IN  ULONG 			Length,
		OUT PULONG 			ResultLength  OPTIONAL)
{	
	return -ENOSYS;
}
#endif

/* 135 */
NTSTATUS SERVICECALL
NtQueryPerformanceCounter(OUT PLARGE_INTEGER PerformanceCounter,
		OUT PLARGE_INTEGER PerformanceFrequency OPTIONAL)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtQueryPerformanceCounter);

NTSTATUS SERVICECALL
NtQueryQuotaInformationFile(IN  HANDLE		 FileHandle,
		OUT PIO_STATUS_BLOCK IoStatusBlock,
		OUT PVOID		 Buffer,
		IN  ULONG		 Length,
		IN  BOOLEAN		 ReturnSingleEntry,
		IN  PVOID	 SidList OPTIONAL,
		IN  ULONG		 SidListLength,
		IN  PSID 		 StartSid OPTIONAL,
		IN  BOOLEAN 	 RestartScan)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtQueryQuotaInformationFile);

#if 0
NTSTATUS SERVICECALL
NtQuerySection(IN  HANDLE			SectionHandle,
		IN  SECTION_INFORMATION_CLASS 	SectionInformationClass,
		OUT PVOID 			SectionInformation,
		IN  ULONG 			SectionInformationLength,
		OUT PULONG 			ResultLength  OPTIONAL)
{	
	return -ENOSYS;
}
#endif

NTSTATUS SERVICECALL
NtQuerySecurityObject(IN  HANDLE 		Handle,
		IN  SECURITY_INFORMATION  SecurityInformation,
		OUT PSECURITY_DESCRIPTOR  SecurityDescriptor,
		IN  ULONG 		Length,
		OUT PULONG 		ResultLength)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtQuerySecurityObject);

NTSTATUS SERVICECALL
NtQuerySemaphore(IN  HANDLE 			 SemaphoreHandle,
		IN  SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass,
		OUT PVOID			 SemaphoreInformation,
		IN  ULONG			 SemaphoreInformationLength,
		OUT PULONG			 ReturnLength  OPTIONAL)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtQuerySemaphore);

/* 140 */
#if 0
NTSTATUS SERVICECALL
NtQuerySymbolicLinkObject(IN  HANDLE		LinkHandle,
		OUT PUNICODE_STRING	LinkTarget,
		OUT PULONG 		ResultLength  OPTIONAL)
{	
	return -ENOSYS;
}
#endif

NTSTATUS SERVICECALL
NtQuerySystemEnvironmentValue (IN     PUNICODE_STRING	VariableName,
		OUT    PWSTR		ValueBuffer,
		IN     ULONG		ValueBufferLength,
		IN OUT PULONG		ReturnLength  OPTIONAL)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtQuerySystemEnvironmentValue);

#if 0
NTSTATUS SERVICECALL
NtQuerySystemInformation (IN  SYSTEM_INFORMATION_CLASS  SystemInformationClass,
		OUT PVOID 			SystemInformation,
		IN  ULONG 			Length,
		OUT PULONG 			UnsafeResultLength)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtQuerySystemInformation);
#endif

NTSTATUS SERVICECALL
NtQuerySystemTime(OUT PLARGE_INTEGER SystemTime)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtQuerySystemTime);

NTSTATUS SERVICECALL
NtQueryTimer(IN  HANDLE 		 TimerHandle,
		IN  TIMER_INFORMATION_CLASS TimerInformationClass,
		OUT PVOID			 TimerInformation,
		IN  ULONG			 TimerInformationLength,
		OUT PULONG			 ReturnLength  OPTIONAL)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtQueryTimer);

/* 145 */
NTSTATUS SERVICECALL
NtQueryTimerResolution(OUT PULONG MinimumResolution,
		OUT PULONG MaximumResolution,
		OUT PULONG ActualResolution)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtQueryTimerResolution);

NTSTATUS SERVICECALL
NtQueryValueKey(IN  HANDLE			KeyHandle,
		IN  PUNICODE_STRING 		ValueName,
		IN  KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
		OUT PVOID 			KeyValueInformation,
		IN  ULONG 			Length,
		OUT PULONG 			ResultLength)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtQueryValueKey);

#if 0
NTSTATUS SERVICECALL
NtQueryVirtualMemory (IN  HANDLE		   ProcessHandle,
		IN  PVOID			   Address,
		IN  MEMORY_INFORMATION_CLASS VirtualMemoryInformationClass,
		OUT PVOID			   VirtualMemoryInformation,
		IN  ULONG			   Length,
		OUT PULONG		   UnsafeResultLength)
{	
	return -ENOSYS;
}
#endif

NTSTATUS SERVICECALL
NtQueryVolumeInformationFile(IN  HANDLE 		FileHandle,
		OUT PIO_STATUS_BLOCK 	IoStatusBlock,
		OUT PVOID 			FsInformation,
		IN  ULONG 			Length,
		IN  FS_INFORMATION_CLASS 	FsInformationClass)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtQueryVolumeInformationFile);

#if 0
NTSTATUS SERVICECALL
NtQueueApcThread(HANDLE 	  ThreadHandle,
		PKNORMAL_ROUTINE ApcRoutine,
		PVOID		  NormalContext,
		PVOID		  SystemArgument1,
		PVOID		  SystemArgument2)
{
	return -ENOSYS;
}
#endif

/* 150 */
NTSTATUS SERVICECALL
NtRaiseException(IN PEXCEPTION_RECORD 	ExceptionRecord,
		IN PCONTEXT		Context,
		IN BOOLEAN 		SearchFrames)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtRaiseException);

NTSTATUS SERVICECALL
NtRaiseHardError(IN  NTSTATUS 	ErrorStatus,
		IN  ULONG 	NumberOfParameters,
		IN  ULONG 	UnicodeStringParameterMask,
		IN  PULONG_PTR Parameters,
		IN  ULONG 	ValidResponseOptions,
		OUT PULONG 	Response)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtRaiseHardError);

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
		IN 			 PULONG Key OPTIONAL)
{
	return -ENOSYS;
}
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
		IN  PULONG 			Key OPTIONAL)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtReadFileScatter);

NTSTATUS SERVICECALL
NtReadRequestData (HANDLE		PortHandle,
		PPORT_MESSAGE	Message,
		ULONG		Index,
		PVOID		Buffer,
		ULONG		BufferLength,
		PULONG		Returnlength)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtReadRequestData);

/* 155 */
#if 0
NTSTATUS SERVICECALL
NtReadVirtualMemory(IN  HANDLE ProcessHandle,
		IN  PVOID  BaseAddress,
		OUT PVOID  Buffer,
		IN  ULONG  NumberOfBytesToRead,
		OUT PULONG NumberOfBytesRead OPTIONAL)
{	
	return -ENOSYS;
}
#endif

NTSTATUS SERVICECALL
NtRegisterThreadTerminatePort(HANDLE PortHandle)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtRegisterThreadTerminatePort);

#if 0
NTSTATUS SERVICECALL
NtReleaseMutant(IN HANDLE MutantHandle,
		IN PLONG  PreviousCount  OPTIONAL)
{
	return -ENOSYS;
}

NTSTATUS SERVICECALL
NtReleaseSemaphore(IN  HANDLE SemaphoreHandle,
		IN  LONG   ReleaseCount,
		OUT PLONG  PreviousCount  OPTIONAL)
{	
	return -ENOSYS;
}
#endif

NTSTATUS SERVICECALL
NtRemoveIoCompletion(IN  HANDLE		  IoCompletionHandle,
		OUT PVOID 		  *CompletionKey,
		OUT PVOID 		  *CompletionContext,
		OUT PIO_STATUS_BLOCK IoStatusBlock,
		IN  PLARGE_INTEGER   Timeout OPTIONAL)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtRemoveIoCompletion);

/* 160  */
NTSTATUS SERVICECALL
NtReplaceKey (IN POBJECT_ATTRIBUTES ObjectAttributes,
		IN HANDLE 	    Key,
		IN POBJECT_ATTRIBUTES ReplacedObjectAttributes)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtReplaceKey);

NTSTATUS SERVICECALL
NtReplyPort (IN	HANDLE		PortHandle,
		IN	PPORT_MESSAGE	LpcReply)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtReplyPort);

NTSTATUS SERVICECALL
NtReplyWaitReceivePort(IN  HANDLE	 PortHandle,
		OUT PVOID 	 *PortContext OPTIONAL,
		IN  PPORT_MESSAGE ReplyMessage OPTIONAL,
		OUT PPORT_MESSAGE ReceiveMessage)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtReplyWaitReceivePort);

NTSTATUS SERVICECALL
NtReplyWaitReplyPort (HANDLE		PortHandle,
		PPORT_MESSAGE	ReplyMessage)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtReplyWaitReplyPort);

NTSTATUS SERVICECALL 
NtRequestPort (IN HANDLE	PortHandle,
		IN PPORT_MESSAGE	LpcMessage)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtRequestPort);

/* 165 */
NTSTATUS SERVICECALL
NtRequestWaitReplyPort (IN HANDLE        PortHandle,
		PPORT_MESSAGE UnsafeLpcRequest,
		PPORT_MESSAGE UnsafeLpcReply)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtRequestWaitReplyPort);

#if 0
NTSTATUS SERVICECALL
NtResetEvent(IN  HANDLE EventHandle,
		OUT PLONG  PreviousState OPTIONAL)
{
	return -ENOSYS;
}
#endif

NTSTATUS SERVICECALL
NtRestoreKey (IN HANDLE KeyHandle,
		IN HANDLE FileHandle,
		IN ULONG  RestoreFlags)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtRestoreKey);

#if 0
NTSTATUS SERVICECALL
NtResumeThread(IN HANDLE ThreadHandle,
		IN PULONG SuspendCount  OPTIONAL)
{
	return -ENOSYS;
}
#endif

NTSTATUS SERVICECALL
NtSaveKey (IN HANDLE KeyHandle,
		IN HANDLE FileHandle)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtSaveKey);

/* 170 */
NTSTATUS SERVICECALL
NtSaveKeyEx(IN HANDLE KeyHandle,
		IN HANDLE FileHandle,
		IN ULONG  Flags) /* REG_STANDARD_FORMAT, etc.. */
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtSaveKeyEx);

NTSTATUS SERVICECALL
NtSetBootEntryOrder(IN ULONG Unknown1,
		IN ULONG Unknown2)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtSetBootEntryOrder);

NTSTATUS SERVICECALL
NtSetBootOptions(ULONG Unknown1,
		ULONG Unknown2)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtSetBootOptions);

NTSTATUS SERVICECALL
NtSetIoCompletion(IN HANDLE   IoCompletionPortHandle,
		IN PVOID    CompletionKey,
		IN PVOID    CompletionContext,
		IN NTSTATUS CompletionStatus,
		IN ULONG    CompletionInformation)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtSetIoCompletion);

#if 0
NTSTATUS SERVICECALL
NtSetContextThread(IN HANDLE   ThreadHandle,
		IN PCONTEXT ThreadContext)
{
	return -ENOSYS;
}
#endif

/* 175 */
NTSTATUS SERVICECALL
NtSetDefaultHardErrorPort(IN HANDLE PortHandle)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtSetDefaultHardErrorPort);

NTSTATUS SERVICECALL
NtSetDefaultLocale(IN BOOLEAN UserProfile,
		IN LCID    DefaultLocaleId)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtSetDefaultLocale);

NTSTATUS SERVICECALL
NtSetDefaultUILanguage(IN LANGID LanguageId)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtSetDefaultUILanguage);

NTSTATUS SERVICECALL
NtSetEaFile(IN HANDLE 		FileHandle,
		IN PIO_STATUS_BLOCK IoStatusBlock,
		IN PVOID 		EaBuffer,
		IN ULONG 		EaBufferSize)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtSetEaFile);

#if 0
NTSTATUS SERVICECALL
NtSetEvent(IN  HANDLE EventHandle,
		OUT PLONG  PreviousState  OPTIONAL)
{
	return -ENOSYS;
}
#endif

/* 180 */
NTSTATUS SERVICECALL
NtSetHighEventPair(IN HANDLE EventPairHandle)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtSetHighEventPair);

NTSTATUS SERVICECALL
NtSetHighWaitLowEventPair(IN HANDLE EventPairHandle)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtSetHighWaitLowEventPair);

#if 0
NTSTATUS SERVICECALL
NtSetInformationFile(HANDLE			FileHandle,
		PIO_STATUS_BLOCK		IoStatusBlock,
		PVOID			FileInformation,
		ULONG 			Length,
		FILE_INFORMATION_CLASS 	FileInformationClass)
{	
	return -ENOSYS;
}
#endif

NTSTATUS SERVICECALL
NtSetInformationKey (IN HANDLE 			  KeyHandle,
		IN KEY_SET_INFORMATION_CLASS KeyInformationClass,
		IN PVOID			  KeyInformation,
		IN ULONG			  KeyInformationLength)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtSetInformationKey);

NTSTATUS SERVICECALL
NtSetInformationJobObject (HANDLE 		JobHandle,
		JOBOBJECTINFOCLASS 	JobInformationClass,
		PVOID 		JobInformation,
		ULONG 		JobInformationLength)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtSetInformationJobObject);

/* 185 */
#if 0
NTSTATUS SERVICECALL
NtSetInformationObject (IN HANDLE 			ObjectHandle,
		IN OBJECT_INFORMATION_CLASS 	ObjectInformationClass,
		IN PVOID 			ObjectInformation,
		IN ULONG 			Length)
{	
	return -ENOSYS;
}

NTSTATUS SERVICECALL
NtSetInformationProcess(IN HANDLE 		ProcessHandle,
		IN PROCESSINFOCLASS 	ProcessInformationClass,
		IN PVOID 		ProcessInformation,
		IN ULONG 		ProcessInformationLength)
{	
	return -ENOSYS;
}

NTSTATUS SERVICECALL
NtSetInformationThread (IN HANDLE 		ThreadHandle,
		IN THREADINFOCLASS 	ThreadInformationClass,
		IN PVOID 		ThreadInformation,
		IN ULONG 		ThreadInformationLength)
{	
	return -ENOSYS;
}
#endif

NTSTATUS SERVICECALL
NtSetInformationToken(IN  HANDLE 		  TokenHandle,
		IN  TOKEN_INFORMATION_CLASS TokenInformationClass,
		OUT PVOID			  TokenInformation,
		IN  ULONG			  TokenInformationLength)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtSetInformationToken);

NTSTATUS
	SERVICECALL
NtSetIntervalProfile(IN ULONG 		Interval,
		IN KPROFILE_SOURCE Source)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtSetIntervalProfile);

/* 190 */
NTSTATUS SERVICECALL
NtSetLdtEntries (ULONG 		Selector1,
		LDT_ENTRY 	LdtEntry1,
		ULONG 		Selector2,
		LDT_ENTRY 	LdtEntry2)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtSetLdtEntries);

NTSTATUS SERVICECALL
NtSetLowEventPair(IN HANDLE EventPairHandle)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtSetLowEventPair);

NTSTATUS SERVICECALL
NtSetLowWaitHighEventPair(IN HANDLE EventPairHandle)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtSetLowWaitHighEventPair);

NTSTATUS SERVICECALL
NtSetQuotaInformationFile(HANDLE 		FileHandle,
		PIO_STATUS_BLOCK 	IoStatusBlock,
		PVOID 		Buffer,
		ULONG 		BufferLength)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtSetQuotaInformationFile);

NTSTATUS SERVICECALL
NtSetSecurityObject(IN HANDLE 		    Handle,
		IN SECURITY_INFORMATION SecurityInformation,
		IN PSECURITY_DESCRIPTOR SecurityDescriptor)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtSetSecurityObject);

/* 195 */
NTSTATUS SERVICECALL
NtSetSystemEnvironmentValue (IN	PUNICODE_STRING	VariableName,
		IN	PUNICODE_STRING	Value)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtSetSystemEnvironmentValue);

NTSTATUS SERVICECALL
NtSetSystemInformation (IN SYSTEM_INFORMATION_CLASS	SystemInformationClass,
		IN PVOID			SystemInformation,
		IN ULONG			SystemInformationLength)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtSetSystemInformation);

NTSTATUS SERVICECALL
NtSetSystemPowerState(IN POWER_ACTION 		SystemAction,
		IN SYSTEM_POWER_STATE 	MinSystemState,
		IN ULONG 			Flags)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtSetSystemPowerState);

NTSTATUS SERVICECALL
NtSetSystemTime(IN  PLARGE_INTEGER SystemTime,
		OUT PLARGE_INTEGER PreviousTime OPTIONAL)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtSetSystemTime);

NTSTATUS SERVICECALL
NtSetTimer(IN  HANDLE 			TimerHandle,
		IN  PLARGE_INTEGER 		DueTime,
		IN  PTIMER_APC_ROUTINE 	TimerApcRoutine OPTIONAL,
		IN  PVOID 			TimerContext OPTIONAL,
		IN  BOOLEAN 			WakeTimer,
		IN  LONG 			Period OPTIONAL,
		OUT PBOOLEAN 		PreviousState OPTIONAL)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtSetTimer);

/* 200 */
NTSTATUS SERVICECALL
NtSetTimerResolution(IN  ULONG   DesiredResolution,
		IN  BOOLEAN SetResolution,
		OUT PULONG  CurrentResolution)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtSetTimerResolution);

NTSTATUS SERVICECALL
NtSetUuidSeed(IN PUCHAR Seed)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtSetUuidSeed);

NTSTATUS SERVICECALL
NtSetValueKey(IN HANDLE 	 KeyHandle,
		IN PUNICODE_STRING ValueName,
		IN ULONG		 TitleIndex,
		IN ULONG		 Type,
		IN PVOID		 Data,
		IN ULONG		 DataSize)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtSetValueKey);

NTSTATUS SERVICECALL
NtSetVolumeInformationFile(IN  HANDLE 			FileHandle,
		OUT PIO_STATUS_BLOCK 	IoStatusBlock,
		IN  PVOID 			FsInformation,
		IN  ULONG 			Length,
		IN  FS_INFORMATION_CLASS 	FsInformationClass)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtSetVolumeInformationFile);

NTSTATUS SERVICECALL
NtShutdownSystem(IN SHUTDOWN_ACTION Action)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtShutdownSystem);

/* 205*/
#if 0
NTSTATUS SERVICECALL
NtSignalAndWaitForSingleObject(IN HANDLE 	 ObjectHandleToSignal,
		IN HANDLE 	 WaitableObjectHandle,
		IN BOOLEAN	  Alertable,
		IN PLARGE_INTEGER TimeOut  OPTIONAL)
{
	return -ENOSYS;
}
#endif

NTSTATUS SERVICECALL
NtStartProfile(IN HANDLE ProfileHandle)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtStartProfile);

NTSTATUS SERVICECALL
NtStopProfile(IN HANDLE ProfileHandle)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtStopProfile);

#if 0
NTSTATUS SERVICECALL
NtSuspendThread(IN HANDLE ThreadHandle,
		IN PULONG PreviousSuspendCount  OPTIONAL)
{
	return -ENOSYS;
}
#endif

NTSTATUS SERVICECALL
NtSystemDebugControl(DEBUG_CONTROL_CODE ControlCode,
		PVOID 		InputBuffer,
		ULONG 		InputBufferLength,
		PVOID 		OutputBuffer,
		ULONG 		OutputBufferLength,
		PULONG 		ReturnLength)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtSystemDebugControl);

/* 210 */
NTSTATUS SERVICECALL
NtTerminateJobObject(HANDLE   JobHandle,
		NTSTATUS ExitStatus)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtTerminateJobObject);

#if 0
NTSTATUS SERVICECALL
NtTerminateProcess(IN HANDLE   ProcessHandle  OPTIONAL,
		IN NTSTATUS ExitStatus)
{
	return -ENOSYS;
}

NTSTATUS SERVICECALL
NtTerminateThread(IN HANDLE   ThreadHandle,
		IN NTSTATUS ExitStatus)
{
	return -ENOSYS;
}
#endif

NTSTATUS SERVICECALL
NtTestAlert(VOID)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtTestAlert);

NTSTATUS SERVICECALL
NtTraceEvent(IN ULONG 				TraceHandle,
		IN ULONG 				Flags,
		IN ULONG 				TraceHeaderLength,
		IN struct _EVENT_TRACE_HEADER* 	TraceHeader)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtTraceEvent);

/* 215 */
NTSTATUS SERVICECALL
NtTranslateFilePath(ULONG Unknown1,
		ULONG Unknown2,
		ULONG Unknown3)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtTranslateFilePath);

NTSTATUS SERVICECALL
NtUnloadDriver(IN PUNICODE_STRING DriverServiceName)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtUnloadDriver);

NTSTATUS SERVICECALL
NtUnloadKey (IN POBJECT_ATTRIBUTES KeyObjectAttributes)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtUnloadKey);

NTSTATUS SERVICECALL
NtUnlockFile(IN  HANDLE 	  FileHandle,
		OUT PIO_STATUS_BLOCK IoStatusBlock,
		IN  PLARGE_INTEGER	  ByteOffset,
		IN  PLARGE_INTEGER	  Length,
		OUT ULONG 		  Key OPTIONAL)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtUnlockFile);

#if 0
NTSTATUS SERVICECALL
NtUnlockVirtualMemory(HANDLE ProcessHandle,
		PVOID  BaseAddress,
		ULONG  NumberOfBytesToUnlock,
		PULONG NumberOfBytesUnlocked OPTIONAL)
{	
	return -ENOSYS;
}
EXPORT_SYMBOL(NtUnlockVirtualMemory);

/* 220 */
NTSTATUS SERVICECALL
NtUnmapViewOfSection (HANDLE ProcessHandle,
		PVOID  BaseAddress)
{	
	return -ENOSYS;
}
#endif

NTSTATUS SERVICECALL 
NtVdmControl(ULONG ControlCode,
		PVOID ControlData)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtVdmControl);

#if 0
NTSTATUS SERVICECALL
NtWaitForMultipleObjects(IN ULONG 	   ObjectCount,
		IN PHANDLE	   HandleArray,
		IN WAIT_TYPE	   WaitType,
		IN BOOLEAN	   Alertable,
		IN PLARGE_INTEGER TimeOut  OPTIONAL)
{

	return -ENOSYS;
}

NTSTATUS SERVICECALL
NtWaitForSingleObject(IN HANDLE 	ObjectHandle,
		IN BOOLEAN 	Alertable,
		IN PLARGE_INTEGER TimeOut  OPTIONAL)
{
	return -ENOSYS;
}
#endif

NTSTATUS SERVICECALL
NtWaitHighEventPair(IN HANDLE EventPairHandle)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtWaitHighEventPair);

/* 225 */
NTSTATUS SERVICECALL
NtWaitLowEventPair(IN HANDLE EventPairHandle)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtWaitLowEventPair);

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
		IN  PULONG 	  Key OPTIONAL)
{
	return -ENOSYS;
}
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
		IN  PULONG 		   Key OPTIONAL)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtWriteFileGather);

NTSTATUS SERVICECALL 
NtWriteRequestData (HANDLE		PortHandle,
		PPORT_MESSAGE	Message,
		ULONG		Index,
		PVOID		Buffer,
		ULONG		BufferLength,
		PULONG		ReturnLength)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtWriteRequestData);

#if 0
NTSTATUS SERVICECALL
NtWriteVirtualMemory(IN  HANDLE ProcessHandle,
		IN  PVOID  BaseAddress,
		IN  PVOID  Buffer,
		IN  ULONG  NumberOfBytesToWrite,
		OUT PULONG NumberOfBytesWritten  OPTIONAL)
{	
	return -ENOSYS;
}
#endif

/* 230 */
NTSTATUS SERVICECALL
NtW32Call(IN  ULONG  RoutineIndex,
		IN  PVOID  Argument,
		IN  ULONG  ArgumentLength,
		OUT PVOID* Result OPTIONAL,
		OUT PULONG ResultLength OPTIONAL)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtW32Call);

NTSTATUS SERVICECALL
NtYieldExecution(VOID)
{
	return -ENOSYS;
}
EXPORT_SYMBOL(NtYieldExecution);

const char* wine_service[];

/* not win32 syscall, just for wine service use */
NTSTATUS call_req_handler(struct w32thread * thread) 
{
	enum request req = thread->req.request_header.req;
	req_handler handler;

	thread->reply_size = 0;
	set_error(STATUS_SUCCESS);
	memset(&thread->reply, 0, sizeof(thread->reply));

	if (req < REQ_NB_REQUESTS) {
		handler = req_handlers[req];
		if (handler) {
			ktrace("NtWineService %d:%s\n", req, wine_service[req]);
			handler(&thread->req, &thread->reply);
		}
		else {
			ktrace("invalid call %d:(%s)\n", req, wine_service[req]);
			set_error(STATUS_NOT_IMPLEMENTED);
		}
	} else {
		set_error(STATUS_NOT_IMPLEMENTED);
	}

	thread->reply.reply_header.error = thread->error;
	thread->reply.reply_header.reply_size = thread->reply_size;

	return (NTSTATUS)thread->error;
}

/* not win32 syscall, just for wine service use */
NTSTATUS SERVICECALL
NtWineService(PSERVER_REQUEST_INFO ReqMsg)
{
	struct w32thread * thread = (PTSB)get_current_w32thread();
	struct __server_request_info req_msg;
	NTSTATUS status = STATUS_SUCCESS;
	int i;

	set_error(STATUS_SUCCESS);

	if(!ReqMsg || !thread)
		return STATUS_UNSUCCESSFUL;

	if (copy_from_user(&req_msg, ReqMsg, sizeof(req_msg)))
		return STATUS_UNSUCCESSFUL;

	memcpy(&thread->req, &req_msg, sizeof(thread->req));

	if((thread->req_toread = thread->req.request_header.request_size)) {
		if (!(thread->req_data = malloc(thread->req_toread))) 
			return STATUS_UNSUCCESSFUL;

		for (i=0; i<req_msg.data_count; ++i) {
			if(copy_from_user(
						(char *)thread->req_data + thread->req.request_header.request_size - thread->req_toread, 
						req_msg.data[i].ptr, req_msg.data[i].size)) { 

				status = STATUS_UNSUCCESSFUL;
				goto out;
			}

			thread->req_toread -= req_msg.data[i].size;		
		}
	}

	status = call_req_handler(thread);

	/*FIXME*/
	if (copy_to_user(ReqMsg, &thread->reply, sizeof(thread->reply))) {
		status = STATUS_UNSUCCESSFUL;
		goto out;
	}

	if (thread->reply_size) {
		if (copy_to_user(req_msg.reply_data, thread->reply_data, thread->reply_size)) {
			status = STATUS_UNSUCCESSFUL;
			goto out;
		}
	}

out:
	if (thread->req_data) {
		kfree(thread->req_data);
		thread->req_data = NULL;
	}

	return status;
}
EXPORT_SYMBOL(NtWineService);

/* Syscall function table. Currently only 2 functions are stubbed for
   testing, and to be used as a prototype */

SSDT MainSSDT[] = {
	(SSDT)NtAcceptConnectPort,		/* 0 */
	(SSDT)NtAccessCheck,			/* 1 */
	(SSDT)NtAccessCheckAndAuditAlarm,
	(SSDT)NtAddAtom,
	(SSDT)NtAddBootEntry,
	(SSDT)NtAdjustGroupsToken,		/* 5 */
	(SSDT)NtAdjustPrivilegesToken,
	(SSDT)NtAlertResumeThread,
	(SSDT)NtAlertThread,
	(SSDT)NtAllocateLocallyUniqueId,
	(SSDT)NtAllocateUuids,			/* 10 */
	(SSDT)NtAllocateVirtualMemory,
	(SSDT)NtAssignProcessToJobObject,
	(SSDT)NtCallbackReturn,
	(SSDT)NtCancelIoFile,
	(SSDT)NtCancelTimer,			/* 15 */
	(SSDT)NtClearEvent,
	(SSDT)NtClose,
	(SSDT)NtCloseObjectAuditAlarm,
	(SSDT)NtCompleteConnectPort,
	(SSDT)NtConnectPort,			/* 20 */
	(SSDT)NtContinue,
	(SSDT)NtCreateDirectoryObject,
	(SSDT)NtCreateEvent,
	(SSDT)NtCreateEventPair,
	(SSDT)NtCreateFile,			/* 25 */
	(SSDT)NtCreateIoCompletion,
	(SSDT)NtCreateJobObject,
	(SSDT)NtCreateKey,
	(SSDT)NtCreateMailslotFile,
	(SSDT)NtCreateMutant,			/* 30 */
	(SSDT)NtCreateNamedPipeFile,
	(SSDT)NtCreatePagingFile,
	(SSDT)NtCreatePort,
	(SSDT)NtCreateProcess,
	(SSDT)NtCreateProfile,			/* 35 */
	(SSDT)NtCreateSection,
	(SSDT)NtCreateSemaphore,
	(SSDT)NtCreateSymbolicLinkObject,
	(SSDT)NtCreateThread,
	(SSDT)NtCreateTimer,			/* 40 */
	(SSDT)NtCreateToken,
	(SSDT)NtCreateWaitablePort,
	(SSDT)NtDelayExecution,
	(SSDT)NtDeleteAtom,
	(SSDT)NtDeleteBootEntry,		/* 45 */
	(SSDT)NtDeleteFile,
	(SSDT)NtDeleteKey,
	(SSDT)NtDeleteObjectAuditAlarm,
	(SSDT)NtDeleteValueKey,
	(SSDT)NtDeviceIoControlFile,		/* 50 */
	(SSDT)NtDisplayString,
	(SSDT)NtDuplicateObject,
	(SSDT)NtDuplicateToken,
	(SSDT)NtEnumerateBootEntries,
	(SSDT)NtEnumerateKey,			/* 55 */
	(SSDT)NtEnumerateValueKey,
	(SSDT)NtExtendSection,
	(SSDT)NtFindAtom,
	(SSDT)NtFlushBuffersFile,
	(SSDT)NtFlushInstructionCache,		/* 60 */
	(SSDT)NtFlushKey,
	(SSDT)NtFlushVirtualMemory,
	(SSDT)NtFlushWriteBuffer,
	(SSDT)NtFreeVirtualMemory,
	(SSDT)NtFsControlFile,			/* 65 */
	(SSDT)NtGetContextThread,
	(SSDT)NtGetPlugPlayEvent,
	(SSDT)NtGetTickCount,
	(SSDT)NtImpersonateClientOfPort,
	(SSDT)NtImpersonateThread,		/* 70 */
	(SSDT)NtInitializeRegistry,
	(SSDT)NtInitiatePowerAction,
	(SSDT)NtIsProcessInJob,
	(SSDT)NtListenPort,
	(SSDT)NtLoadDriver,			/* 75 */
	(SSDT)NtLoadKey,
	(SSDT)NtLoadKey2,
	(SSDT)NtLockFile,
	(SSDT)NtLockVirtualMemory,
	(SSDT)NtMakePermanentObject,		/* 80 */
	(SSDT)NtMakeTemporaryObject,
	(SSDT)NtMapViewOfSection,
	(SSDT)NtNotifyChangeDirectoryFile,
	(SSDT)NtNotifyChangeKey,
	(SSDT)NtOpenDirectoryObject,		/* 85 */
	(SSDT)NtOpenEvent,
	(SSDT)NtOpenEventPair,
	(SSDT)NtOpenFile,
	(SSDT)NtOpenIoCompletion,
	(SSDT)NtOpenJobObject,			/* 90 */
	(SSDT)NtOpenKey,
	(SSDT)NtOpenMutant,
	(SSDT)NtOpenObjectAuditAlarm,
	(SSDT)NtOpenProcess,
	(SSDT)NtOpenProcessToken,		/* 95 */
	(SSDT)NtOpenProcessTokenEx,
	(SSDT)NtOpenSection,
	(SSDT)NtOpenSemaphore,
	(SSDT)NtOpenSymbolicLinkObject,
	(SSDT)NtOpenThread,			/* 100 */
	(SSDT)NtOpenThreadToken,
	(SSDT)NtOpenThreadTokenEx,
	(SSDT)NtOpenTimer,
	(SSDT)NtPlugPlayControl,
	(SSDT)NtPowerInformation,		/* 105 */
	(SSDT)NtPrivilegeCheck,
	(SSDT)NtPrivilegedServiceAuditAlarm,
	(SSDT)NtPrivilegeObjectAuditAlarm,
	(SSDT)NtProtectVirtualMemory,
	(SSDT)NtPulseEvent,			/* 110 */
	(SSDT)NtQueryInformationAtom,
	(SSDT)NtQueryAttributesFile,
	(SSDT)NtQueryBootEntryOrder,
	(SSDT)NtQueryBootOptions,
	(SSDT)NtQueryDefaultLocale,		/* 115 */
	(SSDT)NtQueryDefaultUILanguage,
	(SSDT)NtQueryDirectoryFile,
	(SSDT)NtQueryDirectoryObject,
	(SSDT)NtQueryEaFile,
	(SSDT)NtQueryEvent,			/* 120 */
	(SSDT)NtQueryFullAttributesFile,
	(SSDT)NtQueryInformationFile,
	(SSDT)NtQueryInformationJobObject,
	(SSDT)NtQueryInformationPort,
	(SSDT)NtQueryInformationProcess,	/* 125 */
	(SSDT)NtQueryInformationThread,
	(SSDT)NtQueryInformationToken,
	(SSDT)NtQueryInstallUILanguage,
	(SSDT)NtQueryIntervalProfile,
	(SSDT)NtQueryIoCompletion,		/* 130 */
	(SSDT)NtQueryKey,
	(SSDT)NtQueryMultipleValueKey,
	(SSDT)NtQueryMutant,
	(SSDT)NtQueryObject,
	(SSDT)NtQueryPerformanceCounter,	/* 135 */
	(SSDT)NtQueryQuotaInformationFile,
	(SSDT)NtQuerySection,
	(SSDT)NtQuerySecurityObject,
	(SSDT)NtQuerySemaphore,
	(SSDT)NtQuerySymbolicLinkObject,	/* 140 */
	(SSDT)NtQuerySystemEnvironmentValue,
	(SSDT)NtQuerySystemInformation,
	(SSDT)NtQuerySystemTime,
	(SSDT)NtQueryTimer,
	(SSDT)NtQueryTimerResolution,		/* 145 */
	(SSDT)NtQueryValueKey,
	(SSDT)NtQueryVirtualMemory,
	(SSDT)NtQueryVolumeInformationFile,
	(SSDT)NtQueueApcThread,
	(SSDT)NtRaiseException,			/* 150 */
	(SSDT)NtRaiseHardError,
	(SSDT)NtReadFile,
	(SSDT)NtReadFileScatter,
	(SSDT)NtReadRequestData,
	(SSDT)NtReadVirtualMemory,		/* 155 */
	(SSDT)NtRegisterThreadTerminatePort,
	(SSDT)NtReleaseMutant,
	(SSDT)NtReleaseSemaphore,
	(SSDT)NtRemoveIoCompletion,
	(SSDT)NtReplaceKey,			/* 160 */
	(SSDT)NtReplyPort,
	(SSDT)NtReplyWaitReceivePort,
	(SSDT)NtReplyWaitReplyPort,
	(SSDT)NtRequestPort,
	(SSDT)NtRequestWaitReplyPort,		/* 165 */
	(SSDT)NtResetEvent,
	(SSDT)NtRestoreKey,
	(SSDT)NtResumeThread,
	(SSDT)NtSaveKey,
	(SSDT)NtSaveKeyEx,			/* 170 */
	(SSDT)NtSetBootEntryOrder,
	(SSDT)NtSetBootOptions,
	(SSDT)NtSetIoCompletion,
	(SSDT)NtSetContextThread,
	(SSDT)NtSetDefaultHardErrorPort,	/* 175 */
	(SSDT)NtSetDefaultLocale,
	(SSDT)NtSetDefaultUILanguage,
	(SSDT)NtSetEaFile,
	(SSDT)NtSetEvent,
	(SSDT)NtSetHighEventPair,		/* 180 */
	(SSDT)NtSetHighWaitLowEventPair,
	(SSDT)NtSetInformationFile,
	(SSDT)NtSetInformationKey,
	(SSDT)NtSetInformationJobObject,
	(SSDT)NtSetInformationObject,		/* 185 */
	(SSDT)NtSetInformationProcess,
	(SSDT)NtSetInformationThread,
	(SSDT)NtSetInformationToken,
	(SSDT)NtSetIntervalProfile,
	(SSDT)NtSetLdtEntries,			/* 190 */
	(SSDT)NtSetLowEventPair,
	(SSDT)NtSetLowWaitHighEventPair,
	(SSDT)NtSetQuotaInformationFile,
	(SSDT)NtSetSecurityObject,
	(SSDT)NtSetSystemEnvironmentValue,	/* 195 */
	(SSDT)NtSetSystemInformation,
	(SSDT)NtSetSystemPowerState,
	(SSDT)NtSetSystemTime,
	(SSDT)NtSetTimer,
	(SSDT)NtSetTimerResolution,		/* 200 */
	(SSDT)NtSetUuidSeed,
	(SSDT)NtSetValueKey,
	(SSDT)NtSetVolumeInformationFile,
	(SSDT)NtShutdownSystem,
	(SSDT)NtSignalAndWaitForSingleObject,	/* 205 */
	(SSDT)NtStartProfile,
	(SSDT)NtStopProfile,
	(SSDT)NtSuspendThread,
	(SSDT)NtSystemDebugControl,
	(SSDT)NtTerminateJobObject,		/* 210 */
	(SSDT)NtTerminateProcess,
	(SSDT)NtTerminateThread,
	(SSDT)NtTestAlert,
	(SSDT)NtTraceEvent,
	(SSDT)NtTranslateFilePath,		/* 215 */
	(SSDT)NtUnloadDriver,
	(SSDT)NtUnloadKey,
	(SSDT)NtUnlockFile,
	(SSDT)NtUnlockVirtualMemory,
	(SSDT)NtUnmapViewOfSection,		/* 220 */
	(SSDT)NtVdmControl,
	(SSDT)NtWaitForMultipleObjects,
	(SSDT)NtWaitForSingleObject,
	(SSDT)NtWaitHighEventPair,
	(SSDT)NtWaitLowEventPair,		/* 225 */
	(SSDT)NtWriteFile,
	(SSDT)NtWriteFileGather,
	(SSDT)NtWriteRequestData,
	(SSDT)NtWriteVirtualMemory,
	(SSDT)NtW32Call,			/* 230 */
	(SSDT)NtYieldExecution,
	(SSDT)NtWineService,
	(SSDT)NtCatchApc,
};
EXPORT_SYMBOL(MainSSDT);

/* number of parameters for each function */

SSPT MainSSPT[] = {
	6,  8,  11, 3,  2, /* 0 */
	6,  6,  2,  1,  1,
	4,  6,  2,  3,  2, /* 10 */
	2,  1,  1,  3,  1,
	8,  2,  3,  5,  3, /* 20 */
	11, 4,  3,  7,  8,
	4,  14, 4,  5,  8, /* 30 */
	9,  7,  5,  4,  8,
	4,  13, 5,  2,  1, /* 40 */
	2,  1,  1,  3,  2,
	10, 1,  7,  6,  2, /* 50 */
	6,  6,  2,  3,  2,
	3,  1,  4,  0,  4, /* 60 */
	10, 2,  4,  0,  2,
	3,  1,  4,  2,  2, /* 70 */
	1,  2,  3,  10, 4,
	1,  1,  10, 9,  10,/* 80 */
	3,  3,  3,  6,  3,
	3,  3,  3,  12, 4, /* 90 */
	3,  4,  3,  3,  3,
	4,  4,  5,  3,  3, /* 100 */
	5,  3,  5,  6,  5,
	2,  5,  2,  2,  2, /* 110 */
	2,  1,  11, 7,  9,
	5,  2,  5,  5,  5, /* 120 */
	5,  5,  5,  1,  2,
	5,  5,  6,  5,  5, /* 130 */
	2,  9,  5,  5,  5,
	3,  4,  4,  1,  5, /* 140 */
	3,  6,  6,  5,  5,
	3,  6,  9,  9,  6, /* 150 */
	5,  1,  2,  3,  5,
	3,  2,  4,  2,  2, /* 160 */
	3,  2,  3,  2,  2,
	3,  2,  2,  5,  2, /* 170 */
	1,  2,  1,  4,  2,
	1,  1,  5,  4,  4, /* 180 */
	4,  4,  4,  4,  2,
	4,  1,  1,  4,  3, /* 190 */
	2,  3,  3,  2,  7,
	3,  1,  6,  5,  1, /* 200 */
	4,  1,  1,  2,  6,
	2,  2,  2,  0,  4, /* 210 */
	3,  1,  1,  5,  4,
	2,  2,  5,  3,  1, /* 220 */
	1,  9,  9,  6,  5,
	5,  0,  1,  1      /* 230 */
};
EXPORT_SYMBOL(MainSSPT);


#define MIN_SYSCALL_NUMBER    0
#define MAX_SYSCALL_NUMBER    233
#define NUMBER_OF_SYSCALLS    234

/* From ReactOS, don't touch. */

SSDT_ENTRY
KeServiceDescriptorTable[4] = {
	{ MainSSDT,  NULL,  NUMBER_OF_SYSCALLS,  MainSSPT },
	{ NULL,     NULL,   0,   NULL   },
	{ NULL,     NULL,   0,   NULL   },
	{ NULL,     NULL,   0,   NULL   }
};
EXPORT_SYMBOL(KeServiceDescriptorTable);

void enter_win_syscall(void)
{
	ktrace("enter <==================\n");
}

void leave_win_syscall(void)
{
	ktrace("leave ==================>\n");
}

EXPORT_SYMBOL(enter_win_syscall);
EXPORT_SYMBOL(leave_win_syscall);


char* syscall[] = {
	"NtAcceptConnectPort",		/* 0 */
	"NtAccessCheck",			/* 1 */
	"NtAccessCheckAndAuditAlarm",
	"NtAddAtom",
	"NtAddBootEntry",
	"NtAdjustGroupsToken",		/* 5 */
	"NtAdjustPrivilegesToken",
	"NtAlertResumeThread",
	"NtAlertThread",
	"NtAllocateLocallyUniqueId",
	"NtAllocateUuids",			/* 10 */
	"NtAllocateVirtualMemory",
	"NtAssignProcessToJobObject",
	"NtCallbackReturn",
	"NtCancelIoFile",
	"NtCancelTimer",			/* 15 */
	"NtClearEvent",
	"NtClose",
	"NtCloseObjectAuditAlarm",
	"NtCompleteConnectPort",
	"NtConnectPort",			/* 20 */
	"NtContinue",
	"NtCreateDirectoryObject",
	"NtCreateEvent",
	"NtCreateEventPair",
	"NtCreateFile",			/* 25 */
	"NtCreateIoCompletion",
	"NtCreateJobObject",
	"NtCreateKey",
	"NtCreateMailslotFile",
	"NtCreateMutant",			/* 30 */
	"NtCreateNamedPipeFile",
	"NtCreatePagingFile",
	"NtCreatePort",
	"NtCreateProcess",
	"NtCreateProfile",			/* 35 */
	"NtCreateSection",
	"NtCreateSemaphore",
	"NtCreateSymbolicLinkObject",
	"NtCreateThread",
	"NtCreateTimer",			/* 40 */
	"NtCreateToken",
	"NtCreateWaitablePort",
	"NtDelayExecution",
	"NtDeleteAtom",
	"NtDeleteBootEntry",		/* 45 */
	"NtDeleteFile",
	"NtDeleteKey",
	"NtDeleteObjectAuditAlarm",
	"NtDeleteValueKey",
	"NtDeviceIoControlFile",		/* 50 */
	"NtDisplayString",
	"NtDuplicateObject",
	"NtDuplicateToken",
	"NtEnumerateBootEntries",
	"NtEnumerateKey",			/* 55 */
	"NtEnumerateValueKey",
	"NtExtendSection",
	"NtFindAtom",
	"NtFlushBuffersFile",
	"NtFlushInstructionCache",		/* 60 */
	"NtFlushKey",
	"NtFlushVirtualMemory",
	"NtFlushWriteBuffer",
	"NtFreeVirtualMemory",
	"NtFsControlFile",			/* 65 */
	"NtGetContextThread",
	"NtGetPlugPlayEvent",
	"NtGetTickCount",
	"NtImpersonateClientOfPort",
	"NtImpersonateThread",		/* 70 */
	"NtInitializeRegistry",
	"NtInitiatePowerAction",
	"NtIsProcessInJob",
	"NtListenPort",
	"NtLoadDriver",			/* 75 */
	"NtLoadKey",
	"NtLoadKey2",
	"NtLockFile",
	"NtLockVirtualMemory",
	"NtMakePermanentObject",		/* 80 */
	"NtMakeTemporaryObject",
	"NtMapViewOfSection",
	"NtNotifyChangeDirectoryFile",
	"NtNotifyChangeKey",
	"NtOpenDirectoryObject",		/* 85 */
	"NtOpenEvent",
	"NtOpenEventPair",
	"NtOpenFile",
	"NtOpenIoCompletion",
	"NtOpenJobObject",			/* 90 */
	"NtOpenKey",
	"NtOpenMutant",
	"NtOpenObjectAuditAlarm",
	"NtOpenProcess",
	"NtOpenProcessToken",		/* 95 */
	"NtOpenProcessTokenEx",
	"NtOpenSection",
	"NtOpenSemaphore",
	"NtOpenSymbolicLinkObject",
	"NtOpenThread",			/* 100 */
	"NtOpenThreadToken",
	"NtOpenThreadTokenEx",
	"NtOpenTimer",
	"NtPlugPlayControl",
	"NtPowerInformation",		/* 105 */
	"NtPrivilegeCheck",
	"NtPrivilegedServiceAuditAlarm",
	"NtPrivilegeObjectAuditAlarm",
	"NtProtectVirtualMemory",
	"NtPulseEvent",			/* 110 */
	"NtQueryInformationAtom",
	"NtQueryAttributesFile",
	"NtQueryBootEntryOrder",
	"NtQueryBootOptions",
	"NtQueryDefaultLocale",		/* 115 */
	"NtQueryDefaultUILanguage",
	"NtQueryDirectoryFile",
	"NtQueryDirectoryObject",
	"NtQueryEaFile",
	"NtQueryEvent",			/* 120 */
	"NtQueryFullAttributesFile",
	"NtQueryInformationFile",
	"NtQueryInformationJobObject",
	"NtQueryInformationPort",
	"NtQueryInformationProcess",	/* 125 */
	"NtQueryInformationThread",
	"NtQueryInformationToken",
	"NtQueryInstallUILanguage",
	"NtQueryIntervalProfile",
	"NtQueryIoCompletion",		/* 130 */
	"NtQueryKey",
	"NtQueryMultipleValueKey",
	"NtQueryMutant",
	"NtQueryObject",
	"NtQueryPerformanceCounter",	/* 135 */
	"NtQueryQuotaInformationFile",
	"NtQuerySection",
	"NtQuerySecurityObject",
	"NtQuerySemaphore",
	"NtQuerySymbolicLinkObject",	/* 140 */
	"NtQuerySystemEnvironmentValue",
	"NtQuerySystemInformation",
	"NtQuerySystemTime",
	"NtQueryTimer",
	"NtQueryTimerResolution",		/* 145 */
	"NtQueryValueKey",
	"NtQueryVirtualMemory",
	"NtQueryVolumeInformationFile",
	"NtQueueApcThread",
	"NtRaiseException",			/* 150 */
	"NtRaiseHardError",
	"NtReadFile",
	"NtReadFileScatter",
	"NtReadRequestData",
	"NtReadVirtualMemory",		/* 155 */
	"NtRegisterThreadTerminatePort",
	"NtReleaseMutant",
	"NtReleaseSemaphore",
	"NtRemoveIoCompletion",
	"NtReplaceKey",			/* 160 */
	"NtReplyPort",
	"NtReplyWaitReceivePort",
	"NtReplyWaitReplyPort",
	"NtRequestPort",
	"NtRequestWaitReplyPort",		/* 165 */
	"NtResetEvent",
	"NtRestoreKey",
	"NtResumeThread",
	"NtSaveKey",
	"NtSaveKeyEx",			/* 170 */
	"NtSetBootEntryOrder",
	"NtSetBootOptions",
	"NtSetIoCompletion",
	"NtSetContextThread",
	"NtSetDefaultHardErrorPort",	/* 175 */
	"NtSetDefaultLocale",
	"NtSetDefaultUILanguage",
	"NtSetEaFile",
	"NtSetEvent",
	"NtSetHighEventPair",		/* 180 */
	"NtSetHighWaitLowEventPair",
	"NtSetInformationFile",
	"NtSetInformationKey",
	"NtSetInformationJobObject",
	"NtSetInformationObject",		/* 185 */
	"NtSetInformationProcess",
	"NtSetInformationThread",
	"NtSetInformationToken",
	"NtSetIntervalProfile",
	"NtSetLdtEntries",			/* 190 */
	"NtSetLowEventPair",
	"NtSetLowWaitHighEventPair",
	"NtSetQuotaInformationFile",
	"NtSetSecurityObject",
	"NtSetSystemEnvironmentValue",	/* 195 */
	"NtSetSystemInformation",
	"NtSetSystemPowerState",
	"NtSetSystemTime",
	"NtSetTimer",
	"NtSetTimerResolution",		/* 200 */
	"NtSetUuidSeed",
	"NtSetValueKey",
	"NtSetVolumeInformationFile",
	"NtShutdownSystem",
	"NtSignalAndWaitForSingleObject",	/* 205 */
	"NtStartProfile",
	"NtStopProfile",
	"NtSuspendThread",
	"NtSystemDebugControl",
	"NtTerminateJobObject",		/* 210 */
	"NtTerminateProcess",
	"NtTerminateThread",
	"NtTestAlert",
	"NtTraceEvent",
	"NtTranslateFilePath",		/* 215 */
	"NtUnloadDriver",
	"NtUnloadKey",
	"NtUnlockFile",
	"NtUnlockVirtualMemory",
	"NtUnmapViewOfSection",		/* 220 */
	"NtVdmControl",
	"NtWaitForMultipleObjects",
	"NtWaitForSingleObject",
	"NtWaitHighEventPair",
	"NtWaitLowEventPair",		/* 225 */
	"NtWriteFile",
	"NtWriteFileGather",
	"NtWriteRequestData",
	"NtWriteVirtualMemory",
	"NtW32Call",			/* 230 */
	"NtYieldExecution",
	"NtWineService",
	"NtCatchApc"
};

const char* wine_service[REQ_NB_REQUESTS] =
{
    "req_new_process",
    "req_get_new_process_info",
    "req_new_thread",
    "req_get_startup_info",
    "req_init_process_done",
    "req_init_thread",
    "req_terminate_process",
    "req_terminate_thread",
    "req_get_process_info",
    "req_set_process_info",
    "req_get_thread_info",
    "req_set_thread_info",
    "req_get_dll_info",
    "req_suspend_thread",
    "req_resume_thread",
    "req_load_dll",
    "req_unload_dll",
    "req_queue_apc",
    "req_get_apc_result",
    "req_close_handle",
    "req_set_handle_info",
    "req_dup_handle",
    "req_open_process",
    "req_open_thread",
    "req_select",
    "req_create_event",
    "req_event_op",
    "req_open_event",
    "req_create_mutex",
    "req_release_mutex",
    "req_open_mutex",
    "req_create_semaphore",
    "req_release_semaphore",
    "req_open_semaphore",
    "req_create_file",
    "req_open_file_object",
    "req_alloc_file_handle",
    "req_get_handle_fd",
    "req_flush_file",
    "req_lock_file",
    "req_unlock_file",
    "req_create_socket",
    "req_accept_socket",
    "req_register_accept_async",
    "req_set_socket_event",
    "req_get_socket_event",
    "req_enable_socket_event",
    "req_set_socket_deferred",
    "req_alloc_console",
    "req_free_console",
    "req_get_console_renderer_events",
    "req_open_console",
    "req_get_console_wait_event",
    "req_get_console_mode",
    "req_set_console_mode",
    "req_set_console_input_info",
    "req_get_console_input_info",
    "req_append_console_input_history",
    "req_get_console_input_history",
    "req_create_console_output",
    "req_set_console_output_info",
    "req_get_console_output_info",
    "req_write_console_input",
    "req_read_console_input",
    "req_write_console_output",
    "req_fill_console_output",
    "req_read_console_output",
    "req_move_console_output",
    "req_send_console_signal",
    "req_read_directory_changes",
    "req_read_change",
    "req_create_mapping",
    "req_open_mapping",
    "req_get_mapping_info",
    "req_create_snapshot",
    "req_next_process",
    "req_next_thread",
    "req_next_module",
    "req_wait_debug_event",
    "req_queue_exception_event",
    "req_get_exception_status",
    "req_output_debug_string",
    "req_continue_debug_event",
    "req_debug_process",
    "req_debug_break",
    "req_set_debugger_kill_on_exit",
    "req_read_process_memory",
    "req_write_process_memory",
    "req_create_key",
    "req_open_key",
    "req_delete_key",
    "req_flush_key",
    "req_enum_key",
    "req_set_key_value",
    "req_get_key_value",
    "req_enum_key_value",
    "req_delete_key_value",
    "req_load_registry",
    "req_unload_registry",
    "req_save_registry",
    "req_set_registry_notification",
    "req_create_timer",
    "req_open_timer",
    "req_set_timer",
    "req_cancel_timer",
    "req_get_timer_info",
    "req_get_thread_context",
    "req_set_thread_context",
    "req_get_selector_entry",
    "req_add_atom",
    "req_delete_atom",
    "req_find_atom",
    "req_get_atom_information",
    "req_set_atom_information",
    "req_empty_atom_table",
    "req_init_atom_table",
    "req_get_msg_queue",
    "req_set_queue_fd",
    "req_set_queue_mask",
    "req_get_queue_status",
    "req_get_process_idle_event",
    "req_send_message",
    "req_post_quit_message",
    "req_send_hardware_message",
    "req_get_message",
    "req_reply_message",
    "req_accept_hardware_message",
    "req_get_message_reply",
    "req_set_win_timer",
    "req_kill_win_timer",
    "req_is_window_hung",
    "req_get_serial_info",
    "req_set_serial_info",
    "req_register_async",
    "req_cancel_async",
    "req_ioctl",
    "req_get_ioctl_result",
    "req_create_named_pipe",
    "req_get_named_pipe_info",
    "req_create_window",
    "req_destroy_window",
    "req_get_desktop_window",
    "req_set_window_owner",
    "req_get_window_info",
    "req_set_window_info",
    "req_set_parent",
    "req_get_window_parents",
    "req_get_window_children",
    "req_get_window_children_from_point",
    "req_get_window_tree",
    "req_set_window_pos",
    "req_set_window_visible_rect",
    "req_get_window_rectangles",
    "req_get_window_text",
    "req_set_window_text",
    "req_get_windows_offset",
    "req_get_visible_region",
    "req_get_window_region",
    "req_set_window_region",
    "req_get_update_region",
    "req_update_window_zorder",
    "req_redraw_window",
    "req_set_window_property",
    "req_remove_window_property",
    "req_get_window_property",
    "req_get_window_properties",
    "req_create_winstation",
    "req_open_winstation",
    "req_close_winstation",
    "req_get_process_winstation",
    "req_set_process_winstation",
    "req_enum_winstation",
    "req_create_desktop",
    "req_open_desktop",
    "req_close_desktop",
    "req_get_thread_desktop",
    "req_set_thread_desktop",
    "req_enum_desktop",
    "req_set_user_object_info",
    "req_attach_thread_input",
    "req_get_thread_input",
    "req_get_last_input_time",
    "req_get_key_state",
    "req_set_key_state",
    "req_set_foreground_window",
    "req_set_focus_window",
    "req_set_active_window",
    "req_set_capture_window",
    "req_set_caret_window",
    "req_set_caret_info",
    "req_set_hook",
    "req_remove_hook",
    "req_start_hook_chain",
    "req_finish_hook_chain",
    "req_get_hook_info",
    "req_create_class",
    "req_destroy_class",
    "req_set_class_info",
    "req_set_clipboard_info",
    "req_open_token",
    "req_set_global_windows",
    "req_adjust_token_privileges",
    "req_get_token_privileges",
    "req_check_token_privileges",
    "req_duplicate_token",
    "req_access_check",
    "req_get_token_user",
    "req_get_token_groups",
    "req_set_security_object",
    "req_get_security_object",
    "req_create_mailslot",
    "req_set_mailslot_info",
    "req_create_directory",
    "req_open_directory",
    "req_get_directory_entry",
    "req_create_symlink",
    "req_open_symlink",
    "req_query_symlink",
    "req_get_object_info",
    "req_get_token_impersonation_level",
    "req_allocate_locally_unique_id",
    "req_create_device_manager",
    "req_create_device",
    "req_delete_device",
    "req_get_next_device_request",
    "req_make_process_system",
    "req_get_token_statistics",
    "req_create_completion",
    "req_open_completion",
    "req_add_completion",
    "req_remove_completion",
    "req_query_completion",
    "req_set_completion_info",
    "req_add_fd_completion",
    "req_get_window_layered_info",
    "req_set_window_layered_info",
    "req_async_set_result"
};

void log_call_id(int call_id)
{
	ktrace(" --Syscall: %s\n", syscall[call_id]);
}

EXPORT_SYMBOL(log_call_id);

#endif /* CONFIG_UNIFIED_KERNEL */
