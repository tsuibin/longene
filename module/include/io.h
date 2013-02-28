/*
 * io.h
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
 * io.h: 
 * Refered to ReactOS code
 */
#ifndef _IO_H
#define	_IO_H

#include "win32.h"
#include "object.h"
#include "virtual.h"
#include "ke.h"

#ifdef CONFIG_UNIFIED_KERNEL

#define MAXIMUM_VOLUME_LABEL_LENGTH       (32 * sizeof(WCHAR))
#define DEVICE_TYPE ULONG
#define RESTRICTED_POINTER
#define DUMMYSTRUCTNAME
#define DUMMYUNIONNAME
#define POINTER_ALIGNMENT
#define IRP_MJ_MAXIMUM_FUNCTION           0x1b
#define INITIAL_PRIVILEGE_COUNT		3

struct _IRP;
struct _DEVICE_OBJECT;
struct _DRIVER_OBJECT;

typedef UCHAR KIRQL, *PKIRQL;

typedef enum _DEVICE_POWER_STATE {
	PowerDeviceUnspecified,
	PowerDeviceD0,
	PowerDeviceD1,
	PowerDeviceD2,
	PowerDeviceD3,
	PowerDeviceMaximum
} DEVICE_POWER_STATE, *PDEVICE_POWER_STATE;

typedef struct _SID_IDENTIFIER_AUTHORITY {
	BYTE Value[6];
} SID_IDENTIFIER_AUTHORITY,*PSID_IDENTIFIER_AUTHORITY,*LPSID_IDENTIFIER_AUTHORITY;

typedef struct _SID {
	BYTE  Revision;
	BYTE  SubAuthorityCount;
	SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
	DWORD SubAuthority[ANYSIZE_ARRAY];
} SID, *PISID;

typedef struct _PO_DEVICE_NOTIFY
{
	LIST_ENTRY Link;
	struct _DEVICE_OBJECT* TargetDevice;
	UCHAR WakeNeeded;
	UCHAR OrderLevel;
	struct _DEVICE_OBJECT* DeviceObject;
	PVOID Node;
	PUSHORT DeviceName;
	PUSHORT DriverName;
	ULONG ChildCount;
	ULONG ActiveChild;
} PO_DEVICE_NOTIFY, *PPO_DEVICE_NOTIFY;

typedef struct _DEVICE_RELATIONS {
	ULONG  Count;
	struct _DEVICE_OBJECT* Objects[1];
} DEVICE_RELATIONS, *PDEVICE_RELATIONS;

typedef enum _PNP_DEVNODE_STATE
{
	DeviceNodeUnspecified = 0x300,
	DeviceNodeUninitialized = 0x301,
	DeviceNodeInitialized = 0x302,
	DeviceNodeDriversAdded = 0x303,
	DeviceNodeResourcesAssigned = 0x304,
	DeviceNodeStartPending = 0x305,
	DeviceNodeStartCompletion = 0x306,
	DeviceNodeStartPostWork = 0x307,
	DeviceNodeStarted = 0x308,
	DeviceNodeQueryStopped = 0x309,
	DeviceNodeStopped = 0x30a,
	DeviceNodeRestartCompletion = 0x30b,
	DeviceNodeEnumeratePending = 0x30c,
	DeviceNodeEnumerateCompletion = 0x30d,
	DeviceNodeAwaitingQueuedDeletion = 0x30e,
	DeviceNodeAwaitingQueuedRemoval = 0x30f,
	DeviceNodeQueryRemoved = 0x310,
	DeviceNodeRemovePendingCloses = 0x311,
	DeviceNodeRemoved = 0x312,
	DeviceNodeDeletePendingCloses = 0x313,
	DeviceNodeDeleted = 0x314,
	MaxDeviceNodeState = 0x315,
} PNP_DEVNODE_STATE;

typedef enum _INTERFACE_TYPE {
	InterfaceTypeUndefined = -1,
	Internal,
	Isa,
	Eisa,
	MicroChannel,
	TurboChannel,
	PCIBus,
	VMEBus,
	NuBus,
	PCMCIABus,
	CBus,
	MPIBus,
	MPSABus,
	ProcessorInternal,
	InternalPowerBus,
	PNPISABus,
	PNPBus,
	MaximumInterfaceType
} INTERFACE_TYPE, *PINTERFACE_TYPE;

typedef struct _DEVICE_NODE
{
	/* A tree structure. */
	struct _DEVICE_NODE *Parent;
	struct _DEVICE_NODE *PrevSibling;
	struct _DEVICE_NODE *NextSibling;
	struct _DEVICE_NODE *Child;
	/* The level of deepness in the tree. */
	UINT Level;
	PPO_DEVICE_NOTIFY Notify;
	/* State machine. */
	PNP_DEVNODE_STATE State;
	PNP_DEVNODE_STATE PreviousState;
	PNP_DEVNODE_STATE StateHistory[20];
	UINT StateHistoryEntry;
	/* ? */
	int CompletionStatus;
	/* ? */
	struct _IRP * PendingIrp;
	/* See DNF_* flags below (WinDBG documentation has WRONG values) */
	ULONG Flags;
	/* See DNUF_* flags below (and IRP_MN_QUERY_PNP_DEVICE_STATE) */
	ULONG UserFlags;
	/* See CM_PROB_* values are defined in cfg.h */
	ULONG Problem;
	/* Pointer to the PDO corresponding to the device node. */
	struct _DEVICE_OBJECT* PhysicalDeviceObject;
	/* Resource list as assigned by the PnP arbiter. See IRP_MN_START_DEVICE
	   and ARBITER_INTERFACE (not documented in DDK, but present in headers). */
	struct _CM_RESOURCE_LIST* ResourceList;
	/* Resource list as assigned by the PnP arbiter (translated version). */
	struct _CM_RESOURCE_LIST* ResourceListTranslated;
	/* Instance path relative to the Enum key in registry. */
	UNICODE_STRING InstancePath;
	/* Name of the driver service. */
	UNICODE_STRING ServiceName;
	/* ? */
	struct _DEVICE_OBJECT * DuplicatePDO;
	/* See IRP_MN_QUERY_RESOURCE_REQUIREMENTS. */
	struct _IO_RESOURCE_REQUIREMENTS_LIST* ResourceRequirements;
	/* Information about bus for bus drivers. */
	INTERFACE_TYPE InterfaceType;
	ULONG BusNumber;
	/* Information about underlying bus for child devices. */
	INTERFACE_TYPE ChildInterfaceType;
	ULONG ChildBusNumber;
	USHORT ChildBusTypeIndex;
	/* ? */
	UCHAR RemovalPolicy;
	UCHAR HardwareRemovalPolicy;
	LIST_ENTRY TargetDeviceNotify;
	LIST_ENTRY DeviceArbiterList;
	LIST_ENTRY DeviceTranslatorList;
	USHORT NoTranslatorMask;
	USHORT QueryTranslatorMask;
	USHORT NoArbiterMask;
	USHORT QueryArbiterMask;
	union
	{
		struct _DEVICE_NODE *LegacyDeviceNode;
		PDEVICE_RELATIONS PendingDeviceRelations;
	} OverUsed1;
	union
	{
		struct _DEVICE_NODE *NextResourceDeviceNode;
	} OverUsed2;
	/* See IRP_MN_QUERY_RESOURCES/IRP_MN_FILTER_RESOURCES. */
	struct _CM_RESOURCE_LIST* BootResources;
	/* See the bitfields in DEVICE_CAPABILITIES structure. */
	ULONG CapabilityFlags;
	struct
	{
		ULONG DockStatus;
		LIST_ENTRY ListEntry;
		WCHAR *SerialNumber;
	} DockInfo;
	ULONG DisableableDepends;
	LIST_ENTRY PendedSetInterfaceState;
	LIST_ENTRY LegacyBusListEntry;
	ULONG DriverUnloadRetryCount;
	struct _DEVICE_NODE *PreviousParent;
	ULONG DeletedChidren;

	/* FIXME: Not NT's */
	GUID BusTypeGuid;
	ULONG Address;
} DEVICE_NODE, *PDEVICE_NODE;

typedef struct _MAILSLOT_CREATE_PARAMETERS 
{
	ULONG           MailslotQuota;
	ULONG           MaximumMessageSize;
	LARGE_INTEGER   ReadTimeout;
	BOOLEAN         TimeoutSpecified;
} MAILSLOT_CREATE_PARAMETERS, *PMAILSLOT_CREATE_PARAMETERS;

typedef struct _NAMED_PIPE_CREATE_PARAMETERS 
{
	ULONG           NamedPipeType;
	ULONG           ReadMode;
	ULONG           CompletionMode;
	ULONG           MaximumInstances;
	ULONG           InboundQuota;
	ULONG           OutboundQuota;
	LARGE_INTEGER   DefaultTimeout;
	BOOLEAN         TimeoutSpecified;
} NAMED_PIPE_CREATE_PARAMETERS, *PNAMED_PIPE_CREATE_PARAMETERS;

typedef struct _SCSI_REQUEST_BLOCK {
	USHORT  Length;
	UCHAR  Function;
	UCHAR  SrbStatus;
	UCHAR  ScsiStatus;
	UCHAR  PathId;
	UCHAR  TargetId;
	UCHAR  Lun;
	UCHAR  QueueTag;
	UCHAR  QueueAction;
	UCHAR  CdbLength;
	UCHAR  SenseInfoBufferLength;
	ULONG  SrbFlags;
	ULONG  DataTransferLength;
	ULONG  TimeOutValue;
	PVOID  DataBuffer;
	PVOID  SenseInfoBuffer;
	struct _SCSI_REQUEST_BLOCK  *NextSrb;
	PVOID  OriginalRequest;
	PVOID  SrbExtension;
	_ANONYMOUS_UNION union {
		ULONG  InternalStatus;
		ULONG  QueueSortKey;
	} DUMMYUNIONNAME;
#if defined(_WIN64)
	ULONG Reserved;
#endif
	UCHAR  Cdb[16];
} SCSI_REQUEST_BLOCK, *PSCSI_REQUEST_BLOCK;

typedef struct _DEVOBJ_EXTENSION
{
	CSHORT Type;
	USHORT Size;
	struct _DEVICE_OBJECT* DeviceObject;
	ULONG PowerFlags;
	struct DEVICE_OBJECT_POWER_EXTENSION *Dope;
	ULONG ExtensionFlags;
	struct _DEVICE_NODE *DeviceNode;
	struct _DEVICE_OBJECT* AttachedTo;
	LONG StartIoCount;
	LONG StartIoKey;
	ULONG StartIoFlags;
	struct _VPB *Vpb;
} DEVOBJ_EXTENSION, *PDEVOBJ_EXTENSION;

typedef enum _IO_ALLOCATION_ACTION {
	KeepObject = 1,
	DeallocateObject,
	DeallocateObjectKeepRegisters
} IO_ALLOCATION_ACTION, *PIO_ALLOCATION_ACTION;

typedef IO_ALLOCATION_ACTION
(DDKAPI *PDRIVER_CONTROL)(
		IN struct _DEVICE_OBJECT  *DeviceObject,
		IN struct _IRP  *Irp,
		IN PVOID  MapRegisterBase,
		IN PVOID  Context);

typedef NTSTATUS
(DDKAPI *PDRIVER_ADD_DEVICE)(
		IN struct _DRIVER_OBJECT  *DriverObject,
		IN struct _DEVICE_OBJECT  *PhysicalDeviceObject);

typedef NTSTATUS
(DDKAPI *PIO_COMPLETION_ROUTINE)(
		IN struct _DEVICE_OBJECT  *DeviceObject,
		IN struct _IRP  *Irp,
		IN PVOID  Context);

typedef VOID
(DDKAPI *PDRIVER_CANCEL)(
		IN struct _DEVICE_OBJECT  *DeviceObject,
		IN struct _IRP  *Irp);

typedef NTSTATUS
(DDKAPI *PDRIVER_DISPATCH)(
		IN struct _DEVICE_OBJECT  *DeviceObject,
		IN struct _IRP  *Irp);

typedef NTSTATUS
(DDKAPI *PDRIVER_INITIALIZE)(
		IN struct _DRIVER_OBJECT  *DriverObject,
		IN PUNICODE_STRING  RegistryPath);

typedef VOID
(DDKAPI *PIO_TIMER_ROUTINE)(
		IN struct _DEVICE_OBJECT  *DeviceObject,
		IN PVOID  Context);

typedef struct _COMPRESSED_DATA_INFO {	
	USHORT  CompressionFormatAndEngine;
	UCHAR   CompressionUnitShift;
	UCHAR   ChunkShift;
	UCHAR   ClusterShift;
	UCHAR   Reserved;
	USHORT  NumberOfChunks;
	ULONG   CompressedChunkSizes[ANYSIZE_ARRAY];
} COMPRESSED_DATA_INFO, *PCOMPRESSED_DATA_INFO;

typedef VOID	
(DDKAPI *PDRIVER_STARTIO)(
		IN struct _DEVICE_OBJECT  *DeviceObject,
		IN struct _IRP  *Irp);

typedef VOID
(DDKAPI *PDRIVER_UNLOAD)(
		IN struct _DRIVER_OBJECT  *DriverObject);

typedef VOID
(DDKAPI *PINTERFACE_REFERENCE)(
		PVOID  Context);

typedef union _POWER_STATE {
	SYSTEM_POWER_STATE  SystemState;
	DEVICE_POWER_STATE  DeviceState;
} POWER_STATE, *PPOWER_STATE;

typedef enum _POWER_STATE_TYPE {
	SystemPowerState,
	DevicePowerState
} POWER_STATE_TYPE, *PPOWER_STATE_TYPE;

typedef VOID
(DDKAPI *PINTERFACE_DEREFERENCE)(
		PVOID Context);

typedef struct _DEVICE_CAPABILITIES {	
	USHORT  Size;
	USHORT  Version;
	ULONG  DeviceD1 : 1;
	ULONG  DeviceD2 : 1;
	ULONG  LockSupported : 1;
	ULONG  EjectSupported : 1;
	ULONG  Removable : 1;
	ULONG  DockDevice : 1;
	ULONG  UniqueID : 1;
	ULONG  SilentInstall : 1;
	ULONG  RawDeviceOK : 1;
	ULONG  SurpriseRemovalOK : 1;
	ULONG  WakeFromD0 : 1;
	ULONG  WakeFromD1 : 1;
	ULONG  WakeFromD2 : 1;
	ULONG  WakeFromD3 : 1;
	ULONG  HardwareDisabled : 1;
	ULONG  NonDynamic : 1;
	ULONG  WarmEjectSupported : 1;
	ULONG  NoDisplayInUI : 1;
	ULONG  Reserved : 14;
	ULONG  Address;
	ULONG  UINumber;
	DEVICE_POWER_STATE  DeviceState[PowerSystemMaximum];
	SYSTEM_POWER_STATE  SystemWake;
	DEVICE_POWER_STATE  DeviceWake;
	ULONG  D1Latency;
	ULONG  D2Latency;
	ULONG  D3Latency;
} DEVICE_CAPABILITIES, *PDEVICE_CAPABILITIES;

typedef struct _INTERFACE {
	USHORT  Size;
	USHORT  Version;
	PVOID  Context;
	PINTERFACE_REFERENCE  InterfaceReference;
	PINTERFACE_DEREFERENCE  InterfaceDereference;
} INTERFACE, *PINTERFACE;

typedef enum _BUS_QUERY_ID_TYPE {
	BusQueryDeviceID,
	BusQueryHardwareIDs,
	BusQueryCompatibleIDs,
	BusQueryInstanceID,
	BusQueryDeviceSerialNumber
} BUS_QUERY_ID_TYPE, *PBUS_QUERY_ID_TYPE;

typedef enum _DEVICE_TEXT_TYPE {
	DeviceTextDescription,
	DeviceTextLocationInformation
} DEVICE_TEXT_TYPE, *PDEVICE_TEXT_TYPE;

typedef enum _DEVICE_USAGE_NOTIFICATION_TYPE {	
	DeviceUsageTypeUndefined,
	DeviceUsageTypePaging,
	DeviceUsageTypeHibernation,
	DeviceUsageTypeDumpFile
} DEVICE_USAGE_NOTIFICATION_TYPE;

typedef struct _POWER_SEQUENCE {
	ULONG  SequenceD1;
	ULONG  SequenceD2;
	ULONG  SequenceD3;
} POWER_SEQUENCE, *PPOWER_SEQUENCE;

typedef struct _FILE_GET_QUOTA_INFORMATION {
	ULONG   NextEntryOffset;
	ULONG   SidLength;
	SID     Sid;
} FILE_GET_QUOTA_INFORMATION, *PFILE_GET_QUOTA_INFORMATION;

typedef struct _KDEVICE_QUEUE {
	CSHORT  Type;
	CSHORT  Size;
	LIST_ENTRY  DeviceListHead;
	spinlock_t  Lock;
	BOOLEAN  Busy;
} KDEVICE_QUEUE, *PKDEVICE_QUEUE, *RESTRICTED_POINTER PRKDEVICE_QUEUE;

typedef struct _KDEVICE_QUEUE_ENTRY {
	LIST_ENTRY  DeviceListEntry;
	ULONG  SortKey;
	BOOLEAN  Inserted;
} KDEVICE_QUEUE_ENTRY, *PKDEVICE_QUEUE_ENTRY,
	*RESTRICTED_POINTER PRKDEVICE_QUEUE_ENTRY;

typedef struct _WAIT_CONTEXT_BLOCK {
	KDEVICE_QUEUE_ENTRY  WaitQueueEntry;
	PDRIVER_CONTROL  DeviceRoutine;
	PVOID  DeviceContext;
	ULONG  NumberOfMapRegisters;
	PVOID  DeviceObject;
	PVOID  CurrentIrp;
	struct kdpc*  BufferChainingDpc;
} WAIT_CONTEXT_BLOCK, *PWAIT_CONTEXT_BLOCK;

typedef struct _IRP {
	CSHORT  Type;
	USHORT  Size;
	struct _MDL  *MdlAddress;
	ULONG  Flags;
	union {
		struct _IRP  *MasterIrp;
		LONG  IrpCount;
		PVOID  SystemBuffer;
	} AssociatedIrp;
	LIST_ENTRY  ThreadListEntry;
	IO_STATUS_BLOCK  IoStatus;
	KPROCESSOR_MODE  RequestorMode;
	BOOLEAN  PendingReturned;
	CHAR  StackCount;
	CHAR  CurrentLocation;
	BOOLEAN  Cancel;
	KIRQL  CancelIrql;
	CCHAR  ApcEnvironment;
	UCHAR  AllocationFlags;
	PIO_STATUS_BLOCK  UserIosb;
	struct kevent*  UserEvent;
	union {
		struct {
			PIO_APC_ROUTINE  UserApcRoutine;
			PVOID  UserApcContext;
		} AsynchronousParameters;
		LARGE_INTEGER  AllocationSize;
	} Overlay;
	PDRIVER_CANCEL  CancelRoutine;
	PVOID  UserBuffer;
	union {
		struct {
			_ANONYMOUS_UNION union {
				KDEVICE_QUEUE_ENTRY  DeviceQueueEntry;
				_ANONYMOUS_STRUCT struct {
					PVOID  DriverContext[4];
				} DUMMYSTRUCTNAME;
			} DUMMYUNIONNAME;
			struct ethread* Thread;
			PCHAR  AuxiliaryBuffer;
			_ANONYMOUS_STRUCT struct {
				LIST_ENTRY  ListEntry;
				_ANONYMOUS_UNION union {
					struct _IO_STACK_LOCATION  *CurrentStackLocation;
					ULONG  PacketType;
				} DUMMYUNIONNAME;
			} DUMMYSTRUCTNAME;
			struct _FILE_OBJECT  *OriginalFileObject;
		} Overlay;
		struct kapc  Apc;
		PVOID  CompletionKey;
	} Tail;
} IRP;
typedef struct _IRP *PIRP;

typedef struct _CM_PARTIAL_RESOURCE_DESCRIPTOR {
	UCHAR Type;
	UCHAR ShareDisposition;
	USHORT Flags;
	union {
		struct {
			PHYSICAL_ADDRESS Start;
			ULONG Length;
		} Generic;
		struct {
			PHYSICAL_ADDRESS Start;
			ULONG Length;
		} Port;
		struct {
			ULONG Level;
			ULONG Vector;
			ULONG Affinity;
		} Interrupt;
		struct {
			PHYSICAL_ADDRESS Start;
			ULONG Length;
		} Memory;
		struct {
			ULONG Channel;
			ULONG Port;
			ULONG Reserved1;
		} Dma;
		struct {
			ULONG Data[3];
		} DevicePrivate;
		struct {
			ULONG Start;
			ULONG Length;
			ULONG Reserved;
		} BusNumber;
		struct {
			ULONG DataSize;
			ULONG Reserved1;
			ULONG Reserved2;
		} DeviceSpecificData;
	} u;
} CM_PARTIAL_RESOURCE_DESCRIPTOR, *PCM_PARTIAL_RESOURCE_DESCRIPTOR;

typedef struct _CM_PARTIAL_RESOURCE_LIST {
	USHORT  Version;
	USHORT  Revision;
	ULONG  Count;
	CM_PARTIAL_RESOURCE_DESCRIPTOR PartialDescriptors[1];
} CM_PARTIAL_RESOURCE_LIST, *PCM_PARTIAL_RESOURCE_LIST;

typedef struct _CM_FULL_RESOURCE_DESCRIPTOR {
	INTERFACE_TYPE  InterfaceType;
	ULONG  BusNumber;
	CM_PARTIAL_RESOURCE_LIST  PartialResourceList;
} CM_FULL_RESOURCE_DESCRIPTOR, *PCM_FULL_RESOURCE_DESCRIPTOR;

typedef struct _CM_RESOURCE_LIST {
	ULONG  Count;
	CM_FULL_RESOURCE_DESCRIPTOR  List[1];
} CM_RESOURCE_LIST, *PCM_RESOURCE_LIST;

typedef struct _IO_RESOURCE_DESCRIPTOR {
	UCHAR  Option;
	UCHAR  Type;
	UCHAR  ShareDisposition;
	UCHAR  Spare1;
	USHORT  Flags;
	USHORT  Spare2;
	union {
		struct {
			ULONG  Length;
			ULONG  Alignment;
			PHYSICAL_ADDRESS  MinimumAddress;
			PHYSICAL_ADDRESS  MaximumAddress;
		} Port;
		struct {
			ULONG  Length;
			ULONG  Alignment;
			PHYSICAL_ADDRESS  MinimumAddress;
			PHYSICAL_ADDRESS  MaximumAddress;
		} Memory;
		struct {
			ULONG  MinimumVector;
			ULONG  MaximumVector;
		} Interrupt;
		struct {
			ULONG  MinimumChannel;
			ULONG  MaximumChannel;
		} Dma;
		struct {
			ULONG  Length;
			ULONG  Alignment;
			PHYSICAL_ADDRESS  MinimumAddress;
			PHYSICAL_ADDRESS  MaximumAddress;
		} Generic;
		struct {
			ULONG  Data[3];
		} DevicePrivate;
		struct {
			ULONG  Length;
			ULONG  MinBusNumber;
			ULONG  MaxBusNumber;
			ULONG  Reserved;
		} BusNumber;
		struct {
			ULONG  Priority;
			ULONG  Reserved1;
			ULONG  Reserved2;
		} ConfigData;
	} u;
} IO_RESOURCE_DESCRIPTOR, *PIO_RESOURCE_DESCRIPTOR;

typedef struct _IO_RESOURCE_LIST {
	USHORT  Version;
	USHORT  Revision;
	ULONG  Count;
	IO_RESOURCE_DESCRIPTOR  Descriptors[1];
} IO_RESOURCE_LIST, *PIO_RESOURCE_LIST;

typedef struct _IO_RESOURCE_REQUIREMENTS_LIST {
	ULONG  ListSize;
	INTERFACE_TYPE  InterfaceType;
	ULONG  BusNumber;
	ULONG  SlotNumber;
	ULONG  Reserved[3];
	ULONG  AlternativeLists;
	IO_RESOURCE_LIST  List[1];
} IO_RESOURCE_REQUIREMENTS_LIST, *PIO_RESOURCE_REQUIREMENTS_LIST;

typedef struct _VPB {	
	CSHORT  Type;
	CSHORT  Size;
	USHORT  Flags;
	USHORT  VolumeLabelLength;
	struct _DEVICE_OBJECT  *DeviceObject;
	struct _DEVICE_OBJECT  *RealDevice;
	ULONG  SerialNumber;
	ULONG  ReferenceCount;
	WCHAR  VolumeLabel[MAXIMUM_VOLUME_LABEL_LENGTH / sizeof(WCHAR)];
} VPB, *PVPB;

typedef struct _IO_TIMER 
{
	USHORT Type;
	USHORT TimerEnabled;
	LIST_ENTRY IoTimerList;
	PIO_TIMER_ROUTINE TimerRoutine;
	PVOID Context;
	struct _DEVICE_OBJECT* DeviceObject;
} IO_TIMER, *PIO_TIMER;

typedef struct _DEVICE_OBJECT {
	CSHORT  Type;
	USHORT  Size;
	LONG  ReferenceCount;
	struct _DRIVER_OBJECT  *DriverObject;
	struct _DEVICE_OBJECT  *NextDevice;
	struct _DEVICE_OBJECT  *AttachedDevice;
	struct _IRP  *CurrentIrp;
	PIO_TIMER  Timer;
	ULONG  Flags;
	ULONG  Characteristics;
	PVPB  Vpb;
	PVOID  DeviceExtension;
	DEVICE_TYPE  DeviceType;
	CCHAR  StackSize;
	union {
		LIST_ENTRY  ListEntry;
		WAIT_CONTEXT_BLOCK  Wcb;
	} Queue;
	ULONG  AlignmentRequirement;
	KDEVICE_QUEUE  DeviceQueue;
	struct kdpc  Dpc;
	ULONG  ActiveThreadCount;
	PSECURITY_DESCRIPTOR  SecurityDescriptor;
	struct kevent  DeviceLock;
	USHORT  SectorSize;
	USHORT  Spare1;
	struct _DEVOBJ_EXTENSION  *DeviceObjectExtension;
	PVOID  Reserved;
} DEVICE_OBJECT, *PDEVICE_OBJECT;

typedef enum _DEVICE_RELATION_TYPE {
	BusRelations,
	EjectionRelations,
	PowerRelations,
	RemovalRelations,
	TargetDeviceRelation,
	SingleBusRelations
} DEVICE_RELATION_TYPE, *PDEVICE_RELATION_TYPE;

typedef struct _MDL {
	struct _MDL  *Next;
	CSHORT  Size;
	CSHORT  MdlFlags;
	struct eprocess  *Process;
	PVOID  MappedSystemVa;
	PVOID  StartVa;
	ULONG  ByteCount;
	ULONG  ByteOffset;
} MDL, *PMDL;

typedef struct _DRIVER_EXTENSION {
	struct _DRIVER_OBJECT  *DriverObject;
	PDRIVER_ADD_DEVICE  AddDevice;
	ULONG  Count;
	UNICODE_STRING  ServiceKeyName;
} DRIVER_EXTENSION, *PDRIVER_EXTENSION;

typedef BOOLEAN	
(DDKAPI *PFAST_IO_CHECK_IF_POSSIBLE)(
		IN struct _FILE_OBJECT  *FileObject,
		IN PLARGE_INTEGER  FileOffset,
		IN ULONG  Length,
		IN BOOLEAN  Wait,
		IN ULONG  LockKey,
		IN BOOLEAN  CheckForReadOperation,
		OUT PIO_STATUS_BLOCK  IoStatus,
		IN struct _DEVICE_OBJECT  *DeviceObject);

typedef BOOLEAN
(DDKAPI *PFAST_IO_READ)(
		IN struct _FILE_OBJECT  *FileObject,
		IN PLARGE_INTEGER  FileOffset,
		IN ULONG  Length,
		IN BOOLEAN  Wait,
		IN ULONG  LockKey,
		OUT PVOID  Buffer,
		OUT PIO_STATUS_BLOCK  IoStatus,
		IN struct _DEVICE_OBJECT  *DeviceObject);

typedef BOOLEAN
(DDKAPI *PFAST_IO_WRITE)(
		IN struct _FILE_OBJECT  *FileObject,
		IN PLARGE_INTEGER  FileOffset,
		IN ULONG  Length,
		IN BOOLEAN  Wait,
		IN ULONG  LockKey,
		IN PVOID  Buffer,
		OUT PIO_STATUS_BLOCK  IoStatus,
		IN struct _DEVICE_OBJECT  *DeviceObject);

typedef BOOLEAN
(DDKAPI *PFAST_IO_QUERY_BASIC_INFO)(
		IN struct _FILE_OBJECT  *FileObject,
		IN BOOLEAN  Wait,
		OUT PFILE_BASIC_INFORMATION  Buffer,
		OUT PIO_STATUS_BLOCK  IoStatus,
		IN struct _DEVICE_OBJECT  *DeviceObject);

typedef BOOLEAN
(DDKAPI *PFAST_IO_QUERY_STANDARD_INFO)(
		IN struct _FILE_OBJECT  *FileObject,
		IN BOOLEAN  Wait,
		OUT PFILE_STANDARD_INFORMATION  Buffer,
		OUT PIO_STATUS_BLOCK  IoStatus,
		IN struct _DEVICE_OBJECT  *DeviceObject);

typedef BOOLEAN
(DDKAPI *PFAST_IO_LOCK)(
		IN struct _FILE_OBJECT  *FileObject,
		IN PLARGE_INTEGER  FileOffset,
		IN PLARGE_INTEGER  Length,
		struct eprocess*  ProcessId,
		ULONG  Key,
		BOOLEAN  FailImmediately,
		BOOLEAN  ExclusiveLock,
		OUT PIO_STATUS_BLOCK  IoStatus,
		IN struct _DEVICE_OBJECT  *DeviceObject);

typedef BOOLEAN
(DDKAPI *PFAST_IO_UNLOCK_SINGLE)(
		IN struct _FILE_OBJECT  *FileObject,
		IN PLARGE_INTEGER  FileOffset,
		IN PLARGE_INTEGER  Length,
		struct eprocess*  ProcessId,
		ULONG  Key,
		OUT PIO_STATUS_BLOCK  IoStatus,
		IN struct _DEVICE_OBJECT  *DeviceObject);

typedef BOOLEAN
(DDKAPI *PFAST_IO_UNLOCK_ALL)(
		IN struct _FILE_OBJECT  *FileObject,
		struct eprocess*  ProcessId,
		OUT PIO_STATUS_BLOCK  IoStatus,
		IN struct _DEVICE_OBJECT  *DeviceObject);

typedef BOOLEAN
(DDKAPI *PFAST_IO_UNLOCK_ALL_BY_KEY)(
		IN struct _FILE_OBJECT  *FileObject,
		struct eprocess*  ProcessId,
		ULONG  Key,
		OUT PIO_STATUS_BLOCK  IoStatus,
		IN struct _DEVICE_OBJECT  *DeviceObject);

typedef BOOLEAN
(DDKAPI *PFAST_IO_DEVICE_CONTROL)(
		IN struct _FILE_OBJECT  *FileObject,
		IN BOOLEAN  Wait,
		IN PVOID  InputBuffer  OPTIONAL,
		IN ULONG  InputBufferLength,
		OUT PVOID  OutputBuffer  OPTIONAL,
		IN ULONG  OutputBufferLength,
		IN ULONG  IoControlCode,
		OUT PIO_STATUS_BLOCK  IoStatus,
		IN struct _DEVICE_OBJECT  *DeviceObject);

typedef VOID
(DDKAPI *PFAST_IO_ACQUIRE_FILE)(
		IN struct _FILE_OBJECT  *FileObject);

typedef VOID
(DDKAPI *PFAST_IO_RELEASE_FILE)(
		IN struct _FILE_OBJECT  *FileObject);

typedef VOID
(DDKAPI *PFAST_IO_DETACH_DEVICE)(
		IN struct _DEVICE_OBJECT  *SourceDevice,
		IN struct _DEVICE_OBJECT  *TargetDevice);

typedef BOOLEAN
(DDKAPI *PFAST_IO_QUERY_NETWORK_OPEN_INFO)(
		IN struct _FILE_OBJECT  *FileObject,
		IN BOOLEAN  Wait,
		OUT struct _FILE_NETWORK_OPEN_INFORMATION  *Buffer,
		OUT struct _IO_STATUS_BLOCK  *IoStatus,
		IN struct _DEVICE_OBJECT  *DeviceObject);

typedef NTSTATUS
(DDKAPI *PFAST_IO_ACQUIRE_FOR_MOD_WRITE)(
		IN struct _FILE_OBJECT  *FileObject,
		IN PLARGE_INTEGER  EndingOffset,
		OUT struct eresource  **ResourceToRelease,
		IN struct _DEVICE_OBJECT  *DeviceObject);

typedef BOOLEAN
(DDKAPI *PFAST_IO_MDL_READ)(
		IN struct _FILE_OBJECT  *FileObject,
		IN PLARGE_INTEGER  FileOffset,
		IN ULONG  Length,
		IN ULONG  LockKey,
		OUT PMDL  *MdlChain,
		OUT PIO_STATUS_BLOCK  IoStatus,
		IN struct _DEVICE_OBJECT  *DeviceObject);

typedef BOOLEAN
(DDKAPI *PFAST_IO_MDL_READ_COMPLETE)(
		IN struct _FILE_OBJECT *FileObject,
		IN PMDL MdlChain,
		IN struct _DEVICE_OBJECT *DeviceObject);

typedef BOOLEAN
(DDKAPI *PFAST_IO_PREPARE_MDL_WRITE)(
		IN struct _FILE_OBJECT  *FileObject,
		IN PLARGE_INTEGER  FileOffset,
		IN ULONG  Length,
		IN ULONG  LockKey,
		OUT PMDL  *MdlChain,
		OUT PIO_STATUS_BLOCK  IoStatus,
		IN struct _DEVICE_OBJECT  *DeviceObject);

typedef BOOLEAN
(DDKAPI *PFAST_IO_MDL_WRITE_COMPLETE)(
		IN struct _FILE_OBJECT  *FileObject,
		IN PLARGE_INTEGER  FileOffset,
		IN PMDL  MdlChain,
		IN struct _DEVICE_OBJECT  *DeviceObject);

typedef BOOLEAN
(DDKAPI *PFAST_IO_READ_COMPRESSED)(
		IN struct _FILE_OBJECT  *FileObject,
		IN PLARGE_INTEGER  FileOffset,
		IN ULONG  Length,
		IN ULONG  LockKey,
		OUT PVOID  Buffer,
		OUT PMDL  *MdlChain,
		OUT PIO_STATUS_BLOCK  IoStatus,
		OUT struct _COMPRESSED_DATA_INFO  *CompressedDataInfo,
		IN ULONG  CompressedDataInfoLength,
		IN struct _DEVICE_OBJECT  *DeviceObject);

typedef BOOLEAN
(DDKAPI *PFAST_IO_WRITE_COMPRESSED)(
		IN struct _FILE_OBJECT  *FileObject,
		IN PLARGE_INTEGER  FileOffset,
		IN ULONG  Length,
		IN ULONG  LockKey,
		IN PVOID  Buffer,
		OUT PMDL  *MdlChain,
		OUT PIO_STATUS_BLOCK  IoStatus,
		IN struct _COMPRESSED_DATA_INFO  *CompressedDataInfo,
		IN ULONG  CompressedDataInfoLength,
		IN struct _DEVICE_OBJECT  *DeviceObject);

typedef BOOLEAN
(DDKAPI *PFAST_IO_MDL_READ_COMPLETE_COMPRESSED)(
		IN struct _FILE_OBJECT  *FileObject,
		IN PMDL  MdlChain,
		IN struct _DEVICE_OBJECT  *DeviceObject);

typedef BOOLEAN
(DDKAPI *PFAST_IO_MDL_WRITE_COMPLETE_COMPRESSED)(
		IN struct _FILE_OBJECT  *FileObject,
		IN PLARGE_INTEGER  FileOffset,
		IN PMDL  MdlChain,
		IN struct _DEVICE_OBJECT  *DeviceObject);

typedef BOOLEAN
(DDKAPI *PFAST_IO_QUERY_OPEN)(
		IN struct _IRP  *Irp,
		OUT PFILE_NETWORK_OPEN_INFORMATION  NetworkInformation,
		IN struct _DEVICE_OBJECT  *DeviceObject);

typedef NTSTATUS
(DDKAPI *PFAST_IO_RELEASE_FOR_MOD_WRITE)(
		IN struct _FILE_OBJECT  *FileObject,
		IN struct eresource  *ResourceToRelease,
		IN struct _DEVICE_OBJECT  *DeviceObject);

typedef NTSTATUS
(DDKAPI *PFAST_IO_ACQUIRE_FOR_CCFLUSH)(
		IN struct _FILE_OBJECT  *FileObject,
		IN struct _DEVICE_OBJECT  *DeviceObject);

typedef NTSTATUS
(DDKAPI *PFAST_IO_RELEASE_FOR_CCFLUSH) (
		IN struct _FILE_OBJECT  *FileObject,
		IN struct _DEVICE_OBJECT  *DeviceObject);

typedef struct _FAST_IO_DISPATCH {
	ULONG  SizeOfFastIoDispatch;
	PFAST_IO_CHECK_IF_POSSIBLE  FastIoCheckIfPossible;
	PFAST_IO_READ  FastIoRead;
	PFAST_IO_WRITE  FastIoWrite;
	PFAST_IO_QUERY_BASIC_INFO  FastIoQueryBasicInfo;
	PFAST_IO_QUERY_STANDARD_INFO  FastIoQueryStandardInfo;
	PFAST_IO_LOCK  FastIoLock;
	PFAST_IO_UNLOCK_SINGLE  FastIoUnlockSingle;
	PFAST_IO_UNLOCK_ALL  FastIoUnlockAll;
	PFAST_IO_UNLOCK_ALL_BY_KEY  FastIoUnlockAllByKey;
	PFAST_IO_DEVICE_CONTROL  FastIoDeviceControl;
	PFAST_IO_ACQUIRE_FILE  AcquireFileForNtCreateSection;
	PFAST_IO_RELEASE_FILE  ReleaseFileForNtCreateSection;
	PFAST_IO_DETACH_DEVICE  FastIoDetachDevice;
	PFAST_IO_QUERY_NETWORK_OPEN_INFO  FastIoQueryNetworkOpenInfo;
	PFAST_IO_ACQUIRE_FOR_MOD_WRITE  AcquireForModWrite;
	PFAST_IO_MDL_READ  MdlRead;
	PFAST_IO_MDL_READ_COMPLETE  MdlReadComplete;
	PFAST_IO_PREPARE_MDL_WRITE  PrepareMdlWrite;
	PFAST_IO_MDL_WRITE_COMPLETE  MdlWriteComplete;
	PFAST_IO_READ_COMPRESSED  FastIoReadCompressed;
	PFAST_IO_WRITE_COMPRESSED  FastIoWriteCompressed;
	PFAST_IO_MDL_READ_COMPLETE_COMPRESSED  MdlReadCompleteCompressed;
	PFAST_IO_MDL_WRITE_COMPLETE_COMPRESSED  MdlWriteCompleteCompressed;
	PFAST_IO_QUERY_OPEN  FastIoQueryOpen;
	PFAST_IO_RELEASE_FOR_MOD_WRITE  ReleaseForModWrite;
	PFAST_IO_ACQUIRE_FOR_CCFLUSH  AcquireForCcFlush;
	PFAST_IO_RELEASE_FOR_CCFLUSH  ReleaseForCcFlush;
} FAST_IO_DISPATCH, *PFAST_IO_DISPATCH;

typedef struct _DRIVER_OBJECT {	
	CSHORT  Type;
	CSHORT  Size;
	PDEVICE_OBJECT  DeviceObject;
	ULONG  Flags;
	PVOID  DriverStart;
	ULONG  DriverSize;
	PVOID  DriverSection;
	PDRIVER_EXTENSION  DriverExtension;
	UNICODE_STRING  DriverName;
	PUNICODE_STRING  HardwareDatabase;
	PFAST_IO_DISPATCH  FastIoDispatch;
	PDRIVER_INITIALIZE  DriverInit;
	PDRIVER_STARTIO  DriverStartIo;
	PDRIVER_UNLOAD  DriverUnload;
	PDRIVER_DISPATCH  MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];
} DRIVER_OBJECT;

typedef struct _SECTION_OBJECT_POINTERS {
	PVOID  DataSectionObject;
	PVOID  SharedCacheMap;
	PVOID  ImageSectionObject;
} SECTION_OBJECT_POINTERS, *PSECTION_OBJECT_POINTERS;

typedef struct _IO_COMPLETION_CONTEXT {	
	PVOID  Port;
	PVOID  Key;
} IO_COMPLETION_CONTEXT, *PIO_COMPLETION_CONTEXT;

typedef struct _FILE_OBJECT {
	CSHORT  Type;
	CSHORT  Size;
	PDEVICE_OBJECT  DeviceObject;
	PVPB  Vpb;
	PVOID  FsContext;
	PVOID  FsContext2;
	PSECTION_OBJECT_POINTERS  SectionObjectPointer;
	PVOID  PrivateCacheMap;
	NTSTATUS  FinalStatus;
	struct _FILE_OBJECT  *RelatedFileObject;
	BOOLEAN  LockOperation;
	BOOLEAN  DeletePending;
	BOOLEAN  ReadAccess;
	BOOLEAN  WriteAccess;
	BOOLEAN  DeleteAccess;
	BOOLEAN  SharedRead;
	BOOLEAN  SharedWrite;
	BOOLEAN  SharedDelete;
	ULONG  Flags;
	UNICODE_STRING  FileName;
	LARGE_INTEGER  CurrentByteOffset;
	ULONG  Waiters;
	ULONG  Busy;
	PVOID  LastLock;
	struct kevent  Lock;
	struct kevent  Event;
	PIO_COMPLETION_CONTEXT  CompletionContext;
} FILE_OBJECT;

typedef struct _FILE_OBJECT *PFILE_OBJECT;

typedef struct _INITIAL_PRIVILEGE_SET {
	ULONG  PrivilegeCount;
	ULONG  Control;
	LUID_AND_ATTRIBUTES  Privilege[INITIAL_PRIVILEGE_COUNT];
} INITIAL_PRIVILEGE_SET, * PINITIAL_PRIVILEGE_SET;

typedef struct _SECURITY_SUBJECT_CONTEXT {
	PACCESS_TOKEN  ClientToken;
	SECURITY_IMPERSONATION_LEVEL  ImpersonationLevel;
	PACCESS_TOKEN  PrimaryToken;
	PVOID  ProcessAuditId;
} SECURITY_SUBJECT_CONTEXT, *PSECURITY_SUBJECT_CONTEXT;

typedef struct _IO_SECURITY_CONTEXT {
	PSECURITY_QUALITY_OF_SERVICE  SecurityQos;
	PACCESS_STATE  AccessState;
	ACCESS_MASK  DesiredAccess;
	ULONG  FullCreateOptions;
} IO_SECURITY_CONTEXT, *PIO_SECURITY_CONTEXT;

typedef struct _IO_STACK_LOCATION {
	UCHAR  MajorFunction;
	UCHAR  MinorFunction;
	UCHAR  Flags;
	UCHAR  Control;
	union {
		struct {
			PIO_SECURITY_CONTEXT  SecurityContext;
			ULONG  Options;
			USHORT POINTER_ALIGNMENT  FileAttributes;
			USHORT  ShareAccess;
			ULONG POINTER_ALIGNMENT  EaLength;
		} Create;
		/* FIXME: CreatePipe and CreateMailslot aren't defined in official
		 * DDK/IFS headers. */
		struct {
			PIO_SECURITY_CONTEXT  SecurityContext;
			ULONG  Options;
			USHORT  Reserved;
			USHORT  ShareAccess;
			struct _NAMED_PIPE_CREATE_PARAMETERS  *Parameters;
		} CreatePipe;
		struct {
			PIO_SECURITY_CONTEXT  SecurityContext;
			ULONG  Options;
			USHORT  Reserved;
			USHORT  ShareAccess;
			struct _MAILSLOT_CREATE_PARAMETERS  *Parameters;
		} CreateMailslot;
		struct {
			ULONG  Length;
			ULONG POINTER_ALIGNMENT  Key;
			LARGE_INTEGER  ByteOffset;
		} Read;
		struct {
			ULONG  Length;
			ULONG POINTER_ALIGNMENT  Key;
			LARGE_INTEGER  ByteOffset;
		} Write;
		struct {
			ULONG  Length;
			PUNICODE_STRING  FileName;
			FILE_INFORMATION_CLASS  FileInformationClass;
			ULONG  FileIndex;
		} QueryDirectory;
		struct {
			ULONG  Length;
			ULONG  CompletionFilter;
		} NotifyDirectory;
		struct {
			ULONG  Length;
			FILE_INFORMATION_CLASS POINTER_ALIGNMENT  FileInformationClass;
		} QueryFile;
		struct {
			ULONG  Length;
			FILE_INFORMATION_CLASS POINTER_ALIGNMENT  FileInformationClass;
			PFILE_OBJECT  FileObject;
			_ANONYMOUS_UNION union {
				_ANONYMOUS_STRUCT struct {
					BOOLEAN  ReplaceIfExists;
					BOOLEAN  AdvanceOnly;
				} DUMMYSTRUCTNAME;
				ULONG  ClusterCount;
				HANDLE  DeleteHandle;
			} DUMMYUNIONNAME;
		} SetFile;
		struct {
			ULONG  Length;
			PVOID  EaList;
			ULONG  EaListLength;
			ULONG  EaIndex;
		} QueryEa;
		struct {
			ULONG  Length;
		} SetEa;
		struct {
			ULONG  Length;
			FS_INFORMATION_CLASS POINTER_ALIGNMENT  FsInformationClass;
		} QueryVolume;
		struct {
			ULONG  Length;
			FS_INFORMATION_CLASS  FsInformationClass;
		} SetVolume;
		struct {
			ULONG  OutputBufferLength;
			ULONG  InputBufferLength;
			ULONG  FsControlCode;
			PVOID  Type3InputBuffer;
		} FileSystemControl;
		struct {
			PLARGE_INTEGER  Length;
			ULONG  Key;
			LARGE_INTEGER  ByteOffset;
		} LockControl;
		struct {
			ULONG  OutputBufferLength;
			ULONG POINTER_ALIGNMENT  InputBufferLength;
			ULONG POINTER_ALIGNMENT  IoControlCode;
			PVOID  Type3InputBuffer;
		} DeviceIoControl;
		struct {
			SECURITY_INFORMATION  SecurityInformation;
			ULONG POINTER_ALIGNMENT  Length;
		} QuerySecurity;
		struct {
			SECURITY_INFORMATION  SecurityInformation;
			PSECURITY_DESCRIPTOR  SecurityDescriptor;
		} SetSecurity;
		struct {
			PVPB  Vpb;
			PDEVICE_OBJECT  DeviceObject;
		} MountVolume;
		struct {
			PVPB  Vpb;
			PDEVICE_OBJECT  DeviceObject;
		} VerifyVolume;
		struct {
			struct _SCSI_REQUEST_BLOCK  *Srb;
		} Scsi;
		struct {
			ULONG  Length;
			PSID  StartSid;
			struct _FILE_GET_QUOTA_INFORMATION  *SidList;
			ULONG  SidListLength;
		} QueryQuota;
		struct {
			ULONG  Length;
		} SetQuota;
		struct {
			DEVICE_RELATION_TYPE  Type;
		} QueryDeviceRelations;
		struct {
			const GUID  *InterfaceType;
			USHORT  Size;
			USHORT  Version;
			PINTERFACE  Interface;
			PVOID  InterfaceSpecificData;
		} QueryInterface;
		struct {
			PDEVICE_CAPABILITIES  Capabilities;
		} DeviceCapabilities;
		struct {
			PIO_RESOURCE_REQUIREMENTS_LIST  IoResourceRequirementList;
		} FilterResourceRequirements;
		struct {
			ULONG  WhichSpace;
			PVOID  Buffer;
			ULONG  Offset;
			ULONG POINTER_ALIGNMENT  Length;
		} ReadWriteConfig;
		struct {
			BOOLEAN  Lock;
		} SetLock;
		struct {
			BUS_QUERY_ID_TYPE  IdType;
		} QueryId;
		struct {
			DEVICE_TEXT_TYPE  DeviceTextType;
			LCID POINTER_ALIGNMENT  LocaleId;
		} QueryDeviceText;
		struct {
			BOOLEAN  InPath;
			BOOLEAN  Reserved[3];
			DEVICE_USAGE_NOTIFICATION_TYPE POINTER_ALIGNMENT  Type;
		} UsageNotification;
		struct {
			SYSTEM_POWER_STATE  PowerState;
		} WaitWake;
		struct {
			PPOWER_SEQUENCE  PowerSequence;
		} PowerSequence;
		struct {
			ULONG  SystemContext;
			POWER_STATE_TYPE POINTER_ALIGNMENT  Type;
			POWER_STATE POINTER_ALIGNMENT  State;
			POWER_ACTION POINTER_ALIGNMENT  ShutdownType;
		} Power;
		struct {
			PCM_RESOURCE_LIST  AllocatedResources;
			PCM_RESOURCE_LIST  AllocatedResourcesTranslated;
		} StartDevice;
		struct {
			ULONG_PTR  ProviderId;
			PVOID  DataPath;
			ULONG  BufferSize;
			PVOID  Buffer;
		} WMI;
		struct {
			PVOID  Argument1;
			PVOID  Argument2;
			PVOID  Argument3;
			PVOID  Argument4;
		} Others;
	} Parameters;
	PDEVICE_OBJECT  DeviceObject;
	PFILE_OBJECT  FileObject;
	PIO_COMPLETION_ROUTINE  CompletionRoutine;
	PVOID  Context;
} IO_STACK_LOCATION, *PIO_STACK_LOCATION;

typedef struct _FILE_CONTROL_OBJECT {
	struct list_head FileList;
	ULONG Access;
} FILE_CONTROL_OBJECT, *PFILE_CONTROL_OBJECT;

VOID init_io(VOID);

VOID io_open_file(OB_OPEN_REASON OpenReason,
		struct eprocess* Process OPTIONAL,
		PVOID Object,
		ACCESS_MASK GrantedAccess,
		ULONG HandleCount);

VOID io_close_file(struct eprocess* Process OPTIONAL,
		PVOID Object,
		ACCESS_MASK GrantedAccess,
		ULONG ProcessHandleCount,
		ULONG systemHandleCount);

VOID io_delete_file(PVOID Object);

VOID io_create_file(PVOID Object, PVOID Param);

NTSTATUS
io_create_symbol_link(PUNICODE_STRING SymbolicLinkName,
		PUNICODE_STRING TargetName);

static inline BOOLEAN is_dos_driver(PUNICODE_STRING Name)
{
	/* "[A-Z]:" is Dos driver */
	return (Name->Length == 2 * sizeof(WCHAR)
			&& Name->Buffer[1] == (WCHAR)':'
			&& (*Name->Buffer >= (WCHAR)'A' && *Name->Buffer <= (WCHAR)'Z'))
		? TRUE
		: FALSE;
}

#endif /* CONFIG_UNIFIED_KERNEL */
#endif /* _IO_H */
