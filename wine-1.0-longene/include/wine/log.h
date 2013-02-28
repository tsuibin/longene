#ifndef _LOG_H_
#define	_LOG_H_


#include <stdio.h>
#include <unistd.h>
#include "winternl.h"
#include "winnt.h"

#define LOG_FILE	"/tmp/unified.trace"

#ifdef DEBUG_SYSCALL

static inline unsigned long long rdtsc()
{
	unsigned long long      ret;

	asm volatile ("rdtsc\n" : "=A"(ret));
	return ret >> 20;
}

#define LOG_NO_FUNC(file, fmt...) \
	do \
	{ \
		FILE	*fp; \
		if ((fp = fopen((file), "a+"))) \
		{ \
			fprintf(fp, "%08llx: p %lx t %lx ", rdtsc(), \
					(unsigned long)getpid(), (unsigned long)gettid()); \
			fprintf(fp, fmt); \
			fclose(fp); \
		} \
		else \
			fprintf(stderr, "can not open file %s\n", (file)); \
	} while (0)

#define	LOG(file, trace, status, fmt...) \
	do \
	{ \
		FILE	*fp; \
		if ((fp = fopen((file), "a+"))) \
		{ \
			fprintf(fp, "%08llx: p %lx t %lx %s ", rdtsc(), \
				(unsigned long)getpid(), (unsigned long)gettid(), __FUNCTION__); \
			if (status) \
				fprintf(fp, "ERR: " fmt); \
			else \
				fprintf(fp, fmt); \
			if (trace) \
			{ \
				unsigned long	*frame; \
				unsigned long	ebp, esp; \
				asm volatile ("movl %%esp, %%eax\nmovl %%ebp, %%edx" : "=&a"(esp), "=&d"(ebp)); \
				frame = (unsigned long *)ebp; \
				fprintf(fp, "call trace:\n"); \
				while (ebp && ebp > esp && ebp < esp + 0x10000) \
				{ \
					fprintf(fp, "\treturn address 0x%lx\n", frame[1]); \
					ebp = *frame; \
					frame = (unsigned long *)ebp; \
				} \
			} \
			fclose(fp); \
		} \
		else \
			fprintf(stderr, "can not open file %s,%s\n", __FILE__, __FUNCTION__); \
	} while (0)

#else

#define	LOG(file, trace, status, fmt...)	do { } while (0)
#define LOG_NO_FUNC(file, fmt...)	 	do { } while (0)
#define LOG_SIMPLIFY_START(file, trace, fmt...)	do { } while (0)
#define LOG_SIMPLIFY_END(file, status, fmt...) 	do { } while (0)

#endif	/* DEBUG_SYSCALL */

#define	LOG_NO_TRACE(file, status, fmt...)	LOG(file, 0, status, fmt)
#define	LOG_NO_STATUS(file, trace, fmt...)	LOG(file, trace, 0, fmt)
#define	LOG_NO_TRACE_STATUS(file, fmt...)	LOG(file, 0, 0, fmt)

#define	LOG_TO_FILE_NO_TRACE(status, fmt...)	LOG(LOG_FILE, 0, status, fmt)
#define	LOG_TO_FILE_NO_STATUS(trace, fmt...)	LOG(LOG_FILE, trace, 0, fmt)
#define	LOG_TO_FILE_NO_TRACE_STATUS(fmt...)	LOG(LOG_FILE, 0, 0, fmt)


#ifdef DEBUG_DUMP_ADDR

#define	DUMP_ADDR(file, addr, len) \
	do \
	{ \
		FILE	*fp; \
		if ((fp = fopen((file), "a+"))) \
		{ \
			int	i; \
			unsigned long	*ptr; \
			if (addr) \
			{ \
				ptr = (unsigned long *)(addr); \
				fprintf(fp, "dump %08lx:\n", addr); \
			} \
			else \
			{ \
				asm volatile ("movl %%esp, %%eax\n" : "=&a"(ptr)); \
				fprintf(fp, "dump stack:\n"); \
			} \
			for (i = 0; i < (len) / 4; i++) \
			{ \
				if (i % 8 == 0) \
					fprintf(fp, "%08lx: ", (addr) ? i + 4 : ptr + i); \
				fprintf(fp, "%08lx ", ptr[i]); \
				if (i % 8 == 7) \
					fprintf(fp, "\n"); \
			} \
		} \
	} while (0)

#else

#define	DUMP_ADDR(file, addr, len)		do { } while (0)

#endif	/* DEBUG_DUMP_ADDR */

#define	DUMP_ADDR_FILE	LOG_FILE
#define	DUMP_STACK(file, len)			DUMP_ADDR(file, 0, len)
#define	DUMP_ADDR_TO_FILE(addr, len)		DUMP_ADDR(DUMP_ADDR_FILE, addr, len)
#define	DUMP_STACK_TO_FILE(len)			DUMP_ADDR(DUMP_ADDR_FILE, 0, len)




#define DISPLAY_FIELD(fp, structp, field, fmt)	fprintf(fp, #field fmt "\n", structp->field) 

#ifdef DEBUG_PEB

#define	DUMP_PEB_FILE	LOG_FILE

#define dump_peb(peb) \
	do \
	{ \
		FILE	*fp; \
		int i; \
		if ((fp = fopen(DUMP_PEB_FILE, "a+"))) \
		{ \
			fprintf(fp, "dump_peb:PEB {\n"); \
			DISPLAY_FIELD(fp, peb, InheritedAddressSpace, ":%d"); \
			DISPLAY_FIELD(fp, peb, ReadImageFileExecOptions, ":%d"); \
			DISPLAY_FIELD(fp, peb, BeingDebugged, ":%d"); \
			DISPLAY_FIELD(fp, peb, SpareBool, ":%d"); \
			DISPLAY_FIELD(fp, peb, Mutant, ":%p"); \
			DISPLAY_FIELD(fp, peb, ImageBaseAddress, ":%p"); \
			DISPLAY_FIELD(fp, peb, LdrData, ":%p"); \
			if (peb->LdrData) { \
				fprintf(fp, "\tLdrData->Length:%d\n", peb->LdrData->Length); \
				fprintf(fp, "\tLdrData->Initialized:%d\n", peb->LdrData->Initialized); \
				fprintf(fp, "\tLdrData->SsHandle:%p\n", peb->LdrData->SsHandle); \
			} \
			DISPLAY_FIELD(fp, peb, ProcessParameters, ":%p"); \
			DISPLAY_FIELD(fp, peb, SubSystemData, ":%p"); \
			DISPLAY_FIELD(fp, peb, ProcessHeap, ":%p"); \
			DISPLAY_FIELD(fp, peb, FastPebLock, ":%p"); \
			DISPLAY_FIELD(fp, peb, FastPebLockRoutine, ":%p"); \
			DISPLAY_FIELD(fp, peb, FastPebUnlockRoutine, ":%p"); \
			DISPLAY_FIELD(fp, peb, EnvironmentUpdateCount, ":%d"); \
			DISPLAY_FIELD(fp, peb, KernelCallbackTable, ":%p"); \
			DISPLAY_FIELD(fp, peb, EventLogSection, ":%p"); \
			DISPLAY_FIELD(fp, peb, EventLog, ":%p"); \
			DISPLAY_FIELD(fp, peb, FreeList, ":%p"); \
			DISPLAY_FIELD(fp, peb, TlsExpansionCounter, ":%d"); \
			DISPLAY_FIELD(fp, peb, TlsBitmap, ":%p"); \
			if (peb->TlsBitmap) { \
				fprintf(fp, "TlsBitmap->SizeOfBitMap:%d\n",peb->TlsBitmap->SizeOfBitMap); \
				fprintf(fp, "TlsBitmap->Buffer:%p\n",peb->TlsBitmap->Buffer); \
			} \
			DISPLAY_FIELD(fp, peb, TlsBitmapBits[0], ":%d"); \
			DISPLAY_FIELD(fp, peb, TlsBitmapBits[1], ":%d"); \
			DISPLAY_FIELD(fp, peb, ReadOnlySharedMemoryBase, ":%p"); \
			DISPLAY_FIELD(fp, peb, ReadOnlySharedMemoryHeap, ":%p"); \
			DISPLAY_FIELD(fp, peb, ReadOnlyStaticServerData, ":%p"); \
			DISPLAY_FIELD(fp, peb, AnsiCodePageData, ":%p"); \
			DISPLAY_FIELD(fp, peb, OemCodePageData, ":%p"); \
			DISPLAY_FIELD(fp, peb, UnicodeCaseTableData, ":%p"); \
			DISPLAY_FIELD(fp, peb, NumberOfProcessors, ":%d"); \
			DISPLAY_FIELD(fp, peb, NtGlobalFlag, ":%d"); \
			DISPLAY_FIELD(fp, peb, Spare2[0], ":%d"); \
			DISPLAY_FIELD(fp, peb, Spare2[1], ":%d"); \
			DISPLAY_FIELD(fp, peb, Spare2[2], ":%d"); \
			DISPLAY_FIELD(fp, peb, Spare2[3], ":%d"); \
			DISPLAY_FIELD(fp, peb, CriticalSectionTimeout.QuadPart, ":%lld"); \
			DISPLAY_FIELD(fp, peb, HeapSegmentReserve, ":%d"); \
			DISPLAY_FIELD(fp, peb, HeapSegmentCommit, ":%d"); \
			DISPLAY_FIELD(fp, peb, HeapDeCommitTotalFreeThreshold, ":%d"); \
			DISPLAY_FIELD(fp, peb, HeapDeCommitFreeBlockThreshold, ":%d"); \
			DISPLAY_FIELD(fp, peb, NumberOfHeaps, ":%d"); \
			DISPLAY_FIELD(fp, peb, MaximumNumberOfHeaps, ":%d"); \
			DISPLAY_FIELD(fp, peb, ProcessHeaps, ":%p"); \
			DISPLAY_FIELD(fp, peb, GdiSharedHandleTable, ":%p"); \
			DISPLAY_FIELD(fp, peb, ProcessStarterHelper, ":%p"); \
			DISPLAY_FIELD(fp, peb, GdiDCAttributeList, ":%p"); \
			DISPLAY_FIELD(fp, peb, LoaderLock, ":%p"); \
			DISPLAY_FIELD(fp, peb, OSMajorVersion, ":%d"); \
			DISPLAY_FIELD(fp, peb, OSMinorVersion, ":%d"); \
			DISPLAY_FIELD(fp, peb, OSBuildNumber, ":%d"); \
			DISPLAY_FIELD(fp, peb, OSPlatformId, ":%d"); \
			DISPLAY_FIELD(fp, peb, ImageSubSystem, ":%d"); \
			DISPLAY_FIELD(fp, peb, ImageSubSystemMajorVersion, ":%d"); \
			DISPLAY_FIELD(fp, peb, ImageSubSystemMinorVersion, ":%d"); \
			DISPLAY_FIELD(fp, peb, ImageProcessAffinityMask, ":%d"); \
			fprintf(fp, "peb->GdiHandleBuffer:"); \
			{ \
				for (i = 0; i < 34; i++) \
					fprintf(fp, "%d ", peb->GdiHandleBuffer[i]); \
				fprintf(fp, "\n"); \
			} \
			DISPLAY_FIELD(fp, peb, PostProcessInitRoutine, ":%d"); \
			DISPLAY_FIELD(fp, peb, TlsExpansionBitmap, ":%p"); \
			if (peb->TlsExpansionBitmap) { \
				fprintf(fp, "TlsExpansionBitmap->SizeOfBitMap:%d\n",peb->TlsExpansionBitmap->SizeOfBitMap); \
				fprintf(fp, "TlsExpansionBitmap->Buffer:%p\n",peb->TlsExpansionBitmap->Buffer); \
			} \
			fprintf(fp, "peb->TlsExpansionBitmapBits:"); \
			for (i = 0; i < 32; i++) \
				fprintf(fp, "%d ", peb->TlsExpansionBitmapBits[i]); \
			fprintf(fp, "\n"); \
			DISPLAY_FIELD(fp, peb, SessionId, ":%d"); \
			DISPLAY_FIELD(fp, peb, AppCompatFlags.QuadPart, "%lld"); \
			DISPLAY_FIELD(fp, peb, AppCompatFlagsUser.QuadPart, "%lld"); \
			DISPLAY_FIELD(fp, peb, ShimData, "%p"); \
			DISPLAY_FIELD(fp, peb, AppCompatInfo, "%p"); \
			fprintf(fp, "CSDVersion:%s\n", debugstr_w(peb->CSDVersion.Buffer)); \
			DISPLAY_FIELD(fp, peb, ActivationContextData, "%p"); \
			DISPLAY_FIELD(fp, peb, ProcessAssemblyStorageMap, "%p"); \
			DISPLAY_FIELD(fp, peb, SystemDefaultActivationData, "%p"); \
			DISPLAY_FIELD(fp, peb, SystemAssemblyStorageMap, "%p"); \
			DISPLAY_FIELD(fp, peb, MinimumStackCommit, "%p"); \
			DISPLAY_FIELD(fp, peb, FlsCallback, "%p"); \
			fprintf(fp, "FlsListHead:%p\n", &(peb->FlsListHead)); \
			DISPLAY_FIELD(fp, peb, FlsBitmap, "%p"); \
			fprintf(fp, "peb->FlsBitmapBits:"); \
			for (i = 0; i < 4; i++) \
				fprintf(fp, "%d ", peb->FlsBitmapBits[i]); \
			fprintf(fp,"}\n"); \
			fclose(fp); \
		} \
	} while (0)

#else
#define dump_peb(peb)	do { } while(0)

#endif	/* DEBUG_PEB */


#ifdef DEBUG_TEB

#define	DUMP_TEB_FILE	LOG_FILE

#define dump_teb(teb) \
	do \
	{ \
		FILE	*fp; \
		int i; \
		if ((fp = fopen(DUMP_TEB_FILE, "a+"))) \
		{ \
			fprintf(fp,"dump_teb:{\n"); \
			{ \
				fprintf(fp, "Tib\n"); \
				fprintf(fp, "\tExceptionList:%p\n", teb->Tib.ExceptionList); \
				fprintf(fp, "\tStackBase:%p\n", teb->Tib.StackBase); \
				fprintf(fp, "\tStackLimit:%p\n", teb->Tib.StackLimit); \
				fprintf(fp, "\tSubSystemTib:%p\n", teb->Tib.SubSystemTib); \
				fprintf(fp, "\tArbitraryUserPointer:%p\n", teb->Tib.ArbitraryUserPointer); \
				fprintf(fp, "\tSelf:%p\n", teb->Tib.Self); \
			} \
			fprintf(fp, "Pid:%p\n", teb->ClientId.UniqueProcess); \
			fprintf(fp, "Tid:%p\n", teb->ClientId.UniqueThread); \
			DISPLAY_FIELD(fp, teb, EnvironmentPointer, ":%p"); \
			DISPLAY_FIELD(fp, teb, ActiveRpcHandle, ":%p"); \
			DISPLAY_FIELD(fp, teb, ThreadLocalStoragePointer, ":%p"); \
			DISPLAY_FIELD(fp, teb, Peb, ":%p"); \
			DISPLAY_FIELD(fp, teb, LastErrorValue, ":%p"); \
			DISPLAY_FIELD(fp, teb, CountOfOwnedCriticalSections, ":%p"); \
			DISPLAY_FIELD(fp, teb, CsrClientThread, ":%p"); \
			DISPLAY_FIELD(fp, teb, Win32ThreadInfo, ":%p"); \
			{\
				for (i = 0; i < 31; i++) \
				fprintf(fp, "%d ", teb->Win32ClientInfo[i]); \
				fprintf(fp, "\n"); \
			} \
			DISPLAY_FIELD(fp, teb, WOW32Reserved, ":%p"); \
			DISPLAY_FIELD(fp, teb, CurrentLocale, ":%p"); \
			DISPLAY_FIELD(fp, teb, FpSoftwareStatusRegister, ":%p"); \
			{ \
				for (i = 0; i < 54; i++) \
				fprintf(fp, "%p ", teb->SystemReserved1[i]); \
				fprintf(fp, "\n"); \
			} \
			DISPLAY_FIELD(fp, teb, ExceptionCode, ":%p"); \
			{ \
				fprintf(fp, "ActivationContextStack\n"); \
				fprintf(fp, "\tFlags:%p\n", teb->ActivationContextStack.Flags); \
				fprintf(fp, "\tNextCookieSequenceNumber:%p\n", teb->ActivationContextStack.NextCookieSequenceNumber); \
				fprintf(fp, "\tActiveFrame:%p\n", teb->ActivationContextStack.ActiveFrame); \
				fprintf(fp, "\tFrameListCache:%p\n", &(teb->ActivationContextStack.FrameListCache)); \
			} \
			{ \
				for (i = 0; i < 40; i++) \
				fprintf(fp, "%d ", teb->SpareBytes1[i]); \
				fprintf(fp, "\n"); \
			} \
			{ \
				for (i = 0; i < 10; i++) \
				fprintf(fp, "%p ", teb->SystemReserved2[i]); \
				fprintf(fp, "\n"); \
			} \
			{ \
				fprintf(fp, "GdiTebBatch.Offset:%d\n", teb->GdiTebBatch.Offset); \
				fprintf(fp, "GdiTebBatch.HDC:%p\n", teb->GdiTebBatch.HDC); \
				fprintf(fp, "GdiTebBatch.Buffer:\n"); \
				for (i = 0; i < 0x136; i++) \
				fprintf(fp, "%d ", teb->GdiTebBatch.Buffer[i]); \
				fprintf(fp, "\n"); \
			} \
			DISPLAY_FIELD(fp, teb, gdiRgn, ":%d"); \
			DISPLAY_FIELD(fp, teb, gdiPen, ":%d"); \
			DISPLAY_FIELD(fp, teb, gdiBrush, ":%d"); \
			fprintf(fp, "RealPid:%p\n", teb->RealClientId.UniqueProcess); \
			fprintf(fp, "RealTid:%p\n", teb->RealClientId.UniqueThread); \
			DISPLAY_FIELD(fp, teb, GdiCachedProcessHandle, ":%p"); \
			DISPLAY_FIELD(fp, teb, GdiClientPID, ":%d"); \
			DISPLAY_FIELD(fp, teb, GdiClientTID, ":%d"); \
			DISPLAY_FIELD(fp, teb, GdiThreadLocaleInfo, ":%p"); \
			{ \
				for (i = 0; i < 5; i++) \
				fprintf(fp, "%p ", teb->UserReserved[i]); \
				fprintf(fp, "\n"); \
			} \
			{ \
				for (i = 0; i < 280; i++) \
				fprintf(fp, "%p ", teb->glDispachTable[i]); \
				fprintf(fp, "\n"); \
			} \
			{ \
				for (i = 0; i < 26; i++) \
				fprintf(fp, "%p ", teb->glReserved1[i]); \
				fprintf(fp, "\n"); \
			} \
			DISPLAY_FIELD(fp, teb, glReserved2, ":%p"); \
			DISPLAY_FIELD(fp, teb, glSectionInfo, ":%p"); \
			DISPLAY_FIELD(fp, teb, glSection, ":%p"); \
			DISPLAY_FIELD(fp, teb, glTable, ":%p"); \
			DISPLAY_FIELD(fp, teb, glCurrentRC, ":%p"); \
			DISPLAY_FIELD(fp, teb, glContext, ":%p"); \
			DISPLAY_FIELD(fp, teb, LastStatusValue, ":%d"); \
			fprintf(fp, "StaticUnicodeString:%s\n", debugstr_w(teb->StaticUnicodeString.Buffer)); \
			fprintf(fp, "StaticUnicodeBuffer%s\n", debugstr_w(teb->StaticUnicodeBuffer)); \
			DISPLAY_FIELD(fp, teb, DeallocationStack, ":%p"); \
			{ \
				for (i = 0; i < 64; i++) \
				fprintf(fp, "%p ", teb->TlsSlots[i]); \
				fprintf(fp, "\n"); \
			} \
			fprintf(fp, "TlsLinks:%p\n", &(teb->TlsLinks)); \
			DISPLAY_FIELD(fp, teb, Vdm, ":%p"); \
			DISPLAY_FIELD(fp, teb, ReservedForNtRpc, ":%p"); \
			{ \
				for (i = 0; i < 2; i++) \
				fprintf(fp, "%p ", teb->DbgSsReserved[i]); \
				fprintf(fp, "\n"); \
			} \
			DISPLAY_FIELD(fp, teb, HardErrorDisabled, ":%d"); \
			{ \
				for (i = 0; i < 16; i++) \
				fprintf(fp, "%p ", teb->Instrumentation[i]); \
				fprintf(fp, "\n"); \
			} \
			DISPLAY_FIELD(fp, teb, WinSockData, ":%p"); \
			DISPLAY_FIELD(fp, teb, GdiBatchCount, ":%d"); \
			DISPLAY_FIELD(fp, teb, Spare2, ":%d"); \
			DISPLAY_FIELD(fp, teb, Spare3, ":%d"); \
			DISPLAY_FIELD(fp, teb, Spare4, ":%d"); \
			DISPLAY_FIELD(fp, teb, ReservedForOle, ":%p"); \
			DISPLAY_FIELD(fp, teb, WaitingOnLoaderLock, ":%d"); \
			{ \
				for (i = 0; i < 3; i++) \
				fprintf(fp, "%p ", teb->Reserved5[i]); \
				fprintf(fp, "\n"); \
			} \
			DISPLAY_FIELD(fp, teb, TlsExpansionSlots, ":%p"); \
			DISPLAY_FIELD(fp, teb, ImpersonationLocale, "%d");\
			DISPLAY_FIELD(fp, teb, IsImpersonating, "%d");\
			DISPLAY_FIELD(fp, teb, NlsCache, "%p");\
			DISPLAY_FIELD(fp, teb, ShimData, "%p");\
			DISPLAY_FIELD(fp, teb, HeapVirtualAffinity, "%d");\
			DISPLAY_FIELD(fp, teb, CurrentTransactionHandle, "%p");\
			DISPLAY_FIELD(fp, teb, ActiveFrame, "%p");\
			DISPLAY_FIELD(fp, teb, FlsSlots, "%p");\
			fprintf(fp,"}\n"); \
			fclose(fp); \
		} \
	} while(0)

#else
#define dump_teb(teb)	do { } while (0)

#endif	/* DEBUG_TEB */


#ifdef DEBUG_PPB

#define	DUMP_PPB_FILE	LOG_FILE

#define dump_ppb(ppb) \
	do \
	{ \
		FILE	*fp; \
		if ((fp = fopen(DUMP_PPB_FILE, "a+"))) \
		{ \
			fprintf(fp,"dump_ppb:{\n"); \
			fprintf(fp,"\t"); \
			DISPLAY_FIELD(fp, ppb, AllocationSize, ":%d"); \
			fprintf(fp,"\t"); \
			DISPLAY_FIELD(fp, ppb, Size, ":%d"); \
			fprintf(fp,"\t"); \
			DISPLAY_FIELD(fp, ppb, Flags, ":%d"); \
			fprintf(fp,"\t"); \
			DISPLAY_FIELD(fp, ppb, DebugFlags, ":%d"); \
			fprintf(fp,"\t"); \
			DISPLAY_FIELD(fp, ppb, ConsoleHandle, ":%p"); \
			fprintf(fp,"\t"); \
			DISPLAY_FIELD(fp, ppb, ConsoleFlags, ":%d"); \
			fprintf(fp,"\t"); \
			DISPLAY_FIELD(fp, ppb, hStdInput, ":%p"); \
			fprintf(fp,"\t"); \
			DISPLAY_FIELD(fp, ppb, hStdOutput, ":%p"); \
			fprintf(fp,"\t"); \
			DISPLAY_FIELD(fp, ppb, hStdError, ":%p"); \
			fprintf(fp, "\tCurrentDirectory:%s\n", debugstr_w(ppb->CurrentDirectory.DosPath.Buffer)); \
			fprintf(fp, "\tDllPath:%s\n", debugstr_w(ppb->DllPath.Buffer)); \
			fprintf(fp, "\tImagePathName:%s\n", debugstr_w(ppb->ImagePathName.Buffer)); \
			fprintf(fp, "\tCommandLine:%s\n", debugstr_w(ppb->CommandLine.Buffer)); \
			{ \
				WCHAR* ep = ppb->Environment; \
				fprintf(fp, "\tEnvironment:\n"); \
				while (ep && *ep) { \
					fprintf(fp, "\t\t%s\n", debugstr_w(ep)); \
					ep += strlenW(ep) + 1; \
				} \
			} \
			fprintf(fp,"\t"); \
			DISPLAY_FIELD(fp, ppb, dwX, ":%d"); \
			fprintf(fp,"\t"); \
			DISPLAY_FIELD(fp, ppb, dwY, ":%d"); \
			fprintf(fp,"\t"); \
			DISPLAY_FIELD(fp, ppb, dwXSize, ":%d"); \
			fprintf(fp,"\t"); \
			DISPLAY_FIELD(fp, ppb, dwYSize, ":%d"); \
			fprintf(fp,"\t"); \
			DISPLAY_FIELD(fp, ppb, dwXCountChars, ":%d"); \
			fprintf(fp,"\t"); \
			DISPLAY_FIELD(fp, ppb, dwYCountChars, ":%d"); \
			fprintf(fp,"\t"); \
			DISPLAY_FIELD(fp, ppb, dwFillAttribute, ":%d"); \
			fprintf(fp,"\t"); \
			DISPLAY_FIELD(fp, ppb, dwFlags, ":%d"); \
			fprintf(fp,"\t"); \
			DISPLAY_FIELD(fp, ppb, wShowWindow, ":%d"); \
			fprintf(fp, "\tWindowTitle:%s\n", debugstr_w(ppb->WindowTitle.Buffer)); \
			fprintf(fp, "\tDesktop:%s\n", debugstr_w(ppb->Desktop.Buffer)); \
			fprintf(fp, "\tShellInfo:%s\n", debugstr_w(ppb->ShellInfo.Buffer)); \
			fprintf(fp, "\tRuntimeInfo:%s\n", debugstr_w(ppb->RuntimeInfo.Buffer)); \
			fprintf(fp,"}\n"); \
			fclose(fp); \
		} \
	} while(0)

#else
#define dump_ppb(ppb)	do { } while (0)
#endif	/* DEBUG_PPB */


#endif
