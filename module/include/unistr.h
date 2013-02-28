/*
 * unistr.h
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
 * unistr.h:
 * Refered to ReactOS code
 */
#ifndef _UNISTR_H
#define _UNISTR_H
#include "win32.h"

#ifdef CONFIG_UNIFIED_KERNEL
int char2wchar(struct nls_table *nls, PWSTR pwcs, char *src,int len);

int str2unistr(struct nls_table *nls, PUNICODE_STRING dst, char *src);

int unistr2charstr(PWSTR unistr, LPCSTR chstr);

VOID
STDCALL
init_unistr(
		IN OUT PUNICODE_STRING DestinationString,
		IN PWSTR SourceString
		);

BOOLEAN
STDCALL
equal_unistr(
		IN const UNICODE_STRING *String1,
		IN const UNICODE_STRING *String2,
		IN BOOLEAN  CaseInsensitive);

VOID
STDCALL
free_unistr(
		IN PUNICODE_STRING UnicodeString);

VOID
STDCALL
copy_unistr(
		IN OUT PUNICODE_STRING DestinationString,
		IN PUNICODE_STRING SourceString);

NTSTATUS
capture_unistr(OUT PUNICODE_STRING Dest,
		IN KPROCESSOR_MODE CurrentMode,
		IN POOL_TYPE PoolType,
		IN BOOLEAN CaptureIfKernel,
		IN PUNICODE_STRING UnsafeSrc);

VOID
release_unistr(IN PUNICODE_STRING CapturedString,
		IN KPROCESSOR_MODE CurrentMode,
		IN BOOLEAN CaptureIfKernel);


char *debug_unistr(PUNICODE_STRING us);

#endif /* CONFIG_UNIFIED_KERNEL */
#endif /* _UNISTR_H */

