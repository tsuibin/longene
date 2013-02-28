/*
 * unistr.c
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
 * unistr.c:
 * Refered to ReactOS code
 */
#include <linux/fs.h>
#include "wineserver/lib.h"

#ifdef CONFIG_UNIFIED_KERNEL
/* FIXME */
#define	UpcaseUnicodeChar(wc)	wc

static char debug_buf[1024];

extern size_t wcslen(PWSTR ws);

//translate utf-8 character to wchar_t char
int char2wchar(struct nls_table *nls, PWSTR pwcs, char *src,int len)
{
	char 		*p;
	int   		n,j = 0;
	int 		wcs_len  = 0;
	wchar_t	*wc;
 	
	wc = pwcs;
	p = src; 
	while(p < src + len - 1)
	{
		unsigned char tmp = *(p + j);
		while(j < 6  &&  ((tmp << j)& 0xff) >> 7 &&  (((tmp << (j+1)) & 0xff) >> 7))
		{
			j++;
		}
		j++;	
		n = nls->char2uni(p, j, wc++);
		if (n < 0)
		{
			return -EINVAL;
		}
		p += j;
		j = 0;
		wcs_len++;
	}
 	
	return wcs_len;
}
EXPORT_SYMBOL(char2wchar);

int str2unistr(struct nls_table *nls, PUNICODE_STRING dst, char *src)
{
	int		len, i;
	int		ret = -ENOMEM;
	char		*ksrc, *p;
	wchar_t		*wc;
	int 		j = 0;
	if ((unsigned int) src > TASK_SIZE) {
		ksrc = src;
		len = strlen(src) + 1;
		goto ksrc_ready;
	}

	if (!src || !(len = strlen_user(src))) {
		dst->Length = 0;
		dst->MaximumLength = sizeof(wchar_t);
		dst->Buffer = (PWSTR)L"";
		return 0;
	}

	if (!(ksrc = kmalloc(len, GFP_KERNEL)))
		return ret;

	ret = -EFAULT;
	if (copy_from_user(ksrc, src, len))
		goto out_free_src;

ksrc_ready:
	dst->Length = 0;
	dst->MaximumLength = len * sizeof(wchar_t);
	dst->Buffer = kmalloc(dst->MaximumLength, GFP_KERNEL);
	ret = -ENOMEM;
	if (!dst->Buffer)
		goto out_free_src;

	wc = dst->Buffer;
	p = ksrc;
	while (p < ksrc + len - 1) {
		unsigned char tmp = *(p + j);
		while(j < 6  &&  ((tmp << j)& 0xff) >> 7 &&  (((tmp << (j+1)) & 0xff) >> 7))
		{
			j++;
		}
		j++;	
		i = nls->char2uni(p, j, wc++);
		if (i < 0) {
			ret = -EINVAL;
			goto out_free_dst;
		}
		p += j;
		j = 0;
		dst->Length += sizeof(wchar_t);
	}
	*wc = L'\0';
	ktrace("str2unistr SUCCEDD\n");
	ret = 0;
	goto out_free_src;

out_free_dst:
	kfree(dst->Buffer);
out_free_src:
	if (ksrc != src)
		kfree(ksrc);

	return ret;
}
EXPORT_SYMBOL(str2unistr);

int unistr2charstr(PWSTR unistr, LPCSTR chstr)
{
	struct ethread *thread;
	struct nls_table *nls;
	UCHAR *pch;
	WCHAR *wc;
	int retval = -EFAULT;
	int charlen=0;
	int size = 0;
	thread = get_current_ethread();

	nls = thread ? thread->threads_process->ep_nls : load_nls("utf8"); 
	ktrace("nls :%p\n", nls);
	pch = (UCHAR *)chstr;
	if(nls){
		for(wc = unistr; *wc != 0; wc++){
			if(*wc < 0x0080)
			{
				size = 1;
			}
			else if(*wc < 0x0800)
			{
				size = 2;
			}	
			else if(*wc >= 0x0800)
			{	
				size = 3;
			}
			retval = nls->uni2char(*wc, pch, size);
			if(retval < 0){
				ktrace("uni2char ERROR\n");				
				goto out;
			}
			pch += size;
			charlen += size;
		}
		*pch = 0;
		retval = charlen;
	}
	ktrace("retval :%d\n", retval);
out:
	if (!thread && nls)
		unload_nls(nls);
	return retval;
} /* end unistr2charstr() */
EXPORT_SYMBOL(unistr2charstr);

VOID
STDCALL
init_unistr(
		IN OUT PUNICODE_STRING Dest,
		IN PWSTR Src)
{
	if (Src) {
		Dest->Length = wcslen((PWSTR)Src);
		Dest->MaximumLength = Dest->Length + sizeof(WCHAR);
	}
	else {
		Dest->Length = 0;
		Dest->MaximumLength = 0;
	}
	Dest->Buffer = (PWSTR)Src;
}
EXPORT_SYMBOL(init_unistr);

BOOLEAN
STDCALL
equal_unistr(
		IN const UNICODE_STRING *String1,
		IN const UNICODE_STRING *String2,
		IN BOOLEAN  CaseInsensitive)
{
	ULONG i;
	WCHAR wc1, wc2;
	PWCHAR pw1, pw2;

	if (String1->Length != String2->Length)
		return FALSE;

	pw1 = String1->Buffer;
	pw2 = String2->Buffer;

	for (i = 0; i < String1->Length / sizeof(WCHAR); i++) {
		if (CaseInsensitive == TRUE) {
			wc1 = UpcaseUnicodeChar (*pw1);
			wc2 = UpcaseUnicodeChar (*pw2);
		}
		else {
			wc1 = tolowerW(*pw1);
			wc2 = tolowerW(*pw2);
		}

		if (wc1 != wc2)
			return FALSE;

		pw1++;
		pw2++;
	}

	return TRUE;
}
EXPORT_SYMBOL(equal_unistr);

VOID
STDCALL
free_unistr(IN PUNICODE_STRING UnicodeString)
{
	if (!UnicodeString->Buffer)
		return;

	kfree(UnicodeString->Buffer);
	memset(UnicodeString, 0, sizeof(UNICODE_STRING));
}
EXPORT_SYMBOL(free_unistr);

VOID
STDCALL
copy_unistr(
		IN OUT PUNICODE_STRING DestinationString,
		IN PUNICODE_STRING SourceString)
{
	ULONG CopyLen;

	if (!SourceString) {
		DestinationString->Length = 0;
		return;
	}

	CopyLen = min(DestinationString->MaximumLength, SourceString->Length);
	memcpy(DestinationString->Buffer, SourceString->Buffer, CopyLen);
	if (DestinationString->MaximumLength >= CopyLen + sizeof(WCHAR))
		DestinationString->Buffer[CopyLen / sizeof(WCHAR)] = 0;
	DestinationString->Length = CopyLen;
}
EXPORT_SYMBOL(copy_unistr);

char *debug_unistr(PUNICODE_STRING us)
{
	int	ret;

	if (!us || !us->Buffer)
		return "(null)";

	ret = unistr2charstr(us->Buffer, debug_buf);
	return ret > 0 ? debug_buf : "(invalid unicode string)";
}
EXPORT_SYMBOL(debug_unistr);

NTSTATUS
capture_unistr(OUT PUNICODE_STRING Dest,
		IN KPROCESSOR_MODE CurrentMode,
		IN POOL_TYPE PoolType,
		IN BOOLEAN CaptureIfKernel,
		IN PUNICODE_STRING UnsafeSrc)
{
	UNICODE_STRING Src;

	/*
	 * Copy the source string structure to kernel space.
	 */

	/* FIXME User Mode */
	
	/* Kernel Mode */
	if (!CaptureIfKernel) {
		/* just copy the UNICODE_STRING structure, the pointers are considered valid */
		*Dest = *UnsafeSrc;
		return STATUS_SUCCESS;
	}
	else
		Src = *UnsafeSrc;

	/*
	 * Initialize the destination string.
	 */
	Dest->Length = Src.Length;
	if (Src.Length > 0) {
		Dest->MaximumLength = Src.Length + sizeof(WCHAR);
		Dest->Buffer = kmalloc(Dest->MaximumLength, GFP_KERNEL);
		if (!Dest->Buffer) {
			memset(Dest, 0, sizeof(UNICODE_STRING));
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		/* Copy the source string to kernel space.  */
		memcpy(Dest->Buffer, Src.Buffer, Src.Length);
		Dest->Buffer[Src.Length / sizeof(WCHAR)] = L'\0';
	}
	else {
		Dest->MaximumLength = 0;
		Dest->Buffer = NULL;
	}

	return STATUS_SUCCESS;
}
EXPORT_SYMBOL(capture_unistr);

VOID
release_unistr(IN PUNICODE_STRING CapturedString,
		IN KPROCESSOR_MODE CurrentMode,
		IN BOOLEAN CaptureIfKernel)
{
	if (CurrentMode != KernelMode || CaptureIfKernel)
		kfree(CapturedString->Buffer);
}
EXPORT_SYMBOL(release_unistr);
#endif
