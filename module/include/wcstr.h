/*
 * wcstr.h
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
 * wcstr.h: wide char string functions
 * Refered to Linux kernel code
 */

#ifndef _WCSTR_H
#define _WCSTR_H

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/nls.h>
#include <linux/errno.h>
#include <asm/uaccess.h>
#include "win32.h"

#ifdef CONFIG_UNIFIED_KERNEL

/*
 * Copy a null terminated wide string from userspace.
 */
#define __do_wstrncpy_from_user(dst,src,count,res)			   \
do {									   \
	int __d0, __d1, __d2;						   \
	__asm__ __volatile__(						   \
		"	testl %1,%1\n"					   \
		"	jz 2f\n"					   \
		"0:	lodsw\n"					   \
		"	stosw\n"					   \
		"	testw %%ax,%%ax\n"				   \
		"	jz 1f\n"					   \
		"	decl %1\n"					   \
		"	jnz 0b\n"					   \
		"1:	subl %1,%0\n"					   \
		"2:\n"							   \
		".section .fixup,\"ax\"\n"				   \
		"3:	movl %5,%0\n"					   \
		"	jmp 2b\n"					   \
		".previous\n"						   \
		".section __ex_table,\"a\"\n"				   \
		"	.align 4\n"					   \
		"	.long 0b,3b\n"					   \
		".previous"						   \
		: "=d"(res), "=c"(count), "=&a" (__d0), "=&S" (__d1),	   \
		  "=&D" (__d2)						   \
		: "i"(-EFAULT), "0"(count), "1"(count), "3"(src), "4"(dst) \
		: "memory");						   \
} while (0)

extern long wstrncpy_from_user(wchar_t *dst, const wchar_t *src, long count);
extern long wstrnlen_user(const wchar_t *s, long n);
extern wchar_t *getwname(const wchar_t __user *wname);
extern void putwname(const wchar_t *wname);
extern size_t wcslen(PWSTR ws);
extern WCHAR *wmemchr(const WCHAR *wcs, WCHAR wc, size_t count);
extern WCHAR *wcschr(const WCHAR *wcs, WCHAR wc);
extern WCHAR *wcsrchr(const char *wcs, WCHAR wc);
extern WCHAR *wcscpy(WCHAR *dest, const WCHAR *src);
extern int wcscmp(const WCHAR *wcs,const WCHAR *wct);
extern int wcsncmp(const WCHAR *wcs, const WCHAR *wct, size_t count);

#endif /* CONFIG_UNIFIED_KERNEL */
#endif /* _WCSTR_H */
