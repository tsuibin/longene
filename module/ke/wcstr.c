/*
 * wcstr.c
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
 * wcstr.c: wide char string functions
 * Refered to Linux kernel code
 */

#include "wcstr.h"

#ifdef CONFIG_UNIFIED_KERNEL

/*
 * copy a wide string into kernel-space
 */
long wstrncpy_from_user(wchar_t *dst, const wchar_t *src, long count)
{
	long res = -EFAULT;
	if (access_ok(VERIFY_READ, src, 2))
		__do_wstrncpy_from_user(dst, src, count, res);
	return res;
} /* end wcsncpy_from_user() */
EXPORT_SYMBOL(wstrncpy_from_user);

/*
 * return the size of a wide string (including the ending NUL)
 * - return 0 on exception, a value greater than N if too long
 */
long wstrnlen_user(const wchar_t *s, long n)
{
	unsigned long mask = -__addr_ok(s);
	unsigned long res, tmp;

	__asm__ __volatile__(
		"	andl %0,%%ecx\n"
		"0:	repne; scasw\n"
		"	setne %%al\n"
		"	subl %%ecx,%0\n"
		"	addl %0,%%eax\n"
		"1:\n"
		".section .fixup,\"ax\"\n"
		"2:	xorl %%eax,%%eax\n"
		"	jmp 1b\n"
		".previous\n"
		".section __ex_table,\"a\"\n"
		"	.align 4\n"
		"	.long 0b,2b\n"
		".previous"
		:"=r" (n), "=D" (s), "=a" (res), "=c" (tmp)
		:"0" (n), "1" (s), "2" (0), "3" (mask)
		:"cc");
	return res & mask;
} /* end wcsnlen_user() */
EXPORT_SYMBOL(wstrnlen_user);

static inline int do_getwname(const wchar_t __user *wname, wchar_t *page)
{
	int retval;
	unsigned long len = PATH_MAX;

	if (!segment_eq(get_fs(), KERNEL_DS)) {
		if ((unsigned long) wname >= TASK_SIZE)
			return -EFAULT;
		if (TASK_SIZE - (unsigned long) wname < PATH_MAX)
			len = TASK_SIZE - (unsigned long) wname;
	}

	retval = wstrncpy_from_user(page, wname, len);
	if (retval > 0) {
		if (retval < len)
			return 0;
		return -ENAMETOOLONG;
	} else if (!retval)
		retval = -ENOENT;
	return retval;
} /* end do_getwname() */

wchar_t *getwname(const wchar_t __user *wname)
{
	wchar_t *tmp, *result;

	result = ERR_PTR(-ENOMEM);
	tmp = __getname();
	if (tmp)  {
		int retval = do_getwname(wname, tmp);
		result = tmp;
		if (retval < 0) {
			putwname(tmp);
			result = ERR_PTR(retval);
		}
	}
	return result;
} /* end getwname() */
EXPORT_SYMBOL(getwname);


void putwname(const wchar_t *wname)
{
	__putname(wname);
} /* end putwname */
EXPORT_SYMBOL(putwname);

size_t wcslen(PWSTR ws)
{
	int d0;
	register int __res;

	__asm__ __volatile__(
			"repne\n\t"
			"scasw\n\t"
			"notl %0\n\t"
			"decl %0"
			: "=c"(__res), "=&D"(d0)
			: "1"(ws), "a"(0), "0"(0xffffffffu)
			: "memory");

	return __res * sizeof(WCHAR);
}
EXPORT_SYMBOL(wcslen);

WCHAR *wmemchr(const WCHAR *wcs, WCHAR wc, size_t count)
{
	int d0;
	WCHAR *res;

	if (!count)
		return NULL;

	asm volatile("repne\n\t"
			"scasw\n\t"
			"je 1f\n\t"
			"movl $2,%0\n"
			"1:\tsubl $2, %0"
			: "=D"(res), "=&c"(d0)
			: "a"(wc), "0"(wcs), "1"(count)
			: "memory");

	return res;
}
EXPORT_SYMBOL(wmemchr);

WCHAR *wcschr(const WCHAR *wcs, WCHAR wc)
{
	int d0;
	WCHAR *res;

	asm volatile("movw %%ax,%%bx\n"
			"1:\tlodsw\n\t"
			"cmpw %%bx,%%ax\n\t"
			"je 2f\n\t"
			"testw %%ax,%%ax\n\t"
			"jne 1b\n\t"
			"movl $2,%1\n"
			"2:\tmovl %1,%0\n\t"
			"subl $2, %0"
			: "=a"(res), "=&S"(d0)
			: "1"(wcs), "0"(wc)
			: "memory");

	return res;
}
EXPORT_SYMBOL(wcschr);

WCHAR *wcsrchr(const char *wcs, WCHAR wc)
{
	int d0, d1;
	WCHAR *res;

	asm volatile("movw %%ax,%%bx\n"
			"1:\tlodsw\n\t"
			"cmpw %%bx,%%ax\n\t"
			"jne 2f\n\t"
			"leal -2(%%esi),%0\n"
			"2:\ttestw %%ax,%%ax\n\t"
			"jne 1b"
			: "=g"(res), "=&S"(d0), "=&a"(d1)
			: "0"(0), "1"(wcs), "2"(wc)
			: "memory");

	return res;
}
EXPORT_SYMBOL(wcsrchr);

WCHAR *wcscpy(WCHAR *dest, const WCHAR *src)
{
	int d0, d1, d2;

	asm volatile("1:\tlodsw\n\t"
			"stosw\n\t"
			"testw %%ax, %%ax\n\t"
			"jne 1b"
			: "=&S"(d0), "=&D"(d1), "=&a"(d2)
			: "0"(src), "1"(dest)
			: "memory");

	return dest;
}
EXPORT_SYMBOL(wcscpy);

int wcscmp(const WCHAR *wcs, const WCHAR *wct)
{
	int d0, d1;
	int res;

	asm volatile("1:\tlodsw\n\t"
			"scasw\n\t"
			"jne 2f\n\t"
			"testw %%ax,%%ax\n\t"
			"jne 1b\n\t"
			"xorl %%eax,%%eax\n\t"
			"jmp 3f\n"
			"2:\tsbbl %%eax,%%eax\n\t"
			"orb $1,%%al\n"
			"3:"
			: "=a"(res), "=&S"(d0), "=&D"(d1)
			: "1"(wcs), "2"(wct)
			: "memory");

	return res;
}
EXPORT_SYMBOL(wcscmp);

int wcsncmp(const WCHAR *wcs, const WCHAR *wct, size_t count)
{
	int res;
	int d0, d1, d2;

	asm volatile("1:\tdecl %3\n\t"
			"js 2f\n\t"
			"lodsw\n\t"
			"scasw\n\t"
			"jne 3f\n\t"
			"testw %%ax,%%ax\n\t"
			"jne 1b\n"
			"2:\txorl %%eax,%%eax\n\t"
			"jmp 4f\n"
			"3:\tsbbl %%eax,%%eax\n\t"
			"orb $1,%%al\n"
			"4:"
			: "=a"(res), "=&S"(d0), "=&D"(d1), "=&c"(d2)
			: "1"(wcs), "2"(wct), "3"(count)
			: "memory");

	return res;
}
EXPORT_SYMBOL(wcsncmp);

#endif /* CONFIG_UNIFIED_KERNEL */
