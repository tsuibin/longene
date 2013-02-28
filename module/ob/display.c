/*
 * display.c
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
 * display.c:
 * Refered to ReactOS code
 */
#include "object.h"

#ifdef CONFIG_UNIFIED_KERNEL

extern POBJECT_TYPE	dir_object_type;
extern POBJECT_TYPE	symbol_link_type;
extern POBJECT_DIRECTORY name_space_root;

void display_object(PVOID Object, LONG Depth, BOOLEAN IsDisplayType)
{
	LONG	Length;
	PCHAR	Buffer, p;
	PWCHAR	wc;
	POBJECT_HEADER	Header;
	POBJECT_TYPE	Type;
	POBJECT_HEADER_NAME_INFO	NameInfo;

	Header = BODY_TO_HEADER(Object);
	Type = Header->Type;
	NameInfo = HEADER_TO_OBJECT_NAME(Header);
	if (!NameInfo)
		return;

	Length = Type->Name.Length + 64;

	p = Buffer = (PCHAR)kmalloc(Length, GFP_KERNEL);
	while (p < Buffer + Depth * 2 + 1)
		*p++ = ' ';

	if (Depth) {
		*p++ = '\\';
		*p++ = '_';
		*p++ = ' ';
	}

	for (wc = NameInfo->Name.Buffer;
			wc < NameInfo->Name.Buffer + NameInfo->Name.Length / sizeof(WCHAR);
			wc++)
		*p++ = (char)*wc;

	if (!Depth) {
		*p++ = 'R';
		*p++ = 'o';
		*p++ = 'o';
		*p++ = 't';
	}

	if (Type == symbol_link_type) {
		PUNICODE_STRING	us = &((POBJECT_SYMBOLIC_LINK)Object)->TargetName;

		memcpy(p, " --> ", sizeof(" --> ") - 1);
		p += sizeof(" --> ") - 1;
		for (wc = us->Buffer; wc < us->Buffer + us->Length / sizeof(WCHAR); wc++)
			*p++ = (char)*wc;
	}

	if (!IsDisplayType)
		goto ready;

	while (p < Buffer + 64)
		*p++ = ' ';

	for (wc = Type->Name.Buffer;
			wc < Type->Name.Buffer + Type->Name.Length / sizeof(WCHAR);
			wc++)
		*p++ = (char)*wc;

ready:
	*p = 0;

#if 0
	printk("%s\n", Buffer);
#endif
	kfree(Buffer);
} /* end display_object */
EXPORT_SYMBOL(display_object);

void display_object_dir(POBJECT_DIRECTORY DirectoryObject, LONG Depth)
{
	int	i;
	POBJECT_DIRECTORY_ENTRY	DirectoryEntry;
	POBJECT_DIRECTORY_ENTRY	*HeadDirectoryEntry;

	if (!DirectoryObject)
		DirectoryObject = name_space_root;
	display_object((PVOID)DirectoryObject, Depth - 1, FALSE);
	for (i = 0; i < NUMBER_HASH_BUCKETS; i++) {
		HeadDirectoryEntry = &DirectoryObject->HashBuckets[i];
		while ((DirectoryEntry = *HeadDirectoryEntry) != NULL) {
			if (BODY_TO_HEADER(DirectoryEntry->Object)->Type == dir_object_type)
				display_object_dir((POBJECT_DIRECTORY)DirectoryEntry->Object, Depth + 1);
			else
				display_object(DirectoryEntry->Object, Depth, TRUE);

			HeadDirectoryEntry = &DirectoryEntry->ChainLink;
		}
	}
} /* display_object_dir */
EXPORT_SYMBOL(display_object_dir);
#endif
