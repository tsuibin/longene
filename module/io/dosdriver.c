/*
 * dosdriver.c
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
 * dosdriver.c: DOS driver operation for /proc
 */
#include "object.h"

#ifdef CONFIG_UNIFIED_KERNEL

#define	MAX_DOSDRIVERS	26

char *dosdriver_symlink[MAX_DOSDRIVERS];
EXPORT_SYMBOL(dosdriver_symlink);

extern void create_dosdriver_symlink(int index, char *target_str);
extern void display_object_dir(POBJECT_DIRECTORY DirectoryObject, LONG Depth);

/* add it in proc.c */
void free_dosdriver(void)
{
	int	i;

	for (i = 0; i < MAX_DOSDRIVERS; i++)
		if (dosdriver_symlink[i])
			kfree(dosdriver_symlink[i]);
}
EXPORT_SYMBOL(free_dosdriver);

size_t print_dosdriver(char *buf)
{
	int	i;
	size_t	ret = 0;

	for (i = 0; i < MAX_DOSDRIVERS; i++)
		ret += sprintf(buf + ret, "%c: %s\n", i + 'A', dosdriver_symlink[i]);

	return ret;
}
EXPORT_SYMBOL(print_dosdriver);

int parse_dosdriver(char *buf, size_t count, int append)
{
	int	index, len;
	char	*p, *head;
	char	new[MAX_DOSDRIVERS];

	memset(new, 0, sizeof(new));
	if (!append)
		memset(dosdriver_symlink, 0, sizeof(dosdriver_symlink));

	if (count == PAGE_SIZE)
		buf[PAGE_SIZE - 1] = '\0';
	else
		buf[count++] = '\0';

	head = buf;
	while (head < buf + count) {
		while (*head == ' ' || *head == '\t' || *head == '\r' || *head == '\n')
			head++;
		if (((*head >= 'A' && *head <= 'Z') || (*head >= 'a' && *head <= 'z'))
				&& *(head + 1) == ':' && *(head + 2) == ' ') {
			index = *head - ((*head <= 'Z') ? 'A' : 'a');
			head += 3;
			while (*head == ' ' || *head == '\t')
				head++;
			p = head;
			while (*p != '\n' && *p)
				p++;
			len = p - head - (*(p - 1) == '\r' ? 1 : 0);
			if (dosdriver_symlink[index])
				kfree(dosdriver_symlink[index]);
			dosdriver_symlink[index] = (char *)kmalloc(len + 1, GFP_KERNEL);
			memcpy(dosdriver_symlink[index], head, len);
			dosdriver_symlink[index][len++] = '\0';
			new[index] = 1;
			head = p + 1;
		}
		else {
			p = strchr(head, '\n');
			if (!p)
				break;
			head = p + 1;
		}
	}

	for (index = 0; index < MAX_DOSDRIVERS; index++) {
		if ((p = dosdriver_symlink[index]) && new[index])
			create_dosdriver_symlink(index, p);
	}

	display_object_dir(NULL, 1);
	return count;
}
EXPORT_SYMBOL(parse_dosdriver);
#endif
