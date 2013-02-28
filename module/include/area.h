/*
 * area.h
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
 *   Jun 2008 - Created.
 */

/* 
 * area.h:
 * win32 area
 */
 
#ifndef _AREA_H
#define _AREA_H

#include "win32.h"
#include <asm/page.h>
#include <asm/pgtable.h>

#ifdef CONFIG_UNIFIED_KERNEL

struct win32_area_struct {
	struct list_head	wa_list;
	unsigned long	start;
	unsigned long	end;
	unsigned long	prot;
	void	*section_object;
};

static inline void insert_win32_area(struct list_head *head, unsigned long start,
		unsigned long end, unsigned long prot, void *object)
{
	struct list_head	*pos;
	struct win32_area_struct	*wa;

	if (list_empty(head)) {
		pos = head;
		goto ready;
	}

	list_for_each(pos, head) {
		wa = list_entry(pos, struct win32_area_struct, wa_list);
		if (wa->start >= end)
			break;
	}

ready:
	wa = kmalloc(sizeof(struct win32_area_struct), GFP_KERNEL);
	wa->start = start;
	wa->end = end;
	wa->prot = prot;
	if (object)
		ref_object(object);
	wa->section_object = object;
	list_add_tail(&wa->wa_list, pos);
}

static inline struct win32_area_struct *find_win32_area(
		struct list_head *head, unsigned long start, unsigned long end)
{
	struct list_head	*pos;
	struct win32_area_struct	*wa;

	if (list_empty(head))
		return NULL;

	list_for_each(pos, head) {
		wa = list_entry(pos, struct win32_area_struct, wa_list);
		if (wa->start <= start && wa->end >= end && wa->end > start)
			return wa;
	}

	return NULL;
}

static inline void remove_win32_area(struct win32_area_struct *wa)
{
	list_del(&wa->wa_list);
	if (wa->section_object)
		deref_object(wa->section_object);
	kfree(wa);
}

static inline void remove_all_win32_area(struct list_head *head)
{
	struct list_head	*pos = head->next;
	struct win32_area_struct	*wa;

	while (pos != head) {
		wa = list_entry(pos, struct win32_area_struct, wa_list);
		remove_win32_area(wa);
		pos = head->next;
	}
}

static inline void insert_reserved_area(struct eprocess *process,
		unsigned long start, unsigned long end, unsigned long prot)
{
	insert_win32_area(&process->ep_reserved_head, start, end, prot, NULL);
}

static inline void insert_mapped_area(struct eprocess *process,
		unsigned long start, unsigned long end, unsigned long prot, void *object)
{
	insert_win32_area(&process->ep_mapped_head, start, end, prot, object);
}

static inline struct win32_area_struct *find_reserved_area(
		struct eprocess *process, unsigned long start, unsigned long end)
{
	return find_win32_area(&process->ep_reserved_head, start, end);
}

static inline struct win32_area_struct *find_mapped_area(
		struct eprocess *process, unsigned long start, unsigned long end)
{
	return find_win32_area(&process->ep_mapped_head, start, end);
}

/* address NOT in any reserved area and mapped area */
static inline size_t get_free_area_size(struct eprocess *process, unsigned long address)
{
	struct list_head	*pos, *head;
	struct win32_area_struct	*wa, *prev_wa = NULL;
	int	ntry = 0;

	head = &process->ep_reserved_head;

retry:
	if (list_empty(head))
		return 0;

	list_for_each(pos, head) {
		wa = list_entry(pos, struct win32_area_struct, wa_list);
		if (wa->start > address)
			return prev_wa ? (wa->start - prev_wa->end) : wa->start;
		prev_wa = wa;
	}

	if (!ntry) {
		head = &process->ep_mapped_head;
		prev_wa = NULL;
		ntry++;
		goto retry;
	}

	return 0;
}

#endif /* CONFIG_UNIFIED_KERNEL */

#endif /* _AREA_H */
