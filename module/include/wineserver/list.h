/*
 * list.h
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
 *   Dec 2008 - Created.
 */

/* 
 * list.h:
 * Refered to Wine code
 */
#ifndef _WINESERVER_LIST_H
#define _WINESERVER_LIST_H

#include <linux/list.h>

#ifdef CONFIG_UNIFIED_KERNEL
/* add an element after the specified one */
static inline void list_add_after(struct list_head *elem, struct list_head *to_add)
{
	to_add->next = elem->next;
	to_add->prev = elem;
	elem->next->prev = to_add;
	elem->next = to_add;
}

/* add element at the head of the list */
static inline void list_add_head(struct list_head *list, struct list_head *elem)
{
	list_add_after(list, elem);
}

/* get the next element */
static inline struct list_head *list_next(const struct list_head *list, const struct list_head *elem)
{
	struct list_head *ret = elem->next;
	if (elem->next == list) 
		ret = NULL;
	return ret;
}

/* get the previous element */
static inline struct list_head *list_prev(const struct list_head *list, const struct list_head *elem)
{
	struct list_head *ret = elem->prev;
	if (elem->prev == list) 
		ret = NULL;
	return ret;
}

/* get the first element */
static inline struct list_head *list_head(const struct list_head *list)
{
	return list_next(list, list);
}

/* count the elements of a list */
static inline unsigned int list_count(const struct list_head *list)
{
	unsigned count = 0;
	const struct list_head *ptr;
	for (ptr = list->next; ptr != list; ptr = ptr->next)
		count++;
	return count;
}

/* get the last element */
static inline struct list_head *list_tail(const struct list_head *list)
{
	return list_prev(list, list);
}

/* remove an element from its list */
static inline void list_remove(struct list_head *elem)
{
	elem->next->prev = elem->prev;
	elem->prev->next = elem->next;
}

/* add an element before the specified one */
static inline void list_add_before(struct list_head *elem, struct list_head *to_add)
{
	to_add->next = elem;
	to_add->prev = elem->prev;
	elem->prev->next = to_add;
	elem->prev = to_add;
}

static inline int is_last_list(const struct list_head *head)
{
	return head->next->next == head && head->next != head;
}

/* iterate through the list */
#define LIST_FOR_EACH(cursor,list) \
    for ((cursor) = (list)->next; (cursor) != (list); (cursor) = (cursor)->next)

/* iterate through the list, with safety against removal */
#define LIST_FOR_EACH_SAFE(cursor, cursor2, list) \
    for ((cursor) = (list)->next, (cursor2) = (cursor)->next; \
         (cursor) != (list); \
         (cursor) = (cursor2), (cursor2) = (cursor)->next)

/* iterate through the list using a list entry */
#define LIST_FOR_EACH_ENTRY(elem, list, type, field) \
    for ((elem) = LIST_ENTRY((list)->next, type, field); \
         &(elem)->field != (list); \
         (elem) = LIST_ENTRY((elem)->field.next, type, field))

/* iterate through the list using a list entry, with safety against removal */
#define LIST_FOR_EACH_ENTRY_SAFE(cursor, cursor2, list, type, field) \
    for ((cursor) = LIST_ENTRY((list)->next, type, field), \
         (cursor2) = LIST_ENTRY((cursor)->field.next, type, field); \
         &(cursor)->field != (list); \
         (cursor) = (cursor2), \
         (cursor2) = LIST_ENTRY((cursor)->field.next, type, field))

/* iterate through the list in reverse order */
#define LIST_FOR_EACH_REV(cursor,list) \
    for ((cursor) = (list)->prev; (cursor) != (list); (cursor) = (cursor)->prev)

/* iterate through the list in reverse order, with safety against removal */
#define LIST_FOR_EACH_SAFE_REV(cursor, cursor2, list) \
    for ((cursor) = (list)->prev, (cursor2) = (cursor)->prev; \
         (cursor) != (list); \
         (cursor) = (cursor2), (cursor2) = (cursor)->prev)

/* iterate through the list in reverse order using a list entry */
#define LIST_FOR_EACH_ENTRY_REV(elem, list, type, field) \
    for ((elem) = LIST_ENTRY((list)->prev, type, field); \
         &(elem)->field != (list); \
         (elem) = LIST_ENTRY((elem)->field.prev, type, field))

/* iterate through the list in reverse order using a list entry, with safety against removal */
#define LIST_FOR_EACH_ENTRY_SAFE_REV(cursor, cursor2, list, type, field) \
    for ((cursor) = LIST_ENTRY((list)->prev, type, field), \
         (cursor2) = LIST_ENTRY((cursor)->field.prev, type, field); \
         &(cursor)->field != (list); \
         (cursor) = (cursor2), \
         (cursor2) = LIST_ENTRY((cursor)->field.prev, type, field))

/* macros for statically initialized lists */
#define LIST_INIT(list)  { &(list), &(list) }

/* get pointer to object containing list element */
#define LIST_ENTRY(elem, type, field) \
    ((type *)((char *)(elem) - (unsigned int)(&((type *)0)->field)))

#endif /* CONFIG_UNIFIED_KERNEL */
#endif /* _WINESERVER_LIST_H */
