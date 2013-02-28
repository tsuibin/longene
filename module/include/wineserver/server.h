/*
 * server.h
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
 *   Mar 2009 - Created.
 */

/* 
 * server.h:
 * Refered to Wine code
 */

#ifndef _WINESERVER_SERVER_H
#define _WINESERVER_SERVER_H
#include "protocol.h"

#ifdef CONFIG_UNIFIED_KERNEL
struct __server_iovec
{
	const void  *ptr;
	data_size_t  size;
};

#define __SERVER_MAX_DATA 5

typedef struct __server_request_info
{
	union
	{
		union generic_request req;    /* request structure */
		union generic_reply   reply;  /* reply structure */
	} u;
	unsigned int          data_count; /* count of request data pointers */
	void                 *reply_data; /* reply data pointer */
	struct __server_iovec data[__SERVER_MAX_DATA];  /* request variable size data */
} *PSERVER_REQUEST_INFO;
#endif /* CONFIG_UNIFIED_KERNEL */
#endif /* _WINESERVER_SERVER_H */
