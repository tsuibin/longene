/*
 * request.c
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
 * request.c:
 * Refered to Wine code
 */

#include "wineserver/request.h"

#ifdef CONFIG_UNIFIED_KERNEL
DECL_HANDLER(queue_exception_event){ }
DECL_HANDLER(get_exception_status){ }

DECL_HANDLER(output_debug_string){ }
DECL_HANDLER(wait_debug_event){ }
DECL_HANDLER(continue_debug_event){ }
DECL_HANDLER(debug_process){ }
DECL_HANDLER(debug_break){ }
DECL_HANDLER(set_debugger_kill_on_exit){ }

#endif /* CONFIG_UNIFIED_KERNEL */ 
