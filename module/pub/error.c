/*
 * error.c
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
 * translate Linux errno to Windows NTSTATUS
 */

#include "win32.h"
#include "ntstatus.h"

#ifdef CONFIG_UNIFIED_KERNEL
#define MAX_BASE_ERROR  131

static NTSTATUS error_table_base[MAX_BASE_ERROR] =
{
	STATUS_ACCESS_DENIED,           /* EPERM        1   Operation not permitted */
	STATUS_NO_SUCH_FILE,            /* ENOENT       2   No such file or directory */
	STATUS_ACCESS_DENIED,           /* ESRCH        3   No such process */
	STATUS_UNSUCCESSFUL,            /* EINTR        4   Interrupted system call */
	STATUS_ACCESS_VIOLATION,        /* EIO          5   I/O error */
	STATUS_NO_SUCH_DEVICE,          /* ENXIO        6   No such device or address */
	STATUS_UNSUCCESSFUL,            /* E2BIG        7   Argument list too long */
	STATUS_UNSUCCESSFUL,            /* ENOEXEC      8   Exec format error */
	STATUS_INVALID_HANDLE,          /* EBADF        9   Bad file number */
	STATUS_UNSUCCESSFUL,            /* ECHILD      10   No child processes */
	STATUS_SHARING_VIOLATION,       /* EAGAIN      11   Try again */
	STATUS_NO_MEMORY,               /* ENOMEM      12   Out of memory */
	STATUS_ACCESS_DENIED,           /* EACCES      13   Permission denied */
	STATUS_INVALID_ADDRESS,         /* EFAULT      14   Bad address */
	STATUS_UNSUCCESSFUL,            /* ENOTBLK     15   Block device required */
	STATUS_DEVICE_BUSY,             /* EBUSY       16   Device or resource busy */
	STATUS_OBJECT_NAME_COLLISION,   /* EEXIST      17   File exists */
	STATUS_UNSUCCESSFUL,            /* EXDEV       18   Cross-device link */
	STATUS_NO_SUCH_DEVICE,          /* ENODEV      19   No such device */
	STATUS_NOT_A_DIRECTORY,         /* ENOTDIR     20   Not a directory */
	STATUS_FILE_IS_A_DIRECTORY,     /* EISDIR      21   Is a directory */
	STATUS_INVALID_PARAMETER,       /* EINVAL      22   Invalid argument */
	STATUS_UNSUCCESSFUL,            /* ENFILE      23   File table overflow */
	STATUS_TOO_MANY_OPENED_FILES,   /* EMFILE      24   Too many open files */
	STATUS_UNSUCCESSFUL,            /* ENOTTY      25   Not a typewriter */
	STATUS_UNSUCCESSFUL,            /* ETXTBSY     26   Text file busy */
	STATUS_SECTION_TOO_BIG,         /* EFBIG       27   File too large */
	STATUS_DISK_FULL,               /* ENOSPC      28   No space left on device */
	STATUS_ILLEGAL_FUNCTION,        /* ESPIPE      29   Illegal seek */
	STATUS_MEDIA_WRITE_PROTECTED,   /* EROFS       30   Read-only file system */
	STATUS_UNSUCCESSFUL,            /* EMLINK      31   Too many links */
	STATUS_UNSUCCESSFUL,            /* EPIPE       32   Broken pipe */
	STATUS_UNSUCCESSFUL,            /* EDOM        33   Math argument out of domain of func */
	STATUS_UNSUCCESSFUL,            /* ERANGE      34   Math result not representable */
	STATUS_UNSUCCESSFUL,            /* EDEADLK/EDEADLOCK    35     Resource deadlock would occur */
	STATUS_UNSUCCESSFUL,            /* ENAMETOOLONG 36     File name too long */
	STATUS_UNSUCCESSFUL,            /* ENOLCK      37     No record locks available */
	STATUS_UNSUCCESSFUL,            /* ENOSYS      38     Function not implemented */
	STATUS_DIRECTORY_NOT_EMPTY,     /* ENOTEMPTY   39     Directory not empty */
	STATUS_UNSUCCESSFUL,            /* ELOOP       40     Too many symbolic links encountered */
	STATUS_UNSUCCESSFUL,            /* EWOULDBLOCK/EAGAIN     Operation would block */
	STATUS_UNSUCCESSFUL,            /* ENOMSG      42     No message of desired type */
	STATUS_UNSUCCESSFUL,            /* EIDRM       43     Identifier removed */
	STATUS_UNSUCCESSFUL,            /* ECHRNG      44     Channel number out of range */
	STATUS_UNSUCCESSFUL,            /* EL2NSYNC    45     Level 2 not synchronized */
	STATUS_UNSUCCESSFUL,            /* EL3HLT      46     Level 3 halted */
	STATUS_UNSUCCESSFUL,            /* EL3RST      47     Level 3 reset */
	STATUS_UNSUCCESSFUL,            /* ELNRNG      48     Link number out of range */
	STATUS_UNSUCCESSFUL,            /* EUNATCH     49     Protocol driver not attached */
	STATUS_UNSUCCESSFUL,            /* ENOCSI      50     No CSI structure available */
	STATUS_UNSUCCESSFUL,            /* EL2HLT      51     Level 2 halted */
	STATUS_UNSUCCESSFUL,            /* EBADE       52     Invalid exchange */
	STATUS_UNSUCCESSFUL,            /* EBADR       53     Invalid request descriptor */
	STATUS_UNSUCCESSFUL,            /* EXFULL      54     Exchange full */
	STATUS_UNSUCCESSFUL,            /* ENOANO      55     No anode */
	STATUS_UNSUCCESSFUL,            /* EBADRQC     56     Invalid request code */
	STATUS_UNSUCCESSFUL,            /* EBADSLT     57     Invalid slot */
	STATUS_UNSUCCESSFUL,            /* 58 not used */
	STATUS_UNSUCCESSFUL,            /* EBFONT      59     Bad font file format */
	STATUS_UNSUCCESSFUL,            /* ENOSTR      60     Device not a stream */
	STATUS_UNSUCCESSFUL,            /* ENODATA     61     No data available */
	STATUS_UNSUCCESSFUL,            /* ETIME       62     Timer expired */
	STATUS_UNSUCCESSFUL,            /* ENOSR       63     Out of streams resources */
	STATUS_UNSUCCESSFUL,            /* ENONET      64     Machine is not on the network */
	STATUS_UNSUCCESSFUL,            /* ENOPKG      65     Package not installed */
	STATUS_UNSUCCESSFUL,            /* EREMOTE     66     Object is remote */
	STATUS_UNSUCCESSFUL,            /* ENOLINK     67     Link has been severed */
	STATUS_UNSUCCESSFUL,            /* EADV        68     Advertise error */
	STATUS_UNSUCCESSFUL,            /* ESRMNT      69     Srmount error */
	STATUS_UNSUCCESSFUL,            /* ECOMM       70     Communication error on send */
	STATUS_UNSUCCESSFUL,            /* EPROTO      71     Protocol error */
	STATUS_UNSUCCESSFUL,            /* EMULTIHOP   72     Multihop attempted */
	STATUS_UNSUCCESSFUL,            /* EDOTDOT     73     RFS specific error */
	STATUS_UNSUCCESSFUL,            /* EBADMSG     74     Not a data message */
	STATUS_INVALID_PARAMETER,       /* EOVERFLOW   75     Value too large for defined data type */
	STATUS_UNSUCCESSFUL,            /* ENOTUNIQ    76     Name not unique on network */
	STATUS_UNSUCCESSFUL,            /* EBADFD      77     File descriptor in bad state */
	STATUS_UNSUCCESSFUL,            /* EREMCHG     78     Remote address changed */
	STATUS_UNSUCCESSFUL,            /* ELIBACC     79     Can not access a needed shared library */
	STATUS_UNSUCCESSFUL,            /* ELIBBAD     80     Accessing a corrupted shared library */
	STATUS_UNSUCCESSFUL,            /* ELIBSCN     81     .lib section in a.out corrupted */
	STATUS_UNSUCCESSFUL,            /* ELIBMAX     82     Attempting to link in too many shared libraries */
	STATUS_UNSUCCESSFUL,            /* ELIBEXEC    83     Cannot exec a shared library directly */
	STATUS_UNSUCCESSFUL,            /* EILSEQ      84     Illegal byte sequence */
	STATUS_UNSUCCESSFUL,            /* ERESTART    85     Interrupted system call should be restarted */
	STATUS_UNSUCCESSFUL,            /* ESTRPIPE    86     Streams pipe error */
	STATUS_UNSUCCESSFUL,            /* EUSERS      87     Too many users */
	STATUS_UNSUCCESSFUL,            /* ENOTSOCK    88     Socket operation on non-socket */
	STATUS_UNSUCCESSFUL,            /* EDESTADDRREQ 89     Destination address required */
	STATUS_UNSUCCESSFUL,            /* EMSGSIZE    90     Message too long */
	STATUS_UNSUCCESSFUL,            /* EPROTOTYPE  91     Protocol wrong type for socket */
	STATUS_UNSUCCESSFUL,            /* ENOPROTOOPT 92     Protocol not available */
	STATUS_UNSUCCESSFUL,            /* EPROTONOSUPPORT    93     Protocol not supported */
	STATUS_UNSUCCESSFUL,            /* ESOCKTNOSUPPORT    94     Socket type not supported */
	STATUS_UNSUCCESSFUL,            /* EOPNOTSUPP  95     Operation not supported on transport endpoint */
	STATUS_UNSUCCESSFUL,            /* EPFNOSUPPORT 96     Protocol family not supported */
	STATUS_UNSUCCESSFUL,            /* EAFNOSUPPORT 97     Address family not supported by protocol */
	STATUS_UNSUCCESSFUL,            /* EADDRINUSE  98     Address already in use */
	STATUS_UNSUCCESSFUL,            /* EADDRNOTAVAIL 99     Cannot assign requested address */
	STATUS_UNSUCCESSFUL,            /* ENETDOWN    100     Network is down */
	STATUS_UNSUCCESSFUL,            /* ENETUNREACH 101     Network is unreachable */
	STATUS_UNSUCCESSFUL,            /* ENETRESET   102     Network dropped connection because of reset */
	STATUS_UNSUCCESSFUL,            /* ECONNABORTED 103     Software caused connection abort */
	STATUS_UNSUCCESSFUL,            /* ECONNRESET  104     Connection reset by peer */
	STATUS_UNSUCCESSFUL,            /* ENOBUFS     105     No buffer space available */
	STATUS_UNSUCCESSFUL,            /* EISCONN     106     Transport endpoint is already connected */
	STATUS_UNSUCCESSFUL,            /* ENOTCONN    107     Transport endpoint is not connected */
	STATUS_UNSUCCESSFUL,            /* ESHUTDOWN   108     Cannot send after transport endpoint shutdown */
	STATUS_UNSUCCESSFUL,            /* ETOOMANYREFS 109     Too many references: cannot splice */
	STATUS_UNSUCCESSFUL,            /* ETIMEDOUT   110     Connection timed out */
	STATUS_UNSUCCESSFUL,            /* ECONNREFUSED 111     Connection refused */
	STATUS_UNSUCCESSFUL,            /* EHOSTDOWN   112     Host is down */
	STATUS_UNSUCCESSFUL,            /* EHOSTUNREACH 113     No route to host */
	STATUS_UNSUCCESSFUL,            /* EALREADY    114     Operation already in progress */
	STATUS_UNSUCCESSFUL,            /* EINPROGRESS 115     Operation now in progress */
	STATUS_UNSUCCESSFUL,            /* ESTALE      116     Stale NFS file handle */
	STATUS_UNSUCCESSFUL,            /* EUCLEAN     117     Structure needs cleaning */
	STATUS_UNSUCCESSFUL,            /* ENOTNAM     118     Not a XENIX named type file */
	STATUS_UNSUCCESSFUL,            /* ENAVAIL     119     No XENIX semaphores available */
	STATUS_UNSUCCESSFUL,            /* EISNAM      120     Is a named type file */
	STATUS_UNSUCCESSFUL,            /* EREMOTEIO   121     Remote I/O error */
	STATUS_UNSUCCESSFUL,            /* EDQUOT      122     Quota exceeded */
	STATUS_UNSUCCESSFUL,            /* ENOMEDIUM   123     No medium found */
	STATUS_UNSUCCESSFUL,            /* EMEDIUMTYPE 124     Wrong medium type */
	STATUS_UNSUCCESSFUL,            /* ECANCELED   125     Operation Canceled */
	STATUS_UNSUCCESSFUL,            /* ENOKEY      126     Required key not available */
	STATUS_UNSUCCESSFUL,            /* EKEYEXPIRED 127     Key has expired */
	STATUS_UNSUCCESSFUL,            /* EKEYREVOKED 128     Key has been revoked */
	STATUS_UNSUCCESSFUL,            /* EKEYREJECTED 129     Key was rejected by service */
	STATUS_UNSUCCESSFUL,            /* EOWNERDEAD  130    Owner died */
	STATUS_UNSUCCESSFUL             /* ENOTRECOVERABLE    131    State not recoverable */
};

#define MAX_EX_ERROR    5
#define TABLE_EX_START  512

static NTSTATUS error_table_ex[MAX_EX_ERROR] =
{
	STATUS_UNSUCCESSFUL,    /* ERESTARTSYS    512 */
	STATUS_UNSUCCESSFUL,    /* ERESTARTNOINTR    513 */
	STATUS_UNSUCCESSFUL,    /* ERESTARTNOHAND    514     restart if no handler.. */
	STATUS_UNSUCCESSFUL,    /* ENOIOCTLCMD    515     No ioctl command */
	STATUS_UNSUCCESSFUL     /* ERESTART_RESTARTBLOCK 516  restart by calling sys_restart_syscall */
};

NTSTATUS errno2ntstatus(int error)
{
	if (error >= TABLE_EX_START) {
		error -= TABLE_EX_START;
		return error >= MAX_EX_ERROR ? STATUS_UNSUCCESSFUL : error_table_ex[error];
	} else {
		return error >= MAX_BASE_ERROR ? STATUS_UNSUCCESSFUL : error_table_base[error];
	}
}
#endif /* CONFIG_UNIFIED_KERNEL */
