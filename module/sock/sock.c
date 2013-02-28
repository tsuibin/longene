/*
 * sock.c
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
 * sock.c:
 * Refered to Wine code
 */

/*
#include <linux/mm.h>
#include <linux/syscalls.h>
*/
#include <linux/poll.h>
#include "unistr.h"
#include "handle.h"

#ifdef CONFIG_UNIFIED_KERNEL
/* To avoid conflicts with the Unix socket headers. Plus we only need a few
 * macros anyway.
 */

#define FD_MAX_EVENTS              10
#define FD_READ_BIT                0
#define FD_WRITE_BIT               1
#define FD_OOB_BIT                 2
#define FD_ACCEPT_BIT              3
#define FD_CONNECT_BIT             4
#define FD_CLOSE_BIT               5

/* Flags that make sense only for SOCK_STREAM sockets */
#define STREAM_FLAG_MASK \
	((unsigned int) (FD_CONNECT | FD_ACCEPT | FD_WINE_LISTENING | FD_WINE_CONNECTED))

#define AF_UNIX     1   /* Unix domain sockets      */

#define FD_WINE_ACCEPTING          0x08000000
#define FD_WINE_LISTENING          0x10000000
#define FD_WINE_NONBLOCKING        0x20000000
#define FD_WINE_CONNECTED          0x40000000
#define FD_WINE_RAW                0x80000000
#define FD_WINE_INTERNAL           0xFFFF0000

#define SOL_SOCKET                 0xffff
#define SO_ERROR                   0x1007

#define WSA_FLAG_OVERLAPPED        0x01

/*
 *  * Define flags to be used with the WSAAsyncSelect() call.
 */
#define FD_READ                    0x00000001
#define FD_WRITE                   0x00000002
#define FD_OOB                     0x00000004
#define FD_ACCEPT                  0x00000008
#define FD_CONNECT                 0x00000010
#define FD_CLOSE                   0x00000020

#define MSG_PEEK                   0x0002

#define FILE_SYNCHRONOUS_IO_NONALERT    0x00000020

#define WSABASEERR                 10000
#define WSAEINTR                   (WSABASEERR+4)
#define WSAEBADF                   (WSABASEERR+9)
#define WSAEACCES                  (WSABASEERR+13)
#define WSAEFAULT                  (WSABASEERR+14)
#define WSAEINVAL                  (WSABASEERR+22)
#define WSAEMFILE                  (WSABASEERR+24)

#define WSAEWOULDBLOCK             (WSABASEERR+35)
#define WSAEINPROGRESS             (WSABASEERR+36)
#define WSAEALREADY                (WSABASEERR+37)
#define WSAENOTSOCK                (WSABASEERR+38)
#define WSAEDESTADDRREQ            (WSABASEERR+39)
#define WSAEMSGSIZE                (WSABASEERR+40)
#define WSAEPROTOTYPE              (WSABASEERR+41)
#define WSAENOPROTOOPT             (WSABASEERR+42)
#define WSAEPROTONOSUPPORT         (WSABASEERR+43)
#define WSAESOCKTNOSUPPORT         (WSABASEERR+44)
#define WSAEOPNOTSUPP              (WSABASEERR+45)
#define WSAEPFNOSUPPORT            (WSABASEERR+46)
#define WSAEAFNOSUPPORT            (WSABASEERR+47)
#define WSAEADDRINUSE              (WSABASEERR+48)
#define WSAEADDRNOTAVAIL           (WSABASEERR+49)
#define WSAENETDOWN                (WSABASEERR+50)
#define WSAENETUNREACH             (WSABASEERR+51)
#define WSAENETRESET               (WSABASEERR+52)
#define WSAECONNABORTED            (WSABASEERR+53)
#define WSAECONNRESET              (WSABASEERR+54)
#define WSAENOBUFS                 (WSABASEERR+55)
#define WSAEISCONN                 (WSABASEERR+56)
#define WSAENOTCONN                (WSABASEERR+57)
#define WSAESHUTDOWN               (WSABASEERR+58)
#define WSAETOOMANYREFS            (WSABASEERR+59)
#define WSAETIMEDOUT               (WSABASEERR+60)
#define WSAECONNREFUSED            (WSABASEERR+61)
#define WSAELOOP                   (WSABASEERR+62)
#define WSAENAMETOOLONG            (WSABASEERR+63)
#define WSAEHOSTDOWN               (WSABASEERR+64)
#define WSAEHOSTUNREACH            (WSABASEERR+65)
#define WSAENOTEMPTY               (WSABASEERR+66)
#define WSAEPROCLIM                (WSABASEERR+67)
#define WSAEUSERS                  (WSABASEERR+68)
#define WSAEDQUOT                  (WSABASEERR+69)
#define WSAESTALE                  (WSABASEERR+70)
#define WSAEREMOTE                 (WSABASEERR+71)

typedef unsigned short  sa_family_t;

struct sockaddr {
	sa_family_t sa_family;  /* address family, AF_xxx   */
	char        sa_data[14];    /* 14 bytes of protocol address */
};

struct sock
{
	struct object       obj;         /* object header */
	struct fd          *fd;          /* socket file descriptor */
	unsigned int        state;       /* status bits */
	unsigned int        mask;        /* event mask */
	unsigned int        hmask;       /* held (blocked) events */
	unsigned int        pmask;       /* pending events */
	unsigned int        flags;       /* socket flags */
	int                 polling;     /* is socket being polled? */
	unsigned short      type;        /* socket type */
	unsigned short      family;      /* socket family */
	struct kevent       *event;       /* event object */
	user_handle_t       window;      /* window to send the message to */
	unsigned int        message;     /* message to send */
	obj_handle_t        wparam;      /* message wparam (socket handle) */
	int                 errors[FD_MAX_EVENTS]; /* event errors */
	struct sock        *deferred;    /* socket that waits for a deferred accept */
	struct async       *async;       /* pending accept to this socket */
	struct list_head    accentry;    /* entry in the list below for the request */
	struct list_head    paccepts;    /* pending accepts on this socket */
	struct async_queue *read_q;      /* queue for asynchronous reads */
	struct async_queue *write_q;     /* queue for asynchronous writes */
};

static struct fd *sock_get_fd(struct object *obj);
static void sock_destroy(struct object *obj);

static int sock_signaled(struct object *obj, struct w32thread *thread);
static int sock_get_poll_events(struct fd *fd);
static void sock_poll_event(struct fd *fd, int event);
static enum server_fd_type sock_get_fd_type(struct fd *fd);
static int sock_removable(struct fd *fd);
static void sock_queue_async(struct fd *fd, const async_data_t *data, int type, int count);
static void sock_async_event(struct fd *fd, struct async_queue *queue, struct async *async, int status, int finished);
static int sock_async_terminated(struct fd *fd, struct async_queue *queue, struct async *async, int status);
static void sock_cancel_async(struct fd *fd, struct w32process *process, struct w32thread *thread, unsigned __int64 iosb);

static int sock_get_ntstatus(int err);
static int sock_get_error(int err);
static void sock_set_error(void);
static int accept_into_socket(struct sock *sock, struct sock *acceptsock);
extern unsigned int default_fd_map_access(struct object *obj, unsigned int access);

static const struct object_ops sock_ops =
{
	sizeof(struct sock),       /* size */
	NULL,						  /* dump */
	no_get_type,                  /* get_type */
	sock_get_fd,                  /* get_fd */
	default_fd_map_access,        /* map_access */
	no_lookup_name,               /* lookup_name */
	no_open_file,                 /* open_file */
	fd_close_handle,              /* close_handle */
	sock_destroy,                 /* destroy */

	sock_signaled,                /* signaled */
	no_satisfied,                 /* satisfied */
	no_signal,                    /* signal */
	default_get_sd,               /* get_sd */
	default_set_sd                /* set_sd */
};

static const struct fd_ops sock_fd_ops =
{
	sock_get_poll_events,         /* get_poll_events */
	sock_poll_event,              /* poll_event */
	no_flush,                     /* flush */
	sock_get_fd_type,             /* get_file_info */
	sock_removable,               /* removable */
	default_fd_ioctl,             /* ioctl */
	sock_queue_async,             /* queue_async */
	sock_async_event,             /* async_event */
	sock_async_terminated,        /* async_terminated */
	sock_cancel_async             /* cancel_async */
};

/* Permutation of 0..FD_MAX_EVENTS - 1 representing the order in which
 * we post messages if there are multiple events.  Used to send
 * messages.  The problem is if there is both a FD_CONNECT event and,
 * say, an FD_READ event available on the same socket, we want to
 * notify the app of the connect event first.  Otherwise it may
 * discard the read event because it thinks it hasn't connected yet.
 */
static const int event_bitorder[FD_MAX_EVENTS] =
{
	FD_CONNECT_BIT,
	FD_ACCEPT_BIT,
	FD_OOB_BIT,
	FD_WRITE_BIT,
	FD_READ_BIT,
	FD_CLOSE_BIT,
	6, 7, 8, 9  /* leftovers */
};

typedef enum {
	SOCK_SHUTDOWN_ERROR = -1,
	SOCK_SHUTDOWN_EOF = 0,
	SOCK_SHUTDOWN_POLLHUP = 1
} sock_shutdown_t;

static sock_shutdown_t sock_shutdown_type = SOCK_SHUTDOWN_ERROR;

/* Types of sockets.  */
enum __socket_type
{
	SOCK_STREAM = 1,      /* Sequenced, reliable, connection-based
							 byte streams.  */
#define SOCK_STREAM SOCK_STREAM
	SOCK_DGRAM = 2,       /* Connectionless, unreliable datagrams
							 of fixed maximum length.  */
#define SOCK_DGRAM SOCK_DGRAM
	SOCK_RAW = 3,         /* Raw protocol interface.  */
#define SOCK_RAW SOCK_RAW
	SOCK_RDM = 4,         /* Reliably-delivered messages.  */
#define SOCK_RDM SOCK_RDM
	SOCK_SEQPACKET = 5,       /* Sequenced, reliable, connection-based,
								 datagrams of fixed maximum length.  */
#define SOCK_SEQPACKET SOCK_SEQPACKET
	SOCK_PACKET = 10      /* Linux specific way of getting packets
							 at the dev level.  For writing rarp and
							 other similar things on the user level. */
#define SOCK_PACKET SOCK_PACKET
};

static WCHAR sock_type_name[] = {'S', 'o', 'c', 'k', 0};

POBJECT_TYPE sock_object_type = NULL;
EXPORT_SYMBOL(sock_object_type);

static GENERIC_MAPPING sock_mapping =
{
	STANDARD_RIGHTS_READ | SYNCHRONIZE | 0x1 /* QUERY_STATE */,
	STANDARD_RIGHTS_WRITE | SYNCHRONIZE | 0x2 /* MODIFY_STATE */,
	STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE | 0x1 /* QUERY_STATE */,
	STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3
};

VOID
init_sock_implement(VOID)
{
	OBJECT_TYPE_INITIALIZER ObjectTypeInitializer;
	UNICODE_STRING Name;

	memset(&ObjectTypeInitializer, 0, sizeof(ObjectTypeInitializer));
	init_unistr(&Name, sock_type_name);
	ObjectTypeInitializer.Length = sizeof(ObjectTypeInitializer);
	ObjectTypeInitializer.DefaultNonPagedPoolCharge = sizeof(struct sock);
	ObjectTypeInitializer.GenericMapping = sock_mapping;
	ObjectTypeInitializer.PoolType = NonPagedPool;
	ObjectTypeInitializer.ValidAccessMask = EVENT_ALL_ACCESS;
	ObjectTypeInitializer.UseDefaultObject = TRUE;
	create_type_object(&ObjectTypeInitializer, &Name, &sock_object_type);
}

static sock_shutdown_t sock_check_pollhup(void)
{
	sock_shutdown_t ret = SOCK_SHUTDOWN_ERROR;
	int fd[2], n;
	struct pollfd pfd;
	char dummy;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd)) 
		goto out;
	if (shutdown(fd[0], 1)) 
		goto out;

	pfd.fd = fd[1];
	pfd.events = POLLIN;
	pfd.revents = 0;

	n = poll(&pfd, 1, 0);
	if (n != 1) 
		goto out; /* error or timeout */
	if (pfd.revents & POLLHUP)
		ret = SOCK_SHUTDOWN_POLLHUP;
	else if (pfd.revents & POLLIN && read(fd[1], &dummy, 1) == 0)
		ret = SOCK_SHUTDOWN_EOF;

out:
	close(fd[0]);
	close(fd[1]);
	return ret;
}

void sock_init(void)
{
	sock_shutdown_type = sock_check_pollhup();

	switch (sock_shutdown_type) {
		case SOCK_SHUTDOWN_EOF:
			ktrace("shutdown() causes EOF\n");
			break;
		case SOCK_SHUTDOWN_POLLHUP:
			ktrace("shutdown() causes POLLHUP\n");
			break;
		default:
			ktrace("ERROR in sock_check_pollhup()\n");
			sock_shutdown_type = SOCK_SHUTDOWN_EOF;
	}
}

static int sock_reselect(struct sock *sock)
{
	int ev = sock_get_poll_events(sock->fd);

	ktrace("(%p): new mask %x\n", sock, ev);

	if (!sock->polling)  /* FIXME: should find a better way to do this */ {
		/* previously unconnected socket, is this reselect supposed to connect it? */
		if (!(sock->state & ~(FD_WINE_NONBLOCKING | FD_WINE_ACCEPTING)))
			return 0;
		/* ok, it is, attach it to the wineserver's main poll loop */
		sock->polling = 1;
	}
	/* update condition mask */
	set_fd_events(sock->fd, ev);
	return ev;
}

/* After POLLHUP is received, the socket will no longer be in the main select loop.
   This function is used to signal pending events nevertheless */
static void sock_try_event( struct sock *sock, int event )
{
    event = check_fd_events( sock->fd, event );
    if (event)
    {
        sock_poll_event( sock->fd, event );
    }
}

/* wake anybody waiting on the socket event or send the associated message */
static void sock_wake_up(struct sock *sock)
{
	unsigned int events = sock->pmask & sock->mask;
	int i;

	/* Do not signal events if there are still pending asynchronous IO requests */
	/* We need this to delay FD_CLOSE events until all pending overlapped requests are processed */
	if (!events || async_queued(sock->read_q) || async_queued(sock->write_q)) 
		return;

	if (sock->event) {
		ktrace("signalling events %x ptr %p\n", events, sock->event);
		set_event(sock->event, EVENT_INCREMENT, FALSE);
	}
	if (sock->window) {
		ktrace("signalling events %x win %p\n", events, sock->window);
		for (i = 0; i < FD_MAX_EVENTS; i++) {
			int event = event_bitorder[i];
			if (sock->pmask & (1 << event)) {
				unsigned int lparam = (1 << event) | (sock_get_error(sock->errors[event]) << 16);
				post_message(sock->window, sock->message, (unsigned long)sock->wparam, lparam);
			}
		}
		sock->pmask = 0;
		sock_reselect(sock);
	}
}

static inline int sock_error(struct fd *fd)
{
	unsigned int optval = 0, optlen;

	optlen = sizeof(optval);
	getsockopt(get_unix_fd(fd), SOL_SOCKET, SO_ERROR, (void *) &optval, &optlen);
	return optval;
}

static void sock_dispatch_asyncs( struct sock *sock, int event )
{
    if ( sock->flags & WSA_FLAG_OVERLAPPED )
    {
        if ( event & (POLLIN|POLLPRI|POLLERR|POLLHUP) && async_waiting( sock->read_q ))
        {
            ktrace("activating read queue for socket %p\n", sock );
            async_wake_up( sock->read_q, STATUS_ALERTED );
        }
        if ( event & (POLLOUT|POLLERR|POLLHUP) && async_waiting( sock->write_q ))
        {
            ktrace("activating write queue for socket %p\n", sock );
            async_wake_up( sock->write_q, STATUS_ALERTED );
        }
    }
}

static inline void sock_free_accept_async(struct sock *acceptsock)
{
	list_remove(&acceptsock->accentry);
	acceptsock->state &= ~FD_WINE_ACCEPTING;
	acceptsock->async = NULL;
}

static void sock_poll_event(struct fd *fd, int event)
{
	struct sock *sock = get_fd_user(fd);
	int hangup_seen = 0;

	ktrace("socket %p unix_fd %d, select event: %x\n", sock, get_unix_fd(fd), event);

	/* we may change event later, remove from loop here */
	if (event & (POLLERR | POLLHUP))
		set_fd_events(sock->fd, -1);
	if (sock->state & FD_CONNECT) {
		/* connecting */
		if (event & POLLOUT) {
			/* we got connected */
			sock->state |= FD_WINE_CONNECTED|FD_READ|FD_WRITE;
			sock->state &= ~FD_CONNECT;
			sock->pmask |= FD_CONNECT;
			sock->errors[FD_CONNECT_BIT] = 0;
			ktrace("socket %p connection success\n", sock);
		} else if (event & (POLLERR|POLLHUP)) {
			/* we didn't get connected? */
			sock->state &= ~FD_CONNECT;
			sock->pmask |= FD_CONNECT;
			sock->errors[FD_CONNECT_BIT] = sock_error(fd);
			ktrace("socket %p connection failure\n", sock);
		}
	} else if (sock->state & FD_WINE_LISTENING) {
		/* listening */
		if (event & POLLIN) {
			/* incoming connection */
			sock->pmask |= FD_ACCEPT;
			sock->errors[FD_ACCEPT_BIT] = 0;
			sock->hmask |= FD_ACCEPT;
		}
		else if (event & (POLLERR|POLLHUP)) {
			/* failed incoming connection? */
			sock->pmask |= FD_ACCEPT;
			sock->errors[FD_ACCEPT_BIT] = sock_error(fd);
			sock->hmask |= FD_ACCEPT;
		}
	} else {
		/* normal data flow */
		if (sock->type == SOCK_STREAM && (event & POLLIN)) {
			char dummy;
			int nr;

			/* Linux 2.4 doesn't report POLLHUP if only one side of the socket
			 * has been closed, so we need to check for it explicitly here */
			nr  = recv(get_unix_fd(fd), &dummy, 1, MSG_PEEK);
            if ( nr == 0 )
            {
                hangup_seen = 1;
                event &= ~POLLIN;
            }
            else if ( nr < 0 )
            {
                event &= ~POLLIN;
                /* EAGAIN can happen if an async recv() falls between the server's poll()
                   call and the invocation of this routine */
                if ( errno != EAGAIN )
                {
                    ktrace("recv error on socket %p: %d\n", sock, errno );
                    event |= POLLERR;
                }
            }
        }

        if ( event & POLLIN )
        {
            sock->pmask |= FD_READ;
            sock->hmask |= FD_READ;
            sock->errors[FD_READ_BIT] = 0;
            ktrace("socket %p is readable\n", sock );
        }

        if (event & POLLOUT)
        {
            sock->pmask |= FD_WRITE;
            sock->hmask |= FD_WRITE;
            sock->errors[FD_WRITE_BIT] = 0;
            ktrace("socket %p is writable\n", sock);
        }
        if (event & POLLPRI)
        {
            sock->pmask |= FD_OOB;
            sock->hmask |= FD_OOB;
            sock->errors[FD_OOB_BIT] = 0;
            ktrace("socket %p got OOB data\n", sock);
        }

        if ( (hangup_seen || event & (POLLHUP|POLLERR)) && (sock->state & (FD_READ|FD_WRITE)) )
        {
            sock->errors[FD_CLOSE_BIT] = sock_error( fd );
            if ( (event & POLLERR) || ( sock_shutdown_type == SOCK_SHUTDOWN_EOF && (event & POLLHUP) ))
                sock->state &= ~FD_WRITE;
            sock->state &= ~FD_READ;

            sock->pmask |= FD_CLOSE;
            sock->hmask |= FD_CLOSE;
            ktrace("socket %p aborted by error %d, event: %x - removing from select loop\n",
                        sock, sock->errors[FD_CLOSE_BIT], event);
        }

        if (hangup_seen)
            event |= POLLHUP;
    }

    sock_dispatch_asyncs( sock, event );

    sock_reselect( sock );

    /* wake up anyone waiting for whatever just happened */
    sock_wake_up( sock );

	/* if anyone is stupid enough to wait on the socket object itself,
	 * maybe we should wake them up too, just in case? */
	uk_wake_up(&sock->obj, 0);
}

static int sock_signaled(struct object *obj, struct w32thread *thread)
{
	struct sock *sock = (struct sock *)obj;

	return check_fd_events(sock->fd, sock_get_poll_events(sock->fd)) != 0;
}

static int sock_get_poll_events(struct fd *fd)
{
	struct sock *sock = get_fd_user(fd);
	unsigned int mask = sock->mask & ~sock->hmask;
    unsigned int smask = sock->state & mask;
	int ev = 0;

	if (sock->state & FD_CONNECT)
		/* connecting, wait for writable */
		return POLLOUT;
	if (sock->state & FD_WINE_LISTENING)
		/* listening, wait for readable */
		/* FIXME: conflict with the former? */
		return (!(sock->hmask & FD_ACCEPT) || async_waiting( sock->read_q)) ? POLLIN : 0;

    if ( async_queued( sock->read_q ) )
    {
        if ( async_waiting( sock->read_q ) ) ev |= POLLIN | POLLPRI;
    }
    else if (smask & FD_READ)
        ev |= POLLIN | POLLPRI;
    /* We use POLLIN with 0 bytes recv() as FD_CLOSE indication for stream sockets. */
    else if ( sock->type == SOCK_STREAM && sock->state & FD_READ && mask & FD_CLOSE &&
              !(sock->hmask & FD_READ) )
        ev |= POLLIN;

    if ( async_queued( sock->write_q ) )
    {
        if ( async_waiting( sock->write_q ) ) ev |= POLLOUT;
    }
    else if (smask & FD_WRITE)
        ev |= POLLOUT;

    return ev;
}

static enum server_fd_type sock_get_fd_type(struct fd *fd)
{
	return FD_TYPE_SOCKET;
}

static int sock_removable(struct fd *fd)
{
	struct sock *sock = get_fd_user(fd);

	/* Don't cache SOCK_STREAM sockets until connected (needed for AcceptEx) */
	return sock->type == SOCK_STREAM && !sock->polling;
}

static void sock_queue_async(struct fd *fd, const async_data_t *data, int type, int count)
{
	struct sock *sock = get_fd_user(fd);
	struct async_queue *queue;
	int pollev;

	switch (type) {
		case ASYNC_TYPE_READ:
			if (!sock->read_q && !(sock->read_q = create_async_queue(sock->fd))) 
				return;
			queue = sock->read_q;
			break;
		case ASYNC_TYPE_WRITE:
			if (!sock->write_q && !(sock->write_q = create_async_queue(sock->fd))) 
				return;
			queue = sock->write_q;
			break;
		default:
			set_error(STATUS_INVALID_PARAMETER);
			return;
	}

	if ((!(sock->state & FD_READ) && type == ASYNC_TYPE_READ ) ||
			(!(sock->state & FD_WRITE) && type == ASYNC_TYPE_WRITE)) {
		set_error(STATUS_PIPE_DISCONNECTED);
	} else {
		struct async *async;
		if (!(async = create_async(current_thread, queue, data))) 
			return;
		release_object(async);
		set_error(STATUS_PENDING);
	}

	pollev = sock_reselect(sock);
	if ( pollev ) sock_try_event( sock, pollev );
}

static void sock_async_event(struct fd *fd, struct async_queue *queue, struct async *async, int status, int finished)
{
	struct sock *sock = get_fd_user(fd);
	struct sock *acceptsock, *next;

	if (finished) {
		/* clear pending accepts */
		LIST_FOR_EACH_ENTRY_SAFE(acceptsock, next, &sock->paccepts, struct sock, accentry)
		{
			if (acceptsock->async == async) {
				sock_free_accept_async(acceptsock);
				break;
			}
		}
	}
	sock_reselect(sock);
}

static int sock_async_terminated( struct fd *fd, struct async_queue *queue, struct async *async, int status)
{
	struct sock *sock = get_fd_user( fd );
	struct sock *acceptsock;

	if (status == STATUS_ALERTED) {
		LIST_FOR_EACH_ENTRY( acceptsock, &sock->paccepts, struct sock, accentry )
		{
			if ( acceptsock->async == async ) {
				status = accept_into_socket( sock, acceptsock );

				if (status != WSAEWOULDBLOCK)
					sock_free_accept_async( acceptsock );

				if (status == STATUS_SUCCESS) {
					sock_reselect( acceptsock );
					status = STATUS_ALERTED;
				}
				else if (status == WSAEWOULDBLOCK)
						status = STATUS_PENDING;
				break;
    		}
		}
	}

	return status;
}

static void sock_cancel_async(struct fd *fd, struct w32process *process, struct w32thread *thread, unsigned __int64 iosb)
{
	struct sock *sock = get_fd_user(fd);
	int n = 0;

	n += async_wake_up_by(sock->read_q, process, thread, iosb, STATUS_CANCELLED);
	n += async_wake_up_by(sock->write_q, process, thread, iosb, STATUS_CANCELLED);
	if (!n && iosb)
		set_error(STATUS_NOT_FOUND);
}

static struct fd *sock_get_fd(struct object *obj)
{
	struct sock *sock = (struct sock *)obj;
	return (struct fd *)grab_object(sock->fd);
}

static void sock_destroy(struct object *obj)
{
	struct sock *sock = (struct sock *)obj;
	struct sock *acceptsock, *next;

	/* FIXME: special socket shutdown stuff? */

	if (sock->deferred)
		release_object(sock->deferred);
	if (sock->async) {
		async_terminate(sock->async, STATUS_CANCELLED);
		sock_free_accept_async(sock);
	}
	LIST_FOR_EACH_ENTRY_SAFE(acceptsock, next, &sock->paccepts, struct sock, accentry)
	{
		/* no need to cancel, freeing queues does it */
		sock_free_accept_async(acceptsock);
	}

	free_async_queue(sock->read_q);
	free_async_queue(sock->write_q);
	if (sock->event) 
		release_object(sock->event);
	if (sock->fd) {
		/* shut the socket down to force pending poll() calls in the client to return */
		shutdown(get_unix_fd(sock->fd), SHUT_RDWR);
		release_object(sock->fd);
	}
}

static struct sock *alloc_sock(void)
{
	struct sock *sock;
	NTSTATUS status = STATUS_SUCCESS;

	status = create_object(KernelMode,
			sock_object_type,
			NULL /* obj_attr*/,
			KernelMode,
			NULL,
			sizeof(struct sock),
			0,
			0,
			(PVOID *)&sock);

	if (NT_SUCCESS(status) && sock) {
		INIT_DISP_HEADER(&sock->obj.header, SOCK, 
				sizeof(struct sock) / sizeof(ULONG), 0);
		BODY_TO_HEADER(&(sock->obj))->ops = &sock_ops;

		sock->state = 0;
		sock->mask    = 0;
		sock->hmask   = 0;
		sock->pmask   = 0;
		sock->polling = 0;
		sock->flags   = 0;
		sock->type    = 0;
		sock->family  = 0;
		sock->event   = NULL;
		sock->window  = 0;
		sock->message = 0;
		sock->wparam  = 0;
		sock->deferred = NULL;
		sock->async   = NULL;
		INIT_LIST_HEAD(&sock->paccepts);
		sock->read_q  = NULL;
		sock->write_q = NULL;
	} else {
		ktrace("failed\n");
		return NULL;
	}

	return sock;
}

/* create a new and unconnected socket */
static struct object *create_socket(int family, int type, int protocol, unsigned int flags)
{
	struct sock *sock;
	int sockfd;

	sockfd = socket(family, type, protocol);
	ktrace("socket(%d,%d,%d)=%d\n",family,type,protocol,sockfd);
	if (sockfd == -1) {
		sock_set_error();
		return NULL;
	}
	fcntl(sockfd, F_SETFL, O_NONBLOCK); /* make socket nonblocking */

	if (!(sock = alloc_sock())) {
		close(sockfd);
		return NULL;
	}
	sock->state = (type != SOCK_STREAM) ? (FD_READ|FD_WRITE) : 0;
	sock->flags   = flags;
	sock->type    = type;
	sock->family  = family;
	memset(sock->errors, 0, sizeof(sock->errors));
	if (!(sock->fd = create_anonymous_fd(&sock_fd_ops, sockfd, &sock->obj,
					(flags & WSA_FLAG_OVERLAPPED) ? 0 : FILE_SYNCHRONOUS_IO_NONALERT))) {
		release_object(sock);
		return NULL;
	}

	sock_reselect(sock);
	clear_error();
	return &sock->obj;
}

/* accepts a socket and inits it */
static int accept_new_fd( struct sock *sock )
{
	/* Try to accept(2). We can't be safe that this an already connected socket
	 * or that accept() is allowed on it. In those cases we will get -1/errno
	 * return.
	 */
	int acceptfd;
	struct sockaddr saddr;
	unsigned int slen = sizeof(saddr);
	acceptfd = accept( get_unix_fd(sock->fd), &saddr, &slen);
	if (acceptfd == -1)
		return acceptfd;

	fcntl(acceptfd, F_SETFL, O_NONBLOCK); /* make socket nonblocking */
	return acceptfd;
}

static int accept_into_socket( struct sock *sock, struct sock *acceptsock )
{
	int acceptfd;
	struct fd *oldfd;
	if ( sock->deferred ) {
		acceptfd = dup( get_unix_fd(sock->deferred->fd) );
		if ( acceptfd == -1 )
			return sock_get_error(errno);

        /* Make sure we destroy fd first, so shutdown() isn't called */
		oldfd = sock->deferred->fd;
		sock->deferred->fd = NULL;
		release_object( sock->deferred );
		sock->deferred = NULL;
		release_object( oldfd );
	} else {
		if ((acceptfd = accept_new_fd( sock )) == -1)
			return sock_get_error(errno);
	}

	/* FIXME: need to copy sockopts from the old fd */
	if ( dup2(acceptfd, get_unix_fd(acceptsock->fd)) == -1 ) {
		close(acceptfd);
		return sock_get_error(errno);
	}
	close(acceptfd);

	/* FIXME: Move these into SO_UPDATE_ACCEPT_CONTEXT + validation */
	acceptsock->state  |= FD_WINE_CONNECTED|FD_READ|FD_WRITE;
	acceptsock->mask    = sock->mask;
	acceptsock->hmask   = 0;
	acceptsock->pmask   = 0;
	acceptsock->polling = 0;
	acceptsock->type    = sock->type;
	acceptsock->family  = sock->family;
	acceptsock->window  = sock->window;
	acceptsock->message = sock->message;
	acceptsock->wparam  = 0;
	if (acceptsock->event) release_object(acceptsock->event);
	acceptsock->event   = NULL;
	if (sock->event) acceptsock->event = (struct kevent *)grab_object( sock->event );
	acceptsock->deferred = NULL;

	sock->pmask &= ~FD_ACCEPT;
	sock->hmask &= ~FD_ACCEPT;
	sock_reselect( sock );

	return STATUS_SUCCESS;
}

/* accept a socket (creates a new fd) */
static struct sock *accept_socket(struct sock *sock)
{
	struct sock *acceptsock;
	int	acceptfd;

	if (sock->deferred) {
		acceptsock = sock->deferred;
		sock->deferred = NULL;
	} else {
		if ((acceptfd = accept_new_fd(sock)) == -1) {
			sock_set_error();
			return NULL;
		}
		if (!(acceptsock = alloc_sock())) {
			close(acceptfd);
			return NULL;
		}

		/* newly created socket gets the same properties of the listening socket */
		acceptsock->state  = FD_WINE_CONNECTED|FD_READ|FD_WRITE;
		if (sock->state & FD_WINE_NONBLOCKING)
			acceptsock->state |= FD_WINE_NONBLOCKING;
		acceptsock->mask    = sock->mask;
		acceptsock->type    = sock->type;
		acceptsock->family  = sock->family;
		acceptsock->window  = sock->window;
		acceptsock->message = sock->message;
		if (sock->event) 
			acceptsock->event = (struct kevent *)grab_object(sock->event);
		acceptsock->flags = sock->flags;
		memset(acceptsock->errors, 0, sizeof(acceptsock->errors));
		if (!(acceptsock->fd = create_anonymous_fd(&sock_fd_ops, acceptfd, &acceptsock->obj,
						get_fd_options(sock->fd)))) {
			release_object(acceptsock);
			release_object(sock);
			return NULL;
		}
	}
	clear_error();
	sock->pmask &= ~FD_ACCEPT;
	sock->hmask &= ~FD_ACCEPT;
	sock_reselect(sock);
	return acceptsock;
}

/* set the last error depending on errno */
static int sock_get_error(int err)
{
	switch (err)
	{
		case EINTR:             return WSAEINTR;
		case EBADF:             return WSAEBADF;
		case EPERM:
		case EACCES:            return WSAEACCES;
		case EFAULT:            return WSAEFAULT;
		case EINVAL:            return WSAEINVAL;
		case EMFILE:            return WSAEMFILE;
		case EWOULDBLOCK:       return WSAEWOULDBLOCK;
		case EINPROGRESS:       return WSAEINPROGRESS;
		case EALREADY:          return WSAEALREADY;
		case ENOTSOCK:          return WSAENOTSOCK;
		case EDESTADDRREQ:      return WSAEDESTADDRREQ;
		case EMSGSIZE:          return WSAEMSGSIZE;
		case EPROTOTYPE:        return WSAEPROTOTYPE;
		case ENOPROTOOPT:       return WSAENOPROTOOPT;
		case EPROTONOSUPPORT:   return WSAEPROTONOSUPPORT;
		case ESOCKTNOSUPPORT:   return WSAESOCKTNOSUPPORT;
		case EOPNOTSUPP:        return WSAEOPNOTSUPP;
		case EPFNOSUPPORT:      return WSAEPFNOSUPPORT;
		case EAFNOSUPPORT:      return WSAEAFNOSUPPORT;
		case EADDRINUSE:        return WSAEADDRINUSE;
		case EADDRNOTAVAIL:     return WSAEADDRNOTAVAIL;
		case ENETDOWN:          return WSAENETDOWN;
		case ENETUNREACH:       return WSAENETUNREACH;
		case ENETRESET:         return WSAENETRESET;
		case ECONNABORTED:      return WSAECONNABORTED;
		case EPIPE:
		case ECONNRESET:        return WSAECONNRESET;
		case ENOBUFS:           return WSAENOBUFS;
		case EISCONN:           return WSAEISCONN;
		case ENOTCONN:          return WSAENOTCONN;
		case ESHUTDOWN:         return WSAESHUTDOWN;
		case ETOOMANYREFS:      return WSAETOOMANYREFS;
		case ETIMEDOUT:         return WSAETIMEDOUT;
		case ECONNREFUSED:      return WSAECONNREFUSED;
		case ELOOP:             return WSAELOOP;
		case ENAMETOOLONG:      return WSAENAMETOOLONG;
		case EHOSTDOWN:         return WSAEHOSTDOWN;
		case EHOSTUNREACH:      return WSAEHOSTUNREACH;
		case ENOTEMPTY:         return WSAENOTEMPTY;
#ifdef EPROCLIM
		case EPROCLIM:          return WSAEPROCLIM;
#endif
#ifdef EUSERS
		case EUSERS:            return WSAEUSERS;
#endif
#ifdef EDQUOT
		case EDQUOT:            return WSAEDQUOT;
#endif
#ifdef ESTALE
		case ESTALE:            return WSAESTALE;
#endif
#ifdef EREMOTE
		case EREMOTE:           return WSAEREMOTE;
#endif
		case 0:					return 0;
		default:
#if 0
								errno = err;
								perror("wineserver: sock_get_error() can't map error");
#endif
								return WSAEFAULT;
	}
}

static int sock_get_ntstatus( int err )
{
    switch ( err )
    {
        case EBADF:             return STATUS_INVALID_HANDLE;
        case EBUSY:             return STATUS_DEVICE_BUSY;
        case EPERM:
        case EACCES:            return STATUS_ACCESS_DENIED;
        case EFAULT:            return STATUS_NO_MEMORY;
        case EINVAL:            return STATUS_INVALID_PARAMETER;
        case ENFILE:
        case EMFILE:            return STATUS_TOO_MANY_OPENED_FILES;
        case EWOULDBLOCK:       return STATUS_CANT_WAIT;
        case EINPROGRESS:       return STATUS_PENDING;
        case EALREADY:          return STATUS_NETWORK_BUSY;
        case ENOTSOCK:          return STATUS_OBJECT_TYPE_MISMATCH;
        case EDESTADDRREQ:      return STATUS_INVALID_PARAMETER;
        case EMSGSIZE:          return STATUS_BUFFER_OVERFLOW;
        case EPROTONOSUPPORT:
        case ESOCKTNOSUPPORT:
        case EPFNOSUPPORT:
        case EAFNOSUPPORT:
        case EPROTOTYPE:        return STATUS_NOT_SUPPORTED;
        case ENOPROTOOPT:       return STATUS_INVALID_PARAMETER;
        case EOPNOTSUPP:        return STATUS_NOT_SUPPORTED;
        case EADDRINUSE:        return STATUS_ADDRESS_ALREADY_ASSOCIATED;
        case EADDRNOTAVAIL:     return STATUS_INVALID_PARAMETER;
        case ECONNREFUSED:      return STATUS_CONNECTION_REFUSED;
        case ESHUTDOWN:         return STATUS_PIPE_DISCONNECTED;
        case ENOTCONN:          return STATUS_CONNECTION_DISCONNECTED;
        case ETIMEDOUT:         return STATUS_IO_TIMEOUT;
        case ENETUNREACH:       return STATUS_NETWORK_UNREACHABLE;
        case EHOSTUNREACH:      return STATUS_HOST_UNREACHABLE;
        case ENETDOWN:          return STATUS_NETWORK_BUSY;
        case EPIPE:
        case ECONNRESET:        return STATUS_CONNECTION_RESET;
        case ECONNABORTED:      return STATUS_CONNECTION_ABORTED;

        case 0:                 return STATUS_SUCCESS;
        default:
#if 0
            errno = err;
            perror("wineserver: sock_get_ntstatus() can't map error");
#endif
            return STATUS_UNSUCCESSFUL;
    }
}

/* set the last error depending on errno */
static void sock_set_error(void)
{
	set_error(sock_get_ntstatus(errno));
}

/* create a socket */
DECL_HANDLER(create_socket)
{
	struct object *obj;

	reply->handle = 0;
	if ((obj = create_socket(req->family, req->type, req->protocol, req->flags)) != NULL) {
		reply->handle = alloc_handle(get_current_w32process(), obj, req->access, req->attributes);
		release_object(obj);
	}
}

/* accept a socket */
DECL_HANDLER(accept_socket)
{
	struct sock *sock, *acceptsock;

	reply->handle = 0;
	if (!(sock = (struct sock *)get_wine_handle_obj(get_current_w32process(), req->lhandle,
 									FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | FILE_READ_DATA, &sock_ops))) {
		ktrace("get listen sock failed.\n");
		return;
	}
	if ((acceptsock = accept_socket(sock)) != NULL) {
		reply->handle = alloc_handle(get_current_w32process(), &acceptsock->obj, req->access, req->attributes);
		acceptsock->wparam = reply->handle;  /* wparam for message is the socket handle */
		sock_reselect(acceptsock);
		release_object(&acceptsock->obj);
	}
	release_object(sock);
}

/* set socket event parameters */
DECL_HANDLER(set_socket_event)
{
	struct sock *sock;
	struct kevent *old_event;
	int pollev;

	if (!(sock = (struct sock *)get_wine_handle_obj(get_current_w32process(), req->handle,
					FILE_WRITE_ATTRIBUTES, &sock_ops))) 
		return;
	old_event = sock->event;
	sock->mask    = req->mask;
	sock->hmask   &= ~req->mask; /* re-enable held events */
	sock->event   = NULL;
	sock->window  = req->window;
	sock->message = req->msg;
	sock->wparam  = req->handle;  /* wparam is the socket handle */
	if (req->event) 
		sock->event = get_event_obj(get_current_w32process(), req->event, EVENT_MODIFY_STATE);

	if (sock->event) 
		ktrace("event ptr: %p\n", sock->event);

	pollev = sock_reselect(sock);
	if ( pollev ) sock_try_event( sock, pollev );

	if (sock->mask)
		sock->state |= FD_WINE_NONBLOCKING;

	/* if a network event is pending, signal the event object
	   it is possible that FD_CONNECT or FD_ACCEPT network events has happened
	   before a WSAEventSelect() was done on it.
	   (when dealing with Asynchronous socket)  */
	sock_wake_up(sock);

	if (old_event) 
		release_object(old_event); /* we're through with it */
	release_object(&sock->obj);
}

/* get socket event parameters */
DECL_HANDLER(get_socket_event)
{
	struct sock *sock;
	int i;
	int errors[FD_MAX_EVENTS];

	sock = (struct sock *)get_wine_handle_obj(get_current_w32process(), req->handle, 
			FILE_READ_ATTRIBUTES, &sock_ops);
	if (!sock) {
		reply->mask  = 0;
		reply->pmask = 0;
		reply->state = 0;
		set_error(WSAENOTSOCK);
		return;
	}
	reply->mask  = sock->mask;
	reply->pmask = sock->pmask;
	reply->state = sock->state;
	for (i = 0; i < FD_MAX_EVENTS; i++)
		errors[i] = sock_get_ntstatus(sock->errors[i]);
	set_reply_data(errors, min(get_reply_max_size(), sizeof(errors)));

	if (req->service) {
		if (req->c_event) {
			struct kevent *cevent = get_event_obj(get_current_w32process(), req->c_event,
					EVENT_MODIFY_STATE);
			if (cevent) {
				reset_event(cevent);
				release_object(cevent);
			}
		}
		sock->pmask = 0;
		sock_reselect(sock);
	}
	release_object(&sock->obj);
}

/* re-enable pending socket events */
DECL_HANDLER(enable_socket_event)
{
	struct sock *sock;
	int pollev;

	if (!(sock = (struct sock*)get_wine_handle_obj(get_current_w32process(), req->handle,
					FILE_WRITE_ATTRIBUTES, &sock_ops)))
		return;

	sock->pmask &= ~req->mask; /* is this safe? */
	sock->hmask &= ~req->mask;
	sock->state |= req->sstate;
	sock->state &= ~req->cstate;
	if (sock->type != SOCK_STREAM) sock->state &= ~STREAM_FLAG_MASK;

	pollev = sock_reselect(sock);
	if ( pollev ) sock_try_event( sock, pollev );

	release_object(&sock->obj);
}

DECL_HANDLER(set_socket_deferred)
{
	struct sock *sock, *acceptsock;

	sock = (struct sock *)get_wine_handle_obj(get_current_w32process(), req->handle, 
			FILE_WRITE_ATTRIBUTES, &sock_ops);
	if (!sock) {
		return;
	}
	acceptsock = (struct sock *)get_wine_handle_obj(get_current_w32process(), req->deferred, 
			0, &sock_ops);
	if (!acceptsock) {
		release_object(sock);
		return;
	}
	sock->deferred = acceptsock;
	release_object(sock);
}

DECL_HANDLER(register_accept_async)
{
    struct sock *sock, *acceptsock;

	kdebug("\n");
    sock = (struct sock *)get_wine_handle_obj( get_current_w32process(), req->data.handle,
                                          FILE_READ_ATTRIBUTES, &sock_ops );
    if ( !sock )
    {
        set_error( STATUS_OBJECT_TYPE_MISMATCH );
        return;
    }
    if ( !(sock->state & FD_WINE_LISTENING) )
    {
        release_object( sock );
        set_error( STATUS_OBJECT_TYPE_MISMATCH );
        return;
    }

    acceptsock = (struct sock *)get_wine_handle_obj( get_current_w32process(), req->ahandle,
                                                FILE_WRITE_ATTRIBUTES, &sock_ops );
    if ( !acceptsock )
    {
        release_object( sock );
        set_error( STATUS_INVALID_PARAMETER );
        return;
    }
    if ( acceptsock->state & ~FD_WINE_NONBLOCKING )
    {
        release_object( acceptsock );
        release_object( sock );
        set_error( STATUS_INVALID_PARAMETER );
        return;
    }

    if (!sock->read_q && !(sock->read_q = create_async_queue( sock->fd ))) return;

    acceptsock->async = create_async( get_current_w32thread(), sock->read_q, &req->data );
    if ( !acceptsock->async )
    {
        release_object( acceptsock );
        release_object( sock );
        return;
    }

    list_add_tail( &acceptsock->accentry, &sock->paccepts );
    acceptsock->state |= FD_WINE_ACCEPTING;
    release_object( acceptsock->async );

    sock_reselect( sock );

    set_error( STATUS_PENDING );

    release_object( acceptsock );
    release_object( sock );
}
#endif /* CONFIG_UNIFIED_KERNEL */
