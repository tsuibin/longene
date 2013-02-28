/*
 * Wine server communication
 *
 * Copyright (C) 1998 Alexandre Julliard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "config.h"
#include "wine/port.h"

#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif
#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif
#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "wine/library.h"
#include "wine/pthread.h"
#include "wine/server.h"
#include "wine/debug.h"
#include "ntdll_misc.h"

#include "wine/log.h"

WINE_DEFAULT_DEBUG_CHANNEL(server);

/* Some versions of glibc don't define this */
#ifndef SCM_RIGHTS
#define SCM_RIGHTS 1
#endif

#define SOCKETNAME "socket"        /* name of the socket file */
#define LOCKNAME   "lock"          /* name of the lock file */

#ifndef HAVE_STRUCT_MSGHDR_MSG_ACCRIGHTS
/* data structure used to pass an fd with sendmsg/recvmsg */
struct cmsg_fd
{
    struct
    {
        size_t len;   /* size of structure */
        int    level; /* SOL_SOCKET */
        int    type;  /* SCM_RIGHTS */
    } header;
    int fd;          /* fd to pass */
};
#endif  /* HAVE_STRUCT_MSGHDR_MSG_ACCRIGHTS */

timeout_t server_start_time = 0;  /* time of server startup */

extern struct wine_pthread_functions pthread_functions;

sigset_t server_block_set;  /* signals to block during server calls */
static int fd_socket = -1;  /* socket to exchange file descriptors with the server */

static RTL_CRITICAL_SECTION fd_cache_section;
static RTL_CRITICAL_SECTION_DEBUG critsect_debug =
{
    0, 0, &fd_cache_section,
    { &critsect_debug.ProcessLocksList, &critsect_debug.ProcessLocksList },
      0, 0, { (DWORD_PTR)(__FILE__ ": fd_cache_section") }
};
static RTL_CRITICAL_SECTION fd_cache_section = { &critsect_debug, -1, 0, 0, 0, 0 };


#ifdef __GNUC__
static void fatal_error( const char *err, ... ) __attribute__((noreturn, format(printf,1,2)));
static void fatal_perror( const char *err, ... ) __attribute__((noreturn, format(printf,1,2)));
#endif

const char* wine_service[];

NTSTATUS WINAPI
NtWineService(struct __server_request_info * ReqMsg)
{
    NTSTATUS ret;
	int req;
   
    req = ReqMsg->u.req.request_header.req;
    LOG(LOG_FILE, 0, 0, "req=%d %s\n", req, wine_service[req]);

    __asm__ __volatile__ (
            "movl $0xe8,%%eax\n\t"
            "lea 8(%%ebp),%%edx\n\t"
            "int $0x2E\n\t"
            :"=a" (ret)
            );
	if (ret == STATUS_NOT_IMPLEMENTED)
		LOG(LOG_FILE, 0, ret, "%s NOT_IMPLEMENTED\n", wine_service[req]);
    LOG(LOG_FILE, 0, 0, "done\n");
    return ret /* ret */; //wine service returns its status in req_reply
}

/* die on a fatal error; use only during initialization */
static void fatal_error( const char *err, ... )
{
    va_list args;

    va_start( args, err );
    fprintf( stderr, "wine: " );
    vfprintf( stderr, err, args );
    va_end( args );
    exit(1);
}

/* die on a fatal error; use only during initialization */
static void fatal_perror( const char *err, ... )
{
    va_list args;

    va_start( args, err );
    fprintf( stderr, "wine: " );
    vfprintf( stderr, err, args );
    perror( " " );
    va_end( args );
    exit(1);
}


/***********************************************************************
 *           server_exit_thread
 */
void server_exit_thread( int status )
{
    RtlAcquirePebLock();
    RemoveEntryList( &NtCurrentTeb()->TlsLinks );
    RtlReleasePebLock();

    RtlFreeHeap( GetProcessHeap(), 0, NtCurrentTeb()->FlsSlots ); /* HCZ */
    RtlFreeHeap( GetProcessHeap(), 0, NtCurrentTeb()->TlsExpansionSlots ); /* HCZ */

    sigprocmask( SIG_BLOCK, &server_block_set, NULL );

    NtTerminateThread(GetCurrentThread(),0);
}

/***********************************************************************
 *           server_abort_thread
 */
int server_abort_thread( int status )
{
    sigprocmask( SIG_BLOCK, &server_block_set, NULL );

    close( ntdll_get_thread_data()->wait_fd[0] );
    close( ntdll_get_thread_data()->wait_fd[1] );
    close( ntdll_get_thread_data()->reply_fd );
    close( ntdll_get_thread_data()->request_fd );

    return NtTerminateThread(GetCurrentThread(), status);
}


/***********************************************************************
 *           server_protocol_error
 */
void server_protocol_error( const char *err, ... )
{
    va_list args;

    va_start( args, err );
    fprintf( stderr, "wine client error:%x: ", GetCurrentThreadId() );
    vfprintf( stderr, err, args );
    va_end( args );
    server_abort_thread(1);
}


/***********************************************************************
 *           server_protocol_perror
 */
void server_protocol_perror( const char *err )
{
    fprintf( stderr, "wine client error:%x: ", GetCurrentThreadId() );
    perror( err );
    server_abort_thread(1);
}


/***********************************************************************
 *           read_reply_data
 *
 * Read data from the reply buffer; helper for wait_reply.
 */
static void read_reply_data( void *buffer, size_t size )
{
    int ret;

    for (;;)
    {
        if ((ret = read( ntdll_get_thread_data()->reply_fd, buffer, size )) > 0)
        {
            if (!(size -= ret)) return;
            buffer = (char *)buffer + ret;
            continue;
        }
        if (!ret) break;
        if (errno == EINTR) continue;
        if (errno == EPIPE) break;
        server_protocol_perror("read");
    }
    /* the server closed the connection; time to die... */
    server_abort_thread(0);
}


/***********************************************************************
 *           wait_reply
 *
 * Wait for a reply from the server.
 */
static inline unsigned int wait_reply( struct __server_request_info *req )
{
    read_reply_data( &req->u.reply, sizeof(req->u.reply) );
    if (req->u.reply.reply_header.reply_size)
        read_reply_data( req->reply_data, req->u.reply.reply_header.reply_size );
    return req->u.reply.reply_header.error;
}


/***********************************************************************
 *           wine_server_call (NTDLL.@)
 *
 * Perform a server call.
 *
 * PARAMS
 *     req_ptr [I/O] Function dependent data
 *
 * RETURNS
 *     Depends on server function being called, but usually an NTSTATUS code.
 *
 * NOTES
 *     Use the SERVER_START_REQ and SERVER_END_REQ to help you fill out the
 *     server request structure for the particular call. E.g:
 *|     SERVER_START_REQ( event_op )
 *|     {
 *|         req->handle = handle;
 *|         req->op     = SET_EVENT;
 *|         ret = wine_server_call( req );
 *|     }
 *|     SERVER_END_REQ;
 */

unsigned int wine_server_call( void *req_ptr )
{
     struct __server_request_info * const req = req_ptr;
	 return NtWineService( req );
}

/***********************************************************************
 *           server_enter_uninterrupted_section
 */
void server_enter_uninterrupted_section( RTL_CRITICAL_SECTION *cs, sigset_t *sigset )
{
    sigprocmask( SIG_BLOCK, &server_block_set, sigset );
    RtlEnterCriticalSection( cs );
}


/***********************************************************************
 *           server_leave_uninterrupted_section
 */
void server_leave_uninterrupted_section( RTL_CRITICAL_SECTION *cs, sigset_t *sigset )
{
    RtlLeaveCriticalSection( cs );
    sigprocmask( SIG_SETMASK, sigset, NULL );
}


/***********************************************************************
 *           wine_server_send_fd   (NTDLL.@)
 *
 * Send a file descriptor to the server.
 *
 * PARAMS
 *     fd [I] file descriptor to send
 *
 * RETURNS
 *     nothing
 */
void wine_server_send_fd( int fd )
{
#ifndef HAVE_STRUCT_MSGHDR_MSG_ACCRIGHTS
    struct cmsg_fd cmsg;
#endif
    struct send_fd data;
    struct msghdr msghdr;
    struct iovec vec;
    int ret;

    vec.iov_base = (void *)&data;
    vec.iov_len  = sizeof(data);

    msghdr.msg_name    = NULL;
    msghdr.msg_namelen = 0;
    msghdr.msg_iov     = &vec;
    msghdr.msg_iovlen  = 1;

#ifdef HAVE_STRUCT_MSGHDR_MSG_ACCRIGHTS
    msghdr.msg_accrights    = (void *)&fd;
    msghdr.msg_accrightslen = sizeof(fd);
#else  /* HAVE_STRUCT_MSGHDR_MSG_ACCRIGHTS */
    cmsg.header.len   = sizeof(cmsg.header) + sizeof(fd);
    cmsg.header.level = SOL_SOCKET;
    cmsg.header.type  = SCM_RIGHTS;
    cmsg.fd           = fd;
    msghdr.msg_control    = &cmsg;
    msghdr.msg_controllen = sizeof(cmsg.header) + sizeof(fd);
    msghdr.msg_flags      = 0;
#endif  /* HAVE_STRUCT_MSGHDR_MSG_ACCRIGHTS */

    data.tid = GetCurrentThreadId();
    data.fd  = fd;

    for (;;)
    {
        if ((ret = sendmsg( fd_socket, &msghdr, 0 )) == sizeof(data)) return;
        if (ret >= 0) server_protocol_error( "partial write %d\n", ret );
        if (errno == EINTR) continue;
        if (errno == EPIPE) server_abort_thread(0);
        server_protocol_perror( "sendmsg" );
    }
}


/***********************************************************************/
/* fd cache support */

struct fd_cache_entry
{
    int fd;
    enum server_fd_type type : 6;
    unsigned int        access : 2;
    unsigned int        options : 24;
};

#define FD_CACHE_BLOCK_SIZE  (65536 / sizeof(struct fd_cache_entry))
#define FD_CACHE_ENTRIES     256

static struct fd_cache_entry *fd_cache[FD_CACHE_ENTRIES];
static struct fd_cache_entry fd_cache_initial_block[FD_CACHE_BLOCK_SIZE];

static inline unsigned int handle_to_index( obj_handle_t handle, unsigned int *entry )
{
    unsigned long idx;

    idx = ((unsigned long)handle >> 2) - 1;
    *entry = idx / FD_CACHE_BLOCK_SIZE;
    if (*entry > FD_CACHE_ENTRIES / 2)
        *entry = FD_CACHE_ENTRIES;
    return idx % FD_CACHE_BLOCK_SIZE;
}


/***********************************************************************
 *           add_fd_to_cache
 *
 * Caller must hold fd_cache_section.
 */
static int add_fd_to_cache( obj_handle_t handle, int fd, enum server_fd_type type,
                            unsigned int access, unsigned int options )
{
    unsigned int entry, idx = handle_to_index( handle, &entry );
    int prev_fd;

    if (entry >= FD_CACHE_ENTRIES)
    {
        FIXME( "too many allocated handles, not caching %p\n", handle );
        return 0;
    }

    if (!fd_cache[entry])  /* do we need to allocate a new block of entries? */
    {
        if (!entry) fd_cache[0] = fd_cache_initial_block;
        else
        {
            void *ptr = wine_anon_mmap( NULL, FD_CACHE_BLOCK_SIZE * sizeof(struct fd_cache_entry),
                                        PROT_READ | PROT_WRITE, 0 );
            if (ptr == MAP_FAILED) return 0;
            fd_cache[entry] = ptr;
        }
    }
    /* store fd+1 so that 0 can be used as the unset value */
    prev_fd = interlocked_xchg( &fd_cache[entry][idx].fd, fd + 1 ) - 1;
    fd_cache[entry][idx].type = type;
    fd_cache[entry][idx].access = access;
    fd_cache[entry][idx].options = options;
    if (prev_fd != -1) close( prev_fd );
    return 1;
}


/***********************************************************************
 *           get_cached_fd
 *
 * Caller must hold fd_cache_section.
 */
static inline int get_cached_fd( obj_handle_t handle, enum server_fd_type *type,
                                 unsigned int *access, unsigned int *options )
{
    unsigned int entry, idx = handle_to_index( handle, &entry );
    int fd = -1;

    if (entry < FD_CACHE_ENTRIES && fd_cache[entry])
    {
        fd = fd_cache[entry][idx].fd - 1;
        if (type) *type = fd_cache[entry][idx].type;
        if (access) *access = fd_cache[entry][idx].access;
        if (options) *options = fd_cache[entry][idx].options;
    }
    return fd;
}


/***********************************************************************
 *           server_remove_fd_from_cache
 */
int server_remove_fd_from_cache( obj_handle_t handle )
{
    unsigned int entry, idx = handle_to_index( handle, &entry );
    int fd = -1;

    if (entry < FD_CACHE_ENTRIES && fd_cache[entry])
        fd = interlocked_xchg( &fd_cache[entry][idx].fd, 0 ) - 1;

    return fd;
}


/***********************************************************************
 *           server_get_unix_fd
 *
 * The returned unix_fd should be closed iff needs_close is non-zero.
 */
int server_get_unix_fd( obj_handle_t handle, unsigned int wanted_access, int *unix_fd,
                        int *needs_close, enum server_fd_type *type, unsigned int *options )
{
    sigset_t sigset;
    int ret = 0, fd;
    unsigned int access = 0;

    *unix_fd = -1;
    *needs_close = 0;
    wanted_access &= FILE_READ_DATA | FILE_WRITE_DATA;

    server_enter_uninterrupted_section( &fd_cache_section, &sigset );

    fd = get_cached_fd( handle, type, &access, options );
    if (fd != -1) goto done;

    SERVER_START_REQ( get_handle_fd )
    {
        req->handle = handle;
        ret = wine_server_call( req );

        if (!ret)
        {
            if (type) *type = reply->type;
            if (options) *options = reply->options;
            access = reply->access;
            fd = reply->fd;

            if (fd != -1)
            {
                *needs_close = FALSE;
                add_fd_to_cache( handle, fd, reply->type, reply->access, reply->options);
            }
            else ret = STATUS_TOO_MANY_OPENED_FILES;
        }
    }
    SERVER_END_REQ;
done:
    server_leave_uninterrupted_section( &fd_cache_section, &sigset );
    if (!ret && ((access & wanted_access) != wanted_access))
    {
        ret = STATUS_ACCESS_DENIED;
        if (*needs_close) close( fd );
    }
    if (!ret) *unix_fd = fd;
    return ret;
}


/***********************************************************************
 *           wine_server_fd_to_handle   (NTDLL.@)
 *
 * Allocate a file handle for a Unix file descriptor.
 *
 * PARAMS
 *     fd      [I] Unix file descriptor.
 *     access  [I] Win32 access flags.
 *     attributes [I] Object attributes.
 *     handle  [O] Address where Wine file handle will be stored.
 *
 * RETURNS
 *     NTSTATUS code
 */
int wine_server_fd_to_handle( int fd, unsigned int access, unsigned int attributes, obj_handle_t *handle )
{
    int ret;

    *handle = 0;

    LOG(LOG_FILE, 0, 0, "fd=%d\n", fd);
    SERVER_START_REQ( alloc_file_handle )
    {
        req->access     = access;
        req->attributes = attributes;
        req->fd         = fd;
        if (!(ret = wine_server_call( req ))) *handle = reply->handle;
    }
    SERVER_END_REQ;

    return ret;
}


/***********************************************************************
 *           wine_server_handle_to_fd   (NTDLL.@)
 *
 * Retrieve the file descriptor corresponding to a file handle.
 *
 * PARAMS
 *     handle  [I] Wine file handle.
 *     access  [I] Win32 file access rights requested.
 *     unix_fd [O] Address where Unix file descriptor will be stored.
 *     options [O] Address where the file open options will be stored. Optional.
 *
 * RETURNS
 *     NTSTATUS code
 */
int wine_server_handle_to_fd( obj_handle_t handle, unsigned int access, int *unix_fd,
                              unsigned int *options )
{
    int needs_close, ret = server_get_unix_fd( handle, access, unix_fd, &needs_close, NULL, options );

    if (!ret && !needs_close)
    {
        if ((*unix_fd = dup(*unix_fd)) == -1) ret = FILE_GetNtStatus();
    }
    return ret;
}


/***********************************************************************
 *           wine_server_release_fd   (NTDLL.@)
 *
 * Release the Unix file descriptor returned by wine_server_handle_to_fd.
 *
 * PARAMS
 *     handle  [I] Wine file handle.
 *     unix_fd [I] Unix file descriptor to release.
 *
 * RETURNS
 *     nothing
 */
void wine_server_release_fd( obj_handle_t handle, int unix_fd )
{
    close( unix_fd );
}


/***********************************************************************
 *           setup_config_dir
 *
 * Setup the wine configuration dir.
 */
void setup_config_dir(void)
{
    const char *p, *config_dir = wine_get_config_dir();

    if (chdir( config_dir ) == -1)
    {
        if (errno != ENOENT) fatal_perror( "chdir to %s\n", config_dir );

        if ((p = strrchr( config_dir, '/' )) && p != config_dir)
        {
            struct stat st;
            char *tmp_dir;

            if (!(tmp_dir = malloc( p + 1 - config_dir ))) fatal_error( "out of memory\n" );
            memcpy( tmp_dir, config_dir, p - config_dir );
            tmp_dir[p - config_dir] = 0;
            if (!stat( tmp_dir, &st ) && st.st_uid != getuid())
                fatal_error( "'%s' is not owned by you, refusing to create a configuration directory there\n",
                             tmp_dir );
            free( tmp_dir );
        }

        mkdir( config_dir, 0777 );
        if (chdir( config_dir ) == -1) fatal_perror( "chdir to %s\n", config_dir );
        MESSAGE( "wine: created the configuration directory '%s'\n", config_dir );
    }

    if (mkdir( "dosdevices", 0777 ) == -1)
    {
        if (errno == EEXIST) return;
        fatal_perror( "cannot create %s/dosdevices\n", config_dir );
    }

    /* create the drive symlinks */

    mkdir( "drive_c", 0777 );
    symlink( "../drive_c", "dosdevices/c:" );
    symlink( "/", "dosdevices/z:" );
}


#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/mach_error.h>
#include <servers/bootstrap.h>

/* send our task port to the server */
static void send_server_task_port(void)
{
    mach_port_t bootstrap_port, wineserver_port;
    kern_return_t kret;

    struct {
        mach_msg_header_t           header;
        mach_msg_body_t             body;
        mach_msg_port_descriptor_t  task_port;
    } msg;

    if (task_get_bootstrap_port(mach_task_self(), &bootstrap_port) != KERN_SUCCESS) return;

    kret = bootstrap_look_up(bootstrap_port, (char*)wine_get_server_dir(), &wineserver_port);
    if (kret != KERN_SUCCESS)
        fatal_error( "cannot find the server port: 0x%08x\n", kret );

    mach_port_deallocate(mach_task_self(), bootstrap_port);

    msg.header.msgh_bits        = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
    msg.header.msgh_size        = sizeof(msg);
    msg.header.msgh_remote_port = wineserver_port;
    msg.header.msgh_local_port  = MACH_PORT_NULL;

    msg.body.msgh_descriptor_count  = 1;
    msg.task_port.name              = mach_task_self();
    msg.task_port.disposition       = MACH_MSG_TYPE_COPY_SEND;
    msg.task_port.type              = MACH_MSG_PORT_DESCRIPTOR;

    kret = mach_msg_send(&msg.header);
    if (kret != KERN_SUCCESS)
        server_protocol_error( "mach_msg_send failed: 0x%08x\n", kret );

    mach_port_deallocate(mach_task_self(), wineserver_port);
}
#endif  /* __APPLE__ */


/***********************************************************************
 *           server_init_process_done
 */
NTSTATUS server_init_process_done(void)
{
    PEB *peb = NtCurrentTeb()->Peb;
    IMAGE_NT_HEADERS *nt = RtlImageNtHeader( peb->ImageBaseAddress );
    NTSTATUS status;

    /* Install signal handlers; this cannot be done earlier, since we cannot
     * send exceptions to the debugger before the create process event that
     * is sent by REQ_INIT_PROCESS_DONE.
     * We do need the handlers in place by the time the request is over, so
     * we set them up here. If we segfault between here and the server call
     * something is very wrong... */
    if (!SIGNAL_Init()) exit(1);

    /* Signal the parent process to continue */
    SERVER_START_REQ( init_process_done )
    {
        req->module = peb->ImageBaseAddress;
        req->entry  = (char *)peb->ImageBaseAddress + nt->OptionalHeader.AddressOfEntryPoint;
        req->gui    = (nt->OptionalHeader.Subsystem != IMAGE_SUBSYSTEM_WINDOWS_CUI);
        status = wine_server_call( req );
    }
    SERVER_END_REQ;

    return status;
}


/***********************************************************************
 *           server_init_thread
 *
 * Send an init thread request. Return 0 if OK.
 */
size_t server_init_thread( int unix_pid, int unix_tid, void *entry_point )
{
    int version, ret;
    size_t info_size;

    LOG(LOG_FILE, 0, 0, "server_init_thread()\n");
    setup_config_dir();
    SERVER_START_REQ( init_thread )
    {
        req->unix_pid    = unix_pid;
        req->unix_tid    = unix_tid;
        req->teb         = NtCurrentTeb();
        req->peb         = NtCurrentTeb()->Peb;
        req->entry       = entry_point;
        req->ldt_copy    = &wine_ldt_copy;
        req->reply_fd    = 0; 
        req->wait_fd     = 0; 
        req->debug_level = (TRACE_ON(server) != 0);
        ret = wine_server_call( req );
        info_size         = reply->info_size;
        version           = reply->version;
    }
    SERVER_END_REQ;

    return info_size;
}

const char* wine_service[REQ_NB_REQUESTS+2] =
{
    "new_process",
    "get_new_process_info",
    "new_thread",
    "get_startup_info",
    "init_process_done",
    "init_thread",
    "terminate_process",
    "terminate_thread",
    "get_process_info",
    "set_process_info",
    "get_thread_info",
    "set_thread_info",
    "get_dll_info",
    "suspend_thread",
    "resume_thread",
    "load_dll",
    "unload_dll",
    "queue_apc",
    "get_apc_result",
    "close_handle",
    "set_handle_info",
    "dup_handle",
    "open_process",
    "open_thread",
    "select",
    "create_event",
    "event_op",
    "open_event",
    "create_mutex",
    "release_mutex",
    "open_mutex",
    "create_semaphore",
    "release_semaphore",
    "open_semaphore",
    "create_file",
    "open_file_object",
    "alloc_file_handle",
    "get_handle_fd",
    "flush_file",
    "lock_file",
    "unlock_file",
    "create_socket",
    "accept_socket",
    "set_socket_event",
    "get_socket_event",
    "enable_socket_event",
    "set_socket_deferred",
    "alloc_console",
    "free_console",
    "get_console_renderer_events",
    "open_console",
    "get_console_wait_event",
    "get_console_mode",
    "set_console_mode",
    "set_console_input_info",
    "get_console_input_info",
    "append_console_input_history",
    "get_console_input_history",
    "create_console_output",
    "set_console_output_info",
    "get_console_output_info",
    "write_console_input",
    "read_console_input",
    "write_console_output",
    "fill_console_output",
    "read_console_output",
    "move_console_output",
    "send_console_signal",
    "read_directory_changes",
    "read_change",
    "create_mapping",
    "open_mapping",
    "get_mapping_info",
    "create_snapshot",
    "next_process",
    "next_thread",
    "next_module",
    "wait_debug_event",
    "queue_exception_event",
    "get_exception_status",
    "output_debug_string",
    "continue_debug_event",
    "debug_process",
    "debug_break",
    "set_debugger_kill_on_exit",
    "read_process_memory",
    "write_process_memory",
    "create_key",
    "open_key",
    "delete_key",
    "flush_key",
    "enum_key",
    "set_key_value",
    "get_key_value",
    "enum_key_value",
    "delete_key_value",
    "load_registry",
    "unload_registry",
    "save_registry",
    "set_registry_notification",
    "create_timer",
    "open_timer",
    "set_timer",
    "cancel_timer",
    "get_timer_info",
    "get_thread_context",
    "set_thread_context",
    "get_selector_entry",
    "add_atom",
    "delete_atom",
    "find_atom",
    "get_atom_information",
    "set_atom_information",
    "empty_atom_table",
    "init_atom_table",
    "get_msg_queue",
    "set_queue_fd",
    "set_queue_mask",
    "get_queue_status",
    "get_process_idle_event",
    "send_message",
    "post_quit_message",
    "send_hardware_message",
    "get_message",
    "reply_message",
    "accept_hardware_message",
    "get_message_reply",
    "set_win_timer",
    "kill_win_timer",
    "is_window_hung",
    "get_serial_info",
    "set_serial_info",
    "register_async",
    "cancel_async",
    "ioctl",
    "get_ioctl_result",
    "create_named_pipe",
    "get_named_pipe_info",
    "create_window",
    "destroy_window",
    "get_desktop_window",
    "set_window_owner",
    "get_window_info",
    "set_window_info",
    "set_parent",
    "get_window_parents",
    "get_window_children",
    "get_window_children_from_point",
    "get_window_tree",
    "set_window_pos",
    "set_window_visible_rect",
    "get_window_rectangles",
    "get_window_text",
    "set_window_text",
    "get_windows_offset",
    "get_visible_region",
    "get_window_region",
    "set_window_region",
    "get_update_region",
    "update_window_zorder",
    "redraw_window",
    "set_window_property",
    "remove_window_property",
    "get_window_property",
    "get_window_properties",
    "create_winstation",
    "open_winstation",
    "close_winstation",
    "get_process_winstation",
    "set_process_winstation",
    "enum_winstation",
    "create_desktop",
    "open_desktop",
    "close_desktop",
    "get_thread_desktop",
    "set_thread_desktop",
    "enum_desktop",
    "set_user_object_info",
    "attach_thread_input",
    "get_thread_input",
    "get_last_input_time",
    "get_key_state",
    "set_key_state",
    "set_foreground_window",
    "set_focus_window",
    "set_active_window",
    "set_capture_window",
    "set_caret_window",
    "set_caret_info",
    "set_hook",
    "remove_hook",
    "start_hook_chain",
    "finish_hook_chain",
    "get_hook_info",
    "create_class",
    "destroy_class",
    "set_class_info",
    "set_clipboard_info",
    "open_token",
    "set_global_windows",
    "adjust_token_privileges",
    "get_token_privileges",
    "check_token_privileges",
    "duplicate_token",
    "access_check",
    "get_token_user",
    "get_token_groups",
    "set_security_object",
    "get_security_object",
    "create_mailslot",
    "set_mailslot_info",
    "create_directory",
    "open_directory",
    "get_directory_entry",
    "create_symlink",
    "open_symlink",
    "query_symlink",
    "get_object_info",
    "get_token_impersonation_level",
    "allocate_locally_unique_id",
    "create_device_manager",
    "create_device",
    "delete_device",
    "get_next_device_request",
    "make_process_system",
    "get_token_statistics",
    "create_completion",
    "open_completion",
    "add_completion",
    "remove_completion",
    "query_completion",
    "set_completion_info",
    "add_fd_completion",

    "req_load_init_registry",
    "req_save_branch"
};




