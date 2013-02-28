/*
 * Win32 processes
 *
 * Copyright 1996, 1998 Alexandre Julliard
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
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_SYS_PRCTL_H
# include <sys/prctl.h>
#endif
#include <sys/types.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "wine/winbase16.h"
#include "wine/winuser16.h"
#include "winternl.h"
#include "kernel_private.h"
#include "wine/exception.h"
#include "wine/server.h"
#include "wine/unicode.h"
#include "wine/debug.h"

#include "wine/log.h"

WINE_DEFAULT_DEBUG_CHANNEL(process);
WINE_DECLARE_DEBUG_CHANNEL(file);
WINE_DECLARE_DEBUG_CHANNEL(relay);

typedef struct
{
    LPSTR lpEnvAddress;
    LPSTR lpCmdLine;
    LPSTR lpCmdShow;
    DWORD dwReserved;
} LOADPARMS32;

static UINT process_error_mode;

static DWORD shutdown_flags = 0;
static DWORD shutdown_priority = 0x280;
static DWORD process_dword;

HMODULE kernel32_handle = 0;

const WCHAR *DIR_Windows = NULL;
const WCHAR *DIR_System = NULL;

/* Process flags */
#define PDB32_DEBUGGED      0x0001  /* Process is being debugged */
#define PDB32_WIN16_PROC    0x0008  /* Win16 process */
#define PDB32_DOS_PROC      0x0010  /* Dos process */
#define PDB32_CONSOLE_PROC  0x0020  /* Console process */
#define PDB32_FILE_APIS_OEM 0x0040  /* File APIs are OEM */
#define PDB32_WIN32S_PROC   0x8000  /* Win32s process */

static const WCHAR comW[] = {'.','c','o','m',0};
static const WCHAR batW[] = {'.','b','a','t',0};
static const WCHAR cmdW[] = {'.','c','m','d',0};
static const WCHAR pifW[] = {'.','p','i','f',0};
static const WCHAR winevdmW[] = {'w','i','n','e','v','d','m','.','e','x','e',0};

static void exec_process( LPCWSTR name );

extern void SHELL_LoadRegistry(void);


/***********************************************************************
 *           contains_path
 */
static inline int contains_path( LPCWSTR name )
{
    return ((*name && (name[1] == ':')) || strchrW(name, '/') || strchrW(name, '\\'));
}


/***********************************************************************
 *           is_special_env_var
 *
 * Check if an environment variable needs to be handled specially when
 * passed through the Unix environment (i.e. prefixed with "WINE").
 */
static inline int is_special_env_var( const char *var )
{
    return (!strncmp( var, "PATH=", sizeof("PATH=")-1 ) ||
            !strncmp( var, "HOME=", sizeof("HOME=")-1 ) ||
            !strncmp( var, "TEMP=", sizeof("TEMP=")-1 ) ||
            !strncmp( var, "TMP=", sizeof("TMP=")-1 ));
}


/***************************************************************************
 *	get_builtin_path
 *
 * Get the path of a builtin module when the native file does not exist.
 */
static BOOL get_builtin_path( const WCHAR *libname, const WCHAR *ext, WCHAR *filename, UINT size )
{
    WCHAR *file_part;
    UINT len = strlenW( DIR_System );

    if (contains_path( libname ))
    {
        if (RtlGetFullPathName_U( libname, size * sizeof(WCHAR),
                                  filename, &file_part ) > size * sizeof(WCHAR))
            return FALSE;  /* too long */

        if (strncmpiW( filename, DIR_System, len ) || filename[len] != '\\')
            return FALSE;
        while (filename[len] == '\\') len++;
        if (filename + len != file_part) return FALSE;
    }
    else
    {
        if (strlenW(libname) + len + 2 >= size) return FALSE;  /* too long */
        memcpy( filename, DIR_System, len * sizeof(WCHAR) );
        file_part = filename + len;
        if (file_part > filename && file_part[-1] != '\\') *file_part++ = '\\';
        strcpyW( file_part, libname );
    }
    if (ext && !strchrW( file_part, '.' ))
    {
        if (file_part + strlenW(file_part) + strlenW(ext) + 1 > filename + size)
            return FALSE;  /* too long */
        strcatW( file_part, ext );
    }
    return TRUE;
}


/***********************************************************************
 *           open_exe_file
 *
 * Open a specific exe file, taking load order into account.
 * Returns the file handle or 0 for a builtin exe.
 */
static HANDLE open_exe_file( const WCHAR *name )
{
    HANDLE handle;

    TRACE("looking for %s\n", debugstr_w(name) );

    if ((handle = CreateFileW( name, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_DELETE,
                               NULL, OPEN_EXISTING, 0, 0 )) == INVALID_HANDLE_VALUE)
    {
        WCHAR buffer[MAX_PATH];
        /* file doesn't exist, check for builtin */
        if (!contains_path( name )) goto error;
        if (!get_builtin_path( name, NULL, buffer, sizeof(buffer) )) goto error;
        handle = 0;
    }
    return handle;

 error:
    SetLastError( ERROR_FILE_NOT_FOUND );
    return INVALID_HANDLE_VALUE;
}


/***********************************************************************
 *           build_initial_environment
 *
 * Build the Win32 environment from the Unix environment
 */
static BOOL build_initial_environment( char **environ )
{
    SIZE_T size = 1;
    char **e;
    WCHAR *p, *endptr;
    void *ptr;

    /* Compute the total size of the Unix environment */
    for (e = environ; *e; e++)
    {
        if (is_special_env_var( *e )) continue;
        size += MultiByteToWideChar( CP_UNIXCP, 0, *e, -1, NULL, 0 );
    }
    size *= sizeof(WCHAR);

    /* Now allocate the environment */
    ptr = NULL;
    if (NtAllocateVirtualMemory(NtCurrentProcess(), &ptr, 0, &size,
                                MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) != STATUS_SUCCESS)
        return FALSE;

    NtCurrentTeb()->Peb->ProcessParameters->Environment = p = ptr;
    endptr = p + size / sizeof(WCHAR);

    /* And fill it with the Unix environment */
    for (e = environ; *e; e++)
    {
        char *str = *e;

        /* skip Unix special variables and use the Wine variants instead */
        if (!strncmp( str, "WINE", 4 ))
        {
            if (is_special_env_var( str + 4 )) str += 4;
            else if (!strncmp( str, "WINEPRELOADRESERVE=", 19 )) continue;  /* skip it */
        }
        else if (is_special_env_var( str )) continue;  /* skip it */

        MultiByteToWideChar( CP_UNIXCP, 0, str, -1, p, endptr - p );
        p += strlenW(p) + 1;
    }
    *p = 0;
    return TRUE;
}


/***********************************************************************
 *           set_registry_variables
 *
 * Set environment variables by enumerating the values of a key;
 * helper for set_registry_environment().
 * Note that Windows happily truncates the value if it's too big.
 */
static void set_registry_variables( HANDLE hkey, ULONG type )
{
    UNICODE_STRING env_name, env_value;
    NTSTATUS status;
    DWORD size;
    int index;
    char buffer[1024*sizeof(WCHAR) + sizeof(KEY_VALUE_FULL_INFORMATION)];
    KEY_VALUE_FULL_INFORMATION *info = (KEY_VALUE_FULL_INFORMATION *)buffer;

    for (index = 0; ; index++)
    {
        status = NtEnumerateValueKey( hkey, index, KeyValueFullInformation,
                                      buffer, sizeof(buffer), &size );
        if (status != STATUS_SUCCESS && status != STATUS_BUFFER_OVERFLOW)
            break;
        if (info->Type != type)
            continue;
        env_name.Buffer = info->Name;
        env_name.Length = env_name.MaximumLength = info->NameLength;
        env_value.Buffer = (WCHAR *)(buffer + info->DataOffset);
        env_value.Length = env_value.MaximumLength = info->DataLength;
        if (env_value.Length && !env_value.Buffer[env_value.Length/sizeof(WCHAR)-1])
            env_value.Length -= sizeof(WCHAR);  /* don't count terminating null if any */
        if (info->Type == REG_EXPAND_SZ)
        {
            WCHAR buf_expanded[1024];
            UNICODE_STRING env_expanded;
            env_expanded.Length = env_expanded.MaximumLength = sizeof(buf_expanded);
            env_expanded.Buffer=buf_expanded;
            status = RtlExpandEnvironmentStrings_U(NULL, &env_value, &env_expanded, NULL);
            if (status == STATUS_SUCCESS || status == STATUS_BUFFER_OVERFLOW)
                RtlSetEnvironmentVariable( NULL, &env_name, &env_expanded );
        }
        else
        {
            RtlSetEnvironmentVariable( NULL, &env_name, &env_value );
        }
    }
}


/***********************************************************************
 *           set_registry_environment
 *
 * Set the environment variables specified in the registry.
 *
 * Note: Windows handles REG_SZ and REG_EXPAND_SZ in one pass with the
 * consequence that REG_EXPAND_SZ cannot be used reliably as it depends
 * on the order in which the variables are processed. But on Windows it
 * does not really matter since they only use %SystemDrive% and
 * %SystemRoot% which are predefined. But Wine defines these in the
 * registry, so we need two passes.
 */
static BOOL set_registry_environment(void)
{
    static const WCHAR env_keyW[] = {'M','a','c','h','i','n','e','\\',
                                     'S','y','s','t','e','m','\\',
                                     'C','u','r','r','e','n','t','C','o','n','t','r','o','l','S','e','t','\\',
                                     'C','o','n','t','r','o','l','\\',
                                     'S','e','s','s','i','o','n',' ','M','a','n','a','g','e','r','\\',
                                     'E','n','v','i','r','o','n','m','e','n','t',0};
    static const WCHAR envW[] = {'E','n','v','i','r','o','n','m','e','n','t',0};

    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING nameW;
    HANDLE hkey;
    BOOL ret = FALSE;

    attr.Length = sizeof(attr);
    attr.RootDirectory = 0;
    attr.ObjectName = &nameW;
    attr.Attributes = 0;
    attr.SecurityDescriptor = NULL;
    attr.SecurityQualityOfService = NULL;

    /* first the system environment variables */
    RtlInitUnicodeString( &nameW, env_keyW );
    if (NtOpenKey( &hkey, KEY_ALL_ACCESS, &attr ) == STATUS_SUCCESS)
    {
        set_registry_variables( hkey, REG_SZ );
        set_registry_variables( hkey, REG_EXPAND_SZ );
        NtClose( hkey );
        ret = TRUE;
    }

    /* then the ones for the current user */
    if (RtlOpenCurrentUser( KEY_ALL_ACCESS, &attr.RootDirectory ) != STATUS_SUCCESS) return ret;
    RtlInitUnicodeString( &nameW, envW );
    if (NtOpenKey( &hkey, KEY_ALL_ACCESS, &attr ) == STATUS_SUCCESS)
    {
        set_registry_variables( hkey, REG_SZ );
        set_registry_variables( hkey, REG_EXPAND_SZ );
        NtClose( hkey );
    }
    NtClose( attr.RootDirectory );
    return ret;
}


/***********************************************************************
 *           get_reg_value
 */
static WCHAR *get_reg_value( HKEY hkey, const WCHAR *name )
{
    char buffer[1024 * sizeof(WCHAR) + sizeof(KEY_VALUE_PARTIAL_INFORMATION)];
    KEY_VALUE_PARTIAL_INFORMATION *info = (KEY_VALUE_PARTIAL_INFORMATION *)buffer;
    DWORD len, size = sizeof(buffer);
    WCHAR *ret = NULL;
    UNICODE_STRING nameW;

    RtlInitUnicodeString( &nameW, name );
    if (NtQueryValueKey( hkey, &nameW, KeyValuePartialInformation, buffer, size, &size ))
        return NULL;

    if (size <= FIELD_OFFSET( KEY_VALUE_PARTIAL_INFORMATION, Data )) return NULL;
    len = (size - FIELD_OFFSET( KEY_VALUE_PARTIAL_INFORMATION, Data )) / sizeof(WCHAR);

    if (info->Type == REG_EXPAND_SZ)
    {
        UNICODE_STRING value, expanded;

        value.MaximumLength = len * sizeof(WCHAR);
        value.Buffer = (WCHAR *)info->Data;
        if (!value.Buffer[len - 1]) len--;  /* don't count terminating null if any */
        value.Length = len * sizeof(WCHAR);
        expanded.Length = expanded.MaximumLength = 1024 * sizeof(WCHAR);
        if (!(expanded.Buffer = HeapAlloc( GetProcessHeap(), 0, expanded.MaximumLength ))) return NULL;
        if (!RtlExpandEnvironmentStrings_U( NULL, &value, &expanded, NULL )) ret = expanded.Buffer;
        else RtlFreeUnicodeString( &expanded );
    }
    else if (info->Type == REG_SZ)
    {
        if ((ret = HeapAlloc( GetProcessHeap(), 0, (len + 1) * sizeof(WCHAR) )))
        {
            memcpy( ret, info->Data, len * sizeof(WCHAR) );
            ret[len] = 0;
        }
    }
    return ret;
}


/***********************************************************************
 *           set_additional_environment
 *
 * Set some additional environment variables not specified in the registry.
 */
static void set_additional_environment(void)
{
    static const WCHAR profile_keyW[] = {'M','a','c','h','i','n','e','\\',
                                         'S','o','f','t','w','a','r','e','\\',
                                         'M','i','c','r','o','s','o','f','t','\\',
                                         'W','i','n','d','o','w','s',' ','N','T','\\',
                                         'C','u','r','r','e','n','t','V','e','r','s','i','o','n','\\',
                                         'P','r','o','f','i','l','e','L','i','s','t',0};
    static const WCHAR profiles_valueW[] = {'P','r','o','f','i','l','e','s','D','i','r','e','c','t','o','r','y',0};
    static const WCHAR all_users_valueW[] = {'A','l','l','U','s','e','r','s','P','r','o','f','i','l','e','\0'};
    static const WCHAR usernameW[] = {'U','S','E','R','N','A','M','E',0};
    static const WCHAR userprofileW[] = {'U','S','E','R','P','R','O','F','I','L','E',0};
    static const WCHAR allusersW[] = {'A','L','L','U','S','E','R','S','P','R','O','F','I','L','E',0};
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING nameW;
    WCHAR *user_name = NULL, *profile_dir = NULL, *all_users_dir = NULL;
    HANDLE hkey;
    const char *name = wine_get_user_name();
    DWORD len;

    /* set the USERNAME variable */

    len = MultiByteToWideChar( CP_UNIXCP, 0, name, -1, NULL, 0 );
    if (len)
    {
        user_name = HeapAlloc( GetProcessHeap(), 0, len*sizeof(WCHAR) );
        MultiByteToWideChar( CP_UNIXCP, 0, name, -1, user_name, len );
        SetEnvironmentVariableW( usernameW, user_name );
    }

    /* set the USERPROFILE and ALLUSERSPROFILE variables */

    attr.Length = sizeof(attr);
    attr.RootDirectory = 0;
    attr.ObjectName = &nameW;
    attr.Attributes = 0;
    attr.SecurityDescriptor = NULL;
    attr.SecurityQualityOfService = NULL;
    RtlInitUnicodeString( &nameW, profile_keyW );
    if (!NtOpenKey( &hkey, KEY_ALL_ACCESS, &attr ))
    {
        profile_dir = get_reg_value( hkey, profiles_valueW );
        all_users_dir = get_reg_value( hkey, all_users_valueW );
        NtClose( hkey );
    }

    if (profile_dir)
    {
        WCHAR *value, *p;

        if (all_users_dir) len = max( len, strlenW(all_users_dir) + 1 );
        len += strlenW(profile_dir) + 1;
        value = HeapAlloc( GetProcessHeap(), 0, len * sizeof(WCHAR) );
        strcpyW( value, profile_dir );
        p = value + strlenW(value);
        if (p > value && p[-1] != '\\') *p++ = '\\';
        strcpyW( p, user_name );
        SetEnvironmentVariableW( userprofileW, value );
        if (all_users_dir)
        {
            strcpyW( p, all_users_dir );
            SetEnvironmentVariableW( allusersW, value );
        }
        HeapFree( GetProcessHeap(), 0, value );
    }

    HeapFree( GetProcessHeap(), 0, all_users_dir );
    HeapFree( GetProcessHeap(), 0, profile_dir );
    HeapFree( GetProcessHeap(), 0, user_name );
}

/***********************************************************************
 *              set_library_wargv
 *
 * Set the Wine library Unicode argv global variables.
 */
static void set_library_wargv( char **argv )
{
    int argc;
    char *q;
    WCHAR *p;
    WCHAR **wargv;
    DWORD total = 0;

    for (argc = 0; argv[argc]; argc++)
        total += MultiByteToWideChar( CP_UNIXCP, 0, argv[argc], -1, NULL, 0 );

    wargv = RtlAllocateHeap( GetProcessHeap(), 0,
                             total * sizeof(WCHAR) + (argc + 1) * sizeof(*wargv) );
    p = (WCHAR *)(wargv + argc + 1);
    for (argc = 0; argv[argc]; argc++)
    {
        DWORD reslen = MultiByteToWideChar( CP_UNIXCP, 0, argv[argc], -1, p, total );
        wargv[argc] = p;
        p += reslen;
        total -= reslen;
    }
    wargv[argc] = NULL;

    /* convert argv back from Unicode since it has to be in the Ansi codepage not the Unix one */

    for (argc = 0; wargv[argc]; argc++)
        total += WideCharToMultiByte( CP_ACP, 0, wargv[argc], -1, NULL, 0, NULL, NULL );

    argv = RtlAllocateHeap( GetProcessHeap(), 0, total + (argc + 1) * sizeof(*argv) );
    q = (char *)(argv + argc + 1);
    for (argc = 0; wargv[argc]; argc++)
    {
        DWORD reslen = WideCharToMultiByte( CP_ACP, 0, wargv[argc], -1, q, total, NULL, NULL );
        argv[argc] = q;
        q += reslen;
        total -= reslen;
    }
    argv[argc] = NULL;

    __wine_main_wargv = wargv;
}


/***********************************************************************
 *           build_command_line
 *
 * Build the command line of a process from the argv array.
 *
 * Note that it does NOT necessarily include the file name.
 * Sometimes we don't even have any command line options at all.
 *
 * We must quote and escape characters so that the argv array can be rebuilt
 * from the command line:
 * - spaces and tabs must be quoted
 *   'a b'   -> '"a b"'
 * - quotes must be escaped
 *   '"'     -> '\"'
 * - if '\'s are followed by a '"', they must be doubled and followed by '\"',
 *   resulting in an odd number of '\' followed by a '"'
 *   '\"'    -> '\\\"'
 *   '\\"'   -> '\\\\\"'
 * - '\'s that are not followed by a '"' can be left as is
 *   'a\b'   == 'a\b'
 *   'a\\b'  == 'a\\b'
 */
static BOOL build_command_line( WCHAR **argv )
{
    int len;
    WCHAR **arg;
    LPWSTR p;
    RTL_USER_PROCESS_PARAMETERS* rupp = NtCurrentTeb()->Peb->ProcessParameters;

    if (rupp->CommandLine.Buffer) return TRUE; /* already got it from the server */

    len = 0;
    for (arg = argv; *arg; arg++)
    {
        int has_space,bcount;
        WCHAR* a;

        has_space=0;
        bcount=0;
        a=*arg;
        if( !*a ) has_space=1;
        while (*a!='\0') {
            if (*a=='\\') {
                bcount++;
            } else {
                if (*a==' ' || *a=='\t') {
                    has_space=1;
                } else if (*a=='"') {
                    /* doubling of '\' preceding a '"',
                     * plus escaping of said '"'
                     */
                    len+=2*bcount+1;
                }
                bcount=0;
            }
            a++;
        }
        len+=(a-*arg)+1 /* for the separating space */;
        if (has_space)
            len+=2; /* for the quotes */
    }

    if (!(rupp->CommandLine.Buffer = RtlAllocateHeap( GetProcessHeap(), 0, len * sizeof(WCHAR))))
        return FALSE;

    p = rupp->CommandLine.Buffer;
    rupp->CommandLine.Length = (len - 1) * sizeof(WCHAR);
    rupp->CommandLine.MaximumLength = len * sizeof(WCHAR);
    for (arg = argv; *arg; arg++)
    {
        int has_space,has_quote;
        WCHAR* a;

        /* Check for quotes and spaces in this argument */
        has_space=has_quote=0;
        a=*arg;
        if( !*a ) has_space=1;
        while (*a!='\0') {
            if (*a==' ' || *a=='\t') {
                has_space=1;
                if (has_quote)
                    break;
            } else if (*a=='"') {
                has_quote=1;
                if (has_space)
                    break;
            }
            a++;
        }

        /* Now transfer it to the command line */
        if (has_space)
            *p++='"';
        if (has_quote) {
            int bcount;
            WCHAR* a;

            bcount=0;
            a=*arg;
            while (*a!='\0') {
                if (*a=='\\') {
                    *p++=*a;
                    bcount++;
                } else {
                    if (*a=='"') {
                        int i;

                        /* Double all the '\\' preceding this '"', plus one */
                        for (i=0;i<=bcount;i++)
                            *p++='\\';
                        *p++='"';
                    } else {
                        *p++=*a;
                    }
                    bcount=0;
                }
                a++;
            }
        } else {
            WCHAR* x = *arg;
            while ((*p=*x++)) p++;
        }
        if (has_space)
            *p++='"';
        *p++=' ';
    }
    if (p > rupp->CommandLine.Buffer)
        p--;  /* remove last space */
    *p = '\0';

    return TRUE;
}


/***********************************************************************
 *           init_current_directory
 *
 * Initialize the current directory from the Unix cwd or the parent info.
 */
static void init_current_directory( CURDIR *cur_dir )
{
    UNICODE_STRING dir_str;
    char *cwd;
    int size;

    /* if we received a cur dir from the parent, try this first */

    if (cur_dir->DosPath.Length)
    {
        if (RtlSetCurrentDirectory_U( &cur_dir->DosPath ) == STATUS_SUCCESS) goto done;
    }

    /* now try to get it from the Unix cwd */

    for (size = 256; ; size *= 2)
    {
        if (!(cwd = HeapAlloc( GetProcessHeap(), 0, size ))) break;
        if (getcwd( cwd, size )) break;
        HeapFree( GetProcessHeap(), 0, cwd );
        if (errno == ERANGE) continue;
        cwd = NULL;
        break;
    }

    if (cwd)
    {
        WCHAR *dirW;
        int lenW = MultiByteToWideChar( CP_UNIXCP, 0, cwd, -1, NULL, 0 );
        if ((dirW = HeapAlloc( GetProcessHeap(), 0, lenW * sizeof(WCHAR) )))
        {
            MultiByteToWideChar( CP_UNIXCP, 0, cwd, -1, dirW, lenW );
            RtlInitUnicodeString( &dir_str, dirW );
            RtlSetCurrentDirectory_U( &dir_str );
            RtlFreeUnicodeString( &dir_str );
        }
    }

    if (!cur_dir->DosPath.Length)  /* still not initialized */
    {
        MESSAGE("Warning: could not find DOS drive for current working directory '%s', "
                "starting in the Windows directory.\n", cwd ? cwd : "" );
        RtlInitUnicodeString( &dir_str, DIR_Windows );
        RtlSetCurrentDirectory_U( &dir_str );
    }
    HeapFree( GetProcessHeap(), 0, cwd );

done:
    if (!cur_dir->Handle) chdir("/"); /* change to root directory so as not to lock cdroms */
    TRACE( "starting in %s %p\n", debugstr_w( cur_dir->DosPath.Buffer ), cur_dir->Handle );
}


/***********************************************************************
 *           init_windows_dirs
 *
 * Initialize the windows and system directories from the environment.
 */
static void init_windows_dirs(void)
{
    extern void __wine_init_windows_dir( const WCHAR *windir, const WCHAR *sysdir );

    static const WCHAR windirW[] = {'w','i','n','d','i','r',0};
    static const WCHAR winsysdirW[] = {'w','i','n','s','y','s','d','i','r',0};
    static const WCHAR default_windirW[] = {'C',':','\\','w','i','n','d','o','w','s',0};
    static const WCHAR default_sysdirW[] = {'\\','s','y','s','t','e','m','3','2',0};

    DWORD len;
    WCHAR *buffer;

    if ((len = GetEnvironmentVariableW( windirW, NULL, 0 )))
    {
        buffer = HeapAlloc( GetProcessHeap(), 0, len * sizeof(WCHAR) );
        GetEnvironmentVariableW( windirW, buffer, len );
        DIR_Windows = buffer;
    }
    else DIR_Windows = default_windirW;

    if ((len = GetEnvironmentVariableW( winsysdirW, NULL, 0 )))
    {
        buffer = HeapAlloc( GetProcessHeap(), 0, len * sizeof(WCHAR) );
        GetEnvironmentVariableW( winsysdirW, buffer, len );
        DIR_System = buffer;
    }
    else
    {
        len = strlenW( DIR_Windows );
        buffer = HeapAlloc( GetProcessHeap(), 0, len * sizeof(WCHAR) + sizeof(default_sysdirW) );
        memcpy( buffer, DIR_Windows, len * sizeof(WCHAR) );
        memcpy( buffer + len, default_sysdirW, sizeof(default_sysdirW) );
        DIR_System = buffer;
    }

    if (!CreateDirectoryW( DIR_Windows, NULL ) && GetLastError() != ERROR_ALREADY_EXISTS)
        ERR( "directory %s could not be created, error %u\n",
             debugstr_w(DIR_Windows), GetLastError() );
    if (!CreateDirectoryW( DIR_System, NULL ) && GetLastError() != ERROR_ALREADY_EXISTS)
        ERR( "directory %s could not be created, error %u\n",
             debugstr_w(DIR_System), GetLastError() );

    TRACE_(file)( "WindowsDir = %s\n", debugstr_w(DIR_Windows) );
    TRACE_(file)( "SystemDir  = %s\n", debugstr_w(DIR_System) );

    /* set the directories in ntdll too */
    __wine_init_windows_dir( DIR_Windows, DIR_System );
}


/***********************************************************************
 *           start_wineboot
 *
 * Start the wineboot process if necessary. Return the event to wait on.
 */
static HANDLE start_wineboot(void)
{
    static const WCHAR wineboot_eventW[] = {'_','_','w','i','n','e','b','o','o','t','_','e','v','e','n','t',0};
    HANDLE event;

    if (!(event = CreateEventW( NULL, TRUE, FALSE, wineboot_eventW )))
    {
        ERR( "failed to create wineboot event, expect trouble\n" );
        return 0;
    }
    if (GetLastError() != ERROR_ALREADY_EXISTS)  /* we created it */
    {
        static const WCHAR command_line[] = {'\\','w','i','n','e','b','o','o','t','.','e','x','e',' ','-','-','i','n','i','t',0};
        STARTUPINFOW si;
        PROCESS_INFORMATION pi;
        WCHAR cmdline[MAX_PATH + sizeof(command_line)/sizeof(WCHAR)];

        memset( &si, 0, sizeof(si) );
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput  = 0;
        si.hStdOutput = 0;
        si.hStdError  = GetStdHandle( STD_ERROR_HANDLE );

        GetSystemDirectoryW( cmdline, MAX_PATH );
        lstrcatW( cmdline, command_line );
        if (CreateProcessW( NULL, cmdline, NULL, NULL, FALSE, DETACHED_PROCESS, NULL, NULL, &si, &pi ))
        {
            TRACE( "started wineboot pid %04x tid %04x\n", pi.dwProcessId, pi.dwThreadId );
            CloseHandle( pi.hThread );
            CloseHandle( pi.hProcess );

        }
        else ERR( "failed to start wineboot, err %u\n", GetLastError() );
    }
    return event;
}

/*
 * process_init() has been removed from wine-0.9.53, 
 * but Linux Unified Kernel will use it in ntdll.dll, 
 * so here it is.
 */
BOOL process_init(void)
{
    static const WCHAR kernel32W[] = {'k','e','r','n','e','l','3','2',0};
    PEB *peb = NtCurrentTeb()->Peb;
    RTL_USER_PROCESS_PARAMETERS *params = peb->ProcessParameters;
    BOOL got_environment = TRUE;
    HANDLE boot_event = 0;
    static const WCHAR process_eventW[] = {'_','_','p','r','o','c','e','s','s','_','e','v','e','n','t',0};
    HANDLE event;

    LOG(LOG_FILE, 0, 0, "process_init()\n");
    setbuf(stdout,NULL);
    setbuf(stderr,NULL);

    kernel32_handle = GetModuleHandleW(kernel32W);

    LOCALE_Init();

    if (!params->Environment)
    {
        /* Copy the parent environment */
        if (!build_initial_environment( __wine_main_environ )) return FALSE;

        /* convert old configuration to new format */
        convert_old_config();

        got_environment = set_registry_environment();
        set_additional_environment();
    }

    init_windows_dirs();
    init_current_directory( &params->CurrentDirectory );

    /* start wineboot */
    if (!(event = CreateEventW( NULL, TRUE, FALSE, process_eventW )))
		return FALSE;
    if (GetLastError() != ERROR_ALREADY_EXISTS)
        boot_event = start_wineboot();

    if (boot_event)
    {
        if (WaitForSingleObject( boot_event, 30000 )) WARN( "boot event wait timed out\n" );
        CloseHandle( boot_event );
        /* if we didn't find environment section, try again now that wineboot has run */
        if (!got_environment)
        {
            set_registry_environment();
            set_additional_environment();
        }
    }
    set_library_wargv(__wine_main_argv);

    LOG(LOG_FILE, 0, 0, "process_init() done\n");
    return TRUE;
}

/***********************************************************************
 *           start_process
 *
 * Startup routine of a new process. Runs on the new process stack.
 */
static void start_process( void *arg )
{
    __TRY
    {
        PEB *peb = NtCurrentTeb()->Peb;
        IMAGE_NT_HEADERS *nt;
        LPTHREAD_START_ROUTINE entry;

        nt = RtlImageNtHeader( peb->ImageBaseAddress );
        entry = (LPTHREAD_START_ROUTINE)((char *)peb->ImageBaseAddress +
                                         nt->OptionalHeader.AddressOfEntryPoint);

        if (TRACE_ON(relay))
            DPRINTF( "%04x:Starting process %s (entryproc=%p)\n", GetCurrentThreadId(),
                     debugstr_w(peb->ProcessParameters->ImagePathName.Buffer), entry );

        SetLastError( 0 );  /* clear error code */
        if (peb->BeingDebugged) DbgBreakPoint();
        ExitThread( entry( peb ) );
    }
    __EXCEPT(UnhandledExceptionFilter)
    {
        TerminateThread( GetCurrentThread(), GetExceptionCode() );
    }
    __ENDTRY
}


/***********************************************************************
 *           set_process_name
 *
 * Change the process name in the ps output.
 */
static void set_process_name( int argc, char *argv[] )
{
#ifdef HAVE_SETPROCTITLE
    setproctitle("-%s", argv[1]);
#endif

#ifdef HAVE_PRCTL
    int i, offset;
    char *p, *prctl_name = argv[1];
    char *end = argv[argc-1] + strlen(argv[argc-1]) + 1;

#ifndef PR_SET_NAME
# define PR_SET_NAME 15
#endif

    if ((p = strrchr( prctl_name, '\\' ))) prctl_name = p + 1;
    if ((p = strrchr( prctl_name, '/' ))) prctl_name = p + 1;

    if (prctl( PR_SET_NAME, prctl_name ) != -1)
    {
        offset = argv[1] - argv[0];
        memmove( argv[1] - offset, argv[1], end - argv[1] );
        memset( end - offset, 0, offset );
        for (i = 1; i < argc; i++) argv[i-1] = argv[i] - offset;
        argv[i-1] = NULL;
    }
    else
#endif  /* HAVE_PRCTL */
    {
        /* remove argv[0] */
        memmove( argv, argv + 1, argc * sizeof(argv[0]) );
    }
}


/***********************************************************************
 *           __wine_kernel_init
 *
 * Wine initialisation: load and start the main exe file.
 */
void __wine_kernel_init(void)
{
    static const WCHAR kernel32W[] = {'k','e','r','n','e','l','3','2',0};
    static const WCHAR dotW[] = {'.',0};
    static const WCHAR exeW[] = {'.','e','x','e',0};

    WCHAR *p, main_exe_name[MAX_PATH+1];
    PEB *peb = NtCurrentTeb()->Peb;
    RTL_USER_PROCESS_PARAMETERS *params = peb->ProcessParameters;
    HANDLE boot_event = 0;
    BOOL got_environment = TRUE;

    /* Initialize everything */
    LOG(LOG_FILE, 0, 0, "__wine_kernel_init()\n");
    PTHREAD_Init();

    setbuf(stdout,NULL);
    setbuf(stderr,NULL);
    kernel32_handle = GetModuleHandleW(kernel32W);

    LOCALE_Init();

    if (!params->Environment)
    {
        /* Copy the parent environment */
        if (!build_initial_environment( __wine_main_environ )) exit(1);

        /* convert old configuration to new format */
        convert_old_config();

        got_environment = set_registry_environment();
        set_additional_environment();
    }

    init_windows_dirs();
    init_current_directory( &params->CurrentDirectory );

    set_process_name( __wine_main_argc, __wine_main_argv );
    set_library_wargv( __wine_main_argv );

    if (peb->ProcessParameters->ImagePathName.Buffer)
    {
        strcpyW( main_exe_name, peb->ProcessParameters->ImagePathName.Buffer );
    }
    else
    {
        if (!SearchPathW( NULL, __wine_main_wargv[0], exeW, MAX_PATH, main_exe_name, NULL ) &&
            !get_builtin_path( __wine_main_wargv[0], exeW, main_exe_name, MAX_PATH ))
        {
            MESSAGE( "wine: cannot find '%s'\n", __wine_main_argv[0] );
            ExitProcess( GetLastError() );
        }
        if (!build_command_line( __wine_main_wargv )) goto error;
        boot_event = start_wineboot();
    }

    /* if there's no extension, append a dot to prevent LoadLibrary from appending .dll */
    p = strrchrW( main_exe_name, '.' );
    if (!p || strchrW( p, '/' ) || strchrW( p, '\\' )) strcatW( main_exe_name, dotW );

    TRACE( "starting process name=%s argv[0]=%s\n",
           debugstr_w(main_exe_name), debugstr_w(__wine_main_wargv[0]) );

    RtlInitUnicodeString( &NtCurrentTeb()->Peb->ProcessParameters->DllPath,
                          MODULE_get_dll_load_path(main_exe_name) );

    if (boot_event)
    {
        if (WaitForSingleObject( boot_event, 30000 )) WARN( "boot event wait timed out\n" );
        CloseHandle( boot_event );
        /* if we didn't find environment section, try again now that wineboot has run */
        if (!got_environment)
        {
            set_registry_environment();
            set_additional_environment();
        }
    }

    if (!(peb->ImageBaseAddress = LoadLibraryExW( main_exe_name, 0, DONT_RESOLVE_DLL_REFERENCES )))
    {
        char msg[1024];
        DWORD error = GetLastError();

        /* if Win16/DOS format, or unavailable address, exec a new process with the proper setup */
        if (error == ERROR_BAD_EXE_FORMAT ||
            error == ERROR_INVALID_ADDRESS ||
            error == ERROR_NOT_ENOUGH_MEMORY)
        {
            if (!getenv("WINEPRELOADRESERVE")) exec_process( main_exe_name );
            /* if we get back here, it failed */
        }

        FormatMessageA( FORMAT_MESSAGE_FROM_SYSTEM, NULL, error, 0, msg, sizeof(msg), NULL );
        MESSAGE( "wine: could not load %s: %s", debugstr_w(main_exe_name), msg );
        ExitProcess( error );
    }

    LdrInitializeThunk( 0, 0, 0, 0 );
    /* switch to the new stack */
    wine_switch_to_stack( start_process, NULL, NtCurrentTeb()->Tib.StackBase );

 error:
    ExitProcess( GetLastError() );
}


/***********************************************************************
 *           build_argv
 *
 * Build an argv array from a command-line.
 * 'reserved' is the number of args to reserve before the first one.
 */
static char **build_argv( const WCHAR *cmdlineW, int reserved )
{
    int argc;
    char** argv;
    char *arg,*s,*d,*cmdline;
    int in_quotes,bcount,len;

    len = WideCharToMultiByte( CP_UNIXCP, 0, cmdlineW, -1, NULL, 0, NULL, NULL );
    if (!(cmdline = malloc(len))) return NULL;
    WideCharToMultiByte( CP_UNIXCP, 0, cmdlineW, -1, cmdline, len, NULL, NULL );

    argc=reserved+1;
    bcount=0;
    in_quotes=0;
    s=cmdline;
    while (1) {
        if (*s=='\0' || ((*s==' ' || *s=='\t') && !in_quotes)) {
            /* space */
            argc++;
            /* skip the remaining spaces */
            while (*s==' ' || *s=='\t') {
                s++;
            }
            if (*s=='\0')
                break;
            bcount=0;
            continue;
        } else if (*s=='\\') {
            /* '\', count them */
            bcount++;
        } else if ((*s=='"') && ((bcount & 1)==0)) {
            /* unescaped '"' */
            in_quotes=!in_quotes;
            bcount=0;
        } else {
            /* a regular character */
            bcount=0;
        }
        s++;
    }
    argv=malloc(argc*sizeof(*argv));
    if (!argv)
        return NULL;

    arg=d=s=cmdline;
    bcount=0;
    in_quotes=0;
    argc=reserved;
    while (*s) {
        if ((*s==' ' || *s=='\t') && !in_quotes) {
            /* Close the argument and copy it */
            *d=0;
            argv[argc++]=arg;

            /* skip the remaining spaces */
            do {
                s++;
            } while (*s==' ' || *s=='\t');

            /* Start with a new argument */
            arg=d=s;
            bcount=0;
        } else if (*s=='\\') {
            /* '\\' */
            *d++=*s++;
            bcount++;
        } else if (*s=='"') {
            /* '"' */
            if ((bcount & 1)==0) {
                /* Preceded by an even number of '\', this is half that
                 * number of '\', plus a '"' which we discard.
                 */
                d-=bcount/2;
                s++;
                in_quotes=!in_quotes;
            } else {
                /* Preceded by an odd number of '\', this is half that
                 * number of '\' followed by a '"'
                 */
                d=d-bcount/2-1;
                *d++='"';
                s++;
            }
            bcount=0;
        } else {
            /* a regular character */
            *d++=*s++;
            bcount=0;
        }
    }
    if (*arg) {
        *d='\0';
        argv[argc++]=arg;
    }
    argv[argc]=NULL;

    return argv;
}


/***********************************************************************
 *           create_user_params
 */
static RTL_USER_PROCESS_PARAMETERS *create_user_params( LPCWSTR filename, LPCWSTR cmdline,
                                                        LPCWSTR cur_dir, LPWSTR env, DWORD flags,
                                                        const STARTUPINFOW *startup )
{
    RTL_USER_PROCESS_PARAMETERS *params;
    UNICODE_STRING image_str, cmdline_str, curdir_str, desktop, title, runtime, newdir;
    NTSTATUS status;
    WCHAR buffer[MAX_PATH];

    if(!GetLongPathNameW( filename, buffer, MAX_PATH ))
        lstrcpynW( buffer, filename, MAX_PATH );
    if(!GetFullPathNameW( buffer, MAX_PATH, buffer, NULL ))
        lstrcpynW( buffer, filename, MAX_PATH );
    RtlInitUnicodeString( &image_str, buffer );

    RtlInitUnicodeString( &cmdline_str, cmdline );
    newdir.Buffer = NULL;
    if (cur_dir)
    {
        if (RtlDosPathNameToNtPathName_U( cur_dir, &newdir, NULL, NULL ))
        {
            /* skip \??\ prefix */
            curdir_str.Buffer = newdir.Buffer + 4;
            curdir_str.Length = newdir.Length - 4 * sizeof(WCHAR);
            curdir_str.MaximumLength = newdir.MaximumLength - 4 * sizeof(WCHAR);
        }
        else cur_dir = NULL;
    }
    if (startup->lpDesktop) RtlInitUnicodeString( &desktop, startup->lpDesktop );
    if (startup->lpTitle) RtlInitUnicodeString( &title, startup->lpTitle );
    if (startup->lpReserved2 && startup->cbReserved2)
    {
        runtime.Length = 0;
        runtime.MaximumLength = startup->cbReserved2;
        runtime.Buffer = (WCHAR*)startup->lpReserved2;
    }

    status = RtlCreateProcessParameters( &params, &image_str, NULL,
                                         cur_dir ? &curdir_str : NULL,
                                         &cmdline_str, env,
                                         startup->lpTitle ? &title : NULL,
                                         startup->lpDesktop ? &desktop : NULL,
                                         NULL, 
                                         (startup->lpReserved2 && startup->cbReserved2) ? &runtime : NULL );
    RtlFreeUnicodeString( &newdir );
    if (status != STATUS_SUCCESS)
    {
        SetLastError( RtlNtStatusToDosError(status) );
        return NULL;
    }

    if (flags & CREATE_NEW_PROCESS_GROUP) params->ConsoleFlags = 1;
    if (flags & CREATE_NEW_CONSOLE) params->ConsoleHandle = (HANDLE)1;  /* FIXME: cf. kernel_main.c */

    if (startup->dwFlags & STARTF_USESTDHANDLES)
    {
        params->hStdInput  = startup->hStdInput;
        params->hStdOutput = startup->hStdOutput;
        params->hStdError  = startup->hStdError;
    }
    else
    {
        params->hStdInput  = GetStdHandle( STD_INPUT_HANDLE );
        params->hStdOutput = GetStdHandle( STD_OUTPUT_HANDLE );
        params->hStdError  = GetStdHandle( STD_ERROR_HANDLE );
    }
    params->dwX             = startup->dwX;
    params->dwY             = startup->dwY;
    params->dwXSize         = startup->dwXSize;
    params->dwYSize         = startup->dwYSize;
    params->dwXCountChars   = startup->dwXCountChars;
    params->dwYCountChars   = startup->dwYCountChars;
    params->dwFillAttribute = startup->dwFillAttribute;
    params->dwFlags         = startup->dwFlags;
    params->wShowWindow     = startup->wShowWindow;
    return params;
}


/***********************************************************************
 *           create_process
 *
 * Create a new process. If hFile is a valid handle we have an exe
 * file, otherwise it is a Winelib app.
 */
static BOOL create_process( HANDLE hFile, LPCWSTR filename, LPWSTR cmd_line, LPWSTR env,
                            LPCWSTR cur_dir, LPSECURITY_ATTRIBUTES psa, LPSECURITY_ATTRIBUTES tsa,
                            BOOL inherit, DWORD flags, LPSTARTUPINFOW startup,
                            LPPROCESS_INFORMATION info, LPCSTR unixdir,
                            void *res_start, void *res_end, int exec_only )
{
    BOOL ret, success = FALSE;
    HANDLE process_info;
    WCHAR *env_end;
    char *winedebug = NULL;
    RTL_USER_PROCESS_PARAMETERS *params;
    pid_t pid;
    int err;

    LOG(LOG_FILE, 0, 0, "create_process()\n");
    if (!env) RtlAcquirePebLock();

    if (!(params = create_user_params( filename, cmd_line, cur_dir, env, flags, startup )))
    {
        if (!env) RtlReleasePebLock();
        return FALSE;
    }
    env_end = params->Environment;
    while (*env_end)
    {
        static const WCHAR WINEDEBUG[] = {'W','I','N','E','D','E','B','U','G','=',0};
        if (!winedebug && !strncmpW( env_end, WINEDEBUG, sizeof(WINEDEBUG)/sizeof(WCHAR) - 1 ))
        {
            DWORD len = WideCharToMultiByte( CP_UNIXCP, 0, env_end, -1, NULL, 0, NULL, NULL );
            if ((winedebug = HeapAlloc( GetProcessHeap(), 0, len )))
                WideCharToMultiByte( CP_UNIXCP, 0, env_end, -1, winedebug, len, NULL, NULL );
        }
        env_end += strlenW(env_end) + 1;
    }
    env_end++;

    SERVER_START_REQ( new_process )
    {
        req->inherit_all    = inherit;
        req->create_flags   = flags;
        req->exe_file       = hFile;
        req->process_access = PROCESS_ALL_ACCESS;
        req->process_attr   = (psa && (psa->nLength >= sizeof(*psa)) && psa->bInheritHandle) ? OBJ_INHERIT : 0;
        req->thread_access  = THREAD_ALL_ACCESS;
        req->thread_attr    = (tsa && (tsa->nLength >= sizeof(*tsa)) && tsa->bInheritHandle) ? OBJ_INHERIT : 0;
        req->hstdin         = params->hStdInput;
        req->hstdout        = params->hStdOutput;
        req->hstderr        = params->hStdError;

        if ((flags & (CREATE_NEW_CONSOLE | DETACHED_PROCESS)) != 0)
        {
            /* this is temporary (for console handles). We have no way to control that the handle is invalid in child process otherwise */
            if (is_console_handle(req->hstdin))  req->hstdin  = INVALID_HANDLE_VALUE;
            if (is_console_handle(req->hstdout)) req->hstdout = INVALID_HANDLE_VALUE;
            if (is_console_handle(req->hstderr)) req->hstderr = INVALID_HANDLE_VALUE;
        }
        else
        {
            if (is_console_handle(req->hstdin))  req->hstdin  = console_handle_unmap(req->hstdin);
            if (is_console_handle(req->hstdout)) req->hstdout = console_handle_unmap(req->hstdout);
            if (is_console_handle(req->hstderr)) req->hstderr = console_handle_unmap(req->hstderr);
        }

        wine_server_add_data( req, params, params->Size );
        wine_server_add_data( req, params->Environment, (env_end-params->Environment)*sizeof(WCHAR) );
        if ((ret = !wine_server_call_err( req )))
        {
            info->dwProcessId = (DWORD)reply->pid;
            info->dwThreadId  = (DWORD)reply->tid;
            info->hProcess    = reply->phandle;
            info->hThread     = reply->thandle;
        }
        process_info = reply->info;
    }
    SERVER_END_REQ;

    if (!env) RtlReleasePebLock();
    RtlDestroyProcessParameters( params );
    if (!ret)
    {
        HeapFree( GetProcessHeap(), 0, winedebug );
        return FALSE;
    }

    /* create the child process */

    if (exec_only || !(pid = fork()))  /* child */
    {
        char preloader_reserve[64], socket_env[64];
        char **argv = build_argv( cmd_line, 1 );

        if (flags & (CREATE_NEW_PROCESS_GROUP | CREATE_NEW_CONSOLE | DETACHED_PROCESS))
        {
            if (!(pid = fork()))
            {
                int fd = open( "/dev/null", O_RDWR );
                setsid();
                /* close stdin and stdout */
                if (fd != -1)
                {
                    dup2( fd, 0 );
                    dup2( fd, 1 );
                    close( fd );
                }
            }
            else if (pid != -1) _exit(0);  /* parent */
        }

        /* Reset signals that we previously set to SIG_IGN */
        signal( SIGPIPE, SIG_DFL );
        signal( SIGCHLD, SIG_DFL );

        sprintf( preloader_reserve, "WINEPRELOADRESERVE=%lx-%lx",
                 (unsigned long)res_start, (unsigned long)res_end );

        putenv( preloader_reserve );
        putenv( socket_env );
        if (winedebug) putenv( winedebug );
        if (unixdir) chdir(unixdir);

        if (argv) wine_exec_wine_binary( NULL, argv, getenv("WINELOADER") );
        _exit(1);
    }

    /* this is the parent */

    HeapFree( GetProcessHeap(), 0, winedebug );
    if (pid == -1)
    {
        FILE_SetDosError();
        goto error;
    }

    /* wait for the new process info to be ready */

    WaitForSingleObject( process_info, INFINITE );
    SERVER_START_REQ( get_new_process_info )
    {
        req->info = process_info;
        wine_server_call( req );
        success = reply->success;
        err = reply->exit_code;
    }
    SERVER_END_REQ;

    if (!success)
    {
        SetLastError( err ? err : ERROR_INTERNAL_ERROR );
        goto error;
    }
    CloseHandle( process_info );
    return success;

error:
    CloseHandle( process_info );
    CloseHandle( info->hProcess );
    CloseHandle( info->hThread );
    info->hProcess = info->hThread = 0;
    info->dwProcessId = info->dwThreadId = 0;
    return FALSE;
}


/***********************************************************************
 *           create_vdm_process
 *
 * Create a new VDM process for a 16-bit or DOS application.
 */
static BOOL create_vdm_process( LPCWSTR filename, LPWSTR cmd_line, LPWSTR env, LPCWSTR cur_dir,
                                LPSECURITY_ATTRIBUTES psa, LPSECURITY_ATTRIBUTES tsa,
                                BOOL inherit, DWORD flags, LPSTARTUPINFOW startup,
                                LPPROCESS_INFORMATION info, LPCSTR unixdir, int exec_only )
{
    static const WCHAR argsW[] = {'%','s',' ','-','-','a','p','p','-','n','a','m','e',' ','"','%','s','"',' ','%','s',0};

    BOOL ret;
    LPWSTR new_cmd_line = HeapAlloc( GetProcessHeap(), 0,
                                     (strlenW(filename) + strlenW(cmd_line) + 30) * sizeof(WCHAR) );

    if (!new_cmd_line)
    {
        SetLastError( ERROR_OUTOFMEMORY );
        return FALSE;
    }
    sprintfW( new_cmd_line, argsW, winevdmW, filename, cmd_line );
    ret = create_process( 0, winevdmW, new_cmd_line, env, cur_dir, psa, tsa, inherit,
                          flags, startup, info, unixdir, NULL, NULL, exec_only );
    HeapFree( GetProcessHeap(), 0, new_cmd_line );
    return ret;
}


/**********************************************************************
 *       CreateProcessA          (KERNEL32.@)
 */
BOOL WINAPI CreateProcessA( LPCSTR app_name, LPSTR cmd_line, LPSECURITY_ATTRIBUTES process_attr,
                            LPSECURITY_ATTRIBUTES thread_attr, BOOL inherit,
                            DWORD flags, LPVOID env, LPCSTR cur_dir,
                            LPSTARTUPINFOA startup_info, LPPROCESS_INFORMATION info )
{
    BOOL ret = FALSE;
    WCHAR *app_nameW = NULL, *cmd_lineW = NULL, *cur_dirW = NULL;
    UNICODE_STRING desktopW, titleW;
    STARTUPINFOW infoW;

    desktopW.Buffer = NULL;
    titleW.Buffer = NULL;
    if (app_name && !(app_nameW = FILE_name_AtoW( app_name, TRUE ))) goto done;
    if (cmd_line && !(cmd_lineW = FILE_name_AtoW( cmd_line, TRUE ))) goto done;
    if (cur_dir && !(cur_dirW = FILE_name_AtoW( cur_dir, TRUE ))) goto done;

    if (startup_info->lpDesktop) RtlCreateUnicodeStringFromAsciiz( &desktopW, startup_info->lpDesktop );
    if (startup_info->lpTitle) RtlCreateUnicodeStringFromAsciiz( &titleW, startup_info->lpTitle );

    memcpy( &infoW, startup_info, sizeof(infoW) );
    infoW.lpDesktop = desktopW.Buffer;
    infoW.lpTitle = titleW.Buffer;

    if (startup_info->lpReserved)
      FIXME("StartupInfo.lpReserved is used, please report (%s)\n",
            debugstr_a(startup_info->lpReserved));

    ret = CreateProcessW( app_nameW, cmd_lineW, process_attr, thread_attr,
                          inherit, flags, env, cur_dirW, &infoW, info );
done:
    HeapFree( GetProcessHeap(), 0, app_nameW );
    HeapFree( GetProcessHeap(), 0, cmd_lineW );
    HeapFree( GetProcessHeap(), 0, cur_dirW );
    RtlFreeUnicodeString( &desktopW );
    RtlFreeUnicodeString( &titleW );
    return ret;
}


/**********************************************************************
 *       exec_process
 */
static void exec_process( LPCWSTR name )
{
    HANDLE hFile;
    WCHAR *p;
    void *res_start, *res_end;
    STARTUPINFOW startup_info;
    PROCESS_INFORMATION info;

    hFile = open_exe_file( name );
    if (!hFile || hFile == INVALID_HANDLE_VALUE) return;

    memset( &startup_info, 0, sizeof(startup_info) );
    startup_info.cb = sizeof(startup_info);

    /* Determine executable type */

    switch( MODULE_GetBinaryType( hFile, &res_start, &res_end ))
    {
    case BINARY_PE_EXE:
        TRACE( "starting %s as Win32 binary (%p-%p)\n", debugstr_w(name), res_start, res_end );
        create_process( hFile, name, GetCommandLineW(), NULL, NULL, NULL, NULL,
                        FALSE, 0, &startup_info, &info, NULL, res_start, res_end, TRUE );
        break;
    case BINARY_UNIX_LIB:
        TRACE( "%s is a Unix library, starting as Winelib app\n", debugstr_w(name) );
        create_process( hFile, name, GetCommandLineW(), NULL, NULL, NULL, NULL,
                        FALSE, 0, &startup_info, &info, NULL, NULL, NULL, TRUE );
        break;
    case BINARY_UNKNOWN:
        /* check for .com or .pif extension */
        if (!(p = strrchrW( name, '.' ))) break;
        if (strcmpiW( p, comW ) && strcmpiW( p, pifW )) break;
        /* fall through */
    case BINARY_OS216:
    case BINARY_WIN16:
    case BINARY_DOS:
        TRACE( "starting %s as Win16/DOS binary\n", debugstr_w(name) );
        create_vdm_process( name, GetCommandLineW(), NULL, NULL, NULL, NULL,
                            FALSE, 0, &startup_info, &info, NULL, TRUE );
        break;
    default:
        break;
    }
    CloseHandle( hFile );
}

#define PEB_BASE 0x7ffdf000
extern void set_child_socket_fd(int fd);
void BaseProcessStart(unsigned long start_address, void *param);

extern VOID RtlRosR32AttribsToNativeAttribs(OUT OBJECT_ATTRIBUTES * NativeAttribs,
        IN SECURITY_ATTRIBUTES * Ros32Attribs OPTIONAL);

extern NTSTATUS WINAPI UkQuerySection(
        IN HANDLE SectionHandle,
        IN SECTION_INFORMATION_CLASS SectionInformationClass,
        OUT PVOID SectionInformation,
        IN ULONG Length,
        OUT PULONG ResultLength);

extern NTSTATUS CDECL
RtlRosCreateUserThread(IN HANDLE ProcessHandle,
        IN POBJECT_ATTRIBUTES ObjectAttributes,
        IN BOOLEAN CreateSuspended,
        IN LONG StackZeroBits,
        IN OUT PULONG StackReserve OPTIONAL,
        IN OUT PULONG StackCommit OPTIONAL,
        IN PVOID BaseStartAddress,
        OUT PHANDLE ThreadHandle OPTIONAL,
        OUT PCLIENT_ID ClientId OPTIONAL,
        IN ULONG_PTR StartAddress,
        IN ULONG_PTR Parameter);

NTSTATUS WINAPI
UkOpenFile( PHANDLE handle, ACCESS_MASK access,
        POBJECT_ATTRIBUTES attr, PIO_STATUS_BLOCK io,
        ULONG sharing, ULONG options );

NTSTATUS WINAPI
UkCreateSection( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
        const LARGE_INTEGER *size, ULONG protect,
        ULONG sec_flags, HANDLE file );

NTSTATUS WINAPI NtClose( HANDLE Handle );

static const char fakedll_signature[] = "Wine placeholder DLL";

static BOOL IsFakeDll(HANDLE h)
{
    IMAGE_DOS_HEADER *dos;
    DWORD size;
    BYTE buffer[sizeof(*dos) + sizeof(fakedll_signature)];

    if (!ReadFile( h, buffer, sizeof(buffer), &size, NULL ) || size != sizeof(buffer))
        return FALSE;
    dos = (IMAGE_DOS_HEADER *)buffer;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    if (dos->e_lfanew < size) return FALSE;
    return !memcmp( dos + 1, fakedll_signature, sizeof(fakedll_signature) );
}

static BOOL IsValidPEApp(LPCWSTR AppName)
{
    HANDLE handle;

    handle = CreateFileW(AppName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, 0);
    if (handle == INVALID_HANDLE_VALUE)
        return FALSE;
    if (IsFakeDll(handle)) {
        CloseHandle(handle);
        return FALSE;
    }
    CloseHandle(handle);
    return TRUE;
}


extern char *get_dlldir(char **default_path);
static BOOL NativeToBuiltin(LPWSTR Native, LPWSTR Builtin, unsigned BuiltinLen)
{
    char *prefix = NULL;
    char *c;
    char name[MAX_PATH];
    int  len;
    WCHAR *p;
    struct stat stat_buf;

    p = strrchrW(Native, '\\');
    if (p)
        p++;
    else
        p = Native;

    get_dlldir(&prefix);

    len = strlen(prefix);
    memcpy(name, prefix, len);
    name[len++] = '/';
    WideCharToMultiByte(CP_UNIXCP, 0, p, strlenW(p) + 1, name + len, sizeof(name) - len, 0, NULL);

    c = name + len;
    while (*c) {
        *c = tolower(*c);
        c++;
    }

    len = c - name;
    if (strcasecmp(name + len - 4, ".exe")) {
        memcpy(name + len, ".exe.so", sizeof(".exe.so"));
        len += sizeof(".exe.so") - 1;
    }
    else {
        memcpy(name + len, ".so", sizeof(".so"));
        len += sizeof(".so") - 1;
    }

    if (!stat(name, &stat_buf)) {
        MultiByteToWideChar(CP_UNIXCP, 0, name, len + 1, Builtin, BuiltinLen);
        return TRUE;
    }
    return FALSE;
}

static BOOL SearchApplication(LPWSTR AppName, LPWSTR NativeAppName,
        unsigned NativeAppNameLen, LPWSTR BuiltinAppName,
        unsigned BuiltinAppNameLen, PBOOL UseNative)
{
    WCHAR dotExe[] = {L'.',L'e',L'x',L'e', 0};
    BOOL  Found = FALSE;

    if (SearchPathW(NULL, AppName, dotExe, NativeAppNameLen, NativeAppName, NULL)) {
        /* found pe format application */
        if (!IsValidPEApp(NativeAppName)) {
            if (NativeToBuiltin(NativeAppName, BuiltinAppName, BuiltinAppNameLen)) {
                Found = TRUE;
                *UseNative = FALSE;
            }
        } else {
            Found = TRUE;
            *UseNative = TRUE;
        }
    } else {
        if (NativeToBuiltin(AppName, BuiltinAppName, BuiltinAppNameLen)) {
            Found = TRUE;
            *UseNative = FALSE;
        }
    }

    return Found;
}

static inline void MakeBuiltinCmdLine(LPWSTR CmdLine, LPWSTR AppName, LPWSTR Params)
{
    WCHAR Quotation[] = {L'\"', 0};

    CmdLine[0] = L'"';
    strcpyW(CmdLine + 1, AppName);
    strcatW(CmdLine, Quotation);
    if (Params)
        strcatW(CmdLine, Params);
}


/*
 * GetFileName
 *
 * Helper for CreateProcessW: retrieve the file name to load from the
 * app name and command line. Store the file name in buffer, and
 * return a possibly modified command line.
 *
 * FIXME: use CurDir to search for the executable file in the new working directory
 *
 * modified from ReactOS
 */
static LPWSTR GetFileName(LPCWSTR CurDir, LPCWSTR AppName, LPWSTR CmdLine, LPWSTR Buffer,
        unsigned BufLen, LPWSTR BuiltinCmdLine, LPWSTR BuiltinAppName, unsigned BuiltinAppNameLen)
{
    WCHAR *Name, *Pos, *Ret = NULL;
    WCHAR Quotation[] = {L'\"', 0};
    BOOL  UseNative = TRUE;
    WCHAR *p;

	LOG(LOG_FILE, 0, 0, "\n");
    /* if we have an app name, everything is easy */
    if (AppName) {
        if (!SearchApplication((LPWSTR)AppName, Buffer, BufLen, BuiltinAppName, 
                    BuiltinAppNameLen, &UseNative)) {
            SetLastError(ERROR_FILE_NOT_FOUND);
            return NULL;
        }

        /* use the unmodified app name as file name */
        if (!UseNative)
            lstrcpynW(Buffer, AppName, BufLen );
        Ret = CmdLine;
        if (!Ret || !CmdLine[0]) {
            /* no command-line, create one */
            Ret = RtlAllocateHeap(GetProcessHeap(), 0,
                    (strlenW(Buffer) + 3) * sizeof(WCHAR));
            if (Ret) {
                Ret[0] = L'"';
                strcpyW(Ret + 1, Buffer);
                strcatW(Ret, Quotation);
            }
        }
        if (!UseNative)
            MakeBuiltinCmdLine(BuiltinCmdLine, BuiltinAppName, NULL);
        return Ret;
    }

    if (!CmdLine) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    /* first check for a quoted file name */
    if (L'"' == CmdLine[0] && (p = strchrW(CmdLine + 1, L'"'))) {
        int Len = p - CmdLine - 1;

        /* extract the quoted portion as file name */
        Name = RtlAllocateHeap(GetProcessHeap(), 0, max(((Len + 1) * sizeof(WCHAR)), strlenW(p) * sizeof(WCHAR)));
        if (!Name) {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return NULL;
        }
        memcpy(Name, CmdLine + 1, Len * sizeof(WCHAR));
        Name[Len] = L'\0';

        if (!SearchApplication(Name, Buffer, BufLen, BuiltinAppName, BuiltinAppNameLen, &UseNative)) {
            RtlFreeHeap(GetProcessHeap(), 0, Name);
            SetLastError(ERROR_FILE_NOT_FOUND);
            return NULL;
        }

        if (!UseNative)
            memcpy(Buffer, Name, Len * sizeof(WCHAR) + sizeof(WCHAR));
        strcpyW(Name, ++p);	/* backup param */
        Ret = CmdLine;
        Ret[0] = L'"';
        strcpyW(Ret + 1, Buffer);
        strcatW(Ret, Quotation);
        strcatW(Ret, Name);

        if (!UseNative)
            MakeBuiltinCmdLine(BuiltinCmdLine, BuiltinAppName, (LPWSTR)++p);

        RtlFreeHeap(GetProcessHeap(), 0, Name);
        return Ret;
    }

    /* now try the command-line word by word */
    Name = RtlAllocateHeap(GetProcessHeap(), 0, (strlenW(CmdLine) + 1) * sizeof(WCHAR));
    if (!Name) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    Pos = Name;
    p = CmdLine;

    while (*p) {
        do
            *Pos++ = *p++;
        while (*p && L' ' != *p);
        *Pos = 0;

        if (!SearchApplication(Name, Buffer, BufLen, BuiltinAppName, BuiltinAppNameLen, &UseNative))
            continue;

        if (!UseNative)
            strcpyW(Buffer, Name);
        Ret = CmdLine;

        if (!UseNative)
            MakeBuiltinCmdLine(BuiltinCmdLine, BuiltinAppName, (LPWSTR)p);
        break;
    }

    if (!Ret) {
        RtlFreeHeap(GetProcessHeap(), 0, Name); /* no change necessary */
        return Ret;
    }

    /* now build a new command-line with quotes */
    Ret = RtlAllocateHeap(GetProcessHeap(), 0, (strlenW(CmdLine) + 3 + strlenW(Buffer)) * sizeof(WCHAR));
    if (!Ret) {
        RtlFreeHeap(GetProcessHeap(), 0, Name); /* no change necessary */
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    Ret[0] = L'"';
    strcpyW(Ret + 1, Buffer);
    strcatW(Ret, Quotation);
    strcatW(Ret, p);

    RtlFreeHeap(GetProcessHeap(), 0, Name);
    return Ret;
}

/* modified from ReactOS */
HANDLE KlMapFile(LPCWSTR lpApplicationName)
{
    HANDLE hFile;
    IO_STATUS_BLOCK IoStatusBlock;
    UNICODE_STRING ApplicationNameString;
    OBJECT_ATTRIBUTES ObjectAttributes;
    PSECURITY_DESCRIPTOR SecurityDescriptor = NULL;
    NTSTATUS Status;
    HANDLE hSection;

    hFile = NULL;

    if (!RtlDosPathNameToNtPathName_U(lpApplicationName, &ApplicationNameString, NULL, NULL)) {
        SetLastError(ERROR_PATH_NOT_FOUND);
        return NULL;
    }
    InitializeObjectAttributes(&ObjectAttributes,
            &ApplicationNameString,
            OBJ_CASE_INSENSITIVE,
            NULL,
            SecurityDescriptor);

    /* Try to open the executable */

    Status = UkOpenFile(&hFile,
            SYNCHRONIZE|FILE_EXECUTE|FILE_READ_DATA,
            &ObjectAttributes,
            &IoStatusBlock,
            FILE_SHARE_DELETE|FILE_SHARE_READ,
            FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE);

    RtlFreeUnicodeString (&ApplicationNameString);

    if (Status) {
        SetLastError(Status);
        return NULL;
    }
    Status = UkCreateSection(&hSection,
            SECTION_ALL_ACCESS,
            NULL,
            NULL,
            PAGE_EXECUTE,
            SEC_IMAGE,
            hFile);
    NtClose(hFile);

    if (Status) {
        SetLastError(Status);
        return NULL;
    }

    return hSection;
}

/* modified from ReactOS */
HANDLE KlCreateFirstThread(HANDLE ProcessHandle,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        PSECTION_IMAGE_INFORMATION Sii,
        LPTHREAD_START_ROUTINE lpStartAddress,
        DWORD dwCreationFlags,
        LPDWORD lpThreadId)
{
    OBJECT_ATTRIBUTES oaThreadAttribs;
    CLIENT_ID cidClientId;
    PVOID pTrueStartAddress = NULL;
    NTSTATUS nErrCode;
    HANDLE hThread;

    /* convert the thread attributes */
    RtlRosR32AttribsToNativeAttribs(&oaThreadAttribs, lpThreadAttributes);

    /* native image */
    if(Sii->ImageSubsystem != IMAGE_SUBSYSTEM_NATIVE)
        pTrueStartAddress = NULL;
    /* Win32 image */
    /* FIXME: nothing to do with win32 image */
    else
        ERR("Nothing to do with Win32 image!\n");

    /* create the first thread */
    nErrCode = RtlRosCreateUserThread(ProcessHandle,
            &oaThreadAttribs,
            dwCreationFlags & CREATE_SUSPENDED,
            0,
            &(Sii->StackReserved),
            &(Sii->StackCommit),
            pTrueStartAddress,
            &hThread,
            &cidClientId,
            (ULONG_PTR)lpStartAddress,
            (ULONG_PTR)PEB_BASE);
    /* failure */
    if(nErrCode) {
        SetLastError(nErrCode);
        return NULL;
    }

    /* success */
    if(lpThreadId) 
        *lpThreadId = (DWORD)cidClientId.UniqueThread;

    return hThread;
}

static NTSTATUS KlInitPeb(HANDLE ProcessHandle,
        PRTL_USER_PROCESS_PARAMETERS Ppb,
        PVOID * ImageBaseAddress,
        ULONG ImageSubSystem)
{
    PWCHAR ptr;
    PVOID EnvPtr = NULL;
    PVOID ParentEnv = NULL;
    PVOID PpbBase = NULL;
    ULONG offset = 0;
    ULONG_PTR EnvSize = 0, PpbSize = 0;
    ULONG_PTR EnvSize1 = 0;
    ULONG_PTR ByteWritten = 0;
    ULONG peb_base = 0x7FFDF000;
    NTSTATUS Status;

    if (Ppb->Environment) {
        ptr = Ppb->Environment;
        while (*ptr)
            while (*ptr++);
        ptr++;
        EnvSize = ((ULONG)ptr - (ULONG)Ppb->Environment);
        ParentEnv = Ppb->Environment;
    }

    if (EnvSize != 0) {
        EnvSize1 = EnvSize;
        Status = NtAllocateVirtualMemory(ProcessHandle,
                &EnvPtr,
                0,
                &EnvSize1,
                MEM_COMMIT,
                PAGE_READWRITE);
        if (Status) {
            return(Status);
        }

        NtWriteVirtualMemory(ProcessHandle,
                EnvPtr,
                ParentEnv,
                EnvSize,
                &ByteWritten);
    }

    /* create ppb in child space*/
    PpbSize = Ppb->AllocationSize;

    Status = NtAllocateVirtualMemory(ProcessHandle,
            &PpbBase,
            0,
            &PpbSize,
            MEM_COMMIT,
            PAGE_READWRITE);
    if (Status)
        return Status;

    NtWriteVirtualMemory(ProcessHandle,
            PpbBase,
            Ppb,
            PpbSize,
            &ByteWritten);

    /* write environment */
    offset = FIELD_OFFSET(RTL_USER_PROCESS_PARAMETERS, Environment);
    NtWriteVirtualMemory(ProcessHandle,
            (PVOID)((ULONG)PpbBase + offset),
            &EnvPtr,
            sizeof(EnvPtr),
            &ByteWritten);

    /* write point to ppb */
    offset = FIELD_OFFSET(PEB, ProcessParameters);
    NtWriteVirtualMemory(ProcessHandle,
            (PVOID)(peb_base + offset),
            &PpbBase,
            sizeof(PpbBase),
            &ByteWritten);

    /* FIXME: write image subsystem ? */
    offset = FIELD_OFFSET(PEB, ImageSubSystem);
    NtWriteVirtualMemory(ProcessHandle,
            (PVOID)(peb_base + offset),
            &ImageSubSystem,
            sizeof(ImageSubSystem),
            &ByteWritten);

    /* read image base address */
    offset = FIELD_OFFSET(PEB, ImageBaseAddress);
    NtReadVirtualMemory(ProcessHandle,
            (PVOID)(peb_base + offset),
            ImageBaseAddress,
            sizeof(PVOID),
            &ByteWritten);

    return STATUS_SUCCESS;
}

BOOL RunBuiltinApp(LPWSTR lpApplicationName,
        LPWSTR lpCommandLine,
        LPCWSTR NativeAppName,
        LPWSTR NativeCmdLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL bInheritHandles,
        DWORD dwCreationFlags,
        LPVOID lpEnvironment,
        LPCWSTR lpCurrentDirectory,
        LPSTARTUPINFOW lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation)
{
    WCHAR *TidyCmdLine = lpCommandLine;
    pid_t pid;
    int pipefd[2];
    NTSTATUS Status;
    CLIENT_ID cid;
    OBJECT_ATTRIBUTES attr;

    LOG(LOG_FILE, 0, 0, " %s %s %s %s\n", debugstr_w(lpApplicationName), debugstr_w(lpCommandLine),
		debugstr_w(NativeAppName), debugstr_w(NativeCmdLine));

    if (pipe(pipefd) == -1) {
        return FALSE;
    }

    if (!(pid = fork())) {
        char pipe_env[64];
        char app_env[MAX_PATH + 64];
        char cmdline_env[MAX_PATH * 4 + 64];
        char **argv = build_argv(TidyCmdLine, 1);
        char stdin_env[24];
        char stdout_env[24];
        char stderr_env[24];

        close(pipefd[0]);
        sprintf(pipe_env, "PIDTIDPIPE=%u", pipefd[1]);
        strcpy(app_env, "NATIVEAPP=");
        WideCharToMultiByte(CP_UNIXCP, 0, NativeAppName, strlenW(NativeAppName) + 1,
                app_env + strlen(app_env), sizeof(app_env) - strlen(app_env), 0, NULL);
        strcpy(cmdline_env, "NATIVECMDLINE=");
        WideCharToMultiByte(CP_UNIXCP, 0, NativeCmdLine, strlenW(NativeCmdLine) + 1,
                cmdline_env + strlen(cmdline_env), MAX_PATH * 4, 0, NULL);

        sprintf(stdin_env, "STDINPUT=%08x", lpStartupInfo->hStdInput);
        sprintf(stdout_env, "STDOUTPUT=%08x", lpStartupInfo->hStdOutput);
        sprintf(stderr_env, "STDERROR=%08x", lpStartupInfo->hStdError);

        putenv(pipe_env);
        putenv(app_env);
        putenv(cmdline_env);

        putenv(stdin_env);
        putenv(stdout_env);
        putenv(stderr_env);

        if (argv)
            wine_exec_wine_binary(0, argv, getenv("WINELOADER"));
        _exit(1);
    }

    close(pipefd[1]);
    if (pid == -1) {
        close(pipefd[0]);
        return FALSE;
    }

	if (!read(pipefd[0], &lpProcessInformation->dwProcessId, sizeof(lpProcessInformation->dwProcessId)))
		return FALSE;
	read(pipefd[0], &lpProcessInformation->dwThreadId, sizeof(lpProcessInformation->dwThreadId));

    close(pipefd[0]);

    cid.UniqueProcess = (HANDLE)lpProcessInformation->dwProcessId;
    cid.UniqueThread = (HANDLE)lpProcessInformation->dwThreadId;
    memset(&attr, 0, sizeof(attr));
    attr.Length = sizeof(attr);
    Status = NtOpenProcess(&lpProcessInformation->hProcess, PROCESS_ALL_ACCESS, &attr, &cid);
    if(Status)
        return FALSE;
    Status = NtOpenThread(&lpProcessInformation->hThread, THREAD_ALL_ACCESS, &attr, &cid);
    if(Status) {
        NtClose(lpProcessInformation->hProcess);
        return FALSE;
    }

    LOG(LOG_FILE, 0, 0, "RunBuiltinApp() done\n");
    return TRUE;
}

void
GetFullCmdLine(LPWSTR lpCommandLine)
{
    WCHAR *cmdline = lpCommandLine;
    /* FIXME */
    WCHAR short_cmd[1024], long_cmd[1024], remain[1024];
    WCHAR *temp;
    int i;

    if (*lpCommandLine == L'"') {
        strcpyW(short_cmd, lpCommandLine + 1);
        temp = strchrW(short_cmd, L'"');
        if (temp) {
            strcpyW(remain, temp);
            *temp = L'\0';
        }

        /* FIXME */
        if (!GetLongPathNameW(short_cmd, long_cmd, 1024)) {
			SetLastError(0);
            lstrcpynW(long_cmd, short_cmd, 1024);
        }
        *cmdline++ = L'"';
    } else {
        strcpyW(short_cmd, lpCommandLine);
        temp = strchrW(short_cmd, L' ');
        if (temp) {
            strcpyW(remain, temp);
            *temp = L'\0';
        }
        else{
            return;
        }

        /* FIXME */
        if (!GetLongPathNameW(short_cmd, long_cmd, 1024)) {
			SetLastError(0);
            lstrcpynW(long_cmd, short_cmd, 1024);
        }
    }

    for (i = 0; ;i++) {
        *cmdline++ = long_cmd[i];
        if (long_cmd[i + 1] == L'\0')
            break;
    }
    *cmdline = L'\0';

    strcatW(lpCommandLine, remain);
}

BOOL WINAPI
CreateProcessW(LPCWSTR lpApplicationName,
        LPWSTR lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL bInheritHandles,
        DWORD dwCreationFlags,
        LPVOID lpEnvironment,
        LPCWSTR lpCurrentDirectory,
        LPSTARTUPINFOW lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation)
{
    HANDLE hProcess, hThread;
    ULONG ProcAttributes = 0;
    PVOID ProcSecurity = NULL;
    PVOID ImageBaseAddress;

    WCHAR* TidyCmdLine;
    WCHAR Name[MAX_PATH];
    WCHAR* TempCurrentDirectory;
    WCHAR TempApplicationName[256];
    WCHAR* tmp;
    WCHAR dotExe[] = {'.','e','x','e', 0};
    WCHAR BuiltinCmdLine[MAX_PATH * 4] = {0}, BuiltinAppName[MAX_PATH] = {0};
    WCHAR FullCmdLine[256] = {L'\0'};

    UNICODE_STRING ImagePathName_U;
    UNICODE_STRING CmdLine_U;
    UNICODE_STRING CurrentDirectory_U;
    UNICODE_STRING RuntimeInfo_U;

    OBJECT_ATTRIBUTES ProcObjectAttributes;
    PROCESS_PRIORITY_CLASS PriorityClass;

    PRTL_USER_PROCESS_PARAMETERS ppb;
    PROCESS_BASIC_INFORMATION ProcessBasicInfo;

    long ret;
    pid_t pid;
    char *filename=NULL;

    LOG(LOG_FILE, 0, 0, "CreateProcessW(%s, %s,\n", debugstr_w(lpApplicationName), debugstr_w(lpCommandLine));
    TRACE("CreateProcessW(1:%s,2:%s,3:%p,4:%p,5:%d,6:%d,7:%p,8:%p,9:%p,10:%p)\n",
	    debugstr_w(lpApplicationName),
	    debugstr_w(lpCommandLine),
	    lpProcessAttributes,
	    lpThreadAttributes,
	    bInheritHandles,
	    dwCreationFlags,
	    lpEnvironment,
	    lpCurrentDirectory,
	    lpStartupInfo,
	    lpProcessInformation);

    /* get long path name of commandline */
    if (lpCommandLine) {
	strcpyW(FullCmdLine, lpCommandLine);
	GetFullCmdLine(FullCmdLine);
    }

    /* get file name */
    TidyCmdLine = GetFileName(lpCurrentDirectory, lpApplicationName,
	    FullCmdLine, Name, sizeof(Name)/sizeof(WCHAR),
	    BuiltinCmdLine, BuiltinAppName, sizeof(BuiltinAppName) / sizeof(WCHAR));
    if (!TidyCmdLine)
	return FALSE;

    /* deal with file name */
    if (lpApplicationName && lpApplicationName[0])
	strcpyW(TempApplicationName, lpApplicationName);
    else {
	if (L'"' == TidyCmdLine[0]) {
	    /* command line: "*.exe" */
	    strcpyW(TempApplicationName, TidyCmdLine + 1);
	    tmp = strchrW(TempApplicationName, L'"');
	    if (tmp)
		*tmp = L'\0';
	} else {
	    /* command line: *.exe */
	    strcpyW(TempApplicationName, TidyCmdLine);
	    tmp = strchrW(TempApplicationName, L' ');
	    /* the command line with '"' and followed by ' ' is invalid*/
	    if (tmp) *tmp = L'\0';
	    else if ((tmp = strchrW(TempApplicationName, L'"'))) *tmp = L'\0';
	}
    }
    tmp = max(strchrW(TempApplicationName, L'\\'), strchrW(TempApplicationName, L'/'));
    if (!tmp)
	tmp = TempApplicationName;
    if (!strchrW(TempApplicationName, L'.'))
	strcatW(TempApplicationName, dotExe);

    /*TODO: search path*/

    RtlInitUnicodeString(&ImagePathName_U, TempApplicationName);
    RtlInitUnicodeString(&CmdLine_U, TidyCmdLine);

    if (lpCurrentDirectory != NULL)
	RtlInitUnicodeString(&CurrentDirectory_U,lpCurrentDirectory);
    else {
	if(!(TempCurrentDirectory = RtlAllocateHeap(GetProcessHeap(), 0, 256))) {
	    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
	    return FALSE;
	}
	GetCurrentDirectoryW(256, TempCurrentDirectory);
	RtlInitUnicodeString(&CurrentDirectory_U, TempCurrentDirectory);
	RtlFreeHeap(GetProcessHeap(), 0, TempCurrentDirectory);
    }

    /* FIXME: .cmd and .bat will not be processed */

    filename = wine_get_unix_file_name(BuiltinAppName);
    if (!filename)
    {
	filename = wine_get_unix_file_name(TempApplicationName);
	if(!filename)	return FALSE;
    }

    LOG(LOG_FILE,0,0,"binary: %s\n",filename);

    pid=fork();

    if (pid < 0)
    {
	fprintf(stderr,"%s:fork error \n",__FUNCTION__);
	return FALSE;
    }

    if (pid == 0)
    {
	char app_env[MAX_PATH + 64];
	char cmdline_env[MAX_PATH * 4 + 64];
	char **argv = build_argv(TidyCmdLine, 0);
	argv[0] = filename;

	strcpy(app_env, "NATIVEAPP=");
	WideCharToMultiByte(CP_UNIXCP, 0, TempApplicationName, strlenW(TempApplicationName) + 1,
		app_env + strlen(app_env), sizeof(app_env) - strlen(app_env), 0, NULL);

	strcpy(cmdline_env, "NATIVECMDLINE=");
	WideCharToMultiByte(CP_UNIXCP, 0, TidyCmdLine, strlenW(TidyCmdLine) + 1,
		cmdline_env + strlen(cmdline_env), MAX_PATH * 4, 0, NULL);

	putenv(app_env);
	putenv(cmdline_env);

        execv(filename,argv);

	fprintf(stderr,"%s:execve error\n",__FUNCTION__);

	_exit(1);
    }

    /* initialize object */
    if (lpProcessAttributes)
    {
	if(lpProcessAttributes->bInheritHandle)
	    ProcAttributes |= OBJ_INHERIT;
	ProcSecurity = lpProcessAttributes->lpSecurityDescriptor;
    }
    InitializeObjectAttributes(&ProcObjectAttributes, NULL, ProcAttributes, NULL, ProcSecurity);

    /* initialize priority */
    PriorityClass.Foreground = FALSE;

    if(dwCreationFlags & IDLE_PRIORITY_CLASS)
	PriorityClass.PriorityClass = PROCESS_PRIOCLASS_IDLE;
    else if(dwCreationFlags & BELOW_NORMAL_PRIORITY_CLASS)
	PriorityClass.PriorityClass = PROCESS_PRIOCLASS_BELOW_NORMAL;
    else if(dwCreationFlags & NORMAL_PRIORITY_CLASS)
	PriorityClass.PriorityClass = PROCESS_PRIOCLASS_NORMAL;
    else if(dwCreationFlags & ABOVE_NORMAL_PRIORITY_CLASS)
	PriorityClass.PriorityClass = PROCESS_PRIOCLASS_ABOVE_NORMAL;
    else if(dwCreationFlags & HIGH_PRIORITY_CLASS)
	PriorityClass.PriorityClass = PROCESS_PRIOCLASS_HIGH;
    else if(dwCreationFlags & REALTIME_PRIORITY_CLASS)
	/* FIXME - This is a privileged operation. If we don't have the privilege we should
	 *        rather use PROCESS_PRIOCLASS_HIGH. */
	PriorityClass.PriorityClass = PROCESS_PRIOCLASS_REALTIME;
    else
	/* FIXME - what to do in this case? */
	PriorityClass.PriorityClass = PROCESS_PRIOCLASS_NORMAL;

    LOG(LOG_FILE,0,0,"parent_pid:%d[0x%x] child_pid:%d[0x%x]\n",getpid(),getpid(),pid,pid);

    SERVER_START_REQ( new_process )
    {
	req->child_pid    	= pid;
	req->operation	 	= 0;     //first time
	req->inherit_all    = bInheritHandles;
	req->create_flags   = dwCreationFlags;
	req->process_access = PROCESS_ALL_ACCESS;
	req->process_attr   = bInheritHandles? OBJ_INHERIT : 0;
	req->thread_access  = THREAD_ALL_ACCESS;
	req->thread_attr    = bInheritHandles? OBJ_INHERIT : 0;
	req->hstdin         = lpStartupInfo->hStdInput;
	req->hstdout        = lpStartupInfo->hStdOutput;
	req->hstderr        = lpStartupInfo->hStdError;

	if ((dwCreationFlags & (CREATE_NEW_CONSOLE | DETACHED_PROCESS)) != 0)
	{
	    /* this is temporary (for console handles). We have no way to control that the handle is invalid in child process otherwise */
	    if (is_console_handle(req->hstdin))  req->hstdin  = INVALID_HANDLE_VALUE;
	    if (is_console_handle(req->hstdout)) req->hstdout = INVALID_HANDLE_VALUE;
	    if (is_console_handle(req->hstderr)) req->hstderr = INVALID_HANDLE_VALUE;
	}
	else
	{
	    if (is_console_handle(req->hstdin))  req->hstdin  = console_handle_unmap(req->hstdin);
	    if (is_console_handle(req->hstdout)) req->hstdout = console_handle_unmap(req->hstdout);
	    if (is_console_handle(req->hstderr)) req->hstderr = console_handle_unmap(req->hstderr);
	}

	//wine_server_add_data( req, params, params->Size );
	//wine_server_add_data( req, params->Environment, (env_end-params->Environment)*sizeof(WCHAR) );
	if ((ret = !wine_server_call_err( req )))
	{
	    lpProcessInformation->dwProcessId = (DWORD)reply->pid;
	    lpProcessInformation->dwThreadId  = (DWORD)reply->tid;
	    lpProcessInformation->hProcess    = reply->phandle;
	    lpProcessInformation->hThread     = reply->thandle;

	    hProcess    = reply->phandle;
	    hThread     = reply->thandle;
	}
	else
	{
	    fprintf(stderr,"%s:new_process 1 err\n",__FUNCTION__);
	    return FALSE;
	}
	//process_info = reply->info;
    }
    SERVER_END_REQ;

    LOG(LOG_FILE,0,0,"new_process 1 done. hProcess %p hThread %p\n",hProcess,hThread);

    if(hProcess == NULL || hThread==NULL)
	return FALSE;

    NtSetInformationProcess(hProcess,
	    ProcessPriorityClass,
	    &PriorityClass,
	    sizeof(PROCESS_PRIORITY_CLASS));

    /* TODO: send set information message */

    /* creat ppb */
    RtlInitUnicodeString(&RuntimeInfo_U, NULL);
    if (lpStartupInfo) {
	if (lpStartupInfo->lpReserved2) {
	    /* FIXME:
	     *    ROUND_UP(xxx,2) + 2 is a dirty hack. RtlCreateProcessParameters
	     *    assumes that the runtimeinfo is a unicode string and
	     *    use RtlCopyUnicodeString for duplication.
	     *    If is possible that this function overwrite the last information
	     *    in runtimeinfo with the null terminator for the unicode string.
	     */
	    RuntimeInfo_U.Length = (lpStartupInfo->cbReserved2 + 1) & ~1;
	    RuntimeInfo_U.MaximumLength = (lpStartupInfo->cbReserved2 + 1) & ~1;
	    RuntimeInfo_U.Buffer = RtlAllocateHeap(GetProcessHeap(), 0,
		    RuntimeInfo_U.Length);
	    memcpy(RuntimeInfo_U.Buffer, lpStartupInfo->lpReserved2,
		    lpStartupInfo->cbReserved2);
	}
    }

    if (!(ppb = create_user_params( TempApplicationName, TidyCmdLine, lpCurrentDirectory,
		    lpEnvironment, dwCreationFlags, lpStartupInfo)))
	return FALSE;

    if (lpStartupInfo && lpStartupInfo->lpReserved2)
	RtlFreeHeap(GetProcessHeap(), 0, RuntimeInfo_U.Buffer);

    /* copy ppb->CurrentDirectoryHandle */
    if (ppb->CurrentDirectory.Handle)
    {
	NtDuplicateObject(NtCurrentProcess(),
		ppb->CurrentDirectory.Handle,
		hProcess,
		&ppb->CurrentDirectory.Handle,
		0,
		TRUE,
		DUPLICATE_SAME_ACCESS);
    }

    /* initialize data to send to wine server */
    NtQueryInformationProcess(hProcess,
	    ProcessBasicInformation,
	    &ProcessBasicInfo,
	    sizeof(ProcessBasicInfo),
	    NULL);

    lpProcessInformation->dwProcessId = (DWORD) ProcessBasicInfo.UniqueProcessId;

#if 0   //CREATEPROCESSW
    //We don't know this is a GUI or CUI app, execve() can get
    //this info from the PE header, and so execve() should decide
    //and set the flags.
    if (Sii.ImageSubsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI) {
	/* do not create a console for GUI applications */
	dwCreationFlags &= ~CREATE_NEW_CONSOLE;
	dwCreationFlags |= DETACHED_PROCESS;
    } else if (Sii.ImageSubsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI) {
	if (!ppb->ConsoleHandle) /* FIXME: see dwCreationFlags */
	    dwCreationFlags |= CREATE_NEW_CONSOLE;
    }
#endif

    /* copy ppb */
    if (lpStartupInfo) {
	ppb->dwFlags = lpStartupInfo->dwFlags;

	if (ppb->dwFlags & STARTF_USESHOWWINDOW)
	    ppb->wShowWindow = lpStartupInfo->wShowWindow;
	else
	    ppb->wShowWindow = SW_SHOWDEFAULT;

	ppb->dwX = lpStartupInfo->dwX;
	ppb->dwY = lpStartupInfo->dwY;
	ppb->dwXSize = lpStartupInfo->dwXSize;
	ppb->dwYSize = lpStartupInfo->dwYSize;
	ppb->dwFillAttribute = lpStartupInfo->dwFillAttribute;
    } else
	ppb->Flags = 0;

    KlInitPeb(hProcess, ppb, &ImageBaseAddress, 0);

    RtlDestroyProcessParameters(ppb);


    SERVER_START_REQ( new_process )
    {
	req->child_pid    	= pid;
	req->operation	 	= 1;     //second time

	ret = wine_server_call_err( req );
	if(ret)
	{
	    fprintf(stderr,"%s:new_process 2 err\n",__FUNCTION__);
	    return FALSE;
	}
    }
    SERVER_END_REQ;

    return TRUE;
}
/***********************************************************************
 *           wait_input_idle
 *
 * Wrapper to call WaitForInputIdle USER function
 */
typedef DWORD (WINAPI *WaitForInputIdle_ptr)( HANDLE hProcess, DWORD dwTimeOut );

static DWORD wait_input_idle( HANDLE process, DWORD timeout )
{
    HMODULE mod = GetModuleHandleA( "user32.dll" );
    if (mod)
    {
        WaitForInputIdle_ptr ptr = (WaitForInputIdle_ptr)GetProcAddress( mod, "WaitForInputIdle" );
        if (ptr) return ptr( process, timeout );
    }
    return 0;
}


/***********************************************************************
 *           WinExec   (KERNEL32.@)
 */
UINT WINAPI WinExec( LPCSTR lpCmdLine, UINT nCmdShow )
{
    PROCESS_INFORMATION info;
    STARTUPINFOA startup;
    char *cmdline;
    UINT ret;

    memset( &startup, 0, sizeof(startup) );
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESHOWWINDOW;
    startup.wShowWindow = nCmdShow;

    /* cmdline needs to be writable for CreateProcess */
    if (!(cmdline = HeapAlloc( GetProcessHeap(), 0, strlen(lpCmdLine)+1 ))) return 0;
    strcpy( cmdline, lpCmdLine );

    if (CreateProcessA( NULL, cmdline, NULL, NULL, FALSE,
                        0, NULL, NULL, &startup, &info ))
    {
        /* Give 30 seconds to the app to come up */
        if (wait_input_idle( info.hProcess, 30000 ) == WAIT_FAILED)
            WARN("WaitForInputIdle failed: Error %d\n", GetLastError() );
        ret = 33;
        /* Close off the handles */
        CloseHandle( info.hThread );
        CloseHandle( info.hProcess );
    }
    else if ((ret = GetLastError()) >= 32)
    {
        FIXME("Strange error set by CreateProcess: %d\n", ret );
        ret = 11;
    }
    HeapFree( GetProcessHeap(), 0, cmdline );
    return ret;
}


/**********************************************************************
 *	    LoadModule    (KERNEL32.@)
 */
HINSTANCE WINAPI LoadModule( LPCSTR name, LPVOID paramBlock )
{
    LOADPARMS32 *params = paramBlock;
    PROCESS_INFORMATION info;
    STARTUPINFOA startup;
    HINSTANCE hInstance;
    LPSTR cmdline, p;
    char filename[MAX_PATH];
    BYTE len;

    if (!name) return (HINSTANCE)ERROR_FILE_NOT_FOUND;

    if (!SearchPathA( NULL, name, ".exe", sizeof(filename), filename, NULL ) &&
        !SearchPathA( NULL, name, NULL, sizeof(filename), filename, NULL ))
        return ULongToHandle(GetLastError());

    len = (BYTE)params->lpCmdLine[0];
    if (!(cmdline = HeapAlloc( GetProcessHeap(), 0, strlen(filename) + len + 2 )))
        return (HINSTANCE)ERROR_NOT_ENOUGH_MEMORY;

    strcpy( cmdline, filename );
    p = cmdline + strlen(cmdline);
    *p++ = ' ';
    memcpy( p, params->lpCmdLine + 1, len );
    p[len] = 0;

    memset( &startup, 0, sizeof(startup) );
    startup.cb = sizeof(startup);
    if (params->lpCmdShow)
    {
        startup.dwFlags = STARTF_USESHOWWINDOW;
        startup.wShowWindow = ((WORD *)params->lpCmdShow)[1];
    }

    if (CreateProcessA( filename, cmdline, NULL, NULL, FALSE, 0,
                        params->lpEnvAddress, NULL, &startup, &info ))
    {
        /* Give 30 seconds to the app to come up */
        if (wait_input_idle( info.hProcess, 30000 ) == WAIT_FAILED)
            WARN("WaitForInputIdle failed: Error %d\n", GetLastError() );
        hInstance = (HINSTANCE)33;
        /* Close off the handles */
        CloseHandle( info.hThread );
        CloseHandle( info.hProcess );
    }
    else if ((hInstance = ULongToHandle(GetLastError())) >= (HINSTANCE)32)
    {
        FIXME("Strange error set by CreateProcess: %p\n", hInstance );
        hInstance = (HINSTANCE)11;
    }

    HeapFree( GetProcessHeap(), 0, cmdline );
    return hInstance;
}


/******************************************************************************
 *           TerminateProcess   (KERNEL32.@)
 *
 * Terminates a process.
 *
 * PARAMS
 *  handle    [I] Process to terminate.
 *  exit_code [I] Exit code.
 *
 * RETURNS
 *  Success: TRUE.
 *  Failure: FALSE, check GetLastError().
 */
BOOL WINAPI TerminateProcess( HANDLE handle, DWORD exit_code )
{
    NTSTATUS status = NtTerminateProcess( handle, exit_code );
    if (status) SetLastError( RtlNtStatusToDosError(status) );
    return !status;
}


/***********************************************************************
 *           ExitProcess   (KERNEL32.@)
 *
 * Exits the current process.
 *
 * PARAMS
 *  status [I] Status code to exit with.
 *
 * RETURNS
 *  Nothing.
 */
void WINAPI ExitProcess( DWORD status )
{
    LdrShutdownProcess();
    NtTerminateProcess(GetCurrentProcess(), status);
    exit(status);
}


/***********************************************************************
 * GetExitCodeProcess           [KERNEL32.@]
 *
 * Gets termination status of specified process.
 *
 * PARAMS
 *   hProcess   [in]  Handle to the process.
 *   lpExitCode [out] Address to receive termination status.
 *
 * RETURNS
 *   Success: TRUE
 *   Failure: FALSE
 */
BOOL WINAPI GetExitCodeProcess( HANDLE hProcess, LPDWORD lpExitCode )
{
    NTSTATUS status;
    PROCESS_BASIC_INFORMATION pbi;

    status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi,
                                       sizeof(pbi), NULL);
    if (status == STATUS_SUCCESS)
    {
        if (lpExitCode) *lpExitCode = pbi.ExitStatus;
        return TRUE;
    }
    SetLastError( RtlNtStatusToDosError(status) );
    return FALSE;
}


/***********************************************************************
 *           SetErrorMode   (KERNEL32.@)
 */
UINT WINAPI SetErrorMode( UINT mode )
{
    UINT old = process_error_mode;
    process_error_mode = mode;
    return old;
}


/**********************************************************************
 * TlsAlloc             [KERNEL32.@]
 *
 * Allocates a thread local storage index.
 *
 * RETURNS
 *    Success: TLS index.
 *    Failure: 0xFFFFFFFF
 */
DWORD WINAPI TlsAlloc( void )
{
    DWORD index;
    PEB * const peb = NtCurrentTeb()->Peb;

    RtlAcquirePebLock();
    index = RtlFindClearBitsAndSet( peb->TlsBitmap, 1, 0 );
    if (index != ~0U) NtCurrentTeb()->TlsSlots[index] = 0; /* clear the value */
    else
    {
        index = RtlFindClearBitsAndSet( peb->TlsExpansionBitmap, 1, 0 );
        if (index != ~0U)
        {
            if (!NtCurrentTeb()->TlsExpansionSlots &&
                !(NtCurrentTeb()->TlsExpansionSlots = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY,
                                         8 * sizeof(peb->TlsExpansionBitmapBits) * sizeof(void*) )))
            {
                RtlClearBits( peb->TlsExpansionBitmap, index, 1 );
                index = ~0U;
                SetLastError( ERROR_NOT_ENOUGH_MEMORY );
            }
            else
            {
                NtCurrentTeb()->TlsExpansionSlots[index] = 0; /* clear the value */
                index += TLS_MINIMUM_AVAILABLE;
            }
        }
        else SetLastError( ERROR_NO_MORE_ITEMS );
    }
    RtlReleasePebLock();
    return index;
}


/**********************************************************************
 * TlsFree              [KERNEL32.@]
 *
 * Releases a thread local storage index, making it available for reuse.
 *
 * PARAMS
 *    index [in] TLS index to free.
 *
 * RETURNS
 *    Success: TRUE
 *    Failure: FALSE
 */
BOOL WINAPI TlsFree( DWORD index )
{
    BOOL ret;

    RtlAcquirePebLock();
    if (index >= TLS_MINIMUM_AVAILABLE)
    {
        ret = RtlAreBitsSet( NtCurrentTeb()->Peb->TlsExpansionBitmap, index - TLS_MINIMUM_AVAILABLE, 1 );
        if (ret) RtlClearBits( NtCurrentTeb()->Peb->TlsExpansionBitmap, index - TLS_MINIMUM_AVAILABLE, 1 );
    }
    else
    {
        ret = RtlAreBitsSet( NtCurrentTeb()->Peb->TlsBitmap, index, 1 );
        if (ret) RtlClearBits( NtCurrentTeb()->Peb->TlsBitmap, index, 1 );
    }
    if (ret) NtSetInformationThread( GetCurrentThread(), ThreadZeroTlsCell, &index, sizeof(index) );
    else SetLastError( ERROR_INVALID_PARAMETER );
    RtlReleasePebLock();
    return TRUE;
}


/**********************************************************************
 * TlsGetValue          [KERNEL32.@]
 *
 * Gets value in a thread's TLS slot.
 *
 * PARAMS
 *    index [in] TLS index to retrieve value for.
 *
 * RETURNS
 *    Success: Value stored in calling thread's TLS slot for index.
 *    Failure: 0 and GetLastError() returns NO_ERROR.
 */
LPVOID WINAPI TlsGetValue( DWORD index )
{
    LPVOID ret;

    if (index < TLS_MINIMUM_AVAILABLE)
    {
        ret = NtCurrentTeb()->TlsSlots[index];
    }
    else
    {
        index -= TLS_MINIMUM_AVAILABLE;
        if (index >= 8 * sizeof(NtCurrentTeb()->Peb->TlsExpansionBitmapBits))
        {
            SetLastError( ERROR_INVALID_PARAMETER );
            return NULL;
        }
        if (!NtCurrentTeb()->TlsExpansionSlots) ret = NULL;
        else ret = NtCurrentTeb()->TlsExpansionSlots[index];
    }
    SetLastError( ERROR_SUCCESS );
    return ret;
}


/**********************************************************************
 * TlsSetValue          [KERNEL32.@]
 *
 * Stores a value in the thread's TLS slot.
 *
 * PARAMS
 *    index [in] TLS index to set value for.
 *    value [in] Value to be stored.
 *
 * RETURNS
 *    Success: TRUE
 *    Failure: FALSE
 */
BOOL WINAPI TlsSetValue( DWORD index, LPVOID value )
{
    if (index < TLS_MINIMUM_AVAILABLE)
    {
        NtCurrentTeb()->TlsSlots[index] = value;
    }
    else
    {
        index -= TLS_MINIMUM_AVAILABLE;
        if (index >= 8 * sizeof(NtCurrentTeb()->Peb->TlsExpansionBitmapBits))
        {
            SetLastError( ERROR_INVALID_PARAMETER );
            return FALSE;
        }
        if (!NtCurrentTeb()->TlsExpansionSlots &&
            !(NtCurrentTeb()->TlsExpansionSlots = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY,
                         8 * sizeof(NtCurrentTeb()->Peb->TlsExpansionBitmapBits) * sizeof(void*) )))
        {
            SetLastError( ERROR_NOT_ENOUGH_MEMORY );
            return FALSE;
        }
        NtCurrentTeb()->TlsExpansionSlots[index] = value;
    }
    return TRUE;
}


/***********************************************************************
 *           GetProcessFlags    (KERNEL32.@)
 */
DWORD WINAPI GetProcessFlags( DWORD processid )
{
    IMAGE_NT_HEADERS *nt;
    DWORD flags = 0;

    if (processid && processid != GetCurrentProcessId()) return 0;

    if ((nt = RtlImageNtHeader( NtCurrentTeb()->Peb->ImageBaseAddress )))
    {
        if (nt->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI)
            flags |= PDB32_CONSOLE_PROC;
    }
    if (!AreFileApisANSI()) flags |= PDB32_FILE_APIS_OEM;
    if (IsDebuggerPresent()) flags |= PDB32_DEBUGGED;
    return flags;
}


/***********************************************************************
 *           GetProcessDword    (KERNEL.485)
 *           GetProcessDword    (KERNEL32.18)
 * 'Of course you cannot directly access Windows internal structures'
 */
DWORD WINAPI GetProcessDword( DWORD dwProcessID, INT offset )
{
    DWORD               x, y;
    STARTUPINFOW        siw;

    TRACE("(%d, %d)\n", dwProcessID, offset );

    if (dwProcessID && dwProcessID != GetCurrentProcessId())
    {
        ERR("%d: process %x not accessible\n", offset, dwProcessID);
        return 0;
    }

    switch ( offset )
    {
    case GPD_APP_COMPAT_FLAGS:
        return GetAppCompatFlags16(0);
    case GPD_LOAD_DONE_EVENT:
        return 0;
    case GPD_HINSTANCE16:
        return GetTaskDS16();
    case GPD_WINDOWS_VERSION:
        return GetExeVersion16();
    case GPD_THDB:
        return (DWORD_PTR)NtCurrentTeb() - 0x10 /* FIXME */;
    case GPD_PDB:
        return (DWORD_PTR)NtCurrentTeb()->Peb; /* FIXME: truncating a pointer */
    case GPD_STARTF_SHELLDATA: /* return stdoutput handle from startupinfo ??? */
        GetStartupInfoW(&siw);
        return HandleToULong(siw.hStdOutput);
    case GPD_STARTF_HOTKEY: /* return stdinput handle from startupinfo ??? */
        GetStartupInfoW(&siw);
        return HandleToULong(siw.hStdInput);
    case GPD_STARTF_SHOWWINDOW:
        GetStartupInfoW(&siw);
        return siw.wShowWindow;
    case GPD_STARTF_SIZE:
        GetStartupInfoW(&siw);
        x = siw.dwXSize;
        if ( (INT)x == CW_USEDEFAULT ) x = CW_USEDEFAULT16;
        y = siw.dwYSize;
        if ( (INT)y == CW_USEDEFAULT ) y = CW_USEDEFAULT16;
        return MAKELONG( x, y );
    case GPD_STARTF_POSITION:
        GetStartupInfoW(&siw);
        x = siw.dwX;
        if ( (INT)x == CW_USEDEFAULT ) x = CW_USEDEFAULT16;
        y = siw.dwY;
        if ( (INT)y == CW_USEDEFAULT ) y = CW_USEDEFAULT16;
        return MAKELONG( x, y );
    case GPD_STARTF_FLAGS:
        GetStartupInfoW(&siw);
        return siw.dwFlags;
    case GPD_PARENT:
        return 0;
    case GPD_FLAGS:
        return GetProcessFlags(0);
    case GPD_USERDATA:
        return process_dword;
    default:
        ERR("Unknown offset %d\n", offset );
        return 0;
    }
}

/***********************************************************************
 *           SetProcessDword    (KERNEL.484)
 * 'Of course you cannot directly access Windows internal structures'
 */
void WINAPI SetProcessDword( DWORD dwProcessID, INT offset, DWORD value )
{
    TRACE("(%d, %d)\n", dwProcessID, offset );

    if (dwProcessID && dwProcessID != GetCurrentProcessId())
    {
        ERR("%d: process %x not accessible\n", offset, dwProcessID);
        return;
    }

    switch ( offset )
    {
    case GPD_APP_COMPAT_FLAGS:
    case GPD_LOAD_DONE_EVENT:
    case GPD_HINSTANCE16:
    case GPD_WINDOWS_VERSION:
    case GPD_THDB:
    case GPD_PDB:
    case GPD_STARTF_SHELLDATA:
    case GPD_STARTF_HOTKEY:
    case GPD_STARTF_SHOWWINDOW:
    case GPD_STARTF_SIZE:
    case GPD_STARTF_POSITION:
    case GPD_STARTF_FLAGS:
    case GPD_PARENT:
    case GPD_FLAGS:
        ERR("Not allowed to modify offset %d\n", offset );
        break;
    case GPD_USERDATA:
        process_dword = value;
        break;
    default:
        ERR("Unknown offset %d\n", offset );
        break;
    }
}


/***********************************************************************
 *           ExitProcess   (KERNEL.466)
 */
void WINAPI ExitProcess16( WORD status )
{
    DWORD count;
    ReleaseThunkLock( &count );
    ExitProcess( status );
}


/*********************************************************************
 *           OpenProcess   (KERNEL32.@)
 *
 * Opens a handle to a process.
 *
 * PARAMS
 *  access  [I] Desired access rights assigned to the returned handle.
 *  inherit [I] Determines whether or not child processes will inherit the handle.
 *  id      [I] Process identifier of the process to get a handle to.
 *
 * RETURNS
 *  Success: Valid handle to the specified process.
 *  Failure: NULL, check GetLastError().
 */
HANDLE WINAPI OpenProcess( DWORD access, BOOL inherit, DWORD id )
{
    NTSTATUS            status;
    HANDLE              handle;
    OBJECT_ATTRIBUTES   attr;
    CLIENT_ID           cid;

    cid.UniqueProcess = ULongToHandle(id);
    cid.UniqueThread = 0; /* FIXME ? */

    attr.Length = sizeof(OBJECT_ATTRIBUTES);
    attr.RootDirectory = NULL;
    attr.Attributes = inherit ? OBJ_INHERIT : 0;
    attr.SecurityDescriptor = NULL;
    attr.SecurityQualityOfService = NULL;
    attr.ObjectName = NULL;

    if (GetVersion() & 0x80000000) access = PROCESS_ALL_ACCESS;

    status = NtOpenProcess(&handle, access, &attr, &cid);
    if (status != STATUS_SUCCESS)
    {
        SetLastError( RtlNtStatusToDosError(status) );
        return NULL;
    }
    return handle;
}


/*********************************************************************
 *           MapProcessHandle   (KERNEL.483)
 *           GetProcessId       (KERNEL32.@)
 *
 * Gets the a unique identifier of a process.
 *
 * PARAMS
 *  hProcess [I] Handle to the process.
 *
 * RETURNS
 *  Success: TRUE.
 *  Failure: FALSE, check GetLastError().
 *
 * NOTES
 *
 * The identifier is unique only on the machine and only until the process
 * exits (including system shutdown).
 */
DWORD WINAPI GetProcessId( HANDLE hProcess )
{
    NTSTATUS status;
    PROCESS_BASIC_INFORMATION pbi;

    status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi,
                                       sizeof(pbi), NULL);
    if (status == STATUS_SUCCESS) return pbi.UniqueProcessId;
    SetLastError( RtlNtStatusToDosError(status) );
    return 0;
}


/*********************************************************************
 *           CloseW32Handle (KERNEL.474)
 *           CloseHandle    (KERNEL32.@)
 *
 * Closes a handle.
 *
 * PARAMS
 *  handle [I] Handle to close.
 *
 * RETURNS
 *  Success: TRUE.
 *  Failure: FALSE, check GetLastError().
 */
BOOL WINAPI CloseHandle( HANDLE handle )
{
    NTSTATUS status;

    /* stdio handles need special treatment */
    if ((handle == (HANDLE)STD_INPUT_HANDLE) ||
        (handle == (HANDLE)STD_OUTPUT_HANDLE) ||
        (handle == (HANDLE)STD_ERROR_HANDLE))
        handle = GetStdHandle( HandleToULong(handle) );

    if (is_console_handle(handle))
        return CloseConsoleHandle(handle);

    status = NtClose( handle );
    if (status) SetLastError( RtlNtStatusToDosError(status) );
    return !status;
}


/*********************************************************************
 *           GetHandleInformation   (KERNEL32.@)
 */
BOOL WINAPI GetHandleInformation( HANDLE handle, LPDWORD flags )
{
    OBJECT_DATA_INFORMATION info;
    NTSTATUS status = NtQueryObject( handle, ObjectDataInformation, &info, sizeof(info), NULL );

    if (status) SetLastError( RtlNtStatusToDosError(status) );
    else if (flags)
    {
        *flags = 0;
        if (info.InheritHandle) *flags |= HANDLE_FLAG_INHERIT;
        if (info.ProtectFromClose) *flags |= HANDLE_FLAG_PROTECT_FROM_CLOSE;
    }
    return !status;
}


/*********************************************************************
 *           SetHandleInformation   (KERNEL32.@)
 */
BOOL WINAPI SetHandleInformation( HANDLE handle, DWORD mask, DWORD flags )
{
    OBJECT_DATA_INFORMATION info;
    NTSTATUS status;

    /* if not setting both fields, retrieve current value first */
    if ((mask & (HANDLE_FLAG_INHERIT | HANDLE_FLAG_PROTECT_FROM_CLOSE)) !=
        (HANDLE_FLAG_INHERIT | HANDLE_FLAG_PROTECT_FROM_CLOSE))
    {
        if ((status = NtQueryObject( handle, ObjectDataInformation, &info, sizeof(info), NULL )))
        {
            SetLastError( RtlNtStatusToDosError(status) );
            return FALSE;
        }
    }
    if (mask & HANDLE_FLAG_INHERIT)
        info.InheritHandle = (flags & HANDLE_FLAG_INHERIT) != 0;
    if (mask & HANDLE_FLAG_PROTECT_FROM_CLOSE)
        info.ProtectFromClose = (flags & HANDLE_FLAG_PROTECT_FROM_CLOSE) != 0;

    status = NtSetInformationObject( handle, ObjectDataInformation, &info, sizeof(info) );
    if (status) SetLastError( RtlNtStatusToDosError(status) );
    return !status;
}


/*********************************************************************
 *           DuplicateHandle   (KERNEL32.@)
 */
BOOL WINAPI DuplicateHandle( HANDLE source_process, HANDLE source,
                             HANDLE dest_process, HANDLE *dest,
                             DWORD access, BOOL inherit, DWORD options )
{
    NTSTATUS status;

    if (is_console_handle(source))
    {
        /* FIXME: this test is not sufficient, we need to test process ids, not handles */
        if (source_process != dest_process ||
            source_process != GetCurrentProcess())
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        *dest = DuplicateConsoleHandle( source, access, inherit, options );
        return (*dest != INVALID_HANDLE_VALUE);
    }
    status = NtDuplicateObject( source_process, source, dest_process, dest,
                                access, inherit ? OBJ_INHERIT : 0, options );
    if (status) SetLastError( RtlNtStatusToDosError(status) );
    return !status;
}


/***********************************************************************
 *           ConvertToGlobalHandle   (KERNEL.476)
 *           ConvertToGlobalHandle  (KERNEL32.@)
 */
HANDLE WINAPI ConvertToGlobalHandle(HANDLE hSrc)
{
    HANDLE ret = INVALID_HANDLE_VALUE;
    DuplicateHandle( GetCurrentProcess(), hSrc, GetCurrentProcess(), &ret, 0, FALSE,
                     DUP_HANDLE_MAKE_GLOBAL | DUP_HANDLE_SAME_ACCESS | DUP_HANDLE_CLOSE_SOURCE );
    return ret;
}


/***********************************************************************
 *           SetHandleContext   (KERNEL32.@)
 */
BOOL WINAPI SetHandleContext(HANDLE hnd,DWORD context)
{
    FIXME("(%p,%d), stub. In case this got called by WSOCK32/WS2_32: "
          "the external WINSOCK DLLs won't work with WINE, don't use them.\n",hnd,context);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}


/***********************************************************************
 *           GetHandleContext   (KERNEL32.@)
 */
DWORD WINAPI GetHandleContext(HANDLE hnd)
{
    FIXME("(%p), stub. In case this got called by WSOCK32/WS2_32: "
          "the external WINSOCK DLLs won't work with WINE, don't use them.\n",hnd);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return 0;
}


/***********************************************************************
 *           CreateSocketHandle   (KERNEL32.@)
 */
HANDLE WINAPI CreateSocketHandle(void)
{
    FIXME("(), stub. In case this got called by WSOCK32/WS2_32: "
          "the external WINSOCK DLLs won't work with WINE, don't use them.\n");
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return INVALID_HANDLE_VALUE;
}


/***********************************************************************
 *           SetPriorityClass   (KERNEL32.@)
 */
BOOL WINAPI SetPriorityClass( HANDLE hprocess, DWORD priorityclass )
{
    NTSTATUS                    status;
    PROCESS_PRIORITY_CLASS      ppc;

    ppc.Foreground = FALSE;
    switch (priorityclass)
    {
    case IDLE_PRIORITY_CLASS:
        ppc.PriorityClass = PROCESS_PRIOCLASS_IDLE; break;
    case BELOW_NORMAL_PRIORITY_CLASS:
        ppc.PriorityClass = PROCESS_PRIOCLASS_BELOW_NORMAL; break;
    case NORMAL_PRIORITY_CLASS:
        ppc.PriorityClass = PROCESS_PRIOCLASS_NORMAL; break;
    case ABOVE_NORMAL_PRIORITY_CLASS:
        ppc.PriorityClass = PROCESS_PRIOCLASS_ABOVE_NORMAL; break;
    case HIGH_PRIORITY_CLASS:
        ppc.PriorityClass = PROCESS_PRIOCLASS_HIGH; break;
    case REALTIME_PRIORITY_CLASS:
        ppc.PriorityClass = PROCESS_PRIOCLASS_REALTIME; break;
    default:
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    status = NtSetInformationProcess(hprocess, ProcessPriorityClass,
                                     &ppc, sizeof(ppc));

    if (status != STATUS_SUCCESS)
    {
        SetLastError( RtlNtStatusToDosError(status) );
        return FALSE;
    }
    return TRUE;
}


/***********************************************************************
 *           GetPriorityClass   (KERNEL32.@)
 */
DWORD WINAPI GetPriorityClass(HANDLE hProcess)
{
    NTSTATUS status;
    PROCESS_BASIC_INFORMATION pbi;

    status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi,
                                       sizeof(pbi), NULL);
    if (status != STATUS_SUCCESS)
    {
        SetLastError( RtlNtStatusToDosError(status) );
        return 0;
    }
    switch (pbi.BasePriority)
    {
    case PROCESS_PRIOCLASS_IDLE: return IDLE_PRIORITY_CLASS;
    case PROCESS_PRIOCLASS_BELOW_NORMAL: return BELOW_NORMAL_PRIORITY_CLASS;
    case PROCESS_PRIOCLASS_NORMAL: return NORMAL_PRIORITY_CLASS;
    case PROCESS_PRIOCLASS_ABOVE_NORMAL: return ABOVE_NORMAL_PRIORITY_CLASS;
    case PROCESS_PRIOCLASS_HIGH: return HIGH_PRIORITY_CLASS;
    case PROCESS_PRIOCLASS_REALTIME: return REALTIME_PRIORITY_CLASS;
    }
    SetLastError( ERROR_INVALID_PARAMETER );
    return 0;
}


/***********************************************************************
 *          SetProcessAffinityMask   (KERNEL32.@)
 */
BOOL WINAPI SetProcessAffinityMask( HANDLE hProcess, DWORD_PTR affmask )
{
    NTSTATUS status;

    status = NtSetInformationProcess(hProcess, ProcessAffinityMask,
                                     &affmask, sizeof(DWORD_PTR));
    if (!status)
    {
        SetLastError( RtlNtStatusToDosError(status) );
        return FALSE;
    }
    return TRUE;
}


/**********************************************************************
 *          GetProcessAffinityMask    (KERNEL32.@)
 */
BOOL WINAPI GetProcessAffinityMask( HANDLE hProcess,
                                    PDWORD_PTR lpProcessAffinityMask,
                                    PDWORD_PTR lpSystemAffinityMask )
{
    PROCESS_BASIC_INFORMATION   pbi;
    NTSTATUS                    status;

    status = NtQueryInformationProcess(hProcess,
                                       ProcessBasicInformation,
                                       &pbi, sizeof(pbi), NULL);
    if (status)
    {
        SetLastError( RtlNtStatusToDosError(status) );
        return FALSE;
    }
    if (lpProcessAffinityMask) *lpProcessAffinityMask = pbi.AffinityMask;
    if (lpSystemAffinityMask)  *lpSystemAffinityMask = (1 << NtCurrentTeb()->Peb->NumberOfProcessors) - 1;
    return TRUE;
}


/***********************************************************************
 *           GetProcessVersion    (KERNEL32.@)
 */
DWORD WINAPI GetProcessVersion( DWORD processid )
{
    IMAGE_NT_HEADERS *nt;

    if (processid && processid != GetCurrentProcessId())
    {
        FIXME("should use ReadProcessMemory\n");
        return 0;
    }
    if ((nt = RtlImageNtHeader( NtCurrentTeb()->Peb->ImageBaseAddress )))
        return ((nt->OptionalHeader.MajorSubsystemVersion << 16) |
                nt->OptionalHeader.MinorSubsystemVersion);
    return 0;
}


/***********************************************************************
 *		SetProcessWorkingSetSize	[KERNEL32.@]
 * Sets the min/max working set sizes for a specified process.
 *
 * PARAMS
 *    hProcess [I] Handle to the process of interest
 *    minset   [I] Specifies minimum working set size
 *    maxset   [I] Specifies maximum working set size
 *
 * RETURNS
 *  Success: TRUE
 *  Failure: FALSE
 */
BOOL WINAPI SetProcessWorkingSetSize(HANDLE hProcess, SIZE_T minset,
                                     SIZE_T maxset)
{
    WARN("(%p,%ld,%ld): stub - harmless\n",hProcess,minset,maxset);
    if(( minset == (SIZE_T)-1) && (maxset == (SIZE_T)-1)) {
        /* Trim the working set to zero */
        /* Swap the process out of physical RAM */
    }
    return TRUE;
}

/***********************************************************************
 *           GetProcessWorkingSetSize    (KERNEL32.@)
 */
BOOL WINAPI GetProcessWorkingSetSize(HANDLE hProcess, PSIZE_T minset,
                                     PSIZE_T maxset)
{
    FIXME("(%p,%p,%p): stub\n",hProcess,minset,maxset);
    /* 32 MB working set size */
    if (minset) *minset = 32*1024*1024;
    if (maxset) *maxset = 32*1024*1024;
    return TRUE;
}


/***********************************************************************
 *           SetProcessShutdownParameters    (KERNEL32.@)
 */
BOOL WINAPI SetProcessShutdownParameters(DWORD level, DWORD flags)
{
    FIXME("(%08x, %08x): partial stub.\n", level, flags);
    shutdown_flags = flags;
    shutdown_priority = level;
    return TRUE;
}


/***********************************************************************
 * GetProcessShutdownParameters                 (KERNEL32.@)
 *
 */
BOOL WINAPI GetProcessShutdownParameters( LPDWORD lpdwLevel, LPDWORD lpdwFlags )
{
    *lpdwLevel = shutdown_priority;
    *lpdwFlags = shutdown_flags;
    return TRUE;
}


/***********************************************************************
 *           GetProcessPriorityBoost    (KERNEL32.@)
 */
BOOL WINAPI GetProcessPriorityBoost(HANDLE hprocess,PBOOL pDisablePriorityBoost)
{
    FIXME("(%p,%p): semi-stub\n", hprocess, pDisablePriorityBoost);
    
    /* Report that no boost is present.. */
    *pDisablePriorityBoost = FALSE;
    
    return TRUE;
}

/***********************************************************************
 *           SetProcessPriorityBoost    (KERNEL32.@)
 */
BOOL WINAPI SetProcessPriorityBoost(HANDLE hprocess,BOOL disableboost)
{
    FIXME("(%p,%d): stub\n",hprocess,disableboost);
    /* Say we can do it. I doubt the program will notice that we don't. */
    return TRUE;
}


/***********************************************************************
 *		ReadProcessMemory (KERNEL32.@)
 */
BOOL WINAPI ReadProcessMemory( HANDLE process, LPCVOID addr, LPVOID buffer, SIZE_T size,
                               SIZE_T *bytes_read )
{
    NTSTATUS status = NtReadVirtualMemory( process, addr, buffer, size, bytes_read );
    if (status) SetLastError( RtlNtStatusToDosError(status) );
    return !status;
}


/***********************************************************************
 *           WriteProcessMemory    		(KERNEL32.@)
 */
BOOL WINAPI WriteProcessMemory( HANDLE process, LPVOID addr, LPCVOID buffer, SIZE_T size,
                                SIZE_T *bytes_written )
{
    NTSTATUS status = NtWriteVirtualMemory( process, addr, buffer, size, bytes_written );
    if (status) SetLastError( RtlNtStatusToDosError(status) );
    return !status;
}


/****************************************************************************
 *		FlushInstructionCache (KERNEL32.@)
 */
BOOL WINAPI FlushInstructionCache(HANDLE hProcess, LPCVOID lpBaseAddress, SIZE_T dwSize)
{
    NTSTATUS status;
    status = NtFlushInstructionCache( hProcess, lpBaseAddress, dwSize );
    if (status) SetLastError( RtlNtStatusToDosError(status) );
    return !status;
}


/******************************************************************
 *		GetProcessIoCounters (KERNEL32.@)
 */
BOOL WINAPI GetProcessIoCounters(HANDLE hProcess, PIO_COUNTERS ioc)
{
    NTSTATUS    status;

    status = NtQueryInformationProcess(hProcess, ProcessIoCounters, 
                                       ioc, sizeof(*ioc), NULL);
    if (status) SetLastError( RtlNtStatusToDosError(status) );
    return !status;
}

/******************************************************************
 *		GetProcessHandleCount (KERNEL32.@)
 */
BOOL WINAPI GetProcessHandleCount(HANDLE hProcess, DWORD *cnt)
{
    NTSTATUS status;

    status = NtQueryInformationProcess(hProcess, ProcessHandleCount,
                                       cnt, sizeof(*cnt), NULL);
    if (status) SetLastError( RtlNtStatusToDosError(status) );
    return !status;
}

/***********************************************************************
 * ProcessIdToSessionId   (KERNEL32.@)
 * This function is available on Terminal Server 4SP4 and Windows 2000
 */
BOOL WINAPI ProcessIdToSessionId( DWORD procid, DWORD *sessionid_ptr )
{
    /* According to MSDN, if the calling process is not in a terminal
     * services environment, then the sessionid returned is zero.
     */
    *sessionid_ptr = 0;
    return TRUE;
}


/***********************************************************************
 *		RegisterServiceProcess (KERNEL.491)
 *		RegisterServiceProcess (KERNEL32.@)
 *
 * A service process calls this function to ensure that it continues to run
 * even after a user logged off.
 */
DWORD WINAPI RegisterServiceProcess(DWORD dwProcessId, DWORD dwType)
{
    /* I don't think that Wine needs to do anything in this function */
    return 1; /* success */
}


/**********************************************************************
 *           IsWow64Process         (KERNEL32.@)
 */
BOOL WINAPI IsWow64Process(HANDLE hProcess, PBOOL Wow64Process)
{
    ULONG pbi;
    NTSTATUS status;

    status = NtQueryInformationProcess( hProcess, ProcessWow64Information, &pbi, sizeof(pbi), NULL );

    if (status != STATUS_SUCCESS)
    {
        SetLastError( RtlNtStatusToDosError( status ) );
        return FALSE;
    }
    *Wow64Process = (pbi != 0);
    return TRUE;
}


/***********************************************************************
 *           GetCurrentProcess   (KERNEL32.@)
 *
 * Get a handle to the current process.
 *
 * PARAMS
 *  None.
 *
 * RETURNS
 *  A handle representing the current process.
 */
#undef GetCurrentProcess
HANDLE WINAPI GetCurrentProcess(void)
{
    return (HANDLE)0xffffffff;
}

/***********************************************************************
 *           CmdBatNotification   (KERNEL32.@)
 *
 * Notifies the system that a batch file has started or finished.
 *
 * PARAMS
 *  bBatchRunning [I]  TRUE if a batch file has started or 
 *                     FALSE if a batch file has finished executing.
 *
 * RETURNS
 *  Unknown.
 */
BOOL WINAPI CmdBatNotification( BOOL bBatchRunning )
{
    FIXME("%d\n", bBatchRunning);
    return FALSE;
}


/***********************************************************************
 *           RegisterApplicationRestart       (KERNEL32.@)
 */
HRESULT WINAPI RegisterApplicationRestart(PCWSTR pwzCommandLine, DWORD dwFlags)
{
    FIXME("(%s,%d)\n", debugstr_w(pwzCommandLine), dwFlags);

    return S_OK;
}

void BaseProcessStart(unsigned long start_address, void *param)
{
    unsigned long   exit_code;
    LPTHREAD_START_ROUTINE  entry;

    SERVER_START_REQ( new_thread )
    {
		int ret=0;
		ret = wine_server_call_err( req );
		if(ret)
		{
			fprintf(stderr,"ERROR:new_thread\n");
			return;
		}
    }
   SERVER_END_REQ;

   {
       PEB *peb = NtCurrentTeb()->Peb;
       LOG(LOG_FILE,0,0, "%04x:Starting process %s \n",\
	       GetCurrentThreadId(), debugstr_w(peb->ProcessParameters->ImagePathName.Buffer));
   }

    __TRY
    {
        entry = (LPTHREAD_START_ROUTINE)start_address;
        exit_code = entry(param);
    }
    __EXCEPT(UnhandledExceptionFilter)
    {
        exit_code = GetExceptionCode();
    }
    __ENDTRY;

    ExitProcess(exit_code);
}
