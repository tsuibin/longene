/*
 * init.c
 *
 * Copyright (C) 2006  Insigme Co., Ltd
 *
 * This software has been developed while working on the Linux Unified Kernel
 * project (http://linux.insigma.com.cn) in the Insigma Research Institute,  
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
 * init.c: initiliase all that should be done before LdrInitializThunk
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <link.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <dlfcn.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winnt.h"
#include "winternl.h"
#include "wine/library.h"
#include "wine/unicode.h"
#include "wine/server.h"
#include "wine/debug.h"

#include "ntdll_misc.h"
#include "wine/list.h"
#include "wine/log.h"

WINE_DEFAULT_DEBUG_CHANNEL(apc);

#define	AT_BAK		1005
extern void setup_config_dir(void);
static WCHAR *SystemDir = NULL;
static WCHAR *WindowsDir = NULL;
struct list handle_refer = LIST_INIT(handle_refer);

extern struct _KUSER_SHARED_DATA *user_shared_data;

int child_socket_fd = 0;
typedef struct _wine_modref
{
    LDR_MODULE            ldr;
    int                   nDeps;
    struct _wine_modref **deps;
} WINE_MODREF;
const char __dynamic_linker__[] __attribute__ ((section (".interp"))) = RUNTIME_LINKER;

static PEB_LDR_DATA ldr;
static RTL_BITMAP _tls_bitmap;
static RTL_BITMAP _tls_expansion_bitmap;
static RTL_BITMAP _fls_bitmap;
extern int __wine_main_argc;
extern char **__wine_main_argv;
extern char **__wine_main_environ;
extern unsigned long BaseProcessStartEntry;
extern LIST_ENTRY tls_links;

extern void debug_usage(void);
extern void parse_options(const char *str);
extern WINE_MODREF *alloc_module(HMODULE hModule, LPCWSTR filename);
extern void server_init_process(void);
extern size_t server_init_thread(int unix_pid, int unix_tid, void *entry_point);
extern int __cxa_atexit (void (*func) (void *), void *arg, void *d);
extern void build_dll_path(void);
void _init(void);
void StartInterp(PIO_APC_ROUTINE ApcRoutine, void *stack,
        void *interp_start, unsigned long bak_addr, void *Context);
extern void __wine_init_codepages(const union cptable *ansi, const union cptable *oem,
        const union cptable *ucp);
extern const union cptable *wine_cp_get_table(unsigned int codepage);
extern NTSTATUS create_pe_sec_view(HANDLE hmodule);
typedef void (*BaseProcessStartFunc)(unsigned long, void *);
extern void uk_reserve_dos_area();

ElfW(auxv_t) *auxvec;
size_t auxvec_len;

void set_child_socket_fd(int fd)
{
    child_socket_fd = fd;
}

int get_child_socket_fd()
{
    return child_socket_fd;
}

NTSTATUS  WINAPI NtContinue(PCONTEXT param0, BOOLEAN param1) 
{
    NTSTATUS ret;
    __asm__ __volatile__ (
            "movl $0x15, %%eax\n\t"
            "lea 8(%%ebp), %%edx\n\t"
            "int $0x2E\n\t"
            :"=a" (ret)
            );
    return ret;
}


void ProcessStartForward(unsigned long start_address, void *peb)
{
    BaseProcessStartFunc	BaseProcessStart;

    BaseProcessStart = (BaseProcessStartFunc)BaseProcessStartEntry;
    BaseProcessStart(start_address, peb);
}

__attribute__ ((no_instrument_function)) void StartInterp();

    /*
     * StartInterp
     *
     * The linux interpreter here is used to link .so such as libwine.so for built-in dlls.
     * ALl the dlls will be linked by ntdll.dll.so
     */
__asm__ (
        ".globl StartInterp\n"
        "StartInterp:\n\t"
        "pusha\n\t"
        "mov 0x28(%esp), %ecx\n\t"	/* stack top used for linux arg */
        "sub %esp, %ecx\n\t"		/* stack size need backup */
        "mov %esp, %esi\n\t"
        "mov 0x30(%esp), %edi\n\t"
        "mov %ecx, (%edi)\n\t"		/* backup the size */
        "add $0x4, %edi\n\t"
        "shr $2, %ecx\n\t"
        "rep movsl\n\t"
        "mov 0x28(%esp), %ecx\n\t"
        "mov 0x2c(%esp), %esi\n\t"	/* Iosb, here in interpreter */
        "mov %ecx, %esp\n\t"
        "jmp *%esi\n"				/* _start in interpreter */
        /* finally jmp to AT_ENTRY */

        ".globl StartThunk\n"		/* set StartThunk to AT_ENTRY in kernel */
        "StartThunk:\n\t"
        "xorl %ebp, %ebp\n\t"		/* ABI need */
        "movl (%esp), %esi\n\t"		/* Pop the argument count.  */
        "leal 0x4(%esp), %ecx\n\t"		/* argv starts just at the current stack top.*/
        "movl %esp, %ebp\n\t"
        /* Before pushing the arguments align the stack to a 16-byte
           (SSE needs 16-byte alignment) boundary to avoid penalties from
           misaligned accesses. */
        "andl $0xfffffff0, %esp\n\t"
        "pushl %eax\n\t"	  /* push garbage */
        "pushl %eax\n\t"	  /* push garbage */
        "pushl %eax\n\t"	  /* push garbage */
        "pushl %ebp\n\t"
        "pushl %edx\n\t"      /* Push address of the shared library termination function. */
        "pushl $0x0\n\t"      /* __libc_csu_init */
        "pushl %ecx\n\t"      /* Push second argument: argv.  */
        "pushl %esi\n\t"      /* Push first argument: argc.  */
        "call PrepareThunk\n\t"
        "movl (%esp), %esp\n\t"		/* restore %esp */
        "movl (%eax), %ecx\n\t"		/* stack size backuped */
        "leal 0x4(%eax), %esi\n\t"	/* stack data backuped in %esi */
        "subl %ecx, %esp\n\t"		/* restore %esp */
        "movl %esp, %edi\n\t"
        "shrl $0x2, %ecx\n\t"
        "rep movsl\n\t"				/* restore stack */
        "popa\n\t"
        "ret\n"						/* return from StartInterp */
    );

static unsigned long extra_page = 0;

void __attribute__((stdcall, no_instrument_function))
KiUserApcDispatcher(PIO_APC_ROUTINE ApcRoutine, void *ApcContext,
        void *Iosb, unsigned long Reserved, void *Context)
{
    if (Reserved) {
        extra_page = Reserved;
        StartInterp(ApcRoutine, ApcContext, Iosb, Reserved, Context);
    }
    ApcRoutine(ApcContext, Iosb, Reserved);
    /* switch back to the interrupted context */
    NtContinue((PCONTEXT)Context, 1);
}

char *get_wine_bindir()
{
    char *wine_path, *bin_dir, *p, *temp;
    char *paths = getenv("PATH");
    char wine[] = "/wine";
    struct stat st;
    int path_len;

    wine_path = malloc(MAX_PATH + sizeof(wine));
    if (paths) {
        paths = strdup(paths);
        temp = paths;
        for (p = paths; *p != 0; p++) {
            while (*p != ':' && *p)
                p++;
            *p = 0;
            strcpy(wine_path, temp);
            strcat(wine_path, wine);

            if (!stat(wine_path, &st))
                if (S_ISREG(st.st_mode)) {
                    path_len = strrchr(wine_path, '/') - wine_path;
                    bin_dir = malloc((path_len + 1) * sizeof(char));
                    memcpy(bin_dir, wine_path, path_len);
                    bin_dir[path_len] = 0;
                    free(paths);
                    free(wine_path);
                    return bin_dir;
                }
            temp = p + 1;
        }
        free(paths);
    }
    free(wine_path);
    return NULL;
}

static NTSTATUS get_system_paths()
{
    static const WCHAR windirW[] = {'w','i','n','d','i','r',0};
    static const WCHAR sysdirW[] = {'w','i','n','s','y','s','d','i','r',0};
    static const WCHAR default_windirW[] = {'c',':','\\','w','i','n','d','o','w','s',0};
    static const WCHAR default_sysdirW[] = {'\\','s','y','s','t','e','m','3','2',0};
    UNICODE_STRING sys_value,win_value;
    UNICODE_STRING sys_name,win_name;
    int path_len = 0;

    win_value.Length = 0;
    win_value.MaximumLength = 0;
    win_value.Buffer = NULL;
    RtlInitUnicodeString(&win_name, windirW);
    if (RtlQueryEnvironmentVariable_U(NULL, &win_name, &win_value) == STATUS_BUFFER_TOO_SMALL) {
        path_len = win_value.Length;
        win_value.MaximumLength = path_len + sizeof(WCHAR);
        win_value.Buffer = RtlAllocateHeap(GetProcessHeap(), 0, win_value.MaximumLength);
        if (!win_value.Buffer)
            return STATUS_NO_MEMORY;

        RtlQueryEnvironmentVariable_U(NULL, &win_name, &win_value);
        win_value.Buffer[path_len / sizeof(WCHAR)] = 0;
        WindowsDir = win_value.Buffer;
    } else /* this could be happened with the STATUS_VARIABLE_NOT_FOUND */
        WindowsDir = (WCHAR *)default_windirW;

    sys_value.Length = 0;
    sys_value.MaximumLength = 0;
    sys_value.Buffer = NULL;
    RtlInitUnicodeString(&sys_name, sysdirW);
    if (RtlQueryEnvironmentVariable_U(NULL, &sys_name, &sys_value) == STATUS_BUFFER_TOO_SMALL) {
        path_len = sys_value.Length;
        sys_value.MaximumLength = path_len + sizeof(WCHAR);
        sys_value.Buffer = RtlAllocateHeap(GetProcessHeap(), 0, sys_value.MaximumLength);
        if (!sys_value.Buffer)
            return STATUS_NO_MEMORY;

        RtlQueryEnvironmentVariable_U(NULL, &sys_name, &sys_value);
        sys_value.Buffer[path_len / sizeof(WCHAR)] = 0;
        SystemDir = sys_value.Buffer;
    } else { /* this could be happened with the STATUS_VARIABLE_NOT_FOUND */
        path_len = strlenW(WindowsDir) * sizeof(WCHAR);
        sys_value.Buffer = RtlAllocateHeap(GetProcessHeap(), 0, 
                path_len + sizeof(default_sysdirW));
        if (!sys_value.Buffer)
            return STATUS_NO_MEMORY;

        memcpy(sys_value.Buffer, WindowsDir, path_len);
        memcpy(sys_value.Buffer + path_len / sizeof(WCHAR), default_sysdirW, 
                sizeof(default_sysdirW));
        SystemDir = sys_value.Buffer;
    }

    return STATUS_SUCCESS;
}

static WCHAR *get_dll_path(UNICODE_STRING* full_exe_name)
{
    LPWSTR exe_path, dll_path;
    WCHAR* p;
    int len = 0;
    int exe_path_len = 0;

    WCHAR SystemDir16[] = {'c',':','\\','w','i','n','d','o','w','s','\\','s','y','s','t','e','m',0};
    WCHAR CurrentDirW[] = {'.',0};

    /* get the length:
     * + exe path
     * + system dll path:
     *   + .
     *   + 32-bit system path
     *   + 16-bit system path
     *   + windows path
     * + PATH ? 
     */
    if (!full_exe_name)
        exe_path = NtCurrentTeb()->Peb->ProcessParameters->ImagePathName.Buffer;
    else
        exe_path = full_exe_name->Buffer;
    if (exe_path) {
        exe_path_len = (strrchrW(exe_path, '\\') - exe_path);
        len += exe_path_len + 1;
    }

    len += strlenW(CurrentDirW) + 1;

    get_system_paths();

    if (SystemDir)
        len += strlenW(SystemDir) + 1;

    len += strlenW(SystemDir16) + 1;

    if (WindowsDir)
        len += strlenW(WindowsDir) + 1;

    /* make up dll path */
    if ((p = dll_path = RtlAllocateHeap(GetProcessHeap(), 0, len * sizeof(WCHAR)))) {
        /* exe path */
        if (exe_path) {
            memcpy(dll_path, exe_path, exe_path_len * sizeof(WCHAR));
            p += exe_path_len;
            *p++ = ';';
        }

        /* system dll path */
        strcpyW(p, CurrentDirW);
        p += strlenW(p);
        *p++ = ';';
        if (SystemDir) {
            strcpyW(p, SystemDir);
            p += strlenW(p);
            *p++ = ';';
        }
        strcpyW(p, SystemDir16);
        p += strlenW(p);
        *p++ = ';';
        if (WindowsDir) {
            strcpyW(p, WindowsDir);
            p += strlenW(p);
            *p++ = ';';
        }

        /* PATH */
        dll_path[len - 1] = 0;
        return dll_path;
    }

    return NULL;
}

/* initialize all options at startup for Unified Kernel */
void __debug_init(void)
{
    char *wine_debug;

    if ((wine_debug = getenv("WINEDEBUG")))
    {
        if (!strcmp(wine_debug, "help")) debug_usage();
        parse_options(wine_debug);
    }
}

#define NORMALIZE(x, addr)   if (x) x = (typeof(x))((unsigned long)(x) + (unsigned long)(addr))
#define NORMALIZE_PARAMS(params) \
{ \
    if ((params)) \
    { \
        NORMALIZE((params)->CurrentDirectory.DosPath.Buffer, (params)); \
        NORMALIZE((params)->DllPath.Buffer, (params)); \
        NORMALIZE((params)->ImagePathName.Buffer, (params)); \
        NORMALIZE((params)->CommandLine.Buffer, (params)); \
        NORMALIZE((params)->WindowTitle.Buffer, (params)); \
        NORMALIZE((params)->Desktop.Buffer, (params)); \
        NORMALIZE((params)->ShellInfo.Buffer, (params)); \
        NORMALIZE((params)->RuntimeInfo.Buffer, (params)); \
    } \
}

LPSTR WINAPI GetDir(void)
{
    static char *cmdlineA;  /* ASCII command line */
    ANSI_STRING     ansi;

    cmdlineA = (RtlUnicodeStringToAnsiString( &ansi, 
                &NtCurrentTeb()->Peb->ProcessParameters->CurrentDirectory.DosPath, TRUE) == STATUS_SUCCESS) ?  
        ansi.Buffer : NULL;

    return cmdlineA;
}

/*
 * init_for_load
 * 
 * Initializing all the parts that are done by wine-preloader
 * All this initialization should be done before LdrInitializeThunk
 */
void init_for_load()
{
    WINE_MODREF *wm;
    PEB *peb = NtCurrentTeb()->Peb;
    RTL_USER_PROCESS_PARAMETERS *params = peb->ProcessParameters;
    IMAGE_NT_HEADERS *nt = RtlImageNtHeader(peb->ImageBaseAddress);
    WCHAR *dll_path = NULL;
    UNICODE_STRING fullname;
    struct ntdll_thread_data *thread_data; 
    struct ntdll_thread_regs *thread_regs; 
    static struct debug_info debug_info;
    int* psocketfd;
    char socket_env[64];
    void *addr;
    SIZE_T size;
	
    char *stdin_env;
    char *stdout_env;
    char *stderr_env;

    stdin_env = getenv("STDINPUT");
    stdout_env = getenv("STDOUTPUT");
    stderr_env = getenv("STDERROR");

    LOG(LOG_FILE, 0, 0, "stdin_env = %s, stdout_env = %s, stderr_env = %s\n",stdin_env, stdout_env, stderr_env);
    if (stdin_env && params->hStdInput == INVALID_HANDLE_VALUE)
    {
        params->hStdInput = (HANDLE)strtol(stdin_env, (char **)NULL, 16);
    }

    if (stdout_env && params->hStdOutput == INVALID_HANDLE_VALUE)
    {
        params->hStdOutput = (HANDLE)strtol(stdout_env, (char **)NULL, 16);
    }
    if (stderr_env && params->hStdError == INVALID_HANDLE_VALUE)
    {
        params->hStdError = (HANDLE)strtol(stderr_env, (char **)NULL, 16);
    }

    LOG(LOG_FILE, 0, 0, "params->hStdInput =%p,params->hStdOutput =%p,params->hStdError = %p\n",params->hStdInput,params->hStdOutput, params->hStdError);

    if ( (!params->hStdInput) ||  params->hStdInput == INVALID_HANDLE_VALUE || params->hStdInput == 0)
    {
        wine_server_fd_to_handle( 0, GENERIC_READ|SYNCHRONIZE,  OBJ_INHERIT, &params->hStdInput );
    }

    if ( (!params->hStdOutput) || params->hStdOutput == INVALID_HANDLE_VALUE || params->hStdOutput == 0 )
    {
        wine_server_fd_to_handle( 1, GENERIC_WRITE|SYNCHRONIZE, OBJ_INHERIT, &params->hStdOutput );
    }

    if ( (!params->hStdError) ||  params->hStdError == INVALID_HANDLE_VALUE || params->hStdError == 0 )
    {
        wine_server_fd_to_handle( 2, GENERIC_WRITE|SYNCHRONIZE, OBJ_INHERIT, &params->hStdError );
    }

    LOG(LOG_FILE, 0, 0, "params->hStdInput =%p,params->hStdOutput =%p,params->hStdError = %p\n",params->hStdInput,params->hStdOutput, params->hStdError);

    if (params && (unsigned long)params->CommandLine.Buffer < (unsigned long)params) {
        NORMALIZE((params)->CurrentDirectory.DosPath.Buffer, (params));
        NORMALIZE((params)->DllPath.Buffer, (params));
        NORMALIZE((params)->ImagePathName.Buffer, (params));
        NORMALIZE((params)->CommandLine.Buffer, (params));
        NORMALIZE((params)->WindowTitle.Buffer, (params));
        NORMALIZE((params)->Desktop.Buffer, (params));
        NORMALIZE((params)->ShellInfo.Buffer, (params));
        NORMALIZE((params)->RuntimeInfo.Buffer, (params));
    }

    addr = (void *)0x7ffe0000;
    size = 0x10000;
LOG(LOG_FILE, 0, 0, "init_for_load(),call NtAllocateVirtualMemory, addr=0x7ffe0000\n");
    NtAllocateVirtualMemory( NtCurrentProcess(), &addr, 0, &size, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE );
    user_shared_data = addr;

    /* signal */
    thread_data = (struct ntdll_thread_data *)NtCurrentTeb()->SystemReserved2;
    thread_regs = (struct ntdll_thread_regs *)NtCurrentTeb()->SpareBytes1;
    thread_data->debug_info = &debug_info;
    debug_info.str_pos = debug_info.strings;
    debug_info.out_pos = debug_info.output;

    thread_data->fs = 0;
    asm("mov %%fs, %0\n" : "=m"(thread_data->fs));

    get_signal_stack_total_size();

    /* debug initialization for debug log*/
    __debug_init();

    /* initialize module lists */
    InitializeListHead(&ldr.InLoadOrderModuleList);
    InitializeListHead(&ldr.InMemoryOrderModuleList);
    InitializeListHead(&ldr.InInitializationOrderModuleList);
    NtCurrentTeb()->Peb->LdrData = &ldr;

    /* initialize some fields in teb and peb */
    NtCurrentTeb()->StaticUnicodeString.Length        = 0;
    NtCurrentTeb()->StaticUnicodeString.Buffer        = NtCurrentTeb()->StaticUnicodeBuffer;
    NtCurrentTeb()->StaticUnicodeString.MaximumLength = sizeof(NtCurrentTeb()->StaticUnicodeBuffer);

    peb->TlsBitmap          = &_tls_bitmap;
    peb->TlsExpansionBitmap = &_tls_expansion_bitmap;
    peb->FlsBitmap          = &_fls_bitmap;
    RtlInitializeBitMap(&_tls_bitmap, peb->TlsBitmapBits, sizeof(peb->TlsBitmapBits) * 8);
    RtlInitializeBitMap(&_tls_expansion_bitmap, peb->TlsExpansionBitmapBits,
            sizeof(peb->TlsExpansionBitmapBits) * 8);
    RtlInitializeBitMap( &_fls_bitmap, peb->FlsBitmapBits, sizeof(peb->FlsBitmapBits) * 8 );

    InitializeListHead(&tls_links);
    InitializeListHead(&peb->FlsListHead);
    InsertHeadList(&tls_links, &(NtCurrentTeb()->TlsLinks));

    /* preset codepages before kernel32 being loaded */
    __wine_init_codepages(wine_cp_get_table(1252),
            wine_cp_get_table(437),
            wine_cp_get_table(CP_UTF8));

    /* socket fd is located at the bottom of ppb*/
    if (params) {
        psocketfd = (int *)(params + 1);
        if (*psocketfd) {
            sprintf(socket_env, "WINESERVERSOCKET=%u", *psocketfd);
            putenv(socket_env);
        }
    }

    virtual_init_threading();

	setup_config_dir();

    /* create process heap */
    if (!(peb->ProcessHeap = RtlCreateHeap(HEAP_GROWABLE, NULL, 0, 0, NULL, NULL))) {
        ERR("Error in create heap\n");
        exit(1);
    }

    /* create view for main exe sections */
    if (create_pe_sec_view(peb->ImageBaseAddress)) {
        ERR("error in creating pe sections' views\n");
        exit(1);
    }

    setenv("PWD",GetDir(),1);

    /* allocate a module for main exe */
    if (RtlSetCurrentDirectory_U(&params->CurrentDirectory.DosPath)) {
        ERR( "error in setting current directory\n");
        exit(1);
    }

    RtlDosPathNameToNtPathName_U(params->ImagePathName.Buffer, &fullname, NULL, NULL);
    fullname.Buffer += 4; /* skip \??\ prefix */
    fullname.Length -= 4;

    /* initialize items in ppb */
    params->wShowWindow = 1;

    if (params->CommandLine.Buffer[0] == '.' && params->CommandLine.Buffer[1] == '/')
        params->CommandLine.Buffer = params->CommandLine.Buffer + 2;

    wm = alloc_module(peb->ImageBaseAddress, fullname.Buffer);
    RtlFreeHeap(GetProcessHeap(), 0, fullname.Buffer);
    if (!wm) {
        ERR( "can't load %s\n", debugstr_w(fullname.Buffer));
        exit(1);
    }

    /* set dll path */
    dll_path = get_dll_path(&fullname);
    RtlInitUnicodeString(&params->DllPath,dll_path);

    /* register main exe on wine server */

    SERVER_START_REQ(load_dll)
    {
        req->handle     = 0; /* no handle of main exe */
        req->base       = peb->ImageBaseAddress;
        req->size       = nt->OptionalHeader.SizeOfImage;
        req->dbg_offset = nt->FileHeader.PointerToSymbolTable;
        req->dbg_size   = nt->FileHeader.NumberOfSymbols;
        req->name       = &wm->ldr.FullDllName.Buffer;
        wine_server_add_data(req, wm->ldr.FullDllName.Buffer, wm->ldr.FullDllName.Length);
        wine_server_call(req);
    }
    SERVER_END_REQ;
    LOG(LOG_FILE, 0, 0, "leaving init_for_load()\n");
}

__attribute__((stdcall))
int PrepareThunk(
            int argc,
            char **argv,
            void (*init) (void),
            void (*rtld_fini)(void))
{
    char	**evp, **p;
    char 	*wine_path, *bin_dir;
    char	wine[] = "/wine";

    LOG(LOG_FILE, 0, 0, "PrepareThunk(), init=%p\n", init);
    if (__builtin_expect (rtld_fini != NULL, 1))
        __cxa_atexit ((void (*) (void *)) rtld_fini, NULL, NULL);

    p = evp = argv + argc + 1;

    while (*p++) ;
    auxvec = (ElfW(auxv_t) *)p;
    auxvec_len = (unsigned long)argv[0] - (unsigned long)p;

    bin_dir = get_wine_bindir();
    wine_path = malloc(strlen(bin_dir) + sizeof(wine));
    strcpy(wine_path, bin_dir);
    strcat(wine_path, wine);
    free(bin_dir);

    wine_init_argv0_path(wine_path);
    build_dll_path();
    __wine_main_argc = argc;
    __wine_main_argv = argv;
    __wine_main_environ = evp;
    free(wine_path);

    init_for_load();

    /* Call the initializer of the program, if any.  */
    if (init)
	{
        (*init)();
	}

    /* .init in ntdll.dll.so */
    _init();  //__wine_dll_register() is called here for ntdll.dll
    NtCurrentTeb()->Peb->ProcessParameters->Environment = NULL;
    return extra_page;
}

int UkDebug(unsigned long arg1, unsigned long arg2, unsigned long arg3)
{
    int ret;
    __asm__ __volatile__(
            "movl $234,%%eax\n\t"
            "lea 8(%%ebp),%%edx\n\t"
            "int $0x2E\n\t"
            :"=a" (ret)
            );
    return ret;
}

IMAGE_NT_HEADERS **get_main_exe_ptr();
void *map_dll( const IMAGE_NT_HEADERS *nt_descr );

void __attribute__((regparm(0)))
ntdll_start_thunk(int unknown)
{
    int *pargc = (int *)&unknown - 1;
    char **argv = (char **)&unknown;
    void *image_base;
    PEB *peb = NtCurrentTeb()->Peb;
    IMAGE_NT_HEADERS **nt;
    void *entry;
    char *pipe = NULL;
    int fd;

    uk_reserve_dos_area();
    if (!dlopen(argv[0], RTLD_NOW)) {
        ERR("dlopen %s failed: %s\n", argv[0], dlerror());
		exit(0);
	}

    nt = get_main_exe_ptr();
    entry = (void *)(*nt)->OptionalHeader.AddressOfEntryPoint;
    image_base = map_dll(*nt);
    peb->ImageBaseAddress = image_base;
    *nt = 0;


    PrepareThunk(*pargc, argv, 0, 0);
    /* 
     * set socket fd to the bottom of ppb
     * For built-in exe, we don't get the socket fd from ppb, 
     * and we set it here just for the further check
     */
    //psocketfd = params + 1; /* expand for socket fd */
    //*psocketfd = socket_fd;

    pipe = getenv("PIDTIDPIPE");
    if(pipe) {
        HANDLE pid, tid;
        /* retrive of pid/tid should be after init_for_load() */
        pid = NtCurrentTeb()->ClientId.UniqueProcess;
        tid = NtCurrentTeb()->ClientId.UniqueThread;
        fd = atoi(pipe);
        write(fd, &pid, sizeof(pid));
        write(fd, &tid, sizeof(tid));
		close(fd);
    }

    LdrInitializeThunk(0,0,0,0);

    asm __volatile__ ("movl %0, %%esp\n\t"
            "pushl $0x7ffdf000\n\t"
            "pushl %1\n\t"
            "pushl $0xdeadbeef\n\t"
            "jmp *%2\n\t"
            :: "r"(pargc), "r"(entry),
            "r"(&ProcessStartForward)
            );

    exit(0);
}

void __attribute__((regparm(0)))
exeso_start_thunk(int unknown)
{
    UkDebug(0, 0, 0);
}

