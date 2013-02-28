/*
 * winuser.h
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
 *   Jan 2008 - Created.
 */

#ifndef _WINUSER_H
#define _WINUSER_H

#if !defined(_USER32_)
#define WINUSERAPI DECLSPEC_IMPORT
#else
#define WINUSERAPI
#endif

#ifndef RC_INVOKED
#include <stdarg.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "wtypes.h"

#ifdef CONFIG_UNIFIED_KERNEL
typedef HANDLE HDWP;

#define UOI_FLAGS       1
#define UOI_NAME        2
#define UOI_TYPE        3
#define UOI_USER_SID    4

#define WSF_VISIBLE     1
#define DF_ALLOWOTHERACCOUNTHOOK  1

typedef struct tagUSEROBJECTFLAGS {
	BOOL fInherit;
	BOOL fReserved;
	DWORD dwFlags;
} USEROBJECTFLAGS, *PUSEROBJECTFLAGS;

#define HDESK unsigned int
#define HWND  unsigned int

typedef struct tagBSMINFO {
	UINT  cbSize;
	HDESK hdesk;
	HWND  hwnd;
	LUID  luid;
} BSMINFO, *PBSMINFO;

/* Window stations */
#define WINSTA_ENUMDESKTOPS         0x0001
#define WINSTA_READATTRIBUTES       0x0002
#define WINSTA_ACCESSCLIPBOARD      0x0004
#define WINSTA_CREATEDESKTOP        0x0008
#define WINSTA_WRITEATTRIBUTES      0x0010
#define WINSTA_ACCESSGLOBALATOMS    0x0020
#define WINSTA_EXITWINDOWS          0x0040
#define WINSTA_ENUMERATE            0x0100
#define WINSTA_READSCREEN           0x0200
#define WINSTA_ALL_ACCESS           0x037f

/* Desktops */
#define DESKTOP_READOBJECTS         0x0001
#define DESKTOP_CREATEWINDOW        0x0002
#define DESKTOP_CREATEMENU          0x0004
#define DESKTOP_HOOKCONTROL         0x0008
#define DESKTOP_JOURNALRECORD       0x0010
#define DESKTOP_JOURNALPLAYBACK     0x0020
#define DESKTOP_ENUMERATE           0x0040
#define DESKTOP_WRITEOBJECTS        0x0080
#define DESKTOP_SWITCHDESKTOP       0x0100


/* flags for FILTERKEYS dwFlags field */
#define FKF_AVAILABLE       0x00000002
#define FKF_CLICKON         0x00000040
#define FKF_FILTERKEYSON    0x00000001
#define FKF_HOTKEYACTIVE    0x00000004
#define FKF_HOTKEYSOUND     0x00000010
#define FKF_CONFIRMHOTKEY   0x00000008
#define FKF_INDICATOR       0x00000020

typedef struct tagFILTERKEYS
{
	UINT   cbSize;
	DWORD  dwFlags;
	DWORD  iWaitMSec;
	DWORD  iDelayMSec;
	DWORD  iRepeatMSec;
	DWORD  iBounceMSec;
} FILTERKEYS, *LPFILTERKEYS;

/* flags for TOGGLEKEYS dwFlags field */
#define TKF_AVAILABLE       0x00000002
#define TKF_CONFIRMHOTKEY   0x00000008
#define TKF_HOTKEYACTIVE    0x00000004
#define TKF_HOTKEYSOUND     0x00000010
#define TKF_TOGGLEKEYSON    0x00000001

typedef struct tagTOGGLEKEYS
{
	DWORD   cbSize;
	DWORD   dwFlags;
} TOGGLEKEYS, *LPTOGGLEKEYS;

/* flags for MOUSEKEYS dwFlags field */
#define MKF_AVAILABLE       0x00000002
#define MKF_CONFIRMHOTKEY   0x00000008
#define MKF_HOTKEYACTIVE    0x00000004
#define MKF_HOTKEYSOUND     0x00000010
#define MKF_INDICATOR       0x00000020
#define MKF_MOUSEKEYSON     0x00000001
#define MKF_MODIFIERS       0x00000040
#define MKF_REPLACENUMBERS  0x00000080

typedef struct tagMOUSEKEYS
{
	UINT    cbSize;
	DWORD   dwFlags;
	DWORD   iMaxSpeed;
	DWORD   iTimeToMaxSpeed;
	DWORD   iCtrlSpeed;
	DWORD   dwReserved1;
	DWORD   dwReserved2;
} MOUSEKEYS, *LPMOUSEKEYS;

/* struct and defines for GetMouseMovePointsEx */
#define GMMP_USE_DISPLAY_POINTS 1
#define GMMP_USE_HIGH_RESOLUTION_POINTS 2

typedef struct tagMOUSEMOVEPOINT {
	int x;
	int y;
	DWORD time;
	ULONG_PTR dwExtraInfo;
} MOUSEMOVEPOINT,*PMOUSEMOVEPOINT,*LPMOUSEMOVEPOINT;

/* flags for STICKYKEYS dwFlags field */
#define SKF_AUDIBLEFEEDBACK 0x00000040
#define SKF_AVAILABLE       0x00000002
#define SKF_CONFIRMHOTKEY   0x00000008
#define SKF_HOTKEYACTIVE    0x00000004
#define SKF_HOTKEYSOUND     0x00000010
#define SKF_INDICATOR       0x00000020
#define SKF_STICKYKEYSON    0x00000001
#define SKF_TRISTATE        0x00000080
#define SKF_TWOKEYSOFF      0x00000100

typedef struct tagSTICKYKEYS
{
	DWORD   cbSize;
	DWORD   dwFlags;
} STICKYKEYS, *LPSTICKYKEYS;

/* flags for ACCESSTIMEOUT dwFlags field */
#define ATF_ONOFFFEEDBACK   0x00000002
#define ATF_AVAILABLE       0x00000004
#define ATF_TIMEOUTON       0x00000001

typedef struct tagACCESSTIMEOUT
{
	UINT    cbSize;
	DWORD   dwFlags;
	DWORD   iTimeOutMSec;
} ACCESSTIMEOUT, *LPACCESSTIMEOUT;

/* flags for SERIALKEYS dwFlags field */
#define SERKF_ACTIVE        0x00000008
#define SERKF_AVAILABLE     0x00000002
#define SERKF_INDICATOR     0x00000004
#define SERKF_SERIALKEYSON  0x00000001

typedef struct tagSERIALKEYSA
{
	UINT  cbSize;
	DWORD  dwFlags;
	LPSTR  lpszActivePort;
	LPSTR  lpszPort;
	UINT  iBaudRate;
	UINT  iPortState;
	UINT  iActive;
} SERIALKEYSA, *LPSERIALKEYSA;

typedef struct tagSERIALKEYSW {
	UINT  cbSize;
	DWORD   dwFlags;
	LPWSTR  lpszActivePort;
	LPWSTR  lpszPort;
	UINT   iBaudRate;
	UINT   iPortState;
	UINT   iActive;
} SERIALKEYSW,*LPSERIALKEYSW;

/* flags for SOUNDSENTRY dwFlags field */
#define SSF_AVAILABLE       0x00000002
#define SSF_SOUNDSENTRYON   0x00000001

#define SSTF_BORDER         0x00000002
#define SSTF_CHARS          0x00000001
#define SSTF_DISPLAY        0x00000003
#define SSTF_NONE           0x00000000

#define SSGF_DISPLAY        0x00000003
#define SSGF_NONE           0x00000000

#define SSWF_DISPLAY        0x00000003
#define SSWF_NONE           0x00000000
#define SSWF_TITLE          0x00000001
#define SSWF_WINDOW         0x00000002

typedef struct tagSOUNDSENTRYA
{
	UINT  cbSize;
	DWORD  dwFlags;
	DWORD  iFSTextEffect;
	DWORD  iFSTextEffectMSec;
	DWORD  iFSTextEffectColorBits;
	DWORD  iFSGrafEffect;
	DWORD  iFSGrafEffectMSec;
	DWORD  iFSGrafEffectColor;
	DWORD  iWindowsEffect;
	DWORD  iWindowsEffectMSec;
	LPSTR  lpszWindowsEffectDLL;
	DWORD  iWindowsEffectOrdinal;
} SOUNDSENTRYA, *LPSOUNDSENTRYA;

typedef struct tagSOUNDSENTRYW
{
	UINT  cbSize;
	DWORD  dwFlags;
	DWORD  iFSTextEffect;
	DWORD  iFSTextEffectMSec;
	DWORD  iFSTextEffectColorBits;
	DWORD  iFSGrafEffect;
	DWORD  iFSGrafEffectMSec;
	DWORD  iFSGrafEffectColor;
	DWORD  iWindowsEffect;
	DWORD  iWindowsEffectMSec;
	LPWSTR  lpszWindowsEffectDLL;
	DWORD  iWindowsEffectOrdinal;
} SOUNDSENTRYW, *LPSOUNDSENTRYW;

/* flags for HIGHCONTRAST dwFlags field */
#define HCF_HIGHCONTRASTON  0x00000001
#define HCF_AVAILABLE       0x00000002
#define HCF_HOTKEYACTIVE    0x00000004
#define HCF_CONFIRMHOTKEY   0x00000008
#define HCF_HOTKEYSOUND     0x00000010
#define HCF_INDICATOR       0x00000020
#define HCF_HOTKEYAVAILABLE 0x00000040

typedef struct tagHIGHCONTRASTA
{
	UINT  cbSize;
	DWORD   dwFlags;
	LPSTR   lpszDefaultScheme;
} HIGHCONTRASTA, *LPHIGHCONTRASTA;

typedef struct tagHIGHCONTRASTW
{
	UINT  cbSize;
	DWORD   dwFlags;
	LPWSTR  lpszDefaultScheme;
} HIGHCONTRASTW, *LPHIGHCONTRASTW;

typedef struct tagEVENTMSG
{
	UINT  message;
	UINT  paramL;
	UINT  paramH;
	DWORD   time;
	HWND  hwnd;
} EVENTMSG, *PEVENTMSG, *LPEVENTMSG;

/* WH_KEYBOARD_LL structure */
typedef struct tagKBDLLHOOKSTRUCT
{
	DWORD   vkCode;
	DWORD   scanCode;
	DWORD   flags;
	DWORD   time;
	ULONG_PTR dwExtraInfo;
} KBDLLHOOKSTRUCT, *LPKBDLLHOOKSTRUCT, *PKBDLLHOOKSTRUCT;

#define LLKHF_EXTENDED   (KF_EXTENDED >> 8)
#define LLKHF_INJECTED   0x00000010
#define LLKHF_ALTDOWN    (KF_ALTDOWN >> 8)
#define LLKHF_UP         (KF_UP >> 8)

#define LLMHF_INJECTED  0x00000001

#define HKL_PREV   0
#define HKL_NEXT   1

#define KLF_ACTIVATE       0x00000001
#define KLF_SUBSTITUTE_OK  0x00000002
#define KLF_UNLOADPREVIOUS 0x00000004
#define KLF_REORDER        0x00000008
#define KLF_REPLACELANG    0x00000010
#define KLF_NOTELLSHELL    0x00000080
#define KLF_SETFORPROCESS  0x00000100
#define KLF_SHIFTLOCK      0x00010000
#define KLF_RESET          0x40000000

#define KL_NAMELENGTH      9

typedef struct tagMOUSEINPUT
{
	LONG    dx;
	LONG    dy;
	DWORD   mouseData;
	DWORD   dwFlags;
	DWORD   time;
	ULONG_PTR dwExtraInfo;
} MOUSEINPUT, *PMOUSEINPUT, *LPMOUSEINPUT;

typedef struct tagKEYBDINPUT
{
	WORD    wVk;
	WORD    wScan;
	DWORD   dwFlags;
	DWORD   time;
	ULONG_PTR dwExtraInfo;
} KEYBDINPUT, *PKEYBDINPUT, *LPKEYBDINPUT;

typedef struct tagHARDWAREINPUT
{
	DWORD   uMsg;
	WORD    wParamL;
	WORD    wParamH;
} HARDWAREINPUT, *PHARDWAREINPUT, *LPHARDWAREINPUT;

#define INPUT_MOUSE     0
#define INPUT_KEYBOARD  1
#define INPUT_HARDWARE  2

typedef struct tagINPUT
{
	DWORD type;
	union
	{
		MOUSEINPUT      mi;
		KEYBDINPUT      ki;
		HARDWAREINPUT   hi;
	} DUMMYUNIONNAME;
} INPUT, *PINPUT, *LPINPUT;

typedef struct tagRAWHID {
	DWORD dwSizeHid;
	DWORD dwCount;
	BYTE bRawData;
} RAWHID, *LPRAWHID;

typedef struct tagRAWKEYBOARD {
	USHORT MakeCode;
	USHORT Flags;
	USHORT Reserved;
	USHORT VKey;
	UINT Message;
	ULONG ExtraInformation;
} RAWKEYBOARD, *PRAWKEYBOARD, *LPRAWKEYBOARD;

typedef struct tagRAWMOUSE {
	USHORT usFlags;
	union {
		ULONG ulButtons;
		struct {
			USHORT usButtonFlags;
			USHORT usButtonData;
		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME;
	ULONG ulRawButtons;
	LONG  lLastX;
	LONG  lLastY;
	ULONG ulExtraInformation;
} RAWMOUSE, *PRAWMOUSE, *LPRAWMOUSE;

/* Messages */
#define WM_NULL                 0x0000
#define WM_CREATE               0x0001
#define WM_DESTROY              0x0002
#define WM_MOVE                 0x0003
#define WM_SIZEWAIT             0x0004
#define WM_SIZE                 0x0005
#define WM_ACTIVATE             0x0006
#define WM_SETFOCUS             0x0007
#define WM_KILLFOCUS            0x0008
#define WM_SETVISIBLE           0x0009
#define WM_ENABLE               0x000a
#define WM_SETREDRAW            0x000b
#define WM_SETTEXT              0x000c
#define WM_GETTEXT              0x000d
#define WM_GETTEXTLENGTH        0x000e
#define WM_PAINT                0x000f
#define WM_CLOSE                0x0010
#define WM_QUERYENDSESSION      0x0011
#define WM_QUIT                 0x0012
#define WM_QUERYOPEN            0x0013
#define WM_ERASEBKGND           0x0014
#define WM_SYSCOLORCHANGE       0x0015
#define WM_ENDSESSION           0x0016
#define WM_SYSTEMERROR          0x0017
#define WM_SHOWWINDOW           0x0018
#define WM_CTLCOLOR             0x0019
#define WM_WININICHANGE         0x001a
#define WM_SETTINGCHANGE        WM_WININICHANGE
#define WM_DEVMODECHANGE        0x001b
#define WM_ACTIVATEAPP          0x001c
#define WM_FONTCHANGE           0x001d
#define WM_TIMECHANGE           0x001e
#define WM_CANCELMODE           0x001f
#define WM_SETCURSOR            0x0020
#define WM_MOUSEACTIVATE        0x0021
#define WM_CHILDACTIVATE        0x0022
#define WM_QUEUESYNC            0x0023
#define WM_GETMINMAXINFO        0x0024

#define WM_PAINTICON            0x0026
#define WM_ICONERASEBKGND       0x0027
#define WM_NEXTDLGCTL           0x0028
#define WM_ALTTABACTIVE         0x0029
#define WM_SPOOLERSTATUS        0x002a
#define WM_DRAWITEM             0x002b
#define WM_MEASUREITEM          0x002c
#define WM_DELETEITEM           0x002d
#define WM_VKEYTOITEM           0x002e
#define WM_CHARTOITEM           0x002f
#define WM_SETFONT              0x0030
#define WM_GETFONT              0x0031
#define WM_SETHOTKEY            0x0032
#define WM_GETHOTKEY            0x0033
#define WM_FILESYSCHANGE        0x0034
#define WM_ISACTIVEICON         0x0035
#define WM_QUERYPARKICON        0x0036
#define WM_QUERYDRAGICON        0x0037
#define WM_QUERYSAVESTATE       0x0038
#define WM_COMPAREITEM          0x0039
#define WM_TESTING              0x003a

#define WM_GETOBJECT            0x003d

#define WM_ACTIVATESHELLWINDOW	0x003e

#define WM_COMPACTING		0x0041

#define WM_COMMNOTIFY		0x0044
#define WM_WINDOWPOSCHANGING 	0x0046
#define WM_WINDOWPOSCHANGED 	0x0047
#define WM_POWER		0x0048

  /* Win32 4.0 messages */
#define WM_COPYDATA		0x004a
#define WM_CANCELJOURNAL	0x004b
#define WM_KEYF1		0x004d
#define WM_NOTIFY		0x004e
#define WM_INPUTLANGCHANGEREQUEST       0x0050
#define WM_INPUTLANGCHANGE              0x0051
#define WM_TCARD                0x0052
#define WM_HELP			0x0053
#define WM_USERCHANGED		0x0054
#define WM_NOTIFYFORMAT		0x0055

#define WM_CONTEXTMENU		0x007b
#define WM_STYLECHANGING 	0x007c
#define WM_STYLECHANGED		0x007d
#define WM_DISPLAYCHANGE        0x007e
#define WM_GETICON		0x007f
#define WM_SETICON		0x0080

  /* Non-client system messages */
#define WM_NCCREATE         0x0081
#define WM_NCDESTROY        0x0082
#define WM_NCCALCSIZE       0x0083
#define WM_NCHITTEST        0x0084
#define WM_NCPAINT          0x0085
#define WM_NCACTIVATE       0x0086

#define WM_GETDLGCODE	    0x0087
#define WM_SYNCPAINT	    0x0088
#define WM_SYNCTASK	    0x0089

  /* Non-client mouse messages */
#define WM_NCMOUSEMOVE      0x00a0
#define WM_NCLBUTTONDOWN    0x00a1
#define WM_NCLBUTTONUP      0x00a2
#define WM_NCLBUTTONDBLCLK  0x00a3
#define WM_NCRBUTTONDOWN    0x00a4
#define WM_NCRBUTTONUP      0x00a5
#define WM_NCRBUTTONDBLCLK  0x00a6
#define WM_NCMBUTTONDOWN    0x00a7
#define WM_NCMBUTTONUP      0x00a8
#define WM_NCMBUTTONDBLCLK  0x00a9

#define WM_NCXBUTTONDOWN    0x00ab
#define WM_NCXBUTTONUP      0x00ac
#define WM_NCXBUTTONDBLCLK  0x00ad

  /* Raw input */
#define WM_INPUT_DEVICE_CHANGE 0x00fe
#define WM_INPUT            0x00ff

  /* Keyboard messages */
#define WM_KEYDOWN          0x0100
#define WM_KEYUP            0x0101
#define WM_CHAR             0x0102
#define WM_DEADCHAR         0x0103
#define WM_SYSKEYDOWN       0x0104
#define WM_SYSKEYUP         0x0105
#define WM_SYSCHAR          0x0106
#define WM_SYSDEADCHAR      0x0107
#define WM_UNICHAR          0x0109
#define WM_KEYFIRST         WM_KEYDOWN
#define WM_KEYLAST          0x0109

/* Win32 4.0 messages for IME */
#define WM_IME_STARTCOMPOSITION     0x010d
#define WM_IME_ENDCOMPOSITION       0x010e
#define WM_IME_COMPOSITION          0x010f
#define WM_IME_KEYLAST              0x010f

#define WM_INITDIALOG       0x0110
#define WM_COMMAND          0x0111
#define WM_SYSCOMMAND       0x0112
#define WM_TIMER	    0x0113

  /* scroll messages */
#define WM_HSCROLL          0x0114
#define WM_VSCROLL          0x0115

/* Menu messages */
#define WM_INITMENU         0x0116
#define WM_INITMENUPOPUP    0x0117

#define WM_MENUSELECT       0x011F
#define WM_MENUCHAR         0x0120
#define WM_ENTERIDLE        0x0121

#define WM_MENURBUTTONUP    0x0122
#define WM_MENUDRAG         0x0123
#define WM_MENUGETOBJECT    0x0124
#define WM_UNINITMENUPOPUP  0x0125
#define WM_MENUCOMMAND      0x0126

#define WM_CHANGEUISTATE    0x0127
#define WM_UPDATEUISTATE    0x0128
#define WM_QUERYUISTATE     0x0129

/* UI flags for WM_*UISTATE */
/* for low-order word of wparam */
#define UIS_SET                         1
#define UIS_CLEAR                       2
#define UIS_INITIALIZE                  3
/* for hi-order word of wparam */
#define UISF_HIDEFOCUS                  0x1
#define UISF_HIDEACCEL                  0x2
#define UISF_ACTIVE                     0x4

#define WM_LBTRACKPOINT     0x0131

  /* Win32 CTLCOLOR messages */
#define WM_CTLCOLORMSGBOX    0x0132
#define WM_CTLCOLOREDIT      0x0133
#define WM_CTLCOLORLISTBOX   0x0134
#define WM_CTLCOLORBTN       0x0135
#define WM_CTLCOLORDLG       0x0136
#define WM_CTLCOLORSCROLLBAR 0x0137
#define WM_CTLCOLORSTATIC    0x0138

#define MN_GETHMENU          0x01E1

  /* Mouse messages */
#define WM_MOUSEMOVE	    0x0200
#define WM_LBUTTONDOWN	    0x0201
#define WM_LBUTTONUP	    0x0202
#define WM_LBUTTONDBLCLK    0x0203
#define WM_RBUTTONDOWN	    0x0204
#define WM_RBUTTONUP	    0x0205
#define WM_RBUTTONDBLCLK    0x0206
#define WM_MBUTTONDOWN	    0x0207
#define WM_MBUTTONUP	    0x0208
#define WM_MBUTTONDBLCLK    0x0209
#define WM_MOUSEWHEEL       0x020A
#define WM_XBUTTONDOWN      0x020B
#define WM_XBUTTONUP        0x020C
#define WM_XBUTTONDBLCLK    0x020D
#define WM_MOUSEHWHEEL      0x020E

#define XBUTTON1            0x0001
#define XBUTTON2            0x0002

#define WM_MOUSEFIRST       0x0200
#define WM_MOUSELAST        0x020E

#define WHEEL_DELTA      120
#define WHEEL_PAGESCROLL  (UINT_MAX)
#define GET_WHEEL_DELTA_WPARAM(wParam)  ((short)HIWORD(wParam))

#define WM_PARENTNOTIFY     0x0210
#define WM_ENTERMENULOOP    0x0211
#define WM_EXITMENULOOP     0x0212
#define WM_NEXTMENU	    0x0213

  /* Win32 4.0 messages */
#define WM_SIZING	    0x0214
#define WM_CAPTURECHANGED   0x0215
#define WM_MOVING	    0x0216
#define WM_POWERBROADCAST   0x0218
#define WM_DEVICECHANGE     0x0219

/* wParam for WM_SIZING message */
#define WMSZ_LEFT           1
#define WMSZ_RIGHT          2
#define WMSZ_TOP            3
#define WMSZ_TOPLEFT        4
#define WMSZ_TOPRIGHT       5
#define WMSZ_BOTTOM         6
#define WMSZ_BOTTOMLEFT     7
#define WMSZ_BOTTOMRIGHT    8

/* wParam for WM_POWERBROADCAST */
#define PBT_APMQUERYSUSPEND       0x0000
#define PBT_APMQUERYSTANDBY       0x0001
#define PBT_APMQUERYSUSPENDFAILED 0x0002
#define PBT_APMQUERYSTANDBYFAILED 0x0003
#define PBT_APMSUSPEND            0x0004
#define PBT_APMSTANDBY            0x0005
#define PBT_APMRESUMECRITICAL     0x0006
#define PBT_APMRESUMESUSPEND      0x0007
#define PBT_APMRESUMESTANDBY      0x0008
#define PBT_APMBATTERYLOW         0x0009
#define PBT_APMPOWERSTATUSCHANGE  0x000A
#define PBT_APMOEMEVENT           0x000B
#define PBT_APMRESUMEAUTOMATIC    0x0012

#define PBTF_APMRESUMEFROMFAILURE       0x00000001

  /* MDI messages */
#define WM_MDICREATE	    0x0220
#define WM_MDIDESTROY	    0x0221
#define WM_MDIACTIVATE	    0x0222
#define WM_MDIRESTORE	    0x0223
#define WM_MDINEXT	    0x0224
#define WM_MDIMAXIMIZE	    0x0225
#define WM_MDITILE	    0x0226
#define WM_MDICASCADE	    0x0227
#define WM_MDIICONARRANGE   0x0228
#define WM_MDIGETACTIVE     0x0229
#define WM_MDIREFRESHMENU   0x0234

  /* D&D messages */
#define WM_DROPOBJECT	    0x022A
#define WM_QUERYDROPOBJECT  0x022B
#define WM_BEGINDRAG	    0x022C
#define WM_DRAGLOOP	    0x022D
#define WM_DRAGSELECT	    0x022E
#define WM_DRAGMOVE	    0x022F
#define WM_MDISETMENU	    0x0230

#define WM_ENTERSIZEMOVE    0x0231
#define WM_EXITSIZEMOVE     0x0232
#define WM_DROPFILES	    0x0233


/* Win32 4.0 messages for IME */
#define WM_IME_SETCONTEXT           0x0281
#define WM_IME_NOTIFY               0x0282
#define WM_IME_CONTROL              0x0283
#define WM_IME_COMPOSITIONFULL      0x0284
#define WM_IME_SELECT               0x0285
#define WM_IME_CHAR                 0x0286
/* Win32 5.0 messages for IME */
#define WM_IME_REQUEST              0x0288

/* Win32 4.0 messages for IME */
#define WM_IME_KEYDOWN              0x0290
#define WM_IME_KEYUP                0x0291

#define WM_NCMOUSEHOVER     0x02A0
#define WM_MOUSEHOVER       0x02A1
#define WM_MOUSELEAVE       0x02A3
#define WM_NCMOUSELEAVE     0x02A2

#define WM_WTSSESSION_CHANGE        0x02B1

#define WM_TABLET_FIRST             0x02c0
#define WM_TABLET_LAST              0x02df

/* Clipboard command messages */
#define WM_CUT               0x0300
#define WM_COPY              0x0301
#define WM_PASTE             0x0302
#define WM_CLEAR             0x0303
#define WM_UNDO              0x0304

/* Clipboard owner messages */
#define WM_RENDERFORMAT      0x0305
#define WM_RENDERALLFORMATS  0x0306
#define WM_DESTROYCLIPBOARD  0x0307

/* Clipboard viewer messages */
#define WM_DRAWCLIPBOARD     0x0308
#define WM_PAINTCLIPBOARD    0x0309
#define WM_VSCROLLCLIPBOARD  0x030A
#define WM_SIZECLIPBOARD     0x030B
#define WM_ASKCBFORMATNAME   0x030C
#define WM_CHANGECBCHAIN     0x030D
#define WM_HSCROLLCLIPBOARD  0x030E

#define WM_QUERYNEWPALETTE   0x030F
#define WM_PALETTEISCHANGING 0x0310
#define WM_PALETTECHANGED    0x0311
#define WM_HOTKEY	     0x0312

#define WM_PRINT             0x0317
#define WM_PRINTCLIENT       0x0318
#define WM_APPCOMMAND        0x0319
#define WM_THEMECHANGED      0x031A
#define WM_CLIPBOARDUPDATE   0x031D

#define WM_DWMCOMPOSITIONCHANGED 0x031E
#define WM_DWMNCRENDERINGCHANGED 0x031F
#define WM_DWMCOLORIZATIONCOLORCHANGED 0x0320
#define WM_DWMWINDOWMAXIMIZEDCHANGE 0x0321

#define WM_GETTITLEBARINFOEX 0x033F

#define WM_HANDHELDFIRST     0x0358
#define WM_HANDHELDLAST      0x035F

#define WM_AFXFIRST          0x0360
#define WM_AFXLAST           0x037F

#define WM_PENWINFIRST      0x0380
#define WM_PENWINLAST       0x038F

#define WM_APP               0x8000

#define UNICODE_NOCHAR       0xFFFF

/* MsgWaitForMultipleObjectsEx flags */
#define MWMO_WAITALL         0x0001
#define MWMO_ALERTABLE       0x0002
#define MWMO_INPUTAVAILABLE  0x0004

/* WM_GETDLGCODE values */
#define DLGC_WANTARROWS      0x0001
#define DLGC_WANTTAB         0x0002
#define DLGC_WANTALLKEYS     0x0004
#define DLGC_WANTMESSAGE     0x0004
#define DLGC_HASSETSEL       0x0008
#define DLGC_DEFPUSHBUTTON   0x0010
#define DLGC_UNDEFPUSHBUTTON 0x0020
#define DLGC_RADIOBUTTON     0x0040
#define DLGC_WANTCHARS       0x0080
#define DLGC_STATIC          0x0100
#define DLGC_BUTTON          0x2000

/* Standard dialog button IDs */
#define IDOK                1
#define IDCANCEL            2
#define IDABORT             3
#define IDRETRY             4
#define IDIGNORE            5
#define IDYES               6
#define IDNO                7
#define IDCLOSE             8
#define IDHELP              9
#define IDTRYAGAIN         10
#define IDCONTINUE         11

#ifndef IDTIMEOUT
#define IDTIMEOUT       32000
#endif

/* Used for EnumDisplaySettingsEx */
#define ENUM_CURRENT_SETTINGS  ((DWORD) -1)
#define ENUM_REGISTRY_SETTINGS ((DWORD) -2)

/* SetLayeredWindowAttributes() flags */
#define LWA_COLORKEY        0x00000001
#define LWA_ALPHA           0x00000002

/* UpdateLayeredWindow() flags */
#define ULW_COLORKEY        0x00000001
#define ULW_ALPHA           0x00000002
#define ULW_OPAQUE          0x00000004
#define ULW_EX_NORESIZE     0x00000008

/***** Window hooks *****/

  /* Hook values */
#define WH_MIN		    (-1)
#define WH_MSGFILTER	    (-1)
#define WH_JOURNALRECORD    0
#define WH_JOURNALPLAYBACK  1
#define WH_KEYBOARD	    2
#define WH_GETMESSAGE	    3
#define WH_CALLWNDPROC	    4
#define WH_CBT		    5
#define WH_SYSMSGFILTER	    6
#define WH_MOUSE	    7
#define WH_HARDWARE	    8
#define WH_DEBUG	    9
#define WH_SHELL            10
#define WH_FOREGROUNDIDLE   11
#define WH_CALLWNDPROCRET   12
#define WH_KEYBOARD_LL      13
#define WH_MOUSE_LL         14
#define WH_MAX              14

#define WH_MINHOOK          WH_MIN
#define WH_MAXHOOK          WH_MAX

  /* Hook action codes */
#define HC_ACTION           0
#define HC_GETNEXT          1
#define HC_SKIP             2
#define HC_NOREMOVE         3
#define HC_NOREM            HC_NOREMOVE
#define HC_SYSMODALON       4
#define HC_SYSMODALOFF      5

  /* CallMsgFilter() values */
#define MSGF_DIALOGBOX      0
#define MSGF_MESSAGEBOX     1
#define MSGF_MENU           2
#define MSGF_MOVE           3
#define MSGF_SIZE           4
#define MSGF_SCROLLBAR      5
#define MSGF_NEXTWINDOW     6
#define MSGF_MAX            8
#define MSGF_USER           0x1000
#define MSGF_DDEMGR         0x8001

/* WM_KEYUP/DOWN/CHAR HIWORD(lParam) flags */
#define KF_EXTENDED         0x0100
#define KF_DLGMODE          0x0800
#define KF_MENUMODE         0x1000
#define KF_ALTDOWN          0x2000
#define KF_REPEAT           0x4000
#define KF_UP               0x8000

/* Virtual key codes */
#define VK_LBUTTON          0x01
#define VK_RBUTTON          0x02
#define VK_CANCEL           0x03
#define VK_MBUTTON          0x04
#define VK_XBUTTON1         0x05
#define VK_XBUTTON2         0x06
/*                          0x07  Undefined */
#define VK_BACK             0x08
#define VK_TAB              0x09
/*                          0x0A-0x0B  Undefined */
#define VK_CLEAR            0x0C
#define VK_RETURN           0x0D
/*                          0x0E-0x0F  Undefined */
#define VK_SHIFT            0x10
#define VK_CONTROL          0x11
#define VK_MENU             0x12
#define VK_PAUSE            0x13
#define VK_CAPITAL          0x14

#define VK_KANA             0x15
#define VK_HANGEUL          0x15
#define VK_HANGUL           0x15
#define VK_JUNJA            0x17
#define VK_FINAL            0x18
#define VK_HANJA            0x19
#define VK_KANJI            0x19

/*                          0x1A       Undefined */
#define VK_ESCAPE           0x1B

#define VK_CONVERT          0x1C
#define VK_NONCONVERT       0x1D
#define VK_ACCEPT           0x1E
#define VK_MODECHANGE       0x1F

#define VK_SPACE            0x20
#define VK_PRIOR            0x21
#define VK_NEXT             0x22
#define VK_END              0x23
#define VK_HOME             0x24
#define VK_LEFT             0x25
#define VK_UP               0x26
#define VK_RIGHT            0x27
#define VK_DOWN             0x28
#define VK_SELECT           0x29
#define VK_PRINT            0x2A /* OEM specific in Windows 3.1 SDK */
#define VK_EXECUTE          0x2B
#define VK_SNAPSHOT         0x2C
#define VK_INSERT           0x2D
#define VK_DELETE           0x2E
#define VK_HELP             0x2F
/* VK_0 - VK-9              0x30-0x39  Use ASCII instead */
/*                          0x3A-0x40  Undefined */
/* VK_A - VK_Z              0x41-0x5A  Use ASCII instead */
#define VK_LWIN             0x5B
#define VK_RWIN             0x5C
#define VK_APPS             0x5D
/*                          0x5E Unassigned */
#define VK_SLEEP            0x5F
#define VK_NUMPAD0          0x60
#define VK_NUMPAD1          0x61
#define VK_NUMPAD2          0x62
#define VK_NUMPAD3          0x63
#define VK_NUMPAD4          0x64
#define VK_NUMPAD5          0x65
#define VK_NUMPAD6          0x66
#define VK_NUMPAD7          0x67
#define VK_NUMPAD8          0x68
#define VK_NUMPAD9          0x69
#define VK_MULTIPLY         0x6A
#define VK_ADD              0x6B
#define VK_SEPARATOR        0x6C
#define VK_SUBTRACT         0x6D
#define VK_DECIMAL          0x6E
#define VK_DIVIDE           0x6F
#define VK_F1               0x70
#define VK_F2               0x71
#define VK_F3               0x72
#define VK_F4               0x73
#define VK_F5               0x74
#define VK_F6               0x75
#define VK_F7               0x76
#define VK_F8               0x77
#define VK_F9               0x78
#define VK_F10              0x79
#define VK_F11              0x7A
#define VK_F12              0x7B
#define VK_F13              0x7C
#define VK_F14              0x7D
#define VK_F15              0x7E
#define VK_F16              0x7F
#define VK_F17              0x80
#define VK_F18              0x81
#define VK_F19              0x82
#define VK_F20              0x83
#define VK_F21              0x84
#define VK_F22              0x85
#define VK_F23              0x86
#define VK_F24              0x87
/*                          0x88-0x8F  Unassigned */
#define VK_NUMLOCK          0x90
#define VK_SCROLL           0x91
#define VK_OEM_NEC_EQUAL    0x92
#define VK_OEM_FJ_JISHO     0x92
#define VK_OEM_FJ_MASSHOU   0x93
#define VK_OEM_FJ_TOUROKU   0x94
#define VK_OEM_FJ_LOYA      0x95
#define VK_OEM_FJ_ROYA      0x96
/*                          0x97-0x9F  Unassigned */
/*
 * differencing between right and left shift/control/alt key.
 * Used only by GetAsyncKeyState() and GetKeyState().
 */
#define VK_LSHIFT           0xA0
#define VK_RSHIFT           0xA1
#define VK_LCONTROL         0xA2
#define VK_RCONTROL         0xA3
#define VK_LMENU            0xA4
#define VK_RMENU            0xA5

#define VK_BROWSER_BACK        0xA6
#define VK_BROWSER_FORWARD     0xA7
#define VK_BROWSER_REFRESH     0xA8
#define VK_BROWSER_STOP        0xA9
#define VK_BROWSER_SEARCH      0xAA
#define VK_BROWSER_FAVORITES   0xAB
#define VK_BROWSER_HOME        0xAC
#define VK_VOLUME_MUTE         0xAD
#define VK_VOLUME_DOWN         0xAE
#define VK_VOLUME_UP           0xAF
#define VK_MEDIA_NEXT_TRACK    0xB0
#define VK_MEDIA_PREV_TRACK    0xB1
#define VK_MEDIA_STOP          0xB2
#define VK_MEDIA_PLAY_PAUSE    0xB3
#define VK_LAUNCH_MAIL         0xB4
#define VK_LAUNCH_MEDIA_SELECT 0xB5
#define VK_LAUNCH_APP1         0xB6
#define VK_LAUNCH_APP2         0xB7

/*                          0xB8-0xB9  Unassigned */
#define VK_OEM_1            0xBA
#define VK_OEM_PLUS         0xBB
#define VK_OEM_COMMA        0xBC
#define VK_OEM_MINUS        0xBD
#define VK_OEM_PERIOD       0xBE
#define VK_OEM_2            0xBF
#define VK_OEM_3            0xC0
/*                          0xC1-0xDA  Unassigned */
#define VK_OEM_4            0xDB
#define VK_OEM_5            0xDC
#define VK_OEM_6            0xDD
#define VK_OEM_7            0xDE
#define VK_OEM_8            0xDF
/*                          0xE0       OEM specific */
#define VK_OEM_AX           0xE1  /* "AX" key on Japanese AX keyboard */
#define VK_OEM_102          0xE2  /* "<>" or "\|" on RT 102-key keyboard */
#define VK_ICO_HELP         0xE3  /* Help key on ICO */
#define VK_ICO_00           0xE4  /* 00 key on ICO */
#define VK_PROCESSKEY       0xE5

/*                          0xE6       OEM specific */
/*                          0xE7-0xE8  Unassigned */
/*                          0xE9-0xF5  OEM specific */

#define VK_ATTN             0xF6
#define VK_CRSEL            0xF7
#define VK_EXSEL            0xF8
#define VK_EREOF            0xF9
#define VK_PLAY             0xFA
#define VK_ZOOM             0xFB
#define VK_NONAME           0xFC
#define VK_PA1              0xFD
#define VK_OEM_CLEAR        0xFE

/* MapVirtualKey translation types */
#define MAPVK_VK_TO_VSC     0
#define MAPVK_VSC_TO_VK     1
#define MAPVK_VK_TO_CHAR    2
#define MAPVK_VSC_TO_VK_EX  3
#define MAPVK_VK_TO_VSC_EX  4

  /* Key status flags for mouse events */
#define MK_LBUTTON	    0x0001
#define MK_RBUTTON	    0x0002
#define MK_SHIFT	    0x0004
#define MK_CONTROL	    0x0008
#define MK_MBUTTON	    0x0010
#define MK_XBUTTON1         0x0020
#define MK_XBUTTON2         0x0040


#define TME_HOVER       0x00000001
#define TME_LEAVE       0x00000002
#define TME_NONCLIENT   0x00000010
#define TME_QUERY       0x40000000
#define TME_CANCEL      0x80000000

#define HOVER_DEFAULT   0xFFFFFFFF

typedef struct tagTRACKMOUSEEVENT {
	DWORD cbSize;
	DWORD dwFlags;
	HWND  hwndTrack;
	DWORD dwHoverTime;
} TRACKMOUSEEVENT, *LPTRACKMOUSEEVENT;

  /* Queue status flags */
#define QS_KEY		0x0001
#define QS_MOUSEMOVE	0x0002
#define QS_MOUSEBUTTON	0x0004
#define QS_MOUSE	(QS_MOUSEMOVE | QS_MOUSEBUTTON)
#define QS_POSTMESSAGE	0x0008
#define QS_TIMER	0x0010
#define QS_PAINT	0x0020
#define QS_SENDMESSAGE	0x0040
#define QS_HOTKEY	0x0080
#define QS_ALLPOSTMESSAGE 0x0100
#define QS_RAWINPUT       0x0400
#define QS_INPUT	(QS_MOUSE | QS_KEY | QS_RAWINPUT)
#define QS_ALLEVENTS	(QS_INPUT | QS_POSTMESSAGE | QS_TIMER | QS_PAINT | QS_HOTKEY)
#define QS_ALLINPUT     (QS_ALLEVENTS | QS_SENDMESSAGE)

/* Extra (undocumented) queue wake bits - see "Undoc. Windows" */
#define QS_SMRESULT      0x8000

/* InSendMessageEx flags */
#define ISMEX_NOSEND      0x00000000
#define ISMEX_SEND        0x00000001
#define ISMEX_NOTIFY      0x00000002
#define ISMEX_CALLBACK    0x00000004
#define ISMEX_REPLIED     0x00000008

#define DDL_READWRITE	0x0000
#define DDL_READONLY	0x0001
#define DDL_HIDDEN	0x0002
#define DDL_SYSTEM	0x0004
#define DDL_DIRECTORY	0x0010
#define DDL_ARCHIVE	0x0020

#define DDL_POSTMSGS	0x2000
#define DDL_DRIVES	0x4000
#define DDL_EXCLUSIVE	0x8000

  /* Shell hook values */
#define HSHELL_WINDOWCREATED       1
#define HSHELL_WINDOWDESTROYED     2
#define HSHELL_ACTIVATESHELLWINDOW 3
#define HSHELL_WINDOWACTIVATED     4
#define HSHELL_GETMINRECT          5
#define HSHELL_REDRAW              6
#define HSHELL_TASKMAN             7
#define HSHELL_LANGUAGE            8
#define HSHELL_SYSMENU             9
#define HSHELL_ENDTASK             10
#define HSHELL_ACCESSIBILITYSTATE  11
#define HSHELL_APPCOMMAND          12
#define HSHELL_WINDOWREPLACED      13
#define HSHELL_WINDOWREPLACING     14

#define HSHELL_HIGHBIT             0x8000
#define HSHELL_FLASH               (HSHELL_REDRAW|HSHELL_HIGHBIT)
#define HSHELL_RUDEAPPACTIVATED    (HSHELL_WINDOWACTIVATED|HSHELL_HIGHBIT)

/* App commands */
#define APPCOMMAND_BROWSER_BACKWARD                  1
#define APPCOMMAND_BROWSER_FORWARD                   2
#define APPCOMMAND_BROWSER_REFRESH                   3
#define APPCOMMAND_BROWSER_STOP                      4
#define APPCOMMAND_BROWSER_SEARCH                    5
#define APPCOMMAND_BROWSER_FAVORITES                 6
#define APPCOMMAND_BROWSER_HOME                      7
#define APPCOMMAND_VOLUME_MUTE                       8
#define APPCOMMAND_VOLUME_DOWN                       9
#define APPCOMMAND_VOLUME_UP                         10
#define APPCOMMAND_MEDIA_NEXTTRACK                   11
#define APPCOMMAND_MEDIA_PREVIOUSTRACK               12
#define APPCOMMAND_MEDIA_STOP                        13
#define APPCOMMAND_MEDIA_PLAY_PAUSE                  14
#define APPCOMMAND_LAUNCH_MAIL                       15
#define APPCOMMAND_LAUNCH_MEDIA_SELECT               16
#define APPCOMMAND_LAUNCH_APP1                       17
#define APPCOMMAND_LAUNCH_APP2                       18
#define APPCOMMAND_BASS_DOWN                         19
#define APPCOMMAND_BASS_BOOST                        20
#define APPCOMMAND_BASS_UP                           21
#define APPCOMMAND_TREBLE_DOWN                       22
#define APPCOMMAND_TREBLE_UP                         23
#define APPCOMMAND_MICROPHONE_VOLUME_MUTE            24
#define APPCOMMAND_MICROPHONE_VOLUME_DOWN            25
#define APPCOMMAND_MICROPHONE_VOLUME_UP              26
#define APPCOMMAND_HELP                              27
#define APPCOMMAND_FIND                              28
#define APPCOMMAND_NEW                               29
#define APPCOMMAND_OPEN                              30
#define APPCOMMAND_CLOSE                             31
#define APPCOMMAND_SAVE                              32
#define APPCOMMAND_PRINT                             33
#define APPCOMMAND_UNDO                              34
#define APPCOMMAND_REDO                              35
#define APPCOMMAND_COPY                              36
#define APPCOMMAND_CUT                               37
#define APPCOMMAND_PASTE                             38
#define APPCOMMAND_REPLY_TO_MAIL                     39
#define APPCOMMAND_FORWARD_MAIL                      40
#define APPCOMMAND_SEND_MAIL                         41
#define APPCOMMAND_SPELL_CHECK                       42
#define APPCOMMAND_DICTATE_OR_COMMAND_CONTROL_TOGGLE 43
#define APPCOMMAND_MIC_ON_OFF_TOGGLE                 44
#define APPCOMMAND_CORRECTION_LIST                   45
#define APPCOMMAND_MEDIA_PLAY                        46
#define APPCOMMAND_MEDIA_PAUSE                       47
#define APPCOMMAND_MEDIA_RECORD                      48
#define APPCOMMAND_MEDIA_FAST_FORWARD                49
#define APPCOMMAND_MEDIA_REWIND                      50
#define APPCOMMAND_MEDIA_CHANNEL_UP                  51
#define APPCOMMAND_MEDIA_CHANNEL_DOWN                52
#define APPCOMMAND_DELETE                            53
#define APPCOMMAND_DWM_FLIP3D                        54

#define FAPPCOMMAND_MOUSE 0x8000
#define FAPPCOMMAND_KEY   0
#define FAPPCOMMAND_OEM   0x1000
#define FAPPCOMMAND_MASK  0xF000

#define GET_APPCOMMAND_LPARAM(lParam) ((short)(HIWORD(lParam) & ~FAPPCOMMAND_MASK))
#define GET_DEVICE_LPARAM(lParam)     ((WORD)(HIWORD(lParam) & FAPPCOMMAND_MASK))
#define GET_MOUSEORKEY_LPARAM         GET_DEVICE_LPARAM
#define GET_FLAGS_LPARAM(lParam)      (LOWORD(lParam))
#define GET_KEYSTATE_LPARAM(lParam)   GET_FLAGS_LPARAM(lParam)

/* Predefined Clipboard Formats */
#define CF_TEXT              1
#define CF_BITMAP            2
#define CF_METAFILEPICT      3
#define CF_SYLK              4
#define CF_DIF               5
#define CF_TIFF              6
#define CF_OEMTEXT           7
#define CF_DIB               8
#define CF_PALETTE           9
#define CF_PENDATA          10
#define CF_RIFF             11
#define CF_WAVE             12
#define CF_UNICODETEXT      13
#define CF_ENHMETAFILE      14
#define CF_HDROP            15
#define CF_LOCALE           16
#define CF_DIBV5            17
#define CF_MAX              18

#define CF_OWNERDISPLAY     0x0080
#define CF_DSPTEXT          0x0081
#define CF_DSPBITMAP        0x0082
#define CF_DSPMETAFILEPICT  0x0083
#define CF_DSPENHMETAFILE   0x008E

/* "Private" formats don't get GlobalFree()'d */
#define CF_PRIVATEFIRST     0x0200
#define CF_PRIVATELAST      0x02FF

/* "GDIOBJ" formats do get DeleteObject()'d */
#define CF_GDIOBJFIRST      0x0300
#define CF_GDIOBJLAST       0x03FF


/* types of LoadImage */
#define IMAGE_BITMAP	0
#define IMAGE_ICON	1
#define IMAGE_CURSOR	2
#define IMAGE_ENHMETAFILE	3

/* loadflags to LoadImage */
#define LR_DEFAULTCOLOR		0x0000
#define LR_MONOCHROME		0x0001
#define LR_COLOR		0x0002
#define LR_COPYRETURNORG	0x0004
#define LR_COPYDELETEORG	0x0008
#define LR_LOADFROMFILE		0x0010
#define LR_LOADTRANSPARENT	0x0020
#define LR_DEFAULTSIZE		0x0040
#define LR_VGA_COLOR		0x0080
#define LR_LOADMAP3DCOLORS	0x1000
#define	LR_CREATEDIBSECTION	0x2000
#define LR_COPYFROMRESOURCE	0x4000
#define LR_SHARED		0x8000

/* Flags for DrawIconEx.  */
#define DI_MASK                 0x0001
#define DI_IMAGE                0x0002
#define DI_NORMAL               (DI_MASK | DI_IMAGE)
#define DI_COMPAT               0x0004
#define DI_DEFAULTSIZE          0x0008
#define DI_NOMIRROR             0x0010

/* WM_NOTIFYFORMAT commands and return values */
#define NFR_ANSI	    1
#define NFR_UNICODE	    2
#define NF_QUERY	    3
#define NF_REQUERY	    4

/* RegisterDeviceNotification stuff */
typedef  PVOID           HDEVNOTIFY;
typedef  HDEVNOTIFY     *PHDEVNOTIFY;

#define DEVICE_NOTIFY_WINDOW_HANDLE     0x00000000

/* used for GetWindowInfo() */

#define WS_ACTIVECAPTION    0x0001

/* SetWinEventHook() flags */
#define WINEVENT_OUTOFCONTEXT   0x0
#define WINEVENT_SKIPOWNTHREAD  0x1
#define WINEVENT_SKIPOWNPROCESS 0x2
#define WINEVENT_INCONTEXT      0x4

#define ENDSESSION_LOGOFF    0x80000000

/* Object Id's */
#define CHILDID_SELF      0
#define INDEXID_OBJECT    0
#define INDEXID_CONTAINER 0

/* System object Id's */
#define OBJID_WINDOW            0
#define OBJID_SYSMENU           -1
#define OBJID_TITLEBAR          -2
#define OBJID_MENU              -3
#define OBJID_CLIENT            -4
#define OBJID_VSCROLL           -5
#define OBJID_HSCROLL           -6
#define OBJID_SIZEGRIP          -7
#define OBJID_CARET             -8
#define OBJID_CURSOR            -9
#define OBJID_ALERT             -10
#define OBJID_SOUND             -11
#define OBJID_QUERYCLASSNAMEIDX -12
#define OBJID_NATIVEOM          -16

/* User event Id limits */
#define EVENT_MIN 0x00000001
#define EVENT_MAX 0x7FFFFFFF

/* System events */
#define EVENT_SYSTEM_SOUND            0x01
#define EVENT_SYSTEM_ALERT            0x02
#define EVENT_SYSTEM_FOREGROUND       0x03
#define EVENT_SYSTEM_MENUSTART        0x04
#define EVENT_SYSTEM_MENUEND          0x05
#define EVENT_SYSTEM_MENUPOPUPSTART   0x06
#define EVENT_SYSTEM_MENUPOPUPEND     0x07
#define EVENT_SYSTEM_CAPTURESTART     0x08
#define EVENT_SYSTEM_CAPTUREEND       0x09
#define EVENT_SYSTEM_MOVESIZESTART    0x0A
#define EVENT_SYSTEM_MOVESIZEEND      0x0B
#define EVENT_SYSTEM_CONTEXTHELPSTART 0x0C
#define EVENT_SYSTEM_CONTEXTHELPEND   0x0D
#define EVENT_SYSTEM_DRAGDROPSTART    0x0E
#define EVENT_SYSTEM_DRAGDROPEND      0x0F
#define EVENT_SYSTEM_DIALOGSTART      0x10
#define EVENT_SYSTEM_DIALOGEND        0x11
#define EVENT_SYSTEM_SCROLLINGSTART   0x12
#define EVENT_SYSTEM_SCROLLINGEND     0x13
#define EVENT_SYSTEM_SWITCHSTART      0x14
#define EVENT_SYSTEM_SWITCHEND        0x15
#define EVENT_SYSTEM_MINIMIZESTART    0x16
#define EVENT_SYSTEM_MINIMIZEEND      0x17

/* Console events */
#define EVENT_CONSOLE_CARET             0x4001
#define EVENT_CONSOLE_UPDATE_REGION     0x4002
#define EVENT_CONSOLE_UPDATE_SIMPLE     0x4003
#define EVENT_CONSOLE_UPDATE_SCROLL     0x4004
#define EVENT_CONSOLE_LAYOUT            0x4005
#define EVENT_CONSOLE_START_APPLICATION 0x4006
#define EVENT_CONSOLE_END_APPLICATION   0x4007

#define CONSOLE_APPLICATION_16BIT 0x1
#define CONSOLE_CARET_SELECTION   0x1
#define CONSOLE_CARET_VISIBLE     0x2

/* Object events */
#define EVENT_OBJECT_CREATE            0x8000
#define EVENT_OBJECT_DESTROY           0x8001
#define EVENT_OBJECT_SHOW              0x8002
#define EVENT_OBJECT_HIDE              0x8003
#define EVENT_OBJECT_REORDER           0x8004
#define EVENT_OBJECT_FOCUS             0x8005
#define EVENT_OBJECT_SELECTION         0x8006
#define EVENT_OBJECT_SELECTIONADD      0x8007
#define EVENT_OBJECT_SELECTIONREMOVE   0x8008
#define EVENT_OBJECT_SELECTIONWITHIN   0x8009
#define EVENT_OBJECT_STATECHANGE       0x800A
#define EVENT_OBJECT_LOCATIONCHANGE    0x800B
#define EVENT_OBJECT_NAMECHANGE        0x800C
#define EVENT_OBJECT_DESCRIPTIONCHANGE 0x800D
#define EVENT_OBJECT_VALUECHANGE       0x800E
#define EVENT_OBJECT_PARENTCHANGE      0x800F
#define EVENT_OBJECT_HELPCHANGE        0x8010
#define EVENT_OBJECT_DEFACTIONCHANGE   0x8011
#define EVENT_OBJECT_ACCELERATORCHANGE 0x8012

/* Sound events */
#define SOUND_SYSTEM_STARTUP      1
#define SOUND_SYSTEM_SHUTDOWN     2
#define SOUND_SYSTEM_BEEP         3
#define SOUND_SYSTEM_ERROR        4
#define SOUND_SYSTEM_QUESTION     5
#define SOUND_SYSTEM_WARNING      6
#define SOUND_SYSTEM_INFORMATION  7
#define SOUND_SYSTEM_MAXIMIZE     8
#define SOUND_SYSTEM_MINIMIZE     9
#define SOUND_SYSTEM_RESTOREUP   10
#define SOUND_SYSTEM_RESTOREDOWN 11
#define SOUND_SYSTEM_APPSTART    12
#define SOUND_SYSTEM_FAULT       13
#define SOUND_SYSTEM_APPEND      14
#define SOUND_SYSTEM_MENUCOMMAND 15
#define SOUND_SYSTEM_MENUPOPUP   16
#define CSOUND_SYSTEM            16

/* Alert events */
#define ALERT_SYSTEM_INFORMATIONAL 1
#define ALERT_SYSTEM_WARNING       2
#define ALERT_SYSTEM_ERROR         3
#define ALERT_SYSTEM_QUERY         4
#define ALERT_SYSTEM_CRITICAL      5
#define CALERT_SYSTEM              6

/* System state flags */
#define STATE_SYSTEM_UNAVAILABLE     0x00000001
#define STATE_SYSTEM_SELECTED        0x00000002
#define STATE_SYSTEM_FOCUSED         0x00000004
#define STATE_SYSTEM_PRESSED         0x00000008
#define STATE_SYSTEM_CHECKED         0x00000010
#define STATE_SYSTEM_MIXED           0x00000020
#define STATE_SYSTEM_INDETERMINATE   STATE_SYSTEM_MIXED
#define STATE_SYSTEM_READONLY        0x00000040
#define STATE_SYSTEM_HOTTRACKED      0x00000080
#define STATE_SYSTEM_DEFAULT         0x00000100
#define STATE_SYSTEM_EXPANDED        0x00000200
#define STATE_SYSTEM_COLLAPSED       0x00000400
#define STATE_SYSTEM_BUSY            0x00000800
#define STATE_SYSTEM_FLOATING        0x00001000
#define STATE_SYSTEM_MARQUEED        0x00002000
#define STATE_SYSTEM_ANIMATED        0x00004000
#define STATE_SYSTEM_INVISIBLE       0x00008000
#define STATE_SYSTEM_OFFSCREEN       0x00010000
#define STATE_SYSTEM_SIZEABLE        0x00020000
#define STATE_SYSTEM_MOVEABLE        0x00040000
#define STATE_SYSTEM_SELFVOICING     0x00080000
#define STATE_SYSTEM_FOCUSABLE       0x00100000
#define STATE_SYSTEM_SELECTABLE      0x00200000
#define STATE_SYSTEM_LINKED          0x00400000
#define STATE_SYSTEM_TRAVERSED       0x00800000
#define STATE_SYSTEM_MULTISELECTABLE 0x01000000
#define STATE_SYSTEM_EXTSELECTABLE   0x02000000
#define STATE_SYSTEM_ALERT_LOW       0x04000000
#define STATE_SYSTEM_ALERT_MEDIUM    0x08000000
#define STATE_SYSTEM_ALERT_HIGH      0x10000000
#define STATE_SYSTEM_PROTECTED       0x20000000
#define STATE_SYSTEM_VALID           0x3FFFFFFF

/* Lock codes for LockSetForegroundWindow */
#define LSFW_LOCK   1
#define LSFW_UNLOCK 2

/* Values for AllowSetForegroundWindow */
#define ASFW_ANY    ((DWORD)-1)

#define     EnumTaskWindows(handle,proc,lparam) \
            EnumThreadWindows(handle,proc,lparam)
#define     OemToAnsiA OemToCharA
#define     OemToAnsiW OemToCharW
#define     OemToAnsi WINELIB_NAME_AW(OemToAnsi)
#define     OemToAnsiBuffA OemToCharBuffA
#define     OemToAnsiBuffW OemToCharBuffW
#define     OemToAnsiBuff WINELIB_NAME_AW(OemToAnsiBuff)
#define     AnsiToOemA CharToOemA
#define     AnsiToOemW CharToOemW
#define     AnsiToOem WINELIB_NAME_AW(AnsiToOem)
#define     AnsiToOemBuffA CharToOemBuffA
#define     AnsiToOemBuffW CharToOemBuffW
#define     AnsiToOemBuff WINELIB_NAME_AW(AnsiToOemBuff)

#ifdef __cplusplus
}
#endif

#endif /* CONFIG_UNIFIED_KERNEL */
#endif /* _WINUSER_H */
