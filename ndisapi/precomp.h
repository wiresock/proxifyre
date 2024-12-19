/*************************************************************************/
/*                    Copyright (c) 2000-2024 NT KERNEL.                 */
/*                           All Rights Reserved.                        */
/*                          https://www.ntkernel.com                     */
/*                           ndisrd@ntkernel.com                         */
/*                                                                       */
/* Module Name:  precomp.h                                               */
/*                                                                       */
/* Description: Cumulative include header                                */
/*                                                                       */
/* Environment:                                                          */
/*   User mode                                                           */
/*                                                                       */
/*************************************************************************/

#pragma once

#include <tchar.h>
#include <stdlib.h>
#include <WinSock2.h>
#include <iphlpapi.h>

#include <memory>

#ifdef CYGWIN_BUILD
#include <strings.h> // For strcasecmp
#include <cstring>  // For strcpy, strcat
#include <cwchar>   // For wcscpy, wcscat
#define _stricmp strcasecmp
#ifdef UNICODE
// Define _tcscpy, etc. for Unicode under non-Windows
#define _tcscpy wcscpy
#define _tcscat wcscat
#define TCHAR wchar_t
// ... other wide character (wchar_t) functions as needed ...
#else
// Define _tcscpy, etc. for non-Unicode under non-Windows
#define _tcscpy strcpy
#define _tcscat strcat
// ... other single-byte (char) functions as needed ...
#endif // UNICODE
#endif // CYGWIN_BUILD

#include "../include/common.h"
#include "../include/ndisapi.h"
#include "iphlp.h"
