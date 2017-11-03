/*
* EstEID Minidriver
* 
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL) or the BSD License (see LICENSE.BSD).
* 
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*
*/

#ifndef WINVER				// Allow use of features specific to Windows 7 or later.
#define WINVER 0x0601		// Change this to the appropriate value to target other versions of Windows.
#endif

#ifndef _WIN32_WINNT		// Allow use of features specific to Windows 7 or later.                   
#define _WIN32_WINNT 0x0601	// Change this to the appropriate value to target other versions of Windows.
#endif						

#ifndef _WIN32_WINDOWS		// Allow use of features specific to Windows 7 or later.
#define _WIN32_WINDOWS 0x0601 // Change this to the appropriate value to target other versions of Windows.
#endif

#ifndef _WIN32_IE			// Allow use of features specific to IE 8.0 or later.
#define _WIN32_IE 0x0800	// Change this to the appropriate value to target other versions of IE.
#endif

#define NOMINMAX 
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <Winsock2.h>
#include <Commctrl.h>

#include "cardmod.h"
#include "version.h"

#include <algorithm>
#include <cctype>
#include <io.h>
#include <iomanip>
#include <map>
#include <sstream>
#include <vector>

#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
