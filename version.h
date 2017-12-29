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

#ifndef MAJOR_VERSION
#define MAJOR_VERSION 3
#endif
#ifndef MINOR_VERSION
#define MINOR_VERSION 12
#endif
#ifndef RELEASE_VERSION
#define RELEASE_VERSION 2
#endif
#ifndef BUILD_NUMBER
#define BUILD_NUMBER 0
#endif

#define VER_STR_HELPER(x)	#x
#define VER_STR(x)		VER_STR_HELPER(x)

#define FILE_VERSION         MAJOR_VERSION,MINOR_VERSION,RELEASE_VERSION,BUILD_NUMBER
#define PRODUCT_VERSION      MAJOR_VERSION,MINOR_VERSION,RELEASE_VERSION,BUILD_NUMBER
#define FILE_VERSION_STR     VER_STR(MAJOR_VERSION.MINOR_VERSION.RELEASE_VERSION.BUILD_NUMBER)
#define PRODUCT_VERSION_STR  VER_STR(MAJOR_VERSION.MINOR_VERSION.RELEASE_VERSION.BUILD_NUMBER)
