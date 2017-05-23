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

// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the ESTEIDCM_EXPORTS
// symbol defined on the command line. this symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// ESTEIDCM_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.

#ifndef _ESTEIDCM_H_
#define _ESTEIDCM_H_

#include "cardmod.h"
#include <stdio.h>
#include <time.h>
#include <minmax.h>
#include "notimplemented.h"
#include "EstEidManager.h"

#define _ENC_ (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)
#define CALG_SHA_224 0x0000811d
#define NULLSTR(a) (a == NULL ? "<NULL>" : a)
#define NULLWSTR(a) (a == NULL ? L"<NULL>" : a)
#define AUTH_PIN_ID 1
#define SIGN_PIN_ID 3
#define PUKK_PIN_ID 5
#define MAX_KEYLEN 2048
#define CARDID_LEN 11
#define MIN_DOCUMENT_ID_LEN 8
#define MAX_DOCUMENT_ID_LEN 9
#define AUTH_CONTAINER_INDEX 0
#define SIGN_CONTAINER_INDEX 1

struct cardFiles
{
	BYTE file_appdir[9];
	BYTE file_cardcf[6];
	BYTE file_cardid[16];
};

#endif