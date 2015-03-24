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

#include "precompiled.h"
#include "esteidcm.h"
#include <algorithm>
#include <stdlib.h>
#include <crtdbg.h>
#include <fstream>
#include <string>
#include <Windows.h>
#include <WinBase.h>
#include "PinPadUI.h"
#include <commctrl.h>

using std::wstring;
using std::string;
using std::runtime_error;


void GetFileVersionOfApplication();


HWND cp;
bool TestMode;
char procName[1024];
unsigned int maxSpecVersion = 7;
LPCTSTR subKey = TEXT("Software\\SK\\EstEIDMinidriver");

#define DEFUN(a) a

#pragma comment(lib,"crypt32.lib")

typedef struct _BCRYPT_PKCS1_PADDING_INFO_adhoc
{
  LPCWSTR pszAlgId;
} BCRYPT_PKCS1_PADDING_INFO_adhoc;

const char *debugFile;
const char *APDUdebugFile;
OSVERSIONINFO osver;

bool attachedProcessPermited;

typedef struct _CONTAINERMAPRECORD
{
    BYTE GuidInfo[80];	// 40 x UNICODE char
    BYTE Flags;		// Bit 1 set for default container
    BYTE RFUPadding;
    WORD ui16SigKeySize;
    WORD ui16KeyExchangeKeySize;
} CONTAINERMAPREC;

typedef struct
{
	PUBLICKEYSTRUC  publickeystruc;
	RSAPUBKEY rsapubkey;
	BYTE modulus[MAX_KEYLEN / 8];
} PUBKEYSTRUCT;

LPBYTE file_cmap[sizeof(CONTAINERMAPREC)];

DWORD ret(ErrCodes a)
{
	DWORD ret = a;
#ifdef DEBUG
	if (a == 0x8010001F || a == 0x0000051A || a == SCARD_E_FILE_NOT_FOUND || a == 0x8010006a)
	{
		int k = 1;
	}
	if (a == 0x80090009 )
	{
		int f = 0;
	}
	if (a != E_OK /*&& a!= 0x80100022 */)
	{
		int fck = 0;
	}
#endif
	if (a == E_OK)
	{
		SCardLog::writeLog("[%s:%d][MD] return OK\n", __FUNCTION__, __LINE__);
	}
	else
	{
		SCardLog::writeLog("[%s:%d][MD] return error 0x%08X\n", __FUNCTION__, __LINE__, ret);
	}
	return a;
}

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	SCardLog::writeLog("[%s:%d][MD] DllMain", __FUNCTION__, __LINE__);
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		{
			SCardLog::writeLog("[%s:%d][MD] DLL_PROCESS_ATTACH", __FUNCTION__, __LINE__);
			TestMode = false;
			attachedProcessPermited = false;
			HKEY rootKey;
			DWORD dwType;
			CHAR lpData[1024];
			DWORD lpSize = sizeof(lpData);
			BOOL getVersionExRet = 0;

			if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, subKey, NULL, KEY_READ, &rootKey)==ERROR_SUCCESS)
			{
				if(RegQueryValueEx(rootKey, TEXT("version"), NULL, &dwType, (LPBYTE)&lpData, &lpSize)==ERROR_SUCCESS)
				{
					if(lpSize == 4)
					{
						int tmp = atoi(lpData);
						if(tmp == 5)
							maxSpecVersion = 5;
						else if(tmp == 6)
							maxSpecVersion = 6;
						else
							maxSpecVersion = 7;
					}
					else
					{
						maxSpecVersion = 7;
					}
				}
			}

			WCHAR _cname[MAX_PATH * 4 ] = L"\0";
			PWCHAR cname = _cname + 1;
			HMODULE caller = GetModuleHandle(NULL);
			GetModuleFileName(caller,cname,MAX_PATH);
			PWCHAR fl = (PTCHAR )cname  + lstrlen(cname) -1;
			while (isalnum(*fl) || (L'.' == *fl) || (L'_' == *fl))
				fl--;
			fl++;

			GetFileVersionOfApplication();
			SCardLog::writeLog("[%s:%d][MD] Attached process %S. Using spec version: %i", __FUNCTION__, __LINE__, NULLWSTR(fl), maxSpecVersion);


			osver.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
			getVersionExRet = GetVersionEx((OSVERSIONINFO*)&osver);
			if(getVersionExRet == 0)
				SCardLog::writeLog("[%s:%d][MD] Failed to get operating system info", __FUNCTION__, __LINE__);
			else
				SCardLog::writeLog("[%s:%d][MD] Running on OS version: %i.%i build %i", __FUNCTION__, __LINE__, osver.dwMajorVersion, osver.dwMinorVersion, osver.dwBuildNumber);
			
			/*if (lstrcmpi(fl,L"winlogon.exe") == 0)
			{
				SCardLog::writeLog("[%s:%d][MD] Process is winlogon.exe.", __FUNCTION__, __LINE__);
				attachedProcessPermited = true;
			}
			if (lstrcmpi(fl,L"explorer.exe") == 0)
			{
				SCardLog::writeLog("[%s:%d][MD] Process is explorer.exe.", __FUNCTION__, __LINE__);
				attachedProcessPermited = true;
			}
			if (lstrcmpi(fl,L"lsass.exe") == 0)
			{
				SCardLog::writeLog("[%s:%d][MD] Process is lsass.exe.", __FUNCTION__, __LINE__);
				attachedProcessPermited = true;
			}
			if (lstrcmpi(fl,L"svchost.exe") == 0)
			{
				SCardLog::writeLog("[%s:%d][MD] Process is svchost.exe.", __FUNCTION__, __LINE__);
				attachedProcessPermited = true;
			}
			if (lstrcmpi(fl,L"LogonUI.exe") == 0)
			{
				SCardLog::writeLog("[%s:%d][MD] Process is LogonUI.exe.", __FUNCTION__, __LINE__);
				attachedProcessPermited = true;
			}
			if (lstrcmpi(fl,L"rundll32.exe") == 0)
			{
				SCardLog::writeLog("[%s:%d][MD] Process is rundll32.exe.", __FUNCTION__, __LINE__);
				attachedProcessPermited = true;
			}
			if (lstrcmpi(fl,L"cmck_simuse.exe") == 0)
			{
				SCardLog::writeLog("[%s:%d][MD] Process is cmck_simuse.exe.", __FUNCTION__, __LINE__);
				attachedProcessPermited = true;
			}
			if (lstrcmpi(fl,L"certutil.exe") == 0)
			{
				SCardLog::writeLog("[%s:%d][MD] Process is certutil.exe.", __FUNCTION__, __LINE__);
				attachedProcessPermited = true;
			}
			if (lstrcmpi(fl,L"csp_tool.exe") == 0)
			{
				SCardLog::writeLog("[%s:%d][MD] Process is certutil.exe.", __FUNCTION__, __LINE__);
				attachedProcessPermited = true;
			}
			if (lstrcmpi(fl,L"cmck.exe") == 0)
			{
				SCardLog::writeLog("[%s:%d][MD] Process is cmck.exe.", __FUNCTION__, __LINE__);
				attachedProcessPermited = true;
			}
			if (lstrcmpi(fl,L"iexplore.exe") == 0)
			{
				SCardLog::writeLog("[%s:%d][MD] Process is iexplore.exe.", __FUNCTION__, __LINE__);
				attachedProcessPermited = true;
			}
			if (lstrcmpi(fl,L"digidoc.exe") == 0)
			{
				SCardLog::writeLog("[%s:%d][MD] Process is iexplore.exe.", __FUNCTION__, __LINE__);
				attachedProcessPermited = true;
			}
			if(attachedProcessPermited == false)
			{
				SCardLog::writeLog("[%s:%d][MD] Parent process is not permited. Returning FALSE.", __FUNCTION__, __LINE__);
				return FALSE;
			}
			else
			{
				SCardLog::writeLog("[%s:%d][MD] Parent process is permited. Proceeding", __FUNCTION__, __LINE__);
			}*/
		}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
    return TRUE;
}

DWORD WINAPI CardAcquireContext(IN PCARD_DATA pCardData, __in DWORD dwFlags)
{
	if (!pCardData) 
		return ret(E_PARAM);
	if (dwFlags) return ret(E_PARAM);

	SCardLog::writeLog("[%s:%d][MD] CardAcquireContext, dwVersion=%u, name=%S"", hScard=0x%08X, hSCardCtx=0x%08X", __FUNCTION__, __LINE__, pCardData->dwVersion, NULLWSTR(pCardData->pwszCardName),
		pCardData->hScard, pCardData->hSCardCtx);

	DWORD dwType;
	CHAR lpData[1024];
	DWORD lpSize = sizeof(lpData);
	HKEY rootKey;

	if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, subKey, NULL, KEY_READ, &rootKey)==ERROR_SUCCESS)
	{
		if(RegQueryValueEx(rootKey, TEXT("testmode"), NULL, &dwType, (LPBYTE)&lpData, &lpSize)==ERROR_SUCCESS)
		{
			TestMode = true;
			SCardLog::writeLog("[%s:%d][MD] Found testmode key.", __FUNCTION__, __LINE__);
		}
		else
		{
			TestMode = false;
			SCardLog::writeLog("[%s:%d][MD] testmode registry key not found", __FUNCTION__, __LINE__);
		}
	}

	SCardLog::writeLog("[%s:%d][MD] Running in %s mode", __FUNCTION__, __LINE__, TestMode == true ? "TEST MODE" : "USER MODE");

	if(pCardData->cbAtr == 0) return ret(E_PARAM);
	if(pCardData->cbAtr == 0xffffffff) return ret(E_PARAM);
	if(pCardData->cbAtr < 18 || pCardData->cbAtr > 28)
		return ret(E_PARAM);

	if(osver.dwMajorVersion >= 6)
	{
		if (pCardData->dwVersion < 6 && pCardData->dwVersion != 0)
			return ret(E_REVISION);
	}
	else
	{
		if (pCardData->dwVersion < 4 && pCardData->dwVersion != 0)
			return ret(E_REVISION);
	}

	if (pCardData->dwVersion == 0 && pCardData->cbAtr != 0) //special case
		return ret(E_REVISION);

	pCardData->pfnCardDeleteContext = CardDeleteContext;
    pCardData->pfnCardQueryCapabilities = CardQueryCapabilities;
    pCardData->pfnCardDeleteContainer= CardDeleteContainer;
    pCardData->pfnCardCreateContainer= CardCreateContainer;
    pCardData->pfnCardGetContainerInfo= CardGetContainerInfo;
    pCardData->pfnCardAuthenticatePin= CardAuthenticatePin;
    pCardData->pfnCardGetChallenge= CardGetChallenge;
    pCardData->pfnCardAuthenticateChallenge= CardAuthenticateChallenge;
    pCardData->pfnCardUnblockPin= CardUnblockPin;
    pCardData->pfnCardChangeAuthenticator= CardChangeAuthenticator;
    pCardData->pfnCardDeauthenticate= NULL;// CardDeauthenticate; //CardDeauthenticate; 
    pCardData->pfnCardCreateDirectory= CardCreateDirectory;
    pCardData->pfnCardDeleteDirectory= CardDeleteDirectory;
    pCardData->pvUnused3= NULL;
    pCardData->pvUnused4= NULL;
    pCardData->pfnCardCreateFile= CardCreateFile;
    pCardData->pfnCardReadFile= CardReadFile;
    pCardData->pfnCardWriteFile= CardWriteFile;
    pCardData->pfnCardDeleteFile= CardDeleteFile;
    pCardData->pfnCardEnumFiles= CardEnumFiles;
    pCardData->pfnCardGetFileInfo= CardGetFileInfo;
    pCardData->pfnCardQueryFreeSpace= CardQueryFreeSpace;
    pCardData->pfnCardQueryKeySizes= CardQueryKeySizes;

    pCardData->pfnCardSignData= CardSignData;
    pCardData->pfnCardRSADecrypt= CardRSADecrypt;
    pCardData->pfnCardConstructDHAgreement= NULL;//CardConstructDHAgreement;

	if (pCardData->dwVersion !=0 )
	{
		if (NULL == pCardData->pbAtr )
			return ret(E_PARAM);

		if (NULL == pCardData->pwszCardName )
		{
			SCardLog::writeLog("[%s:%d][MD] Invalid pCardData->pwszCardName", __FUNCTION__, __LINE__);
			return ret(E_PARAM);
		}
		if (NULL == pCardData->pfnCspAlloc)
		{
			SCardLog::writeLog("[%s:%d][MD] Invalid pCardData->pfnCspAlloc", __FUNCTION__, __LINE__);
			return ret(E_PARAM);
		}
		if (NULL == pCardData->pfnCspReAlloc)
		{
			SCardLog::writeLog("[%s:%d][MD] Invalid pCardData->pfnCspReAlloc", __FUNCTION__, __LINE__);
			return ret(E_PARAM);
		}
		if (NULL == pCardData->pfnCspFree)
		{
			SCardLog::writeLog("[%s:%d][MD] Invalid pCardData->pfnCspFree", __FUNCTION__, __LINE__);
			return ret(E_PARAM);
		}

		pCardData->pvVendorSpecific = pCardData->pfnCspAlloc(sizeof(cardFiles));
		if (!pCardData->pvVendorSpecific) return ret(E_MEMORY);
		BYTE empty_appdir[] = {1,'m','s','c','p',0,0,0,0};
		BYTE empty_cardcf[6]={0,0,0,0,0,0};
		BYTE empty_cardid[16]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
		memcpy(((cardFiles *)pCardData->pvVendorSpecific)->file_appdir,empty_appdir,sizeof(empty_appdir));
		memcpy(((cardFiles *)pCardData->pvVendorSpecific)->file_cardcf,empty_cardcf,sizeof(empty_cardcf));
		memcpy(((cardFiles *)pCardData->pvVendorSpecific)->file_cardid,empty_cardid,sizeof(empty_cardid));
		if (0 == pCardData->hScard )
			return ret(E_BADHANDLE);
	}

	unsigned char *ptr = pCardData->pbAtr;
	bool validATR = false;
	for(unsigned int i = 0; i < pCardData->cbAtr; i++)
	{
		if(ptr[i] > 0x00 && ptr[i] < 0xff)
		{
			if(validATR == false)
				validATR = true;
		}
	}

	if(!validATR) return ret(E_WRONG_CARD);
	if (maxSpecVersion < pCardData->dwVersion)
		pCardData->dwVersion = maxSpecVersion;

	if (pCardData->dwVersion > 4)
	{
		pCardData->pfnCardDeriveKey = NULL;
		pCardData->pfnCardDestroyDHAgreement = NULL;
		pCardData->pfnCspGetDHAgreement = NULL;

		if (pCardData->dwVersion > 5 && osver.dwMajorVersion >= 6 && maxSpecVersion >= 6)
		{
			SCardLog::writeLog("[%s:%d][MD] Reporting version 6 on Windows version %i.%i build %i. Max supported spec version is set to %i", __FUNCTION__, __LINE__, osver.dwMajorVersion, osver.dwMinorVersion, osver.dwBuildNumber, maxSpecVersion);

			pCardData->pfnCardGetChallengeEx = CardGetChallengeEx;
			pCardData->pfnCardAuthenticateEx = CardAuthenticateEx;
			pCardData->pfnCardChangeAuthenticatorEx = CardChangeAuthenticatorEx;
			pCardData->pfnCardDeauthenticateEx = CardDeauthenticateEx;
			pCardData->pfnCardGetContainerProperty = CardGetContainerProperty ;
			pCardData->pfnCardSetContainerProperty = CardSetContainerProperty;
			pCardData->pfnCardGetProperty = CardGetProperty;
			pCardData->pfnCardSetProperty = CardSetProperty;
		}
		else
		{
			SCardLog::writeLog("[%s:%d][MD] Version 6 is not supported on Windows version %i.%i build %i. Max supported spec version is set to %i", __FUNCTION__, __LINE__, osver.dwMajorVersion, osver.dwMinorVersion, osver.dwBuildNumber, maxSpecVersion);
		}

		if(pCardData->dwVersion > 6 && osver.dwMajorVersion >= 6 && maxSpecVersion >= 7)
		{
			SCardLog::writeLog("[%s:%d][MD] Reporting version 7 on Windows version %i.%i build %i. Max supported spec version is set to %i", __FUNCTION__, __LINE__, osver.dwMajorVersion, osver.dwMinorVersion, osver.dwBuildNumber, maxSpecVersion);
			pCardData->pfnCardDestroyKey = CardDestroyKey;
			pCardData->pfnCardGetAlgorithmProperty = CardGetAlgorithmProperty;
			pCardData->pfnCardGetKeyProperty = CardGetKeyProperty;
			pCardData->pfnCardGetSharedKeyHandle = CardGetSharedKeyHandle;
			pCardData->pfnCardProcessEncryptedData = CardProcessEncryptedData;
			pCardData->pfnCardSetKeyProperty = CardSetKeyProperty;
			pCardData->pfnCardCreateContainerEx = CardCreateContainerEx;
			pCardData->pfnMDImportSessionKey = MDImportSessionKey;
			pCardData->pfnMDEncryptData = MDEncryptData;
			pCardData->pfnCardImportSessionKey = CardImportSessionKey;
		}
		else
		{
			SCardLog::writeLog("[%s:%d][MD] Version 7 is not supported on Windows version %i.%i build %i. Max supported spec version is set to %i", __FUNCTION__, __LINE__, osver.dwMajorVersion, osver.dwMinorVersion, osver.dwBuildNumber, maxSpecVersion);
		}
	}
	
	return ret(E_OK);
}


DWORD WINAPI CardDeleteContext(__inout PCARD_DATA pCardData)
{
	SCardLog::writeLog("[%s:%d][MD] CardDeleteContext", __FUNCTION__, __LINE__);
	
	
	if (!pCardData)
		return ret(E_PARAM);

	if (pCardData->pvVendorSpecific)
		pCardData->pfnCspFree(pCardData->pvVendorSpecific);

	return ret(E_OK);
}

DWORD WINAPI CardGetContainerProperty(__in PCARD_DATA pCardData, __in BYTE bContainerIndex, __in LPCWSTR wszProperty,
    __out_bcount_part_opt(cbData, *pdwDataLen) PBYTE pbData, __in DWORD cbData, __out PDWORD pdwDataLen, __in DWORD dwFlags)
{
	if (!pCardData) return ret(E_PARAM);
	SCardLog::writeLog("[%s:%d][MD] CardGetContainerProperty bContainerIndex=%u, wszProperty=%S"", cbData=%u, dwFlags=0x%08X",__FUNCTION__, __LINE__, bContainerIndex, NULLWSTR(wszProperty), cbData,dwFlags);
	if (!wszProperty) 
		return ret(E_PARAM);
	if (dwFlags) 
		return ret(E_PARAM);
	if (!pbData)
		return ret(E_PARAM);
	if (!pdwDataLen) 
		return ret(E_PARAM);

	if (wstring(CCP_CONTAINER_INFO) == wszProperty )
	{
		PCONTAINER_INFO p = (PCONTAINER_INFO) pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData >= sizeof(DWORD))
			if (p->dwVersion != CONTAINER_INFO_CURRENT_VERSION && p->dwVersion != 0 )
				return ret(E_REVISION);
		if (cbData < sizeof(*p))
			return ret(E_BUFFER);
		SCardLog::writeLog("[%s:%d][MD] -->calling CardGetContainerInfo",__FUNCTION__, __LINE__);
		DWORD code = CardGetContainerInfo(pCardData,bContainerIndex,0,p);
		SCardLog::writeLog("[%s:%d][MD] <--calling CardGetContainerInfo",__FUNCTION__, __LINE__);
		return code;
	}
	if (wstring(CCP_PIN_IDENTIFIER) == wszProperty )
	{
		PPIN_ID p = (PPIN_ID) pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p))
			return ret(E_BUFFER);
		switch (bContainerIndex)
		{
			case AUTH_CONTAINER_INDEX:
				*p = AUTH_PIN_ID;
				break;
			case SIGN_CONTAINER_INDEX:
				*p = SIGN_PIN_ID;
				break;
			default:
				return ret(E_NOCONTAINER);
		}
		SCardLog::writeLog("[%s:%d][MD] Return Pin id %u",__FUNCTION__, __LINE__, *p);
		return ret(E_OK);
	}
	return ret(E_PARAM);
}

DWORD WINAPI CardSetContainerProperty(__in PCARD_DATA pCardData, __in BYTE bContainerIndex, __in LPCWSTR wszProperty,
    __in_bcount(cbDataLen) PBYTE pbData, __in DWORD cbDataLen, __in DWORD dwFlags)
{
	if (!pCardData) return ret(E_PARAM);
	SCardLog::writeLog("[%s:%d][MD] CardSetContainerProperty bContainerIndex=%u, wszProperty=%S"", cbDataLen=%u, dwFlags=0x%08X",__FUNCTION__, __LINE__, bContainerIndex, NULLWSTR(wszProperty), cbDataLen, dwFlags);
	return ret(E_UNSUPPORTED);
}

DWORD WINAPI CardGetProperty(__in PCARD_DATA pCardData, __in LPCWSTR wszProperty,
	__out_bcount_part_opt(cbData, *pdwDataLen) PBYTE pbData, __in DWORD cbData, __out PDWORD pdwDataLen, __in DWORD dwFlags)
{
	SCardLog::writeLog("[%s:%d][MD] CardGetProperty wszProperty=%S, cbData=%u, dwFlags=%u",__FUNCTION__, __LINE__,NULLWSTR(wszProperty),cbData,dwFlags);
	if (!pCardData)
		return ret(E_PARAM);
	if (!wszProperty)
		return ret(E_PARAM);
	if (!pbData)
		return ret(E_PARAM);
	if (pdwDataLen == NULL)
		return ret(E_PARAM);

	if (wstring(CP_CARD_PIN_STRENGTH_CHANGE) == wszProperty || wstring(CP_CARD_PIN_STRENGTH_UNBLOCK) == wszProperty)
		return ret(E_UNSUPPORTED);

	if (dwFlags)
	{
		if (wstring(CP_CARD_PIN_INFO) != wszProperty && wstring(CP_CARD_PIN_STRENGTH_VERIFY) != wszProperty && wstring(CP_CARD_KEYSIZES) != wszProperty)
			return ret(E_PARAM);
		if (dwFlags > PUKK_PIN_ID )
			return ret(E_PARAM);
	}

	if (wstring(CP_CARD_FREE_SPACE) == wszProperty )
	{
		SCardLog::writeLog("[%s:%d][MD] CardGetProperty: CP_CARD_FREE_SPACE",__FUNCTION__, __LINE__);
		PCARD_FREE_SPACE_INFO p = (PCARD_FREE_SPACE_INFO )pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p))
			return ret(E_SCBUFFER);
		if (p->dwVersion > CARD_FREE_SPACE_INFO_CURRENT_VERSION )
			return ret(E_REVISION);
		p->dwVersion = CARD_FREE_SPACE_INFO_CURRENT_VERSION;
		p->dwBytesAvailable = 0;
		p->dwKeyContainersAvailable = 0;
		p->dwMaxKeyContainers = 2;
		return ret(E_OK);
	}

	if (wstring(CP_CARD_CAPABILITIES) == wszProperty )
	{
		SCardLog::writeLog("[%s:%d][MD] CardGetProperty: CP_CARD_CAPABILITIES",__FUNCTION__, __LINE__);
		PCARD_CAPABILITIES p = (PCARD_CAPABILITIES )pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) return ret(E_SCBUFFER);
		if (p->dwVersion != CARD_CAPABILITIES_CURRENT_VERSION && p->dwVersion != 0)
			return ret(E_REVISION);
		p->fCertificateCompression = TRUE;
		p->fKeyGen = FALSE;
		return ret(E_OK);
	}

	if (wstring(CP_CARD_KEYSIZES) == wszProperty)
	{
		SCardLog::writeLog("[%s:%d][MD] CardGetProperty: CP_CARD_KEYSIZES",__FUNCTION__, __LINE__);
		PCARD_KEY_SIZES p = (PCARD_KEY_SIZES )pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) return ret(E_SCBUFFER);
		if (p->dwVersion != CARD_KEY_SIZES_CURRENT_VERSION && p->dwVersion != 0)
			return ret(E_REVISION);

		p->dwIncrementalBitlen = 0;
		
		unsigned int key_size = NULL;
		try
		{
			EstEIDManager estEIDManager(pCardData->hSCardCtx, pCardData->hScard);
			key_size  = estEIDManager.getKeySize();
		}
		catch (runtime_error &err )
		{
			SCardLog::writeLog("[%s:%d][MD] runtime_error in CardReadFile '%s'",__FUNCTION__, __LINE__, err.what());
			return ret(E_NOFILE);
		}
		if (!key_size)
			return ret(E_INTERNAL);

		p->dwDefaultBitlen = key_size;
		p->dwMaximumBitlen = key_size;
		p->dwMinimumBitlen = key_size;
		
		return ret(E_OK);
	}
	if (wstring(CP_CARD_READ_ONLY) == wszProperty)
	{
		SCardLog::writeLog("[%s:%d][MD] CardGetProperty: CP_CARD_READ_ONLY",__FUNCTION__, __LINE__);
		BOOL *p = (BOOL*)pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) return ret(E_SCBUFFER);
		*p = TRUE; //HACK
		return ret(E_OK);
	}
	if (wstring(CP_CARD_CACHE_MODE) == wszProperty)
	{
		SCardLog::writeLog("[%s:%d][MD] CardGetProperty: CP_CARD_CACHE_MODE",__FUNCTION__, __LINE__);
		DWORD *p = (DWORD *)pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) return ret(E_SCBUFFER);
		*p = CP_CACHE_MODE_SESSION_ONLY;
		return ret(E_OK);
	}
	if (wstring(CP_SUPPORTS_WIN_X509_ENROLLMENT) == wszProperty)
	{
		SCardLog::writeLog("[%s:%d][MD] CardGetProperty: CP_SUPPORTS_WIN_X509_ENROLLMENT",__FUNCTION__, __LINE__);
		DWORD *p = (DWORD *)pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) return ret(E_SCBUFFER);
		*p = 0;
		return ret(E_OK);
	}
	if (wstring(CP_CARD_GUID) == wszProperty)
	{
		SCardLog::writeLog("[%s:%d][MD] CardGetProperty: CP_CARD_GUID",__FUNCTION__, __LINE__);
		cardFiles *ptr = (cardFiles *)pCardData->pvVendorSpecific;
		
		try
		{
			EstEIDManager estEIDManager(pCardData->hSCardCtx, pCardData->hScard);
			string id  = estEIDManager.readDocumentID();
			if (id.length() < MIN_DOCUMENT_ID_LEN || id.length() > MAX_DOCUMENT_ID_LEN)
			{
				SCardLog::writeLog("[%s:%d][MD] Runtime_error in CardReadFile id.length() is %d",__FUNCTION__, __LINE__, id.length());
				
				return ret(E_NOFILE);
			}
			SCardLog::writeLog("[%s:%d][MD] cardid: %s",__FUNCTION__, __LINE__, id.c_str());
			memset(ptr->file_cardid,0, sizeof(ptr->file_cardid));
			CopyMemory( ptr->file_cardid, id.c_str(), id.length());
		}
		catch (runtime_error &err )
		{
			SCardLog::writeLog("[%s:%d][MD] runtime_error in CardReadFile '%s'",__FUNCTION__, __LINE__, err.what());
			return ret(E_NOFILE);
		}
		if (pdwDataLen) *pdwDataLen = sizeof(ptr->file_cardid);
		if (cbData < sizeof(ptr->file_cardid)) return ret(E_SCBUFFER);
		CopyMemory(pbData,ptr->file_cardid,sizeof(ptr->file_cardid));
		
		return ret(E_OK);
	}
	if (wstring(CP_CARD_SERIAL_NO) == wszProperty)
	{
		SCardLog::writeLog("[%s:%d][MD] CardGetProperty: CP_CARD_SERIAL_NO",__FUNCTION__, __LINE__);
		return ret(E_PARAM);
	}
	if (wstring(CP_CARD_PIN_INFO) == wszProperty)
	{
		SCardLog::writeLog("[%s:%d][MD] CardGetProperty: CP_CARD_PIN_INFO",__FUNCTION__, __LINE__);
		PPIN_INFO p = (PPIN_INFO) pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) return ret(E_SCBUFFER);
		if (p->dwVersion != 6) return ret(E_REVISION);
		try
		{
			EstEIDManager estEIDManager(pCardData->hSCardCtx, pCardData->hScard);
			if(estEIDManager.isSecureConnection())
			{
				SCardLog::writeLog("[%s:%d][MD] CardGetProperty: CP_CARD_PIN_INFO: PINPAD enabled",__FUNCTION__, __LINE__);
				p->PinType = ExternalPinType;
			}
			else
			{
				SCardLog::writeLog("[%s:%d][MD] CardGetProperty: CP_CARD_PIN_INFO: No PINPAD found",__FUNCTION__, __LINE__);
				p->PinType = AlphaNumericPinType;
			}

		}
		catch (runtime_error &err )
		{
			SCardLog::writeLog("[%s:%d][MD] runtime_error in CardReadFile '%s'",__FUNCTION__, __LINE__, err.what());
			
			return ret(E_NOFILE);
		}
		p->dwFlags = 0;
		switch (dwFlags)
		{
			case AUTH_PIN_ID:
				SCardLog::writeLog("[%s:%d][MD] returning info on PIN 1 [%u]",__FUNCTION__, __LINE__, dwFlags);
				p->PinPurpose = AuthenticationPin;
				p->PinCachePolicy.dwVersion = 6;
				p->PinCachePolicy.dwPinCachePolicyInfo = 0;
				p->PinCachePolicy.PinCachePolicyType = PinCacheNormal;
				if(TestMode == false)
				{
					p->dwChangePermission = CREATE_PIN_SET(AUTH_PIN_ID);
					p->dwUnblockPermission = CREATE_PIN_SET(PUKK_PIN_ID);
				}
				else
				{
					p->dwChangePermission = 0;
					p->dwUnblockPermission = 0;
				}
				break;
			case SIGN_PIN_ID:
				SCardLog::writeLog("[%s:%d][MD] returning info on PIN 2 [%u]",__FUNCTION__, __LINE__, dwFlags);
				p->PinPurpose = DigitalSignaturePin;
				p->PinCachePolicy.dwVersion = 6;
				p->PinCachePolicy.dwPinCachePolicyInfo = 0;
				p->PinCachePolicy.PinCachePolicyType = PinCacheNone;
				if(TestMode == false)
				{
					p->dwChangePermission = CREATE_PIN_SET(SIGN_PIN_ID);
					p->dwUnblockPermission = CREATE_PIN_SET(PUKK_PIN_ID);
				}
				else
				{
					p->dwChangePermission = 0;
					p->dwUnblockPermission = 0;
				}
				break;
			case PUKK_PIN_ID:
				SCardLog::writeLog("[%s:%d][MD] returning info on PUK [%u]",__FUNCTION__, __LINE__, dwFlags);
				p->PinPurpose = UnblockOnlyPin;
				p->PinCachePolicy.dwVersion = 6;
				p->PinCachePolicy.dwPinCachePolicyInfo = 0;
				p->PinCachePolicy.PinCachePolicyType = PinCacheNone;
				if(TestMode == false)
				{
					p->dwChangePermission = CREATE_PIN_SET(PUKK_PIN_ID);
					p->dwUnblockPermission = 0;
				}
				else
				{
					p->dwChangePermission = 0;
					p->dwUnblockPermission = 0;
				}
				break;
			default:
				SCardLog::writeLog("[%s:%d][MD] Invalid Pin number %u requested",__FUNCTION__, __LINE__, dwFlags);
				return ret(E_PARAM);
		}
		return ret(E_OK);
	}
	if (wstring(CP_CARD_LIST_PINS) == wszProperty)
	{
		SCardLog::writeLog("[%s:%d][MD] CardGetProperty: CP_CARD_LIST_PINS",__FUNCTION__, __LINE__);
		PPIN_SET p = (PPIN_SET) pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) return ret(E_SCBUFFER);
		SET_PIN(*p,AUTH_PIN_ID);
		SET_PIN(*p,SIGN_PIN_ID);
		SET_PIN(*p,PUKK_PIN_ID);
		return ret(E_OK);
	}
	if (wstring(CP_CARD_AUTHENTICATED_STATE) == wszProperty)
	{
		SCardLog::writeLog("[%s:%d][MD] CardGetProperty: CP_CARD_AUTHENTICATED_STATE",__FUNCTION__, __LINE__);
		PPIN_SET p = (PPIN_SET) pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) return ret(E_SCBUFFER);
		return ret(E_PARAM);
	}
	if (wstring(CP_CARD_PIN_STRENGTH_VERIFY) == wszProperty)
	{
		SCardLog::writeLog("[%s:%d][MD] CardGetProperty: CP_CARD_PIN_STRENGTH_VERIFY",__FUNCTION__, __LINE__);
		if (dwFlags < AUTH_PIN_ID || dwFlags > PUKK_PIN_ID) return ret(E_PARAM);
		DWORD *p = (DWORD *)pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) return ret(E_SCBUFFER);
		*p = CARD_PIN_STRENGTH_PLAINTEXT;
		return ret(E_OK);
	}
	if (wstring(CP_CARD_PIN_STRENGTH_CHANGE) == wszProperty)
	{
		SCardLog::writeLog("[%s:%d][MD] CardGetProperty: CP_CARD_PIN_STRENGTH_CHANGE",__FUNCTION__, __LINE__);
		return ret(E_UNSUPPORTED);
	}
	if (wstring(CP_CARD_PIN_STRENGTH_UNBLOCK) == wszProperty)
	{
		SCardLog::writeLog("[%s:%d][MD] CardGetProperty: CP_CARD_PIN_STRENGTH_UNBLOCK",__FUNCTION__, __LINE__);
		return ret(E_UNSUPPORTED);
	}

	if (wstring(CP_KEY_IMPORT_SUPPORT) == wszProperty)
	{
		SCardLog::writeLog("[%s:%d][MD] CardGetProperty: CP_KEY_IMPORT_SUPPORT",__FUNCTION__, __LINE__);
		DWORD *p = (DWORD *)pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		*p = 0;
		return ret(E_OK);
	}
	if (wstring(CP_ENUM_ALGORITHMS) == wszProperty)
	{
		SCardLog::writeLog("[%s:%d][MD] CardGetProperty: CP_ENUM_ALGORITHMS",__FUNCTION__, __LINE__);
		
		return ret(E_UNSUPPORTED);
	}
	if (wstring(CP_PADDING_SCHEMES) == wszProperty)
	{
		SCardLog::writeLog("[%s:%d][MD] CardGetProperty: CP_PADDING_SCHEMES",__FUNCTION__, __LINE__);
		DWORD *p = (DWORD *)pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		*p = CARD_PADDING_NONE;
		return ret(E_OK);
	}
	if (wstring(CP_CHAINING_MODES) == wszProperty)
	{
		SCardLog::writeLog("[%s:%d][MD] CardGetProperty: CP_CHAINING_MODES",__FUNCTION__, __LINE__);
		return ret(E_UNSUPPORTED);
	}

	SCardLog::writeLog("[%s:%d][MD] Fell through..",__FUNCTION__, __LINE__);
	return ret(E_PARAM);
}

DWORD WINAPI CardSetProperty(__in PCARD_DATA pCardData, __in LPCWSTR wszProperty, __in_bcount(cbDataLen) PBYTE pbData,
    __in DWORD cbDataLen, __in DWORD dwFlags)
{
	if (!pCardData) return ret(E_PARAM);
	SCardLog::writeLog("[%s:%d][MD] CardSetProperty wszProperty=%S"", cbDataLen=%u, dwFlags=%u",__FUNCTION__, __LINE__, NULLWSTR(wszProperty), cbDataLen, dwFlags);
	if (!wszProperty) return ret(E_PARAM);

	if (wstring(CP_CARD_PIN_STRENGTH_VERIFY) == wszProperty || wstring(CP_CARD_PIN_INFO) == wszProperty)
		return ret(E_NEEDSAUTH);

	if (dwFlags)
		return ret(E_PARAM);

	if (wstring(CP_PIN_CONTEXT_STRING) == wszProperty)
		return ret(E_OK);

	if (wstring(CP_CARD_CACHE_MODE) == wszProperty ||  wstring(CP_SUPPORTS_WIN_X509_ENROLLMENT) == wszProperty ||
		wstring(CP_CARD_GUID) == wszProperty || wstring(CP_CARD_SERIAL_NO)  == wszProperty )
	{
		return ret(E_NEEDSAUTH);
	}

	if (!pbData)
		return ret(E_PARAM);
	if (!cbDataLen)
		return ret(E_PARAM);

	if (wstring(CP_PARENT_WINDOW) == wszProperty)
	{
		SCardLog::writeLog("[%s:%d][MD] CardSetProperty CP_PARENT_WINDOW", __FUNCTION__, __LINE__);
		if (cbDataLen != sizeof(pCardData)) 
			return ret(E_PARAM);
		cp = *((HWND *) pbData);
		if (cp!=0 && !IsWindow(cp))
		{
			cp = NULL;
			return ret(E_PARAM);
		}
		return ret(E_OK);
	}
	return ret(E_PARAM);
}


DWORD WINAPI CardQueryCapabilities(__in PCARD_DATA pCardData, __in PCARD_CAPABILITIES pCardCapabilities)
{
	if (!pCardData) return ret(E_PARAM);
	if (!pCardCapabilities) return ret(E_PARAM);

	if (pCardCapabilities->dwVersion != CARD_CAPABILITIES_CURRENT_VERSION && pCardCapabilities->dwVersion != 0)
		return ret(E_REVISION);

	pCardCapabilities->dwVersion = CARD_CAPABILITIES_CURRENT_VERSION;
	SCardLog::writeLog("[%s:%d][MD] CardQueryCapabilities dwVersion=%u, fKeyGen=%u, fCertificateCompression=%u",__FUNCTION__, __LINE__, pCardCapabilities->dwVersion,
		pCardCapabilities->fKeyGen ,pCardCapabilities->fCertificateCompression);

	pCardCapabilities->fCertificateCompression = TRUE;
	pCardCapabilities->fKeyGen = FALSE;
	return ret(E_OK);
}

DWORD WINAPI CardCreateContainer(__in PCARD_DATA pCardData, __in BYTE bContainerIndex, __in DWORD dwFlags, __in DWORD dwKeySpec,
    __in DWORD dwKeySize, __in PBYTE pbKeyData)
{
	return ret(E_UNSUPPORTED);
}

DWORD WINAPI
CardGetContainerInfo(__in PCARD_DATA  pCardData, __in BYTE bContainerIndex, __in DWORD dwFlags, __in PCONTAINER_INFO pContainerInfo)
{
	if (!pCardData) return ret(E_PARAM);
	if (!pContainerInfo) return ret(E_PARAM);
	if (dwFlags) return ret(E_PARAM);
	if (pContainerInfo->dwVersion < 0 || pContainerInfo->dwVersion >  CONTAINER_INFO_CURRENT_VERSION)
		return ret(E_REVISION);

	SCardLog::writeLog("[%s:%d][MD] CardGetContainerInfo bContainerIndex=%u, dwFlags=0x%08X, dwVersion=%u"", cbSigPublicKey=%u, cbKeyExPublicKey=%u"
		,__FUNCTION__, __LINE__, bContainerIndex, dwFlags, pContainerInfo->dwVersion, pContainerInfo->cbSigPublicKey, pContainerInfo->cbKeyExPublicKey);

	if (bContainerIndex != SIGN_CONTAINER_INDEX && bContainerIndex != AUTH_CONTAINER_INDEX)
		return ret(E_NOCONTAINER);

	if (bContainerIndex != AUTH_CONTAINER_INDEX && pCardData->dwVersion < 6 )
	{
		SCardLog::writeLog("[%s:%d][MD] Version %u requested container %u",__FUNCTION__, __LINE__, pCardData->dwVersion, bContainerIndex);
		return ret(E_NOCONTAINER);
	}

	PUBKEYSTRUCT oh;
	DWORD sz = sizeof(oh);

	try
	{
		ByteVec reply;

		EstEIDManager estEIDManager(pCardData->hSCardCtx, pCardData->hScard);
		if (bContainerIndex == AUTH_CONTAINER_INDEX)
			reply = estEIDManager.getAuthCert();
		else
			reply = estEIDManager.getSignCert();

		PCCERT_CONTEXT cer = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, &reply[0], (DWORD) reply.size());
		PCERT_PUBLIC_KEY_INFO pinf = &(cer->pCertInfo->SubjectPublicKeyInfo);
		CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, pinf->PublicKey.pbData, pinf->PublicKey.cbData, 0, (LPVOID) &oh, &sz);
	}
	catch (runtime_error & ex)
	{
		SCardLog::writeLog("[%s:%d][MD] runtime_error exception thrown:",__FUNCTION__, __LINE__, ex.what());
		
		return ret(E_INTERNAL);
	}

	if (bContainerIndex == AUTH_CONTAINER_INDEX)
	{
		oh.publickeystruc.aiKeyAlg = CALG_RSA_KEYX;
		pContainerInfo->cbKeyExPublicKey = sz;
		pContainerInfo->pbKeyExPublicKey = (PBYTE)(*pCardData->pfnCspAlloc)(sz);
		if (!pContainerInfo->pbKeyExPublicKey) return ret(E_MEMORY);
		pContainerInfo->cbSigPublicKey = 0;
		pContainerInfo->pbSigPublicKey = NULL;
		CopyMemory(pContainerInfo->pbKeyExPublicKey,&oh,sz);
		SCardLog::writeLog("[%s:%d][MD] return info on AUTH_CONTAINER_INDEX",__FUNCTION__, __LINE__);
	}
	else
	{ //SIGN_CONTAINER_INDEX
		oh.publickeystruc.aiKeyAlg = CALG_RSA_SIGN;
		pContainerInfo->cbKeyExPublicKey = 0;
		pContainerInfo->pbKeyExPublicKey = NULL;
		pContainerInfo->cbSigPublicKey = sz;
		pContainerInfo->pbSigPublicKey = (PBYTE)(*pCardData->pfnCspAlloc)(sz);
		if (!pContainerInfo->pbSigPublicKey) return ret(E_MEMORY);
		CopyMemory(pContainerInfo->pbSigPublicKey,&oh,sz);
		SCardLog::writeLog("[%s:%d][MD] return info on SIGN_CONTAINER_INDEX",__FUNCTION__, __LINE__);
	}

	pContainerInfo->dwVersion = CONTAINER_INFO_CURRENT_VERSION;
	
	return ret(E_OK);
	}


DWORD WINAPI CardAuthenticatePin(__in PCARD_DATA pCardData, __in LPWSTR pwszUserId, __in_bcount(cbPin) PBYTE pbPin, __in DWORD cbPin, __out_opt PDWORD pcAttemptsRemaining)
{
	if (!pCardData) return ret(E_PARAM);
	SCardLog::writeLog("[%s:%d][MD] CardAuthenticatePin: pwszUserId=%S",__FUNCTION__, __LINE__, NULLWSTR(pwszUserId));

	BYTE remaining = 0,dummy = 0xFA;
	try
	{
		EstEIDManager estEIDManager(pCardData->hSCardCtx, pCardData->hScard);

		if(!estEIDManager.isSecureConnection())
		{
			if (NULL == pbPin) return ret(E_PARAM);
			if (NULL == pwszUserId) return ret(E_PARAM);
			if (wstring(wszCARD_USER_USER) != pwszUserId && wstring(wszCARD_USER_ADMIN) != pwszUserId)
				return ret(E_PARAM);

			if (cbPin < 4 || cbPin > 12) return ret(E_WRONGPIN);
			if (wstring(wszCARD_USER_ADMIN) == pwszUserId)
			{
				return ret(E_WRONGPIN);
			}
			char *pin = (char *)pbPin;
			PinString tmp(pin , pin+cbPin );
			BYTE ddd = tmp.at(cbPin-1);
			if(ddd == 0x00)
				return ret(E_WRONGPIN);

			if (pcAttemptsRemaining)
			{
				byte puk,pinSign;
				estEIDManager.getRetryCounts(puk,remaining,pinSign);
			}
			try
			{
				estEIDManager.validateAuthPin(tmp,dummy);
			}
			catch (AuthError err)
			{
				if(NULL != pcAttemptsRemaining)
				{
					if(remaining > 0 && remaining < 4)
						*pcAttemptsRemaining = remaining-1;
					else
						*pcAttemptsRemaining = 0x0;
				}
				SCardLog::writeLog("[%s:%d][MD] CardAuthenticatePin: AuthError pcAttemptsRemaining=%i",__FUNCTION__, __LINE__, NULL == pcAttemptsRemaining ? 0 : *pcAttemptsRemaining);
				if(err.SW1 == 0x69 && err.SW2 == 0x83)
				{
					SCardLog::writeLog("[%s:%d][MD] PIN code blocked",__FUNCTION__, __LINE__);
					return ret(E_PINBLOCKED);
				}
				else if(err.SW1 == 0x63 && err.SW2 == 0x00)
				{
					SCardLog::writeLog("[%s:%d][MD] CardAuthenticatePin: PIN code blocked",__FUNCTION__, __LINE__);
					return ret(E_PINBLOCKED);
				}
				else if(err.SW1 == 0x63 && err.SW2 == 0xC0)
				{
					SCardLog::writeLog("[%s:%d][MD] CardAuthenticatePin: PIN code blocked",__FUNCTION__, __LINE__);
					return ret(E_PINBLOCKED);
				}
				else
				{
					SCardLog::writeLog("[%s:%d][MD] CardAuthenticatePin: PIN authentication error: %s",__FUNCTION__, __LINE__, err.what());
					return ret(E_WRONGPIN);
				}
			}
			catch (runtime_error &er )
			{
				SCardLog::writeLog("[%s:%d][MD] CardAuthenticatePin: Runtime error",__FUNCTION__, __LINE__, er.what());
				return ret(E_WRONGPIN);
			}
		}
		else
		{
			if (NULL == pwszUserId) return ret(E_PARAM);
			if (wstring(wszCARD_USER_USER) != pwszUserId && wstring(wszCARD_USER_ADMIN) != pwszUserId)
				return ret(E_PARAM);
			EXTERNAL_INFO externalInfo;
			externalInfo.hwndParentWindow = cp;
			externalInfo.pinType = 1;
			HANDLE DialogThreadHandle;

			try
			{
				PinString tmp = PinString("");
				BYTE dummy = 0xFA;
				
				if(estEIDManager.isSecureConnection() == true)
				{
					SCardLog::writeLog("[%s:%d][MD] CardAuthenticatePin: Using secure connection to card",__FUNCTION__, __LINE__);
				}
				else
				{
					SCardLog::writeLog("[%s:%d][MD] CardAuthenticatePin: Secure connection is not used",__FUNCTION__, __LINE__);
				}

				const int BUFFER_SIZE = 512;
				int lReturn = 0;
				WCHAR wcBuffer[BUFFER_SIZE];
				lReturn = GetLocaleInfo(LOCALE_USER_DEFAULT, LOCALE_SENGLANGUAGE, wcBuffer, BUFFER_SIZE);
				if(std::wstring(wcBuffer) == std::wstring(L"Russian"))
				{
					estEIDManager.setReaderLanguageId(estEIDManager.RUS);
					externalInfo.langId = estEIDManager.RUS;
				}
				else if(std::wstring(wcBuffer) == std::wstring(L"Estonian"))
				{
					estEIDManager.setReaderLanguageId(estEIDManager.EST);
					externalInfo.langId = estEIDManager.EST;
				}
				else
				{
					estEIDManager.setReaderLanguageId(estEIDManager.ENG);
					externalInfo.langId = estEIDManager.ENG;
				}
					bool authenticated = false;
					bool blocked = false;
					if(remaining == 0x00)
					{
						SCardLog::writeLog("[%s:%d][MD] PIN code blocked",__FUNCTION__, __LINE__);
						MessageBox(NULL, L"PIN code blocked", L"Authentication error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
						return ret(E_PINBLOCKED);
					}
					while(remaining != 0x00)
					{
						if(authenticated)
							break;
						try
						{
						DialogThreadHandle = CreateThread(NULL, 0, DialogThreadEntry, &externalInfo, 0, NULL);
						estEIDManager.enterPin(EstEIDManager::PIN_AUTH, tmp, false);
						TerminateThread(DialogThreadHandle, ERROR_SUCCESS);
						remaining = 0x03;
						authenticated = true;
					}
					catch(AuthError)
					{
						SCardLog::writeLog("[%s:%d][MD] Wrong PIN presented %i attempts remaining",__FUNCTION__, __LINE__, 3-remaining);
						MessageBox(cp, L"Wrong PIN presented.", L"Authentication error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
						remaining--;
					}
					TerminateThread(DialogThreadHandle, ERROR_SUCCESS);
				}
			}
			catch (AuthError err)
			{
				TerminateThread(DialogThreadHandle, ERROR_SUCCESS);
				SCardLog::writeLog("[%s:%d][MD] CardAuthenticatePin: AuthError",__FUNCTION__, __LINE__);
				if(err.SW1 == 0x69 && err.SW2 == 0x83)
				{
					SCardLog::writeLog("[%s:%d][MD] CardAuthenticatePin: PIN code blocked",__FUNCTION__, __LINE__);
					MessageBox(NULL, L"PIN code blocked", L"Authentication error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
					return ret(E_PINBLOCKED);
				}
				else if(err.SW1 == 0x63 && err.SW2 == 0x00)
				{
					SCardLog::writeLog("[%s:%d][MD] CardAuthenticatePin: PIN code blocked",__FUNCTION__, __LINE__);
					MessageBox(NULL, L"PIN code blocked", L"Authentication error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
					return ret(E_PINBLOCKED);
				}
				else if(err.SW1 == 0x63 && err.SW2 == 0xC0)
				{
					SCardLog::writeLog("[%s:%d][MD] CardAuthenticatePin: PIN code blocked",__FUNCTION__, __LINE__);
					MessageBox(NULL, L"PIN code blocked", L"Authentication error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
					return ret(E_PINBLOCKED);
				}
				else if(err.SW1 == 0x63)
				{
					SCardLog::writeLog("[%s:%d][MD] CardAuthenticatePin: Wrong PIN presented",__FUNCTION__, __LINE__);
					MessageBox(cp, L"Wrong PIN presented", L"Authentication error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
					return ret(E_WRONGPIN);
				}
				else
				{
					SCardLog::writeLog("[%s:%d][MD] CardAuthenticatePin: PIN authentication error: %s",__FUNCTION__, __LINE__, err.what());
					MessageBox(NULL, L"PIN authentication error", L"Authentication error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
					return ret(E_WRONGPIN);
				}
			}
			catch (runtime_error &er )
			{
				TerminateThread(DialogThreadHandle, ERROR_SUCCESS);
				SCardLog::writeLog("[%s:%d][MD] CardAuthenticatePin: Runtime error",__FUNCTION__, __LINE__, er.what());
				return ret(E_WRONGPIN);
			}
		}
	}
	catch (runtime_error &ex)
	{
		if (pcAttemptsRemaining)
			*pcAttemptsRemaining = remaining - 1;
		SCardLog::writeLog("[%s:%d][MD] CardAuthenticatePin: Exception %s",__FUNCTION__, __LINE__, ex.what());
		return ret(E_WRONGPIN);
	}
	
	return ret(E_OK);
}

DWORD WINAPI CardAuthenticateEx(__in PCARD_DATA pCardData, __in PIN_ID PinId, __in DWORD dwFlags, __in PBYTE pbPinData, __in DWORD cbPinData,
    __deref_out_bcount_opt(*pcbSessionPin) PBYTE  *ppbSessionPin, __out_opt PDWORD pcbSessionPin, __out_opt PDWORD pcAttemptsRemaining)
{
	if (!pCardData) return ret(E_PARAM);
	SCardLog::writeLog("[%s:%d][MD] CardAuthenticateEx: PinId=%u, dwFlags=0x%08X, cbPinData=%u, Attempts %s",__FUNCTION__, __LINE__, PinId, dwFlags, cbPinData, pcAttemptsRemaining ? "YES" : "NO");

	EstEIDManager estEIDManager(pCardData->hSCardCtx, pCardData->hScard);

	if(pbPinData == NULL && !estEIDManager.isSecureConnection())
		return SCARD_E_INVALID_PARAMETER;

	if(!estEIDManager.isSecureConnection())
	{
		if (dwFlags == CARD_AUTHENTICATE_GENERATE_SESSION_PIN || dwFlags == CARD_AUTHENTICATE_SESSION_PIN)
			return ret(E_UNSUPPORTED);
		if (dwFlags && dwFlags != CARD_PIN_SILENT_CONTEXT) 
			return ret(E_PARAM);
		if (pcAttemptsRemaining)
		{
			*pcAttemptsRemaining = 3;
		}

		if (cbPinData < 4 || cbPinData > 12)
			return ret(E_WRONGPIN);

		char *pin = (char *)pbPinData;

		PinString tmp(pin , pin+cbPinData );
		BYTE remaining = 0,dummy = 0xFA;
		
		byte puk = 0,pinAuth = 0,pinSign = 0;
		if (PinId != AUTH_PIN_ID && PinId != SIGN_PIN_ID && PinId != PUKK_PIN_ID) 
			return ret(E_PARAM);
		try
		{
			if(estEIDManager.isSecureConnection() == true)
			{
				SCardLog::writeLog("[%s:%d][MD] CardAuthenticateEx: Using secure connection to card",__FUNCTION__, __LINE__);
			}
			else
			{
				SCardLog::writeLog("[%s:%d][MD] CardAuthenticateEx: Secure connection is not used",__FUNCTION__, __LINE__);
			}
			if (pcAttemptsRemaining)
			{
				estEIDManager.getRetryCounts(puk,pinAuth,pinSign);
			}
			if (PinId == AUTH_PIN_ID)
			{
				remaining = pinAuth;
				estEIDManager.validateAuthPin(tmp,pinAuth);
				pcAttemptsRemaining = (PDWORD)&remaining;
			}
			if (PinId == SIGN_PIN_ID)
			{
				remaining = pinSign;
				estEIDManager.validateSignPin(tmp,pinSign);
				pcAttemptsRemaining = (PDWORD)&remaining;
			}
			if (PinId == PUKK_PIN_ID)
			{
				remaining = puk;
				estEIDManager.validatePuk(tmp, puk);
				pcAttemptsRemaining = (PDWORD)&remaining;
			}
		}
		catch (AuthError e)
		{
			if (pcAttemptsRemaining)
				*pcAttemptsRemaining = remaining - 1;
			SCardLog::writeLog("[%s:%d][MD] CardAuthenticateEx: AuthError",__FUNCTION__, __LINE__);
			return ret(e.m_blocked ? E_PINBLOCKED : E_WRONGPIN );
		}
		catch (runtime_error & )
		{
			if (pcAttemptsRemaining)
				*pcAttemptsRemaining = remaining - 1;
			SCardLog::writeLog("[%s:%d][MD] CardAuthenticateEx: Runtime error",__FUNCTION__, __LINE__);
			return ret(E_WRONGPIN);
		}
	}
	else
	{
		if (dwFlags != CARD_AUTHENTICATE_GENERATE_SESSION_PIN && dwFlags != CARD_AUTHENTICATE_SESSION_PIN && dwFlags != 0)
			return ret(E_PARAM);
		if(PinId != AUTH_PIN_ID && PinId != SIGN_PIN_ID && PinId != PUKK_PIN_ID)
			return ret(E_PARAM);
		if (pcAttemptsRemaining)
		{
			*pcAttemptsRemaining = 3;
		}
		BYTE remaining = 0,dummy = 0xFA;
		byte puk = 0,pinAuth = 0,pinSign = 0;

			EXTERNAL_INFO externalInfo;
			externalInfo.hwndParentWindow = cp;
			externalInfo.pinType = PinId;
			HANDLE DialogThreadHandle;
			try
			{
				PinString tmp = PinString("");
				if(estEIDManager.isSecureConnection() == true)
				{
					SCardLog::writeLog("[%s:%d][MD] CardAuthenticateEx: Using secure connection to card",__FUNCTION__, __LINE__);
				}
				else
				{
					SCardLog::writeLog("[%s:%d][MD] CardAuthenticateEx: Secure connection is not used",__FUNCTION__, __LINE__);
				}

				estEIDManager.getRetryCounts(puk, pinAuth, pinSign);

				if (PinId == AUTH_PIN_ID)
				{
					const int BUFFER_SIZE = 512;
					int lReturn = 0;
					WCHAR wcBuffer[BUFFER_SIZE];
					lReturn = GetLocaleInfo(LOCALE_USER_DEFAULT, LOCALE_SENGLANGUAGE, wcBuffer, BUFFER_SIZE);
					remaining = pinAuth;
					if(std::wstring(wcBuffer) == std::wstring(L"Russian"))
					{
						estEIDManager.setReaderLanguageId(estEIDManager.RUS);
						externalInfo.langId = estEIDManager.RUS;
					}
					else if(std::wstring(wcBuffer) == std::wstring(L"Estonian"))
					{
						estEIDManager.setReaderLanguageId(estEIDManager.EST);
						externalInfo.langId = estEIDManager.EST;
					}
					else
					{
						estEIDManager.setReaderLanguageId(estEIDManager.ENG);
						externalInfo.langId = estEIDManager.ENG;
					}

					bool authenticated = false;
					bool blocked = false;
					if(remaining == 0x00)
					{
						SCardLog::writeLog("[%s:%d][MD] PIN code blocked",__FUNCTION__, __LINE__);
						MessageBox(NULL, L"PIN code blocked", L"Authentication error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
						return ret(E_PINBLOCKED);
					}
					while(remaining != 0x00)
					{
						if(authenticated)
							break;
						try
						{
							DialogThreadHandle = CreateThread(NULL, 0, DialogThreadEntry, &externalInfo, 0, NULL);
							estEIDManager.isSecureConnection();
							estEIDManager.validateAuthPin(tmp, remaining);
							TerminateThread(DialogThreadHandle, ERROR_SUCCESS);
							remaining = 0x03;
							authenticated = true;
						}
						catch(AuthError &ae)
						{
							if(ae.m_aborted == true)
							{
								SCardLog::writeLog("[%s:%d][MD] PIN input aborted",__FUNCTION__, __LINE__, 3-remaining);
								TerminateThread(DialogThreadHandle, ERROR_SUCCESS);
								return ret(E_CANCELLED_BY_USER);
							}
							else if(ae.m_blocked == true)
							{
								SCardLog::writeLog("[%s:%d][MD] PIN1 blocked",__FUNCTION__, __LINE__, remaining);
								MessageBox(cp, L"PIN1 blocked.", L"Authentication error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
								TerminateThread(DialogThreadHandle, ERROR_SUCCESS);
								return ret(E_PINBLOCKED);
							}
							else if(ae.m_badinput == true)
							{
								SCardLog::writeLog("[%s:%d][MD] Unexpected input",__FUNCTION__, __LINE__, 3-remaining);
								MessageBox(cp, L"Unexpected input.", L"Authentication error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
								break;
							}
							else
							{
								SCardLog::writeLog("[%s:%d][MD] Wrong PIN presented %i attempts remaining",__FUNCTION__, __LINE__, 3-remaining);
								MessageBox(cp, L"Wrong PIN presented.", L"Authentication error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
								remaining--;
								TerminateThread(DialogThreadHandle, ERROR_SUCCESS);
							}
						}
					}
					TerminateThread(DialogThreadHandle, ERROR_SUCCESS);
				}
				if (PinId == SIGN_PIN_ID)
				{
					const int BUFFER_SIZE = 512;
					int lReturn = 0;
					WCHAR wcBuffer[BUFFER_SIZE];
					lReturn = GetLocaleInfo(LOCALE_USER_DEFAULT, LOCALE_SENGLANGUAGE, wcBuffer, BUFFER_SIZE);
					remaining = pinSign;
					if(std::wstring(wcBuffer) == std::wstring(L"Russian"))
					{
						estEIDManager.setReaderLanguageId(estEIDManager.RUS);
						externalInfo.langId = estEIDManager.RUS;
					}
					else if(std::wstring(wcBuffer) == std::wstring(L"Estonian"))
					{
						estEIDManager.setReaderLanguageId(estEIDManager.EST);
						externalInfo.langId = estEIDManager.EST;
					}
					else
					{
						estEIDManager.setReaderLanguageId(estEIDManager.ENG);
						externalInfo.langId = estEIDManager.ENG;
					}

					bool authenticated = false;
					bool blocked = false;
					if(remaining == 0x00)
					{
						SCardLog::writeLog("[%s:%d][MD] PIN code blocked",__FUNCTION__, __LINE__);
						MessageBox(NULL, L"PIN code blocked", L"Authentication error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
						return ret(E_PINBLOCKED);
					}
					while(remaining != 0x00)
					{
						if(authenticated)
							break;
						try
						{
							DialogThreadHandle = CreateThread(NULL, 0, DialogThreadEntry, &externalInfo, 0, NULL);
							estEIDManager.isSecureConnection();
							estEIDManager.validateSignPin(tmp, remaining);
							TerminateThread(DialogThreadHandle, ERROR_SUCCESS);
							remaining = 0x03;
							authenticated = true;
						}
						catch(AuthError &ae)
						{
							if(ae.m_aborted == true)
							{
								SCardLog::writeLog("[%s:%d][MD] PIN input aborted E_CANCELLED_BY_USER",__FUNCTION__, __LINE__, 3-remaining);
								TerminateThread(DialogThreadHandle, ERROR_SUCCESS);
								return ret(E_CANCELLED_BY_USER);
							}
							else if(ae.m_blocked == true)
							{
								SCardLog::writeLog("[%s:%d][MD] PIN2 blocked",__FUNCTION__, __LINE__, 3-remaining);
								MessageBox(cp, L"PIN2 blocked.", L"Authentication error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
								TerminateThread(DialogThreadHandle, ERROR_SUCCESS);
								return ret(E_PINBLOCKED);
							}
							else if(ae.m_badinput == true)
							{
								SCardLog::writeLog("[%s:%d][MD] Unexpected input",__FUNCTION__, __LINE__, 3-remaining);
								MessageBox(cp, L"Unexpected input.", L"Authentication error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
								break;
							}
							else
							{
								SCardLog::writeLog("[%s:%d][MD] Wrong PIN presented %i attempts remaining",__FUNCTION__, __LINE__, 3-remaining);
								MessageBox(cp, L"Wrong PIN presented.", L"Authentication error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
								remaining--;
								TerminateThread(DialogThreadHandle, ERROR_SUCCESS);
							}
						}
					}
					TerminateThread(DialogThreadHandle, ERROR_SUCCESS);
				}
				if(PinId == PUKK_PIN_ID)
				{
					const int BUFFER_SIZE = 512;
					int lReturn = 0;
					WCHAR wcBuffer[BUFFER_SIZE];
					lReturn = GetLocaleInfo(LOCALE_USER_DEFAULT, LOCALE_SENGLANGUAGE, wcBuffer, BUFFER_SIZE);
					remaining = puk;
					if(std::wstring(wcBuffer) == std::wstring(L"Russian"))
					{
						estEIDManager.setReaderLanguageId(estEIDManager.RUS);
						externalInfo.langId = estEIDManager.RUS;
					}
					else if(std::wstring(wcBuffer) == std::wstring(L"Estonian"))
					{
						estEIDManager.setReaderLanguageId(estEIDManager.EST);
						externalInfo.langId = estEIDManager.EST;
					}
					else
					{
						estEIDManager.setReaderLanguageId(estEIDManager.ENG);
						externalInfo.langId = estEIDManager.ENG;
					}

					bool authenticated = false;
					bool blocked = false;
					if(remaining == 0x00)
					{
						SCardLog::writeLog("[%s:%d][MD] PIN code blocked",__FUNCTION__, __LINE__);
						MessageBox(NULL, L"PIN code blocked", L"Authentication error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
						return ret(E_PINBLOCKED);
					}
					while(remaining != 0x00)
					{
						if(authenticated)
							break;
						try
						{
							DialogThreadHandle = CreateThread(NULL, 0, DialogThreadEntry, &externalInfo, 0, NULL);
							estEIDManager.isSecureConnection();
							estEIDManager.validatePuk(tmp, remaining);
							TerminateThread(DialogThreadHandle, ERROR_SUCCESS);
							remaining = 0x03;
							authenticated = true;
						}
						catch(AuthError &ae)
						{
							if(ae.m_aborted == true)
							{
								SCardLog::writeLog("[%s:%d][MD] PUK input aborted",__FUNCTION__, __LINE__, 3-remaining);
								TerminateThread(DialogThreadHandle, ERROR_SUCCESS);
								return ret(E_CANCELLED_BY_USER);
							}
							else if(ae.m_blocked == true)
							{
								SCardLog::writeLog("[%s:%d][MD] PUK blocked",__FUNCTION__, __LINE__, 3-remaining);
								MessageBox(cp, L"PUK blocked.", L"Authentication error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
								TerminateThread(DialogThreadHandle, ERROR_SUCCESS);
								return ret(E_PINBLOCKED);
							}
							else if(ae.m_badinput == true)
							{
								SCardLog::writeLog("[%s:%d][MD] Unexpected input",__FUNCTION__, __LINE__, 3-remaining);
								MessageBox(cp, L"Unexpected input.", L"Authentication error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
								break;
							}
							else
							{
								SCardLog::writeLog("[%s:%d][MD] Wrong PUK presented %i attempts remaining",__FUNCTION__, __LINE__, 3-remaining);
								MessageBox(cp, L"Wrong PUK presented.", L"Authentication error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
								remaining--;
								TerminateThread(DialogThreadHandle, ERROR_SUCCESS);
							}
						}
					}
					TerminateThread(DialogThreadHandle, ERROR_SUCCESS);
				}
			}
			catch (AuthError err)
			{
				TerminateThread(DialogThreadHandle, ERROR_SUCCESS);
				
				if(err.SW1 == 0x69 && err.SW2 == 0x83)
				{
					SCardLog::writeLog("[%s:%d][MD] PIN code blocked",__FUNCTION__, __LINE__);
					MessageBox(NULL, L"PIN code blocked", L"Authentication error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
					return ret(E_PINBLOCKED);
				}
				else if(err.SW1 == 0x63 && err.SW2 == 0x00)
				{
					SCardLog::writeLog("[%s:%d][MD] PIN code blocked",__FUNCTION__, __LINE__);
					MessageBox(NULL, L"PIN code blocked", L"Authentication error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
					return ret(E_PINBLOCKED);
				}
				else if(err.SW1 == 0x63 && err.SW2 == 0xC0)
				{
					SCardLog::writeLog("[%s:%d][MD] PIN code blocked",__FUNCTION__, __LINE__);
					MessageBox(NULL, L"PIN code blocked", L"Authentication error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
					return ret(E_PINBLOCKED);
				}
				else if(err.SW1 == 0x63)
				{
				SCardLog::writeLog("[%s:%d][MD] Wrong PIN presented",__FUNCTION__, __LINE__);
					if (pcAttemptsRemaining)
						*pcAttemptsRemaining = remaining - 1;
					MessageBox(cp, L"Wrong PIN presented", L"Authentication error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
					return ret(E_WRONGPIN);
				}
				else
				{
					if (pcAttemptsRemaining)
						*pcAttemptsRemaining = remaining - 1;
					SCardLog::writeLog("[%s:%d][MD] PIN authentication error: %s",__FUNCTION__, __LINE__, err.what());
					MessageBox(NULL, L"PIN authentication error", L"Authentication error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
					return ret(E_WRONGPIN);
				}
			}
			catch (runtime_error &er )
			{
				TerminateThread(DialogThreadHandle, ERROR_SUCCESS);
				SCardLog::writeLog("[%s:%d][MD] Runtime error",__FUNCTION__, __LINE__, er.what());
				return ret(E_WRONGPIN);
			}
	}
	
	return ret(E_OK);
}


DWORD WINAPI CardEnumFiles(__in PCARD_DATA  pCardData, __in LPSTR pszDirectoryName, __out_ecount(*pdwcbFileName)LPSTR *pmszFileNames, __out LPDWORD pdwcbFileName, __in DWORD dwFlags)
{
	SCardLog::writeLog("[%s:%d][MD] CardEnumFiles",__FUNCTION__, __LINE__);
	const char root_files[] = "cardapps\0cardcf\0cardid\0\0";
	const char mscp_files[] = "kxc00\0kxc01\0cmapfile\0\0";
	if (!pCardData) return ret(E_PARAM);
	if (!pmszFileNames) return ret(E_PARAM);
	if (!pdwcbFileName) return ret(E_PARAM);
	if (dwFlags) return ret(E_PARAM);

	if (!pszDirectoryName || !strlen(pszDirectoryName))
	{
		DWORD sz = sizeof(root_files) - 1;
		LPSTR t = (LPSTR)(*pCardData->pfnCspAlloc)(sz);
		if (!t) return ret(E_MEMORY);
		CopyMemory(t,root_files,sz);
		*pmszFileNames = t;
		*pdwcbFileName = sz;
		return ret(E_OK);
	}
	if (!_strcmpi(pszDirectoryName,"mscp"))
	{
		DWORD sz = sizeof(mscp_files) - 1;
		LPSTR t = (LPSTR)(*pCardData->pfnCspAlloc)(sz);
		if (!t) return ret(E_MEMORY);
		CopyMemory(t,mscp_files,sz);
		*pmszFileNames = t;
		*pdwcbFileName = sz;
		return ret(E_OK);
	}
	return ret(E_NODIRECTORY);
}


DWORD WINAPI CardGetFileInfo(__in PCARD_DATA pCardData, __in LPSTR pszDirectoryName, __in LPSTR pszFileName, __in PCARD_FILE_INFO pCardFileInfo)
{
	SCardLog::writeLog("[%s:%d][MD] CardGetFileInfo",__FUNCTION__, __LINE__);
	if (!pCardData) return ret(E_PARAM);
	if (!pszFileName) return ret(E_PARAM);
	if (!strlen(pszFileName)) return ret(E_PARAM);
	if (!pCardFileInfo) return ret(E_PARAM);

	if (pCardFileInfo->dwVersion != CARD_FILE_INFO_CURRENT_VERSION && 
		pCardFileInfo->dwVersion != 0 ) 
		return ret(E_REVISION);

	pCardFileInfo->AccessCondition = EveryoneReadUserWriteAc;
	if (!pszDirectoryName || !strlen(pszDirectoryName))
	{
		if (!_strcmpi(pszFileName,"cardapps"))
		{
			SCardLog::writeLog("[%s:%d][MD] CardGetFileInfo: cardapps",__FUNCTION__, __LINE__);
			pCardFileInfo->cbFileSize = sizeof( ((cardFiles *)pCardData->pvVendorSpecific)->file_appdir);
			return ret(E_OK);
		}
		if (!_strcmpi(pszFileName,"cardcf"))
		{
			SCardLog::writeLog("[%s:%d][MD] CardGetFileInfo: cardcf",__FUNCTION__, __LINE__);
			pCardFileInfo->cbFileSize = sizeof(((cardFiles *)pCardData->pvVendorSpecific)->file_cardcf);
			return ret(E_OK);
		}
		if (!_strcmpi(pszFileName,"cardid"))
		{
			SCardLog::writeLog("[%s:%d][MD] CardGetFileInfo: cardid",__FUNCTION__, __LINE__);
			pCardFileInfo->cbFileSize = sizeof(((cardFiles *)pCardData->pvVendorSpecific)->file_cardid);
			return ret(E_OK);
		}
		SCardLog::writeLog("[%s:%d][MD] CardGetFileInfo:file not found 0",__FUNCTION__, __LINE__);
		return ret(E_NOFILE);
	}
	if (!_strcmpi(pszDirectoryName,"mscp"))
	{
		if (!_strcmpi(pszFileName,"cmapfile"))
		{
			SCardLog::writeLog("[%s:%d][MD] CardGetFileInfo: cmapfile",__FUNCTION__, __LINE__);
			pCardFileInfo->cbFileSize = sizeof(CONTAINERMAPREC ) * 2;
			return ret(E_OK);
		}
		SCardLog::writeLog("[%s:%d][MD] CardGetFileInfo:file not found 1",__FUNCTION__, __LINE__);
		return ret(E_NOFILE);
	}
	return ret(E_NODIRECTORY);
}

DWORD WINAPI CardReadFile(__in PCARD_DATA pCardData, __in LPSTR pszDirectoryName, __in LPSTR pszFileName, __in DWORD dwFlags, __deref_out_bcount(*pcbData)PBYTE *ppbData, __out PDWORD pcbData)
{
	if (!pCardData)
		return ret(E_PARAM);

	SCardLog::writeLog("[%s:%d][MD] CardReadFile pszDirectoryName=%s, pszFileName=%s, dwFlags=0x%08X",__FUNCTION__, __LINE__, NULLSTR(pszDirectoryName), NULLSTR(pszFileName), dwFlags);

	if (!pszFileName)
		return ret(E_PARAM);
	if (!strlen(pszFileName))
		return ret(E_PARAM);
	if (!ppbData)
		return ret(E_PARAM);
	if (!pcbData)
		return ret(E_PARAM);
	if (dwFlags)
		return ret(E_PARAM);

	if (pszDirectoryName && _strcmpi(pszDirectoryName, "mscp"))
		return ret(E_NODIRECTORY);

	if (!_strcmpi(pszFileName, "cardcf"))
	{
		SCardLog::writeLog("[%s:%d][MD] CardReadFile: Filename cardcf",__FUNCTION__, __LINE__);
		DWORD sz = sizeof(((cardFiles *)pCardData->pvVendorSpecific)->file_cardcf);
		
		PBYTE t = (LPBYTE)(*pCardData->pfnCspAlloc)(sz);
		if (!t)
			return ret(E_MEMORY);
		CopyMemory(t,((cardFiles *)pCardData->pvVendorSpecific)->file_cardcf, sz);

		*ppbData = t;
		*pcbData = sz;
		return ret(E_OK);
	}

	if (!_strcmpi(pszFileName, "cardid"))
	{
		SCardLog::writeLog("[%s:%d][MD] CardReadFile: Filename cardid",__FUNCTION__, __LINE__);
		cardFiles *ptr = (cardFiles *)pCardData->pvVendorSpecific;

		try
		{
			EstEIDManager estEIDManager(pCardData->hSCardCtx, pCardData->hScard);
			string id  = estEIDManager.readDocumentID();

			if (id.length() < MIN_DOCUMENT_ID_LEN || id.length() > MAX_DOCUMENT_ID_LEN)
			{
				SCardLog::writeLog("[%s:%d][MD] Runtime_error in CardReadFile id.length() is %d",__FUNCTION__, __LINE__, id.length());
				return ret(E_NOFILE);
			}

			memset(ptr->file_cardid, 0, sizeof(ptr->file_cardid));
			CopyMemory( ptr->file_cardid, id.c_str(), id.length());

			SCardLog::writeLog("[%s:%d][MD] cardid: '%s'",__FUNCTION__, __LINE__, ptr->file_cardid);
		}
		catch (runtime_error &err)
		{
			SCardLog::writeLog("[%s:%d][MD] runtime_error in CardReadFile '%s'",__FUNCTION__, __LINE__, err.what());
			return ret(E_NOFILE);
		}
		DWORD sz = sizeof(ptr->file_cardid);
		PBYTE t = (PBYTE)(*pCardData->pfnCspAlloc)(sz);
		if (!t)
		{
			SCardLog::writeLog("[%s:%d][MD] return ret(E_MEMORY);",__FUNCTION__, __LINE__);
			return ret(E_MEMORY);
		}
		SCardLog::writeLog("[%s:%d][MD] CopyMemory",__FUNCTION__, __LINE__);
		CopyMemory(t,ptr->file_cardid,sz );

		SCardLog::writeLog("[%s:%d][MD] ppbData",__FUNCTION__, __LINE__);
		*ppbData = t;
		SCardLog::writeLog("[%s:%d][MD] pcbData",__FUNCTION__, __LINE__);
		*pcbData = sz;
		SCardLog::writeLog("[%s:%d][MD] return ret(E_OK);",__FUNCTION__, __LINE__);
		return ret(E_OK);
	}

	if (pszDirectoryName && !_strcmpi(pszDirectoryName, "mscp"))
	{
		if (!_strcmpi(pszFileName,"kxc00"))
		{
			SCardLog::writeLog("[%s:%d][MD] CardReadFile: Filename kxc00 [AUTH CERT]",__FUNCTION__, __LINE__);
			ByteVec reply;
			try
			{
				EstEIDManager estEIDManager(pCardData->hSCardCtx, pCardData->hScard);
				reply = estEIDManager.getAuthCert();
			}
			catch (runtime_error & err)
			{
				SCardLog::writeLog("[%s:%d][MD] runtime_error in CardReadFile, reading kxc00, '%s'",__FUNCTION__, __LINE__, err.what());
				return ret(E_NOFILE);
			}

			DWORD sz = (DWORD) reply.size();
			PBYTE t = (PBYTE)(*pCardData->pfnCspAlloc)(sz);
			if (!t)
				return ret(E_MEMORY);
			CopyMemory(t,&reply[0],sz );

			*ppbData = t;
			*pcbData = sz;
			return ret(E_OK);
		}
		if (!_strcmpi(pszFileName,"kxc01"))
		{
			SCardLog::writeLog("[%s:%d][MD] CardReadFile: Filename kxc01 [AUTH CERT]",__FUNCTION__, __LINE__);
			ByteVec reply;
			try
			{
				EstEIDManager estEIDManager(pCardData->hSCardCtx, pCardData->hScard);
				reply = estEIDManager.getAuthCert();
			}
			catch (runtime_error & err)
			{
				SCardLog::writeLog("[%s:%d][MD] runtime_error in CardReadFile, reading kxc01, '%s'",__FUNCTION__, __LINE__, err.what());
				return ret(E_NOFILE);
			}

			DWORD sz = (DWORD) reply.size();
			PBYTE t = (PBYTE)(*pCardData->pfnCspAlloc)(sz);
			if (!t)
				return ret(E_MEMORY);
			CopyMemory(t,&reply[0],sz );

			*ppbData = t;
			*pcbData = sz;
			return ret(E_OK);
		}

		if (!_strcmpi(pszFileName,"ksc01"))
		{
			SCardLog::writeLog("[%s:%d][MD] CardReadFile: Filename ksc01 [SIGN CERT]",__FUNCTION__, __LINE__);
			if (pCardData->dwVersion < 6 )
			{
				SCardLog::writeLog("[%s:%d][MD] Runtime_error in CardReadFile, reading ksc01,pCardData->dwVersion is %d",__FUNCTION__, __LINE__, pCardData->dwVersion);
				return ret(E_NOFILE);
			}

			ByteVec reply;
			try
			{
				EstEIDManager estEIDManager(pCardData->hSCardCtx, pCardData->hScard);
				reply = estEIDManager.getSignCert();
			}
			catch (runtime_error &err)
			{
				SCardLog::writeLog("[%s:%d][MD] Runtime_error in CardReadFile, reading ksc01, '%s'",__FUNCTION__, __LINE__, err.what());
				return ret(E_NOFILE);
			}

			DWORD sz = (DWORD) reply.size();
			PBYTE t = (PBYTE)(*pCardData->pfnCspAlloc)(sz);
			if (!t)
				return ret(E_MEMORY);
			CopyMemory(t,&reply[0],sz );

			*ppbData = t;
			*pcbData = sz;
			return ret(E_OK);
		}

		if (!_strcmpi(pszFileName,"cmapfile"))
		{
			DWORD numContainers = 1;

			if (pCardData->dwVersion >= 6)
				numContainers = 2;

			string id = "";
			string autContName = "";
			string sigContName = "";
			size_t autConNameLen = 0;
			size_t sigConNameLen = 0;
			size_t i;
			unsigned int key_size = 0;

			try 
			{
				EstEIDManager estEIDManager(pCardData->hSCardCtx, pCardData->hScard);
				id  = estEIDManager.readDocumentID();
				autContName = estEIDManager.getMD5KeyContainerName(EstEIDManager::AUTH);
				sigContName = estEIDManager.getMD5KeyContainerName(EstEIDManager::SIGN);
				key_size = estEIDManager.getKeySize();

			}
			catch (runtime_error & err)
			{
				SCardLog::writeLog("[%s:%d][MD] Runtime_error in CardReadFile, reading cmapfile '%s'",__FUNCTION__, __LINE__, err.what());
				return ret(E_NOFILE);
			}

			if (id.length() < MIN_DOCUMENT_ID_LEN || id.length() > MAX_DOCUMENT_ID_LEN)
			{
				SCardLog::writeLog("[%s:%d][MD] Runtime_error in CardReadFile, id.length is '%d'",__FUNCTION__, __LINE__, id.length());
				return ret(E_NOFILE);
			}

			WCHAR autGuid[] = L"00000000000000000000000000000000";
			WCHAR sigGuid[] = L"00000000000000000000000000000000";
			autConNameLen = autContName.size();
			sigConNameLen = sigContName.size();
			for (i = 0; i<autConNameLen; i++)
			{
				char b = autContName[i];
				autGuid[i] = b;
			}
			for (i = 0; i<sigConNameLen; i++)
			{
				char b = sigContName[i];
				sigGuid[i] = b;
			}

			DWORD sz = sizeof(CONTAINERMAPREC ) * numContainers;
			PBYTE t = (LPBYTE)(*pCardData->pfnCspAlloc)(sz);
			if (!t)
				return ret(E_MEMORY);
			PBYTE originalT = t;
			ZeroMemory(t,sz);

			CONTAINERMAPREC *c1 = (CONTAINERMAPREC *) t;
			wcsncpy((PWCHAR ) c1->GuidInfo,autGuid,sizeof(c1->GuidInfo) / 2);

			c1->Flags = 3; // 1 valid + 2 default
			c1->ui16KeyExchangeKeySize = key_size;
			// don't use the sign key from second container (as there is none)
			c1->ui16SigKeySize = 0;

			if (numContainers == 2)
			{
				SCardLog::writeLog("[%s:%d][MD] CardReadFile returns 2 containers",__FUNCTION__, __LINE__);
				CONTAINERMAPREC *c2 = (CONTAINERMAPREC *)(t + sizeof(CONTAINERMAPREC));
				wcsncpy((PWCHAR ) c2->GuidInfo, sigGuid, sizeof(c2->GuidInfo) / 2);
				c2->Flags = 1; // 1 valid
				// don't use the auth key from first container (as there is none)
				c2->ui16KeyExchangeKeySize = 0;
				c2->ui16SigKeySize = key_size;
			}

			*ppbData = originalT;
			*pcbData = sz;
			return ret(E_OK);
		}
	}

	SCardLog::writeLog("[%s:%d][MD] Returning E_NOFILE",__FUNCTION__, __LINE__);
	return ret(E_NOFILE);
}


DWORD WINAPI CardWriteFile(__in PCARD_DATA pCardData, __in LPSTR pszDirectoryName, __in LPSTR pszFileName, __in DWORD dwFlags, __in_bcount(cbData) PBYTE pbData, __in DWORD cbData)
{
	if (!pCardData) return ret(E_PARAM);
	SCardLog::writeLog("[%s:%d][MD] CardWriteFile pszDirectoryName=%s, pszFileName=%s, dwFlags=0x%08X, cbData=%u",__FUNCTION__, __LINE__,NULLSTR(pszDirectoryName), NULLSTR(pszFileName), dwFlags, cbData);
	return ret(E_UNSUPPORTED);
}


DWORD WINAPI CardQueryFreeSpace( __in PCARD_DATA pCardData, __in DWORD dwFlags, __in PCARD_FREE_SPACE_INFO pCardFreeSpaceInfo)
{
	if (!pCardData) 
		return ret(E_PARAM);
	if (!pCardFreeSpaceInfo) 
		return ret(E_PARAM);
	SCardLog::writeLog("[%s:%d][MD] CardWriteFile dwFlags=0x%08X, dwVersion=%u",__FUNCTION__, __LINE__, dwFlags, pCardFreeSpaceInfo->dwVersion );
	if (dwFlags) 
		return ret(E_PARAM);

	if (pCardFreeSpaceInfo->dwVersion != CARD_FREE_SPACE_INFO_CURRENT_VERSION && pCardFreeSpaceInfo->dwVersion != 0)
		return ret(E_REVISION);

	pCardFreeSpaceInfo->dwVersion = CARD_FREE_SPACE_INFO_CURRENT_VERSION;
	pCardFreeSpaceInfo->dwBytesAvailable = 0;
	pCardFreeSpaceInfo->dwKeyContainersAvailable = 0;
	pCardFreeSpaceInfo->dwMaxKeyContainers = 2;
	return ret(E_OK);
}

DWORD WINAPI CardQueryKeySizes(__in PCARD_DATA pCardData, __in DWORD dwKeySpec, __in DWORD dwFlags, __in PCARD_KEY_SIZES pKeySizes)
{
	if (!pCardData)
		return ret(E_PARAM);

	if (!pKeySizes)
	{
		SCardLog::writeLog("[%s:%d][MD] CardQueryKeySizes NULL pKeySizes",__FUNCTION__, __LINE__);
		return ret(E_PARAM);
	}

	SCardLog::writeLog("[%s:%d][MD] CardQueryKeySizes dwKeySpec=%u, dwFlags=0x%08X, dwVersion=%u",__FUNCTION__, __LINE__,dwKeySpec,dwFlags,pKeySizes->dwVersion );

	if (dwFlags)
		return  ret(E_PARAM);

	if (dwKeySpec > 8 || dwKeySpec == 0)
		return ret(E_PARAM);

	if (dwKeySpec != AT_SIGNATURE && dwKeySpec != AT_KEYEXCHANGE )
		return ret(E_UNSUPPORTED);

	if (pKeySizes->dwVersion > CARD_KEY_SIZES_CURRENT_VERSION)
		return ret(E_REVISION);

	unsigned int key_size = NULL;
	try
	{
		EstEIDManager estEIDManager(pCardData->hSCardCtx, pCardData->hScard);
		key_size  = estEIDManager.getKeySize();
	}
	catch (runtime_error &err )
	{
		SCardLog::writeLog("[%s:%d][MD] runtime_error in CardReadFile '%s'",__FUNCTION__, __LINE__, err.what());
		return ret(E_NOFILE);
	}
	if (!key_size)
		return ret(E_INTERNAL);

	pKeySizes->dwDefaultBitlen = key_size;
	pKeySizes->dwMaximumBitlen = key_size;
	pKeySizes->dwMinimumBitlen = key_size;
	pKeySizes->dwIncrementalBitlen = 0;

	return ret(E_OK);
}

DWORD WINAPI CardRSADecrypt(__in PCARD_DATA pCardData, __inout PCARD_RSA_DECRYPT_INFO  pInfo)
{
	if (!pCardData) return ret(E_PARAM);
	if (!pInfo) return ret(E_PARAM);
	SCardLog::writeLog("[%s:%d][MD] CardRSADecrypt dwVersion=%u, bContainerIndex=%u, dwKeySpec=%u, cbData=%u",__FUNCTION__, __LINE__, pInfo->dwVersion, pInfo->bContainerIndex, pInfo->dwKeySpec, pInfo->cbData);
	if(pInfo->dwVersion == CARD_RSA_KEY_DECRYPT_INFO_VERSION_TWO)
		SCardLog::writeLog("[%s:%d][MD] CardRSADecrypt dwPaddingType=%u, pPaddingInfo=%s",__FUNCTION__, __LINE__, pInfo->dwPaddingType, pInfo->pPaddingInfo);

	if (pInfo->dwVersion < CARD_RSA_KEY_DECRYPT_INFO_VERSION_ONE)
		return ret(E_REVISION);
	if(pInfo->dwVersion > CARD_RSA_KEY_DECRYPT_INFO_VERSION_TWO)
		return ret(E_REVISION);
	if(pInfo->dwKeySpec > AT_SIGNATURE)
		return ret(E_PARAM);

	if(pInfo->dwKeySpec != AT_KEYEXCHANGE)
	{
		if(pInfo->dwKeySpec <= AT_SIGNATURE)
			return ret(E_PARAM);
	}
	if(pInfo->cbData <= 1)
		return ret(E_SCBUFFER);

	if(!pInfo->cbData)
		return ret(E_SCBUFFER);
		
	SCardLog::writeLog("[%s:%d][MD] CardRSADecrypt: Check pbData",__FUNCTION__, __LINE__);
	if (!pInfo->pbData)
	{
		SCardLog::writeLog("[%s:%d][MD] CardRSADecrypt: Check pbData failed",__FUNCTION__, __LINE__);
		return ret(E_PARAM);
	}

	SCardLog::writeLog("[%s:%d][MD] CardRSADecrypt: Check dwKeySpec",__FUNCTION__, __LINE__);
	if (pInfo->dwKeySpec > 8 || pInfo->dwKeySpec == 0 ) 
	{
		return ret(E_PARAM);
	}
	SCardLog::writeLog("[%s:%d][MD] CardRSADecrypt: Check AT_SIGNATURE && AT_KEYEXCHANGE",__FUNCTION__, __LINE__);
	if (pInfo->dwKeySpec != AT_SIGNATURE && pInfo->dwKeySpec != AT_KEYEXCHANGE )
	{	
		return ret(E_PARAM);
	}
	SCardLog::writeLog("[%s:%d][MD] CardRSADecrypt: Check AUTH_CONTAINER_INDEX && SIGN_CONTAINER_INDEX",__FUNCTION__, __LINE__);
	if (pInfo->bContainerIndex != AUTH_CONTAINER_INDEX && pInfo->bContainerIndex != SIGN_CONTAINER_INDEX )
	{
		return ret(E_NOCONTAINER);
	}
	SCardLog::writeLog("[%s:%d][MD] CardRSADecrypt: Check AUTH_CONTAINER_INDEX",__FUNCTION__, __LINE__);
	if (pInfo->bContainerIndex == AUTH_CONTAINER_INDEX)
	{
		if (pInfo->dwKeySpec != AT_KEYEXCHANGE)
		{
			SCardLog::writeLog("[%s:%d][MD] CardRSADecrypt: Check AUTH_CONTAINER_INDEX failed.  Is: %i expected %i",__FUNCTION__, __LINE__, pInfo->bContainerIndex, AUTH_CONTAINER_INDEX);
			return ret(E_PARAM);
		}
	}
	else if (pInfo->dwKeySpec != AT_SIGNATURE)
	{
		SCardLog::writeLog("[%s:%d][MD] CardRSADecrypt: Check AT_SIGNATURE failed",__FUNCTION__, __LINE__);
		return ret(E_PARAM);
	}

	ByteVec reply;
	unsigned int key_size = 0;
	try
	{
		EstEIDManager estEIDManager(pCardData->hSCardCtx, pCardData->hScard);
		SCardLog::writeLog("[%s:%d][MD] CardRSADecrypt: getKeySize",__FUNCTION__, __LINE__);
		key_size = estEIDManager.getKeySize();
		SCardLog::writeLog("[%s:%d][MD] CardRSADecrypt: getKeySize %i",__FUNCTION__, __LINE__, key_size);
		if (pInfo->cbData < key_size / 8)
		{
			SCardLog::writeLog("[%s:%d][MD] getKeySize failed",__FUNCTION__, __LINE__);
			return ret(E_SCBUFFER);
		}


		SCardLog::writeByteBufferLog(__FUNC__, __LINE__, 0, 0, pInfo->pbData, pInfo->cbData, "Suplied cryptogram: ");

		SCardLog::writeLog("[%s:%d][MD] cipher",__FUNCTION__, __LINE__);
		ByteVec cipher(pInfo->pbData ,pInfo->pbData + pInfo->cbData );
		SCardLog::writeLog("[%s:%d][MD] reverse",__FUNCTION__, __LINE__);
		reverse(cipher.begin(),cipher.end());
		SCardLog::writeLog("[%s:%d][MD] RSADecrypt",__FUNCTION__, __LINE__);
		reply = estEIDManager.RSADecrypt(cipher);

		SCardLog::writeByteVecLog(reply, "Decrypted data: ");
	}
	catch (AuthError &err)
	{
		SCardLog::writeLog("[%s:%d][MD] SCError exception thrown: %s",__FUNCTION__, __LINE__, err.what());
		if (err.SW1 == 0x69 && err.SW2 == 0x88 )
		{
			SCardLog::writeLog("[%s:%d][MD] CardRSADecrypt: E_BADDATA",__FUNCTION__, __LINE__);
			return ret(E_BADDATA); //fyr digidoc
		}
		else
		{
			SCardLog::writeLog("[%s:%d][MD] CardRSADecrypt: E_NEEDSAUTH",__FUNCTION__, __LINE__);
			return ret(E_NEEDSAUTH);
		}
	}
	catch (CardError & err)
	{
		SCardLog::writeLog("[%s:%d][MD] CardError exception thrown: %s SW1=0x%02X SW2=0x%02X",__FUNCTION__, __LINE__, err.what(),
			err.SW1 , err.SW2 );
		if (err.SW1 == 0x64 && err.SW2 == 0 )
			return ret(E_BADDATA); //fyr digidoc
		else
			return ret(E_INTERNAL);
	}
	catch (runtime_error & ex)
	{
		SCardLog::writeLog("[%s:%d][MD] runtime_error exception thrown: %s",__FUNCTION__, __LINE__, ex.what());
		return ret(E_INTERNAL);
	}
	//E_NEEDSAUTH

	//our data comes out in wrong order and needs to be repadded
	int psLen = (int)(key_size/8 - reply.size() - 3);

	ByteVec pB(0);

	srand((unsigned int)time(0));
	reverse(reply.begin(),reply.end());
	pB.insert(pB.end(),reply.begin(),reply.end());
	if ((pInfo->dwVersion < CARD_RSA_KEY_DECRYPT_INFO_VERSION_TWO) || 
		((pInfo->dwVersion >= CARD_RSA_KEY_DECRYPT_INFO_VERSION_TWO) && 
		(pInfo->dwPaddingType == CARD_PADDING_NONE)))
	{
		pB.push_back(0);
		for (;psLen > 0;psLen --)
		{
			BYTE br;
			while(0 == (br = LOBYTE(rand())));
				pB.push_back( br );
		}
		pB.push_back(2);
		pB.push_back(0);
	}
	else
	{
		pInfo->cbData = (DWORD)pB.size();
	}

	SCardLog::writeByteVecLog(pB, "Decrypted data reverced & re-padded: ");
	CopyMemory(pInfo->pbData,&pB[0],pB.size());
	return ret(E_OK);
}

DWORD WINAPI CardSignData( __in PCARD_DATA pCardData, __in PCARD_SIGNING_INFO pInfo)
{
	if (!pCardData) return ret(E_PARAM);
	if (!pInfo) return ret(E_PARAM);

	SCardLog::writeLog("[%s:%d][MD] CardSignData dwVersion=%u, bContainerIndex=%u, dwKeySpec=%u"", dwSigningFlags=0x%08X, aiHashAlg=0x%08X, cbData=%u",__FUNCTION__, __LINE__, pInfo->dwVersion,
		pInfo->bContainerIndex, pInfo->dwKeySpec, pInfo->dwSigningFlags, pInfo->aiHashAlg, pInfo->cbData  );

	pInfo->cbSignedData = 0;
	ALG_ID hashAlg;
	if(!pInfo->aiHashAlg)
	{
		hashAlg = CALG_SHA_224;
	}
	else
	{
		hashAlg = pInfo->aiHashAlg;
	}

	if (!pInfo->pbData) return ret(E_PARAM);
	if (pInfo->bContainerIndex != AUTH_CONTAINER_INDEX && pInfo->bContainerIndex != SIGN_CONTAINER_INDEX)
		return ret(E_NOCONTAINER);
	if (pInfo->dwVersion > 1)
	{
		SCardLog::writeLog("[%s:%d][MD] CardSignData(3) dwPaddingType=%u",__FUNCTION__, __LINE__,pInfo->dwPaddingType);
	}

	if (pInfo->dwVersion != 1 && pInfo->dwVersion != 2) 
	{
		SCardLog::writeLog("[%s:%d][MD] Unsupported version",__FUNCTION__, __LINE__);
		return ret(E_REVISION);
	}
	if (pInfo->dwKeySpec != AT_KEYEXCHANGE && pInfo->dwKeySpec != AT_SIGNATURE )
	{
		SCardLog::writeLog("[%s:%d][MD] Unsupported dwKeySpec",__FUNCTION__, __LINE__);
		return ret(E_PARAM);
	}

	DWORD dwFlagMask = CARD_PADDING_INFO_PRESENT | CARD_BUFFER_SIZE_ONLY | CARD_PADDING_NONE | CARD_PADDING_PKCS1 | CARD_PADDING_PSS;
	if (pInfo->dwSigningFlags & (~dwFlagMask))
	{
		SCardLog::writeLog("[%s:%d][MD] Bogus dwSigningFlags",__FUNCTION__, __LINE__);
		return ret(E_PARAM);
	}

	if (CARD_PADDING_INFO_PRESENT & pInfo->dwSigningFlags)
	{
		if (CARD_PADDING_PKCS1 != pInfo->dwPaddingType)
		{
			SCardLog::writeLog("[%s:%d][MD] Unsupported paddingtype",__FUNCTION__, __LINE__);
			return ret(E_UNSUPPORTED);
		}
		BCRYPT_PKCS1_PADDING_INFO_adhoc *pinf = (BCRYPT_PKCS1_PADDING_INFO_adhoc *)pInfo->pPaddingInfo;
		if (!pinf->pszAlgId) 
			hashAlg = CALG_SSL3_SHAMD5;
		else
		{
			if (pinf->pszAlgId == wstring(L"MD5"))  hashAlg = CALG_MD5;
			if (pinf->pszAlgId == wstring(L"SHA1"))  hashAlg = CALG_SHA1;
			if (pinf->pszAlgId == wstring(L"SHA224"))  hashAlg = CALG_SHA_224;
			if (pinf->pszAlgId == wstring(L"SHA256"))  hashAlg = CALG_SHA_256;
			if (pinf->pszAlgId == wstring(L"SHA384"))  hashAlg = CALG_SHA_384;
			if (pinf->pszAlgId == wstring(L"SHA512"))  hashAlg = CALG_SHA_512;
		}
	}
	else
	{
		if (GET_ALG_CLASS(hashAlg) != ALG_CLASS_HASH)
		{
			SCardLog::writeLog("[%s:%d][MD] bogus aiHashAlg",__FUNCTION__, __LINE__);
			return ret(E_PARAM);
		}
		if (hashAlg !=0 && hashAlg != CALG_SSL3_SHAMD5 && hashAlg != CALG_SHA1 && hashAlg != CALG_MD5 && hashAlg != CALG_SHA_256 && hashAlg != CALG_SHA_384 && hashAlg != CALG_SHA_512)
		{
			SCardLog::writeLog("[%s:%d][MD] unsupported aiHashAlg",__FUNCTION__, __LINE__);
			return ret(E_UNSUPPORTED);
		}
	}

	if (pInfo->bContainerIndex != AUTH_CONTAINER_INDEX && pInfo->bContainerIndex != SIGN_CONTAINER_INDEX )
	{
		SCardLog::writeLog("[%s:%d][MD] Invalid container index",__FUNCTION__, __LINE__);
		return ret(E_NOCONTAINER);
	}

	ByteVec reply;
	ByteVec hash(pInfo->pbData ,pInfo->pbData + pInfo->cbData );

	std::stringstream hashString;
	hashString.str("");
	for (ByteVec::iterator it = hash.begin(); it < hash.end(); it++)
		hashString << std::hex << std::setfill('0') << std::setw(2) << (int) *it << " ";

	SCardLog::writeLog("[%s:%d][MD] Hash to sign: %s with size: %i", __FUNCTION__, __LINE__, hashString.str().c_str(), hash.size());

	bool withOID = (pInfo->dwSigningFlags & CRYPT_NOHASHOID) ? false : true;
	try
	{
		EstEIDManager estEIDManager(pCardData->hSCardCtx, pCardData->hScard);
		switch(hashAlg)
		{
		case CALG_MD5:
			SCardLog::writeLog("[%s:%d][MD] CALG_MD5 key size %i with OID: %s",__FUNCTION__, __LINE__, estEIDManager.getKeySize(), withOID == true ? "TRUE" : "FALSE");
			reply = estEIDManager.sign(hash, EstEIDManager::MD5, pInfo->bContainerIndex == AUTH_CONTAINER_INDEX ? EstEIDManager::AUTH : EstEIDManager::SIGN);
			break;
		case CALG_SHA1:
			SCardLog::writeLog("[%s:%d][MD] CALG_SHA1 key size %i with OID: %s",__FUNCTION__, __LINE__, estEIDManager.getKeySize(), withOID == true ? "TRUE" : "FALSE");
			reply = estEIDManager.sign(hash, EstEIDManager::SHA1, pInfo->bContainerIndex == AUTH_CONTAINER_INDEX ? EstEIDManager::AUTH : EstEIDManager::SIGN);
			break;
		case CALG_SHA_224:
			SCardLog::writeLog("[%s:%d][MD] CALG_SHA_224 key size %i with OID: %s",__FUNCTION__, __LINE__, estEIDManager.getKeySize(), withOID == true ? "TRUE" : "FALSE");
			reply = estEIDManager.sign(hash, EstEIDManager::SHA224, pInfo->bContainerIndex == AUTH_CONTAINER_INDEX ? EstEIDManager::AUTH : EstEIDManager::SIGN);
			break;
		case CALG_SHA_256:
			if(estEIDManager.getCardVersion() < EstEIDManager::VER_1_1)
			{
				SCardLog::writeLog("[%s:%d][MD] CALG_SHA_256 key size %i unsupported",__FUNCTION__, __LINE__, estEIDManager.getKeySize());
				ret(E_UNSUPPORTED);
			}
			SCardLog::writeLog("[%s:%d][MD] CALG_SHA_256 key size %i",__FUNCTION__, __LINE__, estEIDManager.getKeySize());
			reply = estEIDManager.sign(hash, EstEIDManager::SHA256, pInfo->bContainerIndex == AUTH_CONTAINER_INDEX ? EstEIDManager::AUTH : EstEIDManager::SIGN);
			break;
		case CALG_SHA_384:
			if(estEIDManager.getCardVersion() < EstEIDManager::VER_1_1)
			{
				SCardLog::writeLog("[%s:%d][MD] CALG_SHA_384 key size %i unsupported",__FUNCTION__, __LINE__, estEIDManager.getKeySize());
				ret(E_UNSUPPORTED);
			}
			SCardLog::writeLog("[%s:%d][MD] CALG_SHA_384 key size %i",__FUNCTION__, __LINE__, estEIDManager.getKeySize());
			reply = estEIDManager.sign(hash, EstEIDManager::SHA384, pInfo->bContainerIndex == AUTH_CONTAINER_INDEX ? EstEIDManager::AUTH : EstEIDManager::SIGN);
			break;
		case CALG_SHA_512:
			if(estEIDManager.getCardVersion() < EstEIDManager::VER_1_1)
			{
				SCardLog::writeLog("[%s:%d][MD] CALG_SHA_512 key size %i unsupported",__FUNCTION__, __LINE__, estEIDManager.getKeySize());
				ret(E_UNSUPPORTED);
			}
			SCardLog::writeLog("[%s:%d][MD] CALG_SHA_512 key size %i",__FUNCTION__, __LINE__, estEIDManager.getKeySize());
			reply = estEIDManager.sign(hash, EstEIDManager::SHA512, pInfo->bContainerIndex == AUTH_CONTAINER_INDEX ? EstEIDManager::AUTH : EstEIDManager::SIGN);
			break;
		case CALG_SSL3_SHAMD5:
		case 0:
			SCardLog::writeLog("[%s:%d][MD] CALG_SSL3_SHAMD5 or 0",__FUNCTION__, __LINE__);
			if (pInfo->bContainerIndex == AUTH_CONTAINER_INDEX)
			{
				SCardLog::writeLog("[%s:%d][MD] SSL requested with authentication key",__FUNCTION__, __LINE__);
				reply = estEIDManager.sign(hash, EstEIDManager::SSL, EstEIDManager::AUTH);
			}
			else if (pInfo->bContainerIndex == SIGN_CONTAINER_INDEX)
			{
				SCardLog::writeLog("[%s:%d][MD] CALG_SHA_1 with SIGN_CONTAINER",__FUNCTION__, __LINE__);
				reply = estEIDManager.sign(hash, EstEIDManager::SHA1, EstEIDManager::SIGN);
			}
			else
			{
				SCardLog::writeLog("[%s:%d][MD] Unsupported container index",__FUNCTION__, __LINE__);
				return ret(E_UNSUPPORTED);
			}
			break;
		default:
			SCardLog::writeLog("[%s:%d][MD] Unsupported hash alogrithm",__FUNCTION__, __LINE__);
			return ret(E_UNSUPPORTED);
		}
		if (reply.size() == 0)
		{
			SCardLog::writeLog("[%s:%d][MD] No function to call, hashAlg 0x%08X, container %d",__FUNCTION__, __LINE__,hashAlg,pInfo->bContainerIndex);
			return ret(E_NEEDSAUTH);
		}
	}
	catch (AuthError &err)
	{
		SCardLog::writeLog("[%s:%d][MD] SCError exception thrown: %s",__FUNCTION__, __LINE__, err.what());
		return ret(E_NEEDSAUTH);
	}
	catch (runtime_error &ex)
	{
		SCardLog::writeLog("[%s:%d][MD] Runtime_error exception thrown:",__FUNCTION__, __LINE__, ex.what());
		return ret(E_INTERNAL);
	}
	
	reverse(reply.begin(),reply.end());

	std::stringstream signedHash;
	signedHash.str("");
	for (ByteVec::iterator it = reply.begin(); it < reply.end(); it++)
		signedHash << std::hex << std::setfill('0') << std::setw(2) << (int) *it << " ";

	SCardLog::writeLog("[%s:%d][MD] Signed hash: %s with size: %i", __FUNCTION__, __LINE__, signedHash.str().c_str(), reply.size());

	pInfo->cbSignedData = (DWORD) reply.size();
	if (!(pInfo->dwSigningFlags & CARD_BUFFER_SIZE_ONLY))
	{
		pInfo->pbSignedData = (PBYTE)(*pCardData->pfnCspAlloc)(reply.size());
		if (!pInfo->pbSignedData) return ret(E_MEMORY);
		CopyMemory(pInfo->pbSignedData,&reply[0],reply.size());
	}
	return ret(E_OK);
}

DWORD WINAPI CardGetChallenge(__in PCARD_DATA pCardData, __deref_out_bcount(*pcbChallengeData) PBYTE *ppbChallengeData, __out PDWORD pcbChallengeData)
{
	SCardLog::writeLog("[%s:%d][MD] CardGetChallenge. Running in %s mode",__FUNCTION__, __LINE__, TestMode == true ? "TEST MODE" : "USER MODE");
	if(TestMode == true)
	{
		SCardLog::writeLog("[%s:%d][MD] This feature is not supported in test mode: ",__FUNCTION__, __LINE__);
		return ret(E_UNSUPPORTED);
	}
	if(NULL == pCardData)
		return ret(E_PARAM);
	if(NULL == ppbChallengeData)
		return ret(E_PARAM);
	if(NULL == pcbChallengeData)
		return ret(E_PARAM);
	try
	{
		std::stringstream APDU;
		EstEIDManager estEIDManager(pCardData->hSCardCtx, pCardData->hScard);
		ByteVec cardChallenge = estEIDManager.cardChallenge();

		APDU.str("");
		for (ByteVec::iterator it = cardChallenge.begin(); it < cardChallenge.end(); it++)
			APDU << std::hex << std::setfill('0') << std::setw(2) << (int) *it << " ";

		SCardLog::writeLog("[%s:%d][MD] Challenge recieved: %s",__FUNCTION__, __LINE__, APDU.str().c_str());

		reverse(cardChallenge.begin(),cardChallenge.end());

		APDU.str("");
		for (ByteVec::iterator it = cardChallenge.begin(); it < cardChallenge.end(); it++)
			APDU << std::hex << std::setfill('0') << std::setw(2) << (int) *it << " ";

		SCardLog::writeLog("[%s:%d][MD] Challenge reverced: %s",__FUNCTION__, __LINE__, APDU.str().c_str());

		DWORD sz = (DWORD)cardChallenge.size();
		PBYTE t = (PBYTE)(*pCardData->pfnCspAlloc)(sz);
		if(!t)
			return ret(E_MEMORY);
		CopyMemory(t, &cardChallenge[0], cardChallenge.size());
		*ppbChallengeData = t;
		*pcbChallengeData = (DWORD)cardChallenge.size();
	}
	catch (AuthError &err)
	{
		SCardLog::writeLog("[%s:%d][MD] SCError exception thrown: %s",__FUNCTION__, __LINE__, err.what());
		return ret(E_NEEDSAUTH);
	}
	catch (runtime_error &ex)
	{
		SCardLog::writeLog("[%s:%d][MD] Runtime_error exception thrown:",__FUNCTION__, __LINE__, ex.what());
		return ret(E_INTERNAL);
	}
	return ret(E_OK);
}

DWORD WINAPI CardChangeAuthenticatorEx(__in PCARD_DATA pCardData, __in DWORD dwFlags, __in PIN_ID dwAuthenticatingPinId,__in_bcount(cbAuthenticatingPinData) PBYTE pbAuthenticatingPinData,
    __in DWORD cbAuthenticatingPinData, __in PIN_ID dwTargetPinId, __in_bcount(cbTargetData)PBYTE pbTargetData, __in DWORD cbTargetData, __in DWORD cRetryCount,
	__out_opt PDWORD pcAttemptsRemaining)
{
	if(!pCardData)
		return ret(E_PARAM);
 	SCardLog::writeLog("[%s:%d][MD] CardChangeAuthenticatorEx. Running in %s mode.  dwVersion=%u, PIN_ID=%i, dwFlags=%s",__FUNCTION__, __LINE__, TestMode == true ? "TEST MODE" : "USER MODE", pCardData->dwVersion, dwAuthenticatingPinId, dwFlags == PIN_CHANGE_FLAG_CHANGEPIN ? "PIN_CHANGE_FLAG_CHANGEPIN" : "PIN_CHANGE_FLAG_UNBLOCK");
	if(TestMode == true)
	{
		SCardLog::writeLog("[%s:%d][MD] This feature is not supported in test mode",__FUNCTION__, __LINE__);
		return ret(E_UNSUPPORTED);
	}
	if(dwFlags == NULL)
		return ret(E_PARAM);
	if(dwFlags != PIN_CHANGE_FLAG_CHANGEPIN && dwFlags != PIN_CHANGE_FLAG_UNBLOCK)
		return ret(E_PARAM);
	if(dwAuthenticatingPinId != AUTH_PIN_ID && dwAuthenticatingPinId != SIGN_PIN_ID && dwAuthenticatingPinId != PUKK_PIN_ID)
		return ret(E_PARAM);
	if(dwTargetPinId != AUTH_PIN_ID && dwTargetPinId != SIGN_PIN_ID && dwTargetPinId != PUKK_PIN_ID)
		return ret(E_PARAM);
	if(NULL == pbAuthenticatingPinData)
		return ret(E_PARAM);
	if(NULL == pbTargetData)
		return ret(E_PARAM);

	if(cRetryCount == 0)
	{
		try
		{
			EstEIDManager estEIDManager(pCardData->hSCardCtx, pCardData->hScard);
			if(dwFlags == PIN_CHANGE_FLAG_CHANGEPIN)
			{
				SCardLog::writeLog("[%s:%d][MD] Changing PIN code",__FUNCTION__, __LINE__);
				if(dwAuthenticatingPinId == AUTH_PIN_ID)
				{
					SCardLog::writeLog("[%s:%d][MD] Changing AUTH PIN",__FUNCTION__, __LINE__);

					PinString oldPin((char *)pbAuthenticatingPinData, (size_t)cbAuthenticatingPinData);
					PinString newPin((char *)pbTargetData, (size_t)cbTargetData);
					byte retriesLeft = 0x03;
					
					estEIDManager.isSecureConnection();
					estEIDManager.changeAuthPin(newPin, oldPin, retriesLeft);
				}
				else if(dwAuthenticatingPinId == SIGN_PIN_ID)
				{
					SCardLog::writeLog("[%s:%d][MD] Changing SIGN PIN",__FUNCTION__, __LINE__);
					PinString oldPin((char *)pbAuthenticatingPinData, (size_t)cbAuthenticatingPinData);
					PinString newPin((char *)pbTargetData, (size_t)cbTargetData);
					byte retriesLeft = 0x03;

					estEIDManager.isSecureConnection();
					estEIDManager.changeSignPin(newPin, oldPin, retriesLeft);
				}
				else if(dwAuthenticatingPinId == PUKK_PIN_ID)
				{
					SCardLog::writeLog("[%s:%d][MD] Changing PUKK code",__FUNCTION__, __LINE__);
					PinString oldPuk((char *)pbAuthenticatingPinData, (size_t)cbAuthenticatingPinData);
					PinString newPuk((char *)pbTargetData, (size_t)cbTargetData);
					byte retriesLeft = 0x03;

					estEIDManager.isSecureConnection();
					estEIDManager.changePUK(newPuk, oldPuk, retriesLeft);
				}
				else
				{
					SCardLog::writeLog("[%s:%d][MD] Invalid dwAuthenticatingPinId",__FUNCTION__, __LINE__);
					return ret(E_PARAM);
				}
			}
			else if(dwFlags == PIN_CHANGE_FLAG_UNBLOCK)
			{
				SCardLog::writeLog("[%s:%d][MD] Unblocking PIN code",__FUNCTION__, __LINE__);
				if(dwTargetPinId == dwAuthenticatingPinId)
					return ret(E_PARAM);

				if(dwTargetPinId == AUTH_PIN_ID)
				{
					SCardLog::writeLog("[%s:%d][MD] Unblocking AUTH PIN",__FUNCTION__, __LINE__);

					PinString puk((char *)pbAuthenticatingPinData, (size_t)cbAuthenticatingPinData);
					PinString newPin((char *)pbTargetData, (size_t)cbTargetData);
					byte retriesLeft = 0x03;

					estEIDManager.isSecureConnection();
					estEIDManager.unblockAuthPin(newPin, puk, retriesLeft);
				}
				else if(dwTargetPinId == SIGN_PIN_ID)
				{
					SCardLog::writeLog("[%s:%d][MD] Unblocking SIGN PIN",__FUNCTION__, __LINE__);
					PinString puk((char *)pbAuthenticatingPinData, (size_t)cbAuthenticatingPinData);
					PinString newPin((char *)pbTargetData, (size_t)cbTargetData);
					byte retriesLeft = 0x03;

					estEIDManager.isSecureConnection();
					estEIDManager.unblockSignPin(newPin, puk, retriesLeft);
				}
				else
				{
					SCardLog::writeLog("[%s:%d][MD] Invalid dwAuthenticatingPinId",__FUNCTION__, __LINE__);
					return ret(E_PARAM);
				}
			}
			else
			{
				SCardLog::writeLog("[%s:%d][MD] Invalid dwFlags",__FUNCTION__, __LINE__);
				return ret(E_PARAM);
			}
		}
		catch (AuthError &err)
		{
			if(err.SW1 == 0x69 && err.SW2 == 0x83)
			{
				SCardLog::writeLog("[%s:%d][MD] PIN code blocked",__FUNCTION__, __LINE__);
				return ret(E_PINBLOCKED);
			}
			else
			{
				SCardLog::writeLog("[%s:%d][MD] PIN authentication error: %s",__FUNCTION__, __LINE__, err.what());
				return ret(E_WRONGPIN);
			}
		}
		catch (runtime_error &ex)
		{
			SCardLog::writeLog("[%s:%d][MD] Runtime_error exception thrown: %s",__FUNCTION__, __LINE__, ex.what());
			return ret(E_INTERNAL);
		}
	}
	else
	{
		return ret(E_PARAM);
	}
	return ret(E_OK);
}

DWORD WINAPI CardChangeAuthenticator(__in PCARD_DATA  pCardData, 
									 __in LPWSTR pwszUserId, 
									 __in_bcount(cbCurrentAuthenticator)PBYTE pbCurrentAuthenticator, 
									 __in DWORD cbCurrentAuthenticator,
									__in_bcount(cbNewAuthenticator)PBYTE pbNewAuthenticator, 
									__in DWORD cbNewAuthenticator, 
									__in DWORD cRetryCount, 
									__in DWORD dwFlags, 
									__out_opt PDWORD pcAttemptsRemaining)
{
	SCardLog::writeLog("[%s:%d][MD] CardChangeAuthenticator. Running in %s mode",__FUNCTION__, __LINE__, TestMode == true ? "TEST MODE" : "USER MODE");

	if(TestMode == true)
	{
		SCardLog::writeLog("[%s:%d][MD] This feature is not supported in test mode: ",__FUNCTION__, __LINE__);
		return ret(E_UNSUPPORTED);
	}
	if(!pCardData)
		return ret(E_PARAM);
	if(!pwszUserId)
		return ret(E_PARAM);
	if(!pbCurrentAuthenticator)
		return ret(E_PARAM);
	if(NULL == cbCurrentAuthenticator && wcscmp(pwszUserId, wszCARD_USER_ADMIN) != 0)
		return ret(E_PARAM);
	if(!pbNewAuthenticator)
		return ret(E_PARAM);
	if(NULL == cbNewAuthenticator)
		return ret(E_PARAM);
	if(wcscmp(pwszUserId, wszCARD_USER_USER) != 0 && wcscmp(pwszUserId, wszCARD_USER_ADMIN) != 0)
		return ret(E_PARAM);

	if(dwFlags == CARD_AUTHENTICATE_PIN_PIN)
	{
		SCardLog::writeLog("[%s:%d][MD] Changing PIN code using CARD_AUTHENTICATE_PIN_PIN",__FUNCTION__, __LINE__);
		PinString oldPin((char *)pbCurrentAuthenticator, (size_t)cbCurrentAuthenticator);
		PinString newPin((char *)pbNewAuthenticator, (size_t)cbNewAuthenticator);
		byte auth, sign, puk = 0;
		try
		{
			EstEIDManager estEIDManager(pCardData->hSCardCtx, pCardData->hScard);
			byte retriesLeft = 0x03;
			estEIDManager.isSecureConnection();
			if (NULL != pcAttemptsRemaining)
			{
				estEIDManager.getRetryCounts(puk,auth,sign);
			}
			estEIDManager.changeAuthPin(newPin, oldPin, retriesLeft);
		}
		catch (AuthError &err)
		{
			if(NULL != pcAttemptsRemaining)
			{
				if(auth > 0 && auth < 4)
					*pcAttemptsRemaining = auth-1;
				else
					*pcAttemptsRemaining = 0x0;
			}
			SCardLog::writeLog("[%s:%d][MD] AuthError pcAttemptsRemaining=%i",__FUNCTION__, __LINE__, NULL == pcAttemptsRemaining ? 0 : *pcAttemptsRemaining);
			if(err.SW1 == 0x69 && err.SW2 == 0x83)
			{
				SCardLog::writeLog("[%s:%d][MD] PIN code blocked",__FUNCTION__, __LINE__);
				return ret(E_PINBLOCKED);
			}
			else if(err.SW1 == 0x63 && err.SW2 == 0x00)
			{
				SCardLog::writeLog("[%s:%d][MD] PIN code blocked",__FUNCTION__, __LINE__);
				return ret(E_PINBLOCKED);
			}
			else if(err.SW1 == 0x63 && err.SW2 == 0xC0)
			{
				SCardLog::writeLog("[%s:%d][MD] PIN code blocked",__FUNCTION__, __LINE__);
				return ret(E_PINBLOCKED);
			}
			else
			{
				SCardLog::writeLog("[%s:%d][MD] PIN authentication error: %s",__FUNCTION__, __LINE__, err.what());
				return ret(E_WRONGPIN);
			}
		}
		catch (runtime_error &ex)
		{
			SCardLog::writeLog("[%s:%d][MD] Runtime_error exception thrown:",__FUNCTION__, __LINE__, ex.what());
			return ret(E_INTERNAL);
		}
	}
	else if(dwFlags == CARD_AUTHENTICATE_PIN_CHALLENGE_RESPONSE)
	{
		SCardLog::writeLog("[%s:%d][MD] Changing PIN code using CARD_AUTHENTICATE_PIN_CHALLENGE_RESPONSE",__FUNCTION__, __LINE__);
		return ret(E_WRONGPIN);
	}
	else
	{
		SCardLog::writeLog("[%s:%d][MD] Changing PIN code using UNSUPPORTED FEATURE 0x%08X",__FUNCTION__, __LINE__, dwFlags);
		return ret(E_PARAM);
	}

	return ret(E_OK);
}

DWORD WINAPI CardUnblockPin(__in PCARD_DATA  pCardData, __in LPWSTR pwszUserId, __in_bcount(cbAuthenticationData)PBYTE pbAuthenticationData, __in DWORD cbAuthenticationData,
	__in_bcount(cbNewPinData)PBYTE pbNewPinData, __in DWORD cbNewPinData, __in DWORD cRetryCount, __in DWORD dwFlags)
{
	SCardLog::writeLog("[%s:%d][MD] CardUnblockPin. Running in %s mode",__FUNCTION__, __LINE__, TestMode == true ? "TEST MODE" : "USER MODE");
	if(TestMode == true)
	{
		SCardLog::writeLog("[%s:%d][MD] This feature is not supported in test mode: ",__FUNCTION__, __LINE__);
		return ret(E_UNSUPPORTED);
	}
	try
	{
		SCardLog::writeLog("[%s:%d][MD] CardUnblockPin: Unblocking AUTH PIN",__FUNCTION__, __LINE__);
		EstEIDManager estEIDManager(pCardData->hSCardCtx, pCardData->hScard);
		PinString puk((char *)pbAuthenticationData, (size_t)cbAuthenticationData);
		PinString newPin((char *)pbNewPinData, (size_t)cbNewPinData);
		byte retriesLeft = 0x03;
		estEIDManager.isSecureConnection();
		estEIDManager.unblockAuthPin(newPin, puk, retriesLeft);
	}
	catch (AuthError &err)
	{
		if(err.SW1 == 0x69 && err.SW2 == 0x83)
		{
			SCardLog::writeLog("[%s:%d][MD] CardUnblockPin: PIN code blocked",__FUNCTION__, __LINE__);
			return ret(E_PINBLOCKED);
		}
		else
		{
			SCardLog::writeLog("[%s:%d][MD] CardUnblockPin: PIN authentication error: %s",__FUNCTION__, __LINE__, err.what());
			return ret(E_WRONGPIN);
		}
	}
	catch (runtime_error &ex)
	{
		SCardLog::writeLog("[%s:%d][MD] CardUnblockPin: Runtime_error exception thrown:",__FUNCTION__, __LINE__, ex.what());
		return ret(E_INTERNAL);
	}
	
	return ret(E_OK);
}

void GetFileVersionOfApplication()
{
	SCardLog::writeLog("[%s:%d][MD] GetFileVersionOfApplication.",__FUNCTION__, __LINE__);
#ifdef _WIN64
	LPTSTR lpszFilePath = L"esteidcm64.dll";
#else
	LPTSTR lpszFilePath = L"esteidcm.dll";
#endif

	DWORD dwDummy;
	DWORD dwFVISize = GetFileVersionInfoSize( lpszFilePath , &dwDummy );

	LPBYTE lpVersionInfo = new BYTE[dwFVISize];

	GetFileVersionInfo( lpszFilePath , 0 , dwFVISize , lpVersionInfo );

	UINT uLen;
	VS_FIXEDFILEINFO *lpFfi;

	BOOL ret = VerQueryValue( lpVersionInfo , _T("\\") , (LPVOID *)&lpFfi , &uLen );

	if(ret == 0)
	{
		SCardLog::writeLog("[%s:%d][MD] Failed to read driver version.",__FUNCTION__, __LINE__);
		return;
	}

	DWORD dwFileVersionMS = lpFfi->dwFileVersionMS;
	DWORD dwFileVersionLS = lpFfi->dwFileVersionLS;

	delete [] lpVersionInfo;

	DWORD dwLeftMost     = HIWORD(dwFileVersionMS);
	DWORD dwSecondLeft   = LOWORD(dwFileVersionMS);
	DWORD dwSecondRight  = HIWORD(dwFileVersionLS);
	DWORD dwRightMost    = LOWORD(dwFileVersionLS);

	size_t size = wcstombs(NULL, lpszFilePath, 0);
	char *chFileName = new char[size+1];
	wcstombs(chFileName, lpszFilePath, size+1);

	SCardLog::writeLog("[%s:%d][MD] Driver version: %s %d.%d.%d.%d",__FUNCTION__, __LINE__, chFileName, dwLeftMost, dwSecondLeft, dwSecondRight, dwRightMost);
	delete chFileName;
}
