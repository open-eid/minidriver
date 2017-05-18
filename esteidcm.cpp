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
#define RETURN(X) return logreturn(__FUNCTION__, __FILE__, __LINE__, #X, X)
#define DECLARE_UNSUPPORTED(name) DWORD WINAPI name { RETURN(SCARD_E_UNSUPPORTED_FEATURE); }


struct cardFiles
{
	BYTE file_appdir[9];
	BYTE file_cardcf[6];
	BYTE file_cardid[16];
};

using namespace std;

typedef struct
{
	HWND hwndParentWindow;
	int pinType;
	int langId;
} EXTERNAL_INFO, *PEXTERNAL_INFO;

static DWORD logreturn(const char *functionName, const char *fileName, int lineNumber, const char *resultstr, DWORD result)
{
	SCardLog::writeLog("[%s:%d][MD] %s Returning %s", fileName, lineNumber, functionName, resultstr);
	return result;
}

void GetFileVersionOfApplication();


HWND cp;
bool TestMode;
char procName[1024];
unsigned int maxSpecVersion = 7;
LPCTSTR subKey = TEXT("Software\\SK\\EstEIDMinidriver");

#define DEFUN(a) a

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

DWORD WINAPI DialogThreadEntry(LPVOID lpParam)
{
	EXTERNAL_INFO *externalInfo = PEXTERNAL_INFO(lpParam);
	TASKDIALOGCONFIG config = { 0 };
	config.cbSize = sizeof(config);
	config.hwndParent = externalInfo->hwndParentWindow;
	config.hInstance = GetModuleHandle(NULL);
	config.dwCommonButtons = TDCBF_CANCEL_BUTTON;
	config.pszMainIcon = TD_INFORMATION_ICON;
	config.dwFlags = TDF_EXPAND_FOOTER_AREA | TDF_SHOW_PROGRESS_BAR | TDF_CALLBACK_TIMER | TDF_ENABLE_HYPERLINKS;
	config.pfCallback = [](HWND hwnd, UINT uNotification, WPARAM wParam, LPARAM lParam, LONG_PTR dwRefData) {
		switch (uNotification)
		{
		case TDN_CREATED:
			SendMessage(hwnd, TDM_SET_PROGRESS_BAR_STATE, 0x0003, 0);
			SendMessage(hwnd, TDM_SET_PROGRESS_BAR_POS, 100, 0L);
			SendMessage(hwnd, TDM_SET_PROGRESS_BAR_STATE, 0x0001, 0);
			break;
		case TDN_TIMER:
			SendMessage(hwnd, TDM_SET_PROGRESS_BAR_POS, (100 - int(wParam) / 300), 0);
			break;
		case TDN_HYPERLINK_CLICKED:
			ShellExecute(0, L"open", LPCTSTR(lParam), 0, 0, SW_SHOW);
			break;
		case TDN_BUTTON_CLICKED:
			SendMessage(hwnd, WM_NCDESTROY, 0, 0);
			return S_FALSE;
		}
		return S_OK;
	};
	switch (externalInfo->langId)
	{
	case 0x0425:
		config.pszMainInstruction = L"PIN Pad kaardilugeja";
		config.pszContent = L"Sisestage PIN";
		switch (externalInfo->pinType)
		{
		case 1:
			config.pszContent = L"Palun sisestage autoriseerimise PIN (PIN1)";
			config.pszExpandedInformation = L"Valitud tegevuse jaoks on vaja kasutada isikutuvastuse sertifikaati. Sertifikaadi kasutamiseks sisesta PIN1 kaardilugeja sõrmistikult.";
			break;
		case 3:
			config.pszContent = L"Palun sisestage digiallkirjastamise PIN (PIN2)";
			config.pszExpandedInformation = L"Valitud tegevuse jaoks on vaja kasutada allkirjastamise sertifikaati. Sertifikaadi kasutamiseks sisesta PIN2 kaardilugeja sõrmistikult.";
			break;
		default: break;
		}
		break;
	case 0x0419:
		config.pszMainInstruction = L"PIN Pad считыватель";
		config.pszContent = L"Введите PIN код";
		switch (externalInfo->pinType)
		{
		case 1:
			config.pszContent = L"Введите код PIN для идентификации (PIN 1)";
			config.pszExpandedInformation = L"Данная операция требует сертификат идентификации. Для использования сертификата идентификации введите PIN1 с клавиатуры считывателя.";
			break;
		case 3:
			config.pszContent = L"Введите код PIN для подписи (PIN 2)";
			config.pszExpandedInformation = L"Для данной операцин необходим сертификат подписи. Для использования сертификата подписи введите PIN2 с клавиатуры считывателя.";
			break;
		default: break;
		}
		break;
	default:
		config.pszMainInstruction = L"PIN Pad Reader";
		config.pszContent = L"Enter PIN code";
		switch (externalInfo->pinType)
		{
		case 1:
			config.pszContent = L"Enter PIN for authentication (PIN 1)";
			config.pszExpandedInformation = L"Selected action requires authentication certificate. For using authentication certificate enter PIN1 at the reader.";
			break;
		case 3:
			config.pszContent = L"Enter PIN for digital signature (PIN 2)";
			config.pszExpandedInformation = L"Selected action requires digital signature certificate. For using signature certificate enter PIN2 at the reader.";
			break;
		default: break;
		}
		break;
	}
	int buttonPressed = 0;
	return TaskDialogIndirect(&config, &buttonPressed, NULL, NULL);
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
		return SCARD_E_INVALID_PARAMETER;
	if (dwFlags) return SCARD_E_INVALID_PARAMETER;

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

	if(pCardData->cbAtr == 0) return SCARD_E_INVALID_PARAMETER;
	if(pCardData->cbAtr == 0xffffffff) return SCARD_E_INVALID_PARAMETER;
	if(pCardData->cbAtr < 18 || pCardData->cbAtr > 28)
		return SCARD_E_INVALID_PARAMETER;

	if(osver.dwMajorVersion >= 6)
	{
		if (pCardData->dwVersion < 6 && pCardData->dwVersion != 0)
			return ERROR_REVISION_MISMATCH;
	}
	else
	{
		if (pCardData->dwVersion < 4 && pCardData->dwVersion != 0)
			return ERROR_REVISION_MISMATCH;
	}

	if (pCardData->dwVersion == 0 && pCardData->cbAtr != 0) //special case
		return ERROR_REVISION_MISMATCH;

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
			return SCARD_E_INVALID_PARAMETER;

		if (NULL == pCardData->pwszCardName )
		{
			SCardLog::writeLog("[%s:%d][MD] Invalid pCardData->pwszCardName", __FUNCTION__, __LINE__);
			return SCARD_E_INVALID_PARAMETER;
		}
		if (NULL == pCardData->pfnCspAlloc)
		{
			SCardLog::writeLog("[%s:%d][MD] Invalid pCardData->pfnCspAlloc", __FUNCTION__, __LINE__);
			return SCARD_E_INVALID_PARAMETER;
		}
		if (NULL == pCardData->pfnCspReAlloc)
		{
			SCardLog::writeLog("[%s:%d][MD] Invalid pCardData->pfnCspReAlloc", __FUNCTION__, __LINE__);
			return SCARD_E_INVALID_PARAMETER;
		}
		if (NULL == pCardData->pfnCspFree)
		{
			SCardLog::writeLog("[%s:%d][MD] Invalid pCardData->pfnCspFree", __FUNCTION__, __LINE__);
			return SCARD_E_INVALID_PARAMETER;
		}

		pCardData->pvVendorSpecific = pCardData->pfnCspAlloc(sizeof(cardFiles));
		if (!pCardData->pvVendorSpecific) return ERROR_NOT_ENOUGH_MEMORY;
		BYTE empty_appdir[] = {1,'m','s','c','p',0,0,0,0};
		BYTE empty_cardcf[6]={0,0,0,0,0,0};
		BYTE empty_cardid[16]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
		memcpy(((cardFiles *)pCardData->pvVendorSpecific)->file_appdir,empty_appdir,sizeof(empty_appdir));
		memcpy(((cardFiles *)pCardData->pvVendorSpecific)->file_cardcf,empty_cardcf,sizeof(empty_cardcf));
		memcpy(((cardFiles *)pCardData->pvVendorSpecific)->file_cardid,empty_cardid,sizeof(empty_cardid));
		if (0 == pCardData->hScard )
			return SCARD_E_INVALID_HANDLE;
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

	if(!validATR) return SCARD_E_UNKNOWN_CARD;
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
	
	return NO_ERROR;
}


DWORD WINAPI CardDeleteContext(__inout PCARD_DATA pCardData)
{
	SCardLog::writeLog("[%s:%d][MD] CardDeleteContext", __FUNCTION__, __LINE__);
	
	
	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	if (pCardData->pvVendorSpecific)
		pCardData->pfnCspFree(pCardData->pvVendorSpecific);

	return NO_ERROR;
}

DWORD WINAPI CardGetContainerProperty(__in PCARD_DATA pCardData, __in BYTE bContainerIndex, __in LPCWSTR wszProperty,
    __out_bcount_part_opt(cbData, *pdwDataLen) PBYTE pbData, __in DWORD cbData, __out PDWORD pdwDataLen, __in DWORD dwFlags)
{
	if (!pCardData) return SCARD_E_INVALID_PARAMETER;
	SCardLog::writeLog("[%s:%d][MD] CardGetContainerProperty bContainerIndex=%u, wszProperty=%S"", cbData=%u, dwFlags=0x%08X",__FUNCTION__, __LINE__, bContainerIndex, NULLWSTR(wszProperty), cbData,dwFlags);
	if (!wszProperty) 
		return SCARD_E_INVALID_PARAMETER;
	if (dwFlags) 
		return SCARD_E_INVALID_PARAMETER;
	if (!pbData)
		return SCARD_E_INVALID_PARAMETER;
	if (!pdwDataLen) 
		return SCARD_E_INVALID_PARAMETER;

	if (wstring(CCP_CONTAINER_INFO) == wszProperty )
	{
		PCONTAINER_INFO p = (PCONTAINER_INFO) pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData >= sizeof(DWORD))
			if (p->dwVersion != CONTAINER_INFO_CURRENT_VERSION && p->dwVersion != 0 )
				return ERROR_REVISION_MISMATCH;
		if (cbData < sizeof(*p))
			return ERROR_INSUFFICIENT_BUFFER;
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
			return ERROR_INSUFFICIENT_BUFFER;
		switch (bContainerIndex)
		{
			case AUTH_CONTAINER_INDEX:
				*p = AUTH_PIN_ID;
				break;
			case SIGN_CONTAINER_INDEX:
				*p = SIGN_PIN_ID;
				break;
			default:
				return SCARD_E_NO_KEY_CONTAINER;
		}
		SCardLog::writeLog("[%s:%d][MD] Return Pin id %u",__FUNCTION__, __LINE__, *p);
		return NO_ERROR;
	}
	return SCARD_E_INVALID_PARAMETER;
}

DWORD WINAPI CardGetProperty(__in PCARD_DATA pCardData, __in LPCWSTR wszProperty,
	__out_bcount_part_opt(cbData, *pdwDataLen) PBYTE pbData, __in DWORD cbData, __out PDWORD pdwDataLen, __in DWORD dwFlags)
{
	SCardLog::writeLog("[%s:%d][MD] CardGetProperty wszProperty=%S, cbData=%u, dwFlags=%u",__FUNCTION__, __LINE__,NULLWSTR(wszProperty),cbData,dwFlags);
	if (!pCardData || !wszProperty || !pbData || !pdwDataLen)
		RETURN(SCARD_E_INVALID_PARAMETER);

	if (wcscmp(CP_CARD_FREE_SPACE, wszProperty) == 0)
	{
		PCARD_FREE_SPACE_INFO p = PCARD_FREE_SPACE_INFO(pbData);
		if (pdwDataLen)
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p))
			RETURN(SCARD_E_INSUFFICIENT_BUFFER);
		return CardQueryFreeSpace(pCardData, dwFlags, p);
	}
	if (wcscmp(CP_CARD_CAPABILITIES, wszProperty) == 0)
	{
		PCARD_CAPABILITIES p = PCARD_CAPABILITIES(pbData);
		if (pdwDataLen)
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p))
			RETURN(SCARD_E_INSUFFICIENT_BUFFER);
		return CardQueryCapabilities(pCardData, p);
	}
	if (wcscmp(CP_CARD_KEYSIZES, wszProperty) == 0)
	{
		PCARD_KEY_SIZES p = PCARD_KEY_SIZES(pbData);
		if (pdwDataLen)
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p))
			RETURN(SCARD_E_INSUFFICIENT_BUFFER);
		return CardQueryKeySizes(pCardData, dwFlags, 0, p);
	}
	if (wcscmp(CP_CARD_READ_ONLY, wszProperty) == 0)
	{
		PBOOL p = PBOOL(pbData);
		if (pdwDataLen)
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p))
			RETURN(SCARD_E_INSUFFICIENT_BUFFER);
		*p = TRUE;
		RETURN(NO_ERROR);
	}
	if (wcscmp(CP_CARD_CACHE_MODE, wszProperty) == 0)
	{
		PDWORD p = PDWORD(pbData);
		if (pdwDataLen)
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p))
			RETURN(SCARD_E_INSUFFICIENT_BUFFER);
		*p = CP_CACHE_MODE_SESSION_ONLY;
		RETURN(NO_ERROR);
	}
	if (wcscmp(CP_SUPPORTS_WIN_X509_ENROLLMENT, wszProperty) == 0)
	{
		PDWORD p = PDWORD(pbData);
		if (pdwDataLen)
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p))
			RETURN(SCARD_E_INSUFFICIENT_BUFFER);
		*p = 0;
		RETURN(NO_ERROR);
	}
	if (wcscmp(CP_CARD_GUID, wszProperty) == 0)
	{
		cardFiles *ptr = (cardFiles *)pCardData->pvVendorSpecific;
		
		try
		{
			EstEIDManager estEIDManager(pCardData->hSCardCtx, pCardData->hScard);
			string id  = estEIDManager.readDocumentID();
			if (id.length() < MIN_DOCUMENT_ID_LEN || id.length() > MAX_DOCUMENT_ID_LEN)
				RETURN(SCARD_E_FILE_NOT_FOUND);
			SCardLog::writeLog("[%s:%d][MD] cardid: %s",__FUNCTION__, __LINE__, id.c_str());
			memset(ptr->file_cardid,0, sizeof(ptr->file_cardid));
			CopyMemory( ptr->file_cardid, id.c_str(), id.length());
		}
		catch (runtime_error &err )
		{
			SCardLog::writeLog("[%s:%d][MD] runtime_error in CardReadFile '%s'",__FUNCTION__, __LINE__, err.what());
			RETURN(SCARD_E_FILE_NOT_FOUND);
		}
		if (pdwDataLen)
			*pdwDataLen = sizeof(ptr->file_cardid);
		if (cbData < sizeof(ptr->file_cardid))
			RETURN(SCARD_E_INSUFFICIENT_BUFFER);
		CopyMemory(pbData, ptr->file_cardid, sizeof(ptr->file_cardid));
		RETURN(NO_ERROR);
	}
	if (wcscmp(CP_CARD_PIN_INFO, wszProperty) == 0)
	{
		PPIN_INFO p = PPIN_INFO(pbData);
		if (pdwDataLen)
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p))
			RETURN(SCARD_E_INSUFFICIENT_BUFFER);
		if (p->dwVersion != PIN_INFO_CURRENT_VERSION)
			RETURN(ERROR_REVISION_MISMATCH);
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
			
			RETURN(SCARD_E_FILE_NOT_FOUND);
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
				RETURN(SCARD_E_INVALID_PARAMETER);
		}
		RETURN(NO_ERROR);
	}
	if (wcscmp(CP_CARD_LIST_PINS, wszProperty) == 0)
	{
		PPIN_SET p = PPIN_SET(pbData);
		if (pdwDataLen)
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p))
			RETURN(SCARD_E_INSUFFICIENT_BUFFER);
		SET_PIN(*p, AUTH_PIN_ID);
		SET_PIN(*p, SIGN_PIN_ID);
		SET_PIN(*p, PUKK_PIN_ID);
		RETURN(NO_ERROR);
	}
	if (wcscmp(CP_CARD_PIN_STRENGTH_VERIFY, wszProperty) == 0)
	{
		if (dwFlags < AUTH_PIN_ID || dwFlags > SIGN_PIN_ID)
			RETURN(SCARD_E_INVALID_PARAMETER);
		PDWORD p = PDWORD(pbData);
		if (pdwDataLen)
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p))
			RETURN(SCARD_E_INSUFFICIENT_BUFFER);
		*p = CARD_PIN_STRENGTH_PLAINTEXT;
		RETURN(NO_ERROR);
	}
	if (wcscmp(CP_KEY_IMPORT_SUPPORT, wszProperty) == 0)
	{
		PDWORD p = PDWORD(pbData);
		if (pdwDataLen)
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p))
			RETURN(SCARD_E_INSUFFICIENT_BUFFER);
		*p = 0;
		RETURN(NO_ERROR);
	}
	if (wcscmp(CP_PADDING_SCHEMES, wszProperty) == 0)
	{
		PDWORD p = PDWORD(pbData);
		if (pdwDataLen)
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p))
			RETURN(SCARD_E_INSUFFICIENT_BUFFER);
		*p = CARD_PADDING_NONE;
		RETURN(NO_ERROR);
	}
	RETURN(SCARD_E_UNSUPPORTED_FEATURE);
}

DWORD WINAPI CardSetProperty(__in PCARD_DATA pCardData, __in LPCWSTR wszProperty, __in_bcount(cbDataLen) PBYTE pbData,
    __in DWORD cbDataLen, __in DWORD dwFlags)
{
	if (!pCardData) return SCARD_E_INVALID_PARAMETER;
	SCardLog::writeLog("[%s:%d][MD] CardSetProperty wszProperty=%S"", cbDataLen=%u, dwFlags=%u",__FUNCTION__, __LINE__, NULLWSTR(wszProperty), cbDataLen, dwFlags);
	if (!wszProperty) return SCARD_E_INVALID_PARAMETER;

	if (wstring(CP_CARD_PIN_STRENGTH_VERIFY) == wszProperty || wstring(CP_CARD_PIN_INFO) == wszProperty)
		return SCARD_W_SECURITY_VIOLATION;

	if (dwFlags)
		return SCARD_E_INVALID_PARAMETER;

	if (wstring(CP_PIN_CONTEXT_STRING) == wszProperty)
		return NO_ERROR;

	if (wstring(CP_CARD_CACHE_MODE) == wszProperty ||  wstring(CP_SUPPORTS_WIN_X509_ENROLLMENT) == wszProperty ||
		wstring(CP_CARD_GUID) == wszProperty || wstring(CP_CARD_SERIAL_NO)  == wszProperty )
	{
		return SCARD_W_SECURITY_VIOLATION;
	}

	if (!pbData)
		return SCARD_E_INVALID_PARAMETER;
	if (!cbDataLen)
		return SCARD_E_INVALID_PARAMETER;

	if (wstring(CP_PARENT_WINDOW) == wszProperty)
	{
		SCardLog::writeLog("[%s:%d][MD] CardSetProperty CP_PARENT_WINDOW", __FUNCTION__, __LINE__);
		if (cbDataLen != sizeof(pCardData)) 
			return SCARD_E_INVALID_PARAMETER;
		cp = *((HWND *) pbData);
		if (cp!=0 && !IsWindow(cp))
		{
			cp = NULL;
			return SCARD_E_INVALID_PARAMETER;
		}
		return NO_ERROR;
	}
	return SCARD_E_INVALID_PARAMETER;
}


DWORD WINAPI CardQueryCapabilities(__in PCARD_DATA pCardData, __in PCARD_CAPABILITIES pCardCapabilities)
{
	if (!pCardData) return SCARD_E_INVALID_PARAMETER;
	if (!pCardCapabilities) return SCARD_E_INVALID_PARAMETER;

	if (pCardCapabilities->dwVersion != CARD_CAPABILITIES_CURRENT_VERSION && pCardCapabilities->dwVersion != 0)
		return ERROR_REVISION_MISMATCH;

	pCardCapabilities->dwVersion = CARD_CAPABILITIES_CURRENT_VERSION;
	SCardLog::writeLog("[%s:%d][MD] CardQueryCapabilities dwVersion=%u, fKeyGen=%u, fCertificateCompression=%u",__FUNCTION__, __LINE__, pCardCapabilities->dwVersion,
		pCardCapabilities->fKeyGen ,pCardCapabilities->fCertificateCompression);

	pCardCapabilities->fCertificateCompression = TRUE;
	pCardCapabilities->fKeyGen = FALSE;
	return NO_ERROR;
}

DWORD WINAPI
CardGetContainerInfo(__in PCARD_DATA  pCardData, __in BYTE bContainerIndex, __in DWORD dwFlags, __in PCONTAINER_INFO pContainerInfo)
{
	if (!pCardData) return SCARD_E_INVALID_PARAMETER;
	if (!pContainerInfo) return SCARD_E_INVALID_PARAMETER;
	if (dwFlags) return SCARD_E_INVALID_PARAMETER;
	if (pContainerInfo->dwVersion < 0 || pContainerInfo->dwVersion >  CONTAINER_INFO_CURRENT_VERSION)
		return ERROR_REVISION_MISMATCH;

	SCardLog::writeLog("[%s:%d][MD] CardGetContainerInfo bContainerIndex=%u, dwFlags=0x%08X, dwVersion=%u"", cbSigPublicKey=%u, cbKeyExPublicKey=%u"
		,__FUNCTION__, __LINE__, bContainerIndex, dwFlags, pContainerInfo->dwVersion, pContainerInfo->cbSigPublicKey, pContainerInfo->cbKeyExPublicKey);

	if (bContainerIndex != SIGN_CONTAINER_INDEX && bContainerIndex != AUTH_CONTAINER_INDEX)
		return SCARD_E_NO_KEY_CONTAINER;

	if (bContainerIndex != AUTH_CONTAINER_INDEX && pCardData->dwVersion < 6 )
	{
		SCardLog::writeLog("[%s:%d][MD] Version %u requested container %u",__FUNCTION__, __LINE__, pCardData->dwVersion, bContainerIndex);
		return SCARD_E_NO_KEY_CONTAINER;
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
		
		return SCARD_E_UNEXPECTED;
	}

	if (bContainerIndex == AUTH_CONTAINER_INDEX)
	{
		oh.publickeystruc.aiKeyAlg = CALG_RSA_KEYX;
		pContainerInfo->cbKeyExPublicKey = sz;
		pContainerInfo->pbKeyExPublicKey = (PBYTE)(*pCardData->pfnCspAlloc)(sz);
		if (!pContainerInfo->pbKeyExPublicKey) return ERROR_NOT_ENOUGH_MEMORY;
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
		if (!pContainerInfo->pbSigPublicKey) return ERROR_NOT_ENOUGH_MEMORY;
		CopyMemory(pContainerInfo->pbSigPublicKey,&oh,sz);
		SCardLog::writeLog("[%s:%d][MD] return info on SIGN_CONTAINER_INDEX",__FUNCTION__, __LINE__);
	}

	pContainerInfo->dwVersion = CONTAINER_INFO_CURRENT_VERSION;
	
	return NO_ERROR;
	}


DWORD WINAPI CardAuthenticatePin(__in PCARD_DATA pCardData, __in LPWSTR pwszUserId, __in_bcount(cbPin) PBYTE pbPin, __in DWORD cbPin, __out_opt PDWORD pcAttemptsRemaining)
{
	SCardLog::writeLog("[%s:%d][MD] CardAuthenticatePin: pwszUserId=%S",__FUNCTION__, __LINE__, NULLWSTR(pwszUserId));
	if (!pwszUserId || wcscmp(pwszUserId, wszCARD_USER_USER) != 0 || !pbPin)
		RETURN(SCARD_E_INVALID_PARAMETER);
	return CardAuthenticateEx(pCardData, AUTH_PIN_ID, CARD_PIN_SILENT_CONTEXT, pbPin, cbPin, nullptr, nullptr, pcAttemptsRemaining);
}

DWORD WINAPI CardAuthenticateEx(__in PCARD_DATA pCardData, __in PIN_ID PinId, __in DWORD dwFlags, __in PBYTE pbPinData, __in DWORD cbPinData,
    __deref_out_bcount_opt(*pcbSessionPin) PBYTE  *ppbSessionPin, __out_opt PDWORD pcbSessionPin, __out_opt PDWORD pcAttemptsRemaining)
{
	if (!pCardData) return SCARD_E_INVALID_PARAMETER;
	SCardLog::writeLog("[%s:%d][MD] CardAuthenticateEx: PinId=%u, dwFlags=0x%08X, cbPinData=%u, Attempts %s",__FUNCTION__, __LINE__, PinId, dwFlags, cbPinData, pcAttemptsRemaining ? "YES" : "NO");

	EstEIDManager estEIDManager(pCardData->hSCardCtx, pCardData->hScard);

	if(pbPinData == NULL && !estEIDManager.isSecureConnection())
		return SCARD_E_INVALID_PARAMETER;

	if(!estEIDManager.isSecureConnection())
	{
		if (dwFlags == CARD_AUTHENTICATE_GENERATE_SESSION_PIN || dwFlags == CARD_AUTHENTICATE_SESSION_PIN)
			return SCARD_E_UNSUPPORTED_FEATURE;
		if (dwFlags && dwFlags != CARD_PIN_SILENT_CONTEXT) 
			return SCARD_E_INVALID_PARAMETER;
		if (pcAttemptsRemaining)
		{
			*pcAttemptsRemaining = 3;
		}

		if (cbPinData < 4 || cbPinData > 12)
			return SCARD_W_WRONG_CHV;

		char *pin = (char *)pbPinData;

		PinString tmp(pin , pin+cbPinData );
		BYTE remaining = 0,dummy = 0xFA;
		
		byte puk = 0,pinAuth = 0,pinSign = 0;
		if (PinId != AUTH_PIN_ID && PinId != SIGN_PIN_ID && PinId != PUKK_PIN_ID) 
			return SCARD_E_INVALID_PARAMETER;
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
			return e.m_blocked ? SCARD_W_CHV_BLOCKED : SCARD_W_WRONG_CHV;
		}
		catch (runtime_error & )
		{
			if (pcAttemptsRemaining)
				*pcAttemptsRemaining = remaining - 1;
			SCardLog::writeLog("[%s:%d][MD] CardAuthenticateEx: Runtime error",__FUNCTION__, __LINE__);
			return SCARD_W_WRONG_CHV;
		}
	}
	else
	{
		if (dwFlags != CARD_AUTHENTICATE_GENERATE_SESSION_PIN && dwFlags != CARD_AUTHENTICATE_SESSION_PIN && dwFlags != 0)
			return SCARD_E_INVALID_PARAMETER;
		if(PinId != AUTH_PIN_ID && PinId != SIGN_PIN_ID && PinId != PUKK_PIN_ID)
			return SCARD_E_INVALID_PARAMETER;
		if (pcAttemptsRemaining)
		{
			*pcAttemptsRemaining = 3;
		}
		BYTE remaining = 0,dummy = 0xFA;
		byte puk = 0,pinAuth = 0,pinSign = 0;
		const int BUFFER_SIZE = 512;
		int lReturn = 0;
		WCHAR wcBuffer[BUFFER_SIZE];

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
						return SCARD_W_CHV_BLOCKED;
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
								return SCARD_W_CANCELLED_BY_USER;
							}
							else if(ae.m_timeout == true)
							{
								SCardLog::writeLog("[%s:%d][MD] PIN1 input timeout",__FUNCTION__, __LINE__, remaining);
								MessageBox(cp, L"PIN1 timeout.", L"PIN1 timeout", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
								TerminateThread(DialogThreadHandle, ERROR_SUCCESS);
								return SCARD_W_CANCELLED_BY_USER;
							}
							else if(ae.m_blocked == true)
							{
								SCardLog::writeLog("[%s:%d][MD] PIN1 blocked",__FUNCTION__, __LINE__, remaining);
								MessageBox(cp, L"PIN1 blocked.", L"Authentication error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
								TerminateThread(DialogThreadHandle, ERROR_SUCCESS);
								return SCARD_W_CHV_BLOCKED;
							}
							else if(ae.m_badinput == true)
							{
								SCardLog::writeLog("[%s:%d][MD] Unexpected input",__FUNCTION__, __LINE__, 3-remaining);
								MessageBox(cp, L"Unexpected input.", L"Authentication error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
								break;
							}
							else
							{
								remaining--;
								wsprintf(wcBuffer, L"A wrong PIN was presented to the card: %i  retries left.", remaining);
								SCardLog::writeLog("[%s:%d][MD] Wrong PIN presented %i attempts remaining",__FUNCTION__, __LINE__, remaining);
								MessageBox(cp, wcBuffer, L"Authentication error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
								TerminateThread(DialogThreadHandle, ERROR_SUCCESS);
							}
						}
					}
					TerminateThread(DialogThreadHandle, ERROR_SUCCESS);
				}
				if (PinId == SIGN_PIN_ID)
				{
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
						return SCARD_W_CHV_BLOCKED;
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
								return SCARD_W_CANCELLED_BY_USER;
							}
							else if(ae.m_timeout == true)
							{
								SCardLog::writeLog("[%s:%d][MD] PIN2 input timeout",__FUNCTION__, __LINE__, remaining);
								MessageBox(cp, L"PIN2 timeout.", L"PIN2 timeout", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
								TerminateThread(DialogThreadHandle, ERROR_SUCCESS);
								return SCARD_W_CANCELLED_BY_USER;
							}
							else if(ae.m_blocked == true)
							{
								SCardLog::writeLog("[%s:%d][MD] PIN2 blocked",__FUNCTION__, __LINE__, 3-remaining);
								MessageBox(cp, L"PIN2 blocked.", L"Authentication error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
								TerminateThread(DialogThreadHandle, ERROR_SUCCESS);
								return SCARD_W_CHV_BLOCKED;
							}
							else if(ae.m_badinput == true)
							{
								SCardLog::writeLog("[%s:%d][MD] Unexpected input",__FUNCTION__, __LINE__, 3-remaining);
								MessageBox(cp, L"Unexpected input.", L"Authentication error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
								break;
							}
							else
							{
								remaining--;
								wsprintf(wcBuffer, L"A wrong PIN was presented to the card: %i  retries left.", remaining);
								SCardLog::writeLog("[%s:%d][MD] Wrong PIN presented %i attempts remaining",__FUNCTION__, __LINE__, remaining);
								MessageBox(cp, wcBuffer, L"Authentication error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
								TerminateThread(DialogThreadHandle, ERROR_SUCCESS);
							}
						}
					}
					TerminateThread(DialogThreadHandle, ERROR_SUCCESS);
				}
				if(PinId == PUKK_PIN_ID)
				{
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
						return SCARD_W_CHV_BLOCKED;
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
								return SCARD_W_CANCELLED_BY_USER;
							}
							else if(ae.m_timeout == true)
							{
								SCardLog::writeLog("[%s:%d][MD] PUK input timeout",__FUNCTION__, __LINE__, remaining);
								MessageBox(cp, L"PUK timeout.", L"PUK timeout", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
								TerminateThread(DialogThreadHandle, ERROR_SUCCESS);
								return SCARD_W_CANCELLED_BY_USER;
							}
							else if(ae.m_blocked == true)
							{
								SCardLog::writeLog("[%s:%d][MD] PUK blocked",__FUNCTION__, __LINE__, 3-remaining);
								MessageBox(cp, L"PUK blocked.", L"Authentication error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
								TerminateThread(DialogThreadHandle, ERROR_SUCCESS);
								return SCARD_W_CHV_BLOCKED;
							}
							else if(ae.m_badinput == true)
							{
								SCardLog::writeLog("[%s:%d][MD] Unexpected input",__FUNCTION__, __LINE__, 3-remaining);
								MessageBox(cp, L"Unexpected input.", L"Authentication error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
								break;
							}
							else
							{
								remaining--;
								wsprintf(wcBuffer, L"A wrong PIN was presented to the card: %i  retries left.", remaining);
								SCardLog::writeLog("[%s:%d][MD] Wrong PIN presented %i attempts remaining",__FUNCTION__, __LINE__, remaining);
								MessageBox(cp, wcBuffer, L"Authentication error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
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
					return SCARD_W_CHV_BLOCKED;
				}
				else if(err.SW1 == 0x63 && err.SW2 == 0x00)
				{
					SCardLog::writeLog("[%s:%d][MD] PIN code blocked",__FUNCTION__, __LINE__);
					MessageBox(NULL, L"PIN code blocked", L"Authentication error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
					return SCARD_W_CHV_BLOCKED;
				}
				else if(err.SW1 == 0x63 && err.SW2 == 0xC0)
				{
					SCardLog::writeLog("[%s:%d][MD] PIN code blocked",__FUNCTION__, __LINE__);
					MessageBox(NULL, L"PIN code blocked", L"Authentication error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
					return SCARD_W_CHV_BLOCKED;
				}
				else if(err.SW1 == 0x63)
				{
				SCardLog::writeLog("[%s:%d][MD] Wrong PIN presented",__FUNCTION__, __LINE__);
					if (pcAttemptsRemaining)
						*pcAttemptsRemaining = remaining - 1;
					MessageBox(cp, L"Wrong PIN presented", L"Authentication error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
					return SCARD_W_WRONG_CHV;
				}
				else
				{
					if (pcAttemptsRemaining)
						*pcAttemptsRemaining = remaining - 1;
					SCardLog::writeLog("[%s:%d][MD] PIN authentication error: %s",__FUNCTION__, __LINE__, err.what());
					MessageBox(NULL, L"PIN authentication error", L"Authentication error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
					return SCARD_W_WRONG_CHV;
				}
			}
			catch (runtime_error &er )
			{
				TerminateThread(DialogThreadHandle, ERROR_SUCCESS);
				SCardLog::writeLog("[%s:%d][MD] Runtime error",__FUNCTION__, __LINE__, er.what());
				return SCARD_W_WRONG_CHV;
			}
	}
	
	return NO_ERROR;
}


DWORD WINAPI CardEnumFiles(__in PCARD_DATA  pCardData, __in LPSTR pszDirectoryName, __out_ecount(*pdwcbFileName)LPSTR *pmszFileNames, __out LPDWORD pdwcbFileName, __in DWORD dwFlags)
{
	SCardLog::writeLog("[%s:%d][MD] CardEnumFiles",__FUNCTION__, __LINE__);
	const char root_files[] = "cardapps\0cardcf\0cardid\0\0";
	const char mscp_files[] = "kxc00\0kxc01\0cmapfile\0\0";
	if (!pCardData) return SCARD_E_INVALID_PARAMETER;
	if (!pmszFileNames) return SCARD_E_INVALID_PARAMETER;
	if (!pdwcbFileName) return SCARD_E_INVALID_PARAMETER;
	if (dwFlags) return SCARD_E_INVALID_PARAMETER;

	if (!pszDirectoryName || !strlen(pszDirectoryName))
	{
		DWORD sz = sizeof(root_files) - 1;
		LPSTR t = (LPSTR)(*pCardData->pfnCspAlloc)(sz);
		if (!t) return ERROR_NOT_ENOUGH_MEMORY;
		CopyMemory(t,root_files,sz);
		*pmszFileNames = t;
		*pdwcbFileName = sz;
		return NO_ERROR;
	}
	if (!_strcmpi(pszDirectoryName,"mscp"))
	{
		DWORD sz = sizeof(mscp_files) - 1;
		LPSTR t = (LPSTR)(*pCardData->pfnCspAlloc)(sz);
		if (!t) return ERROR_NOT_ENOUGH_MEMORY;
		CopyMemory(t,mscp_files,sz);
		*pmszFileNames = t;
		*pdwcbFileName = sz;
		return NO_ERROR;
	}
	return SCARD_E_DIR_NOT_FOUND;
}


DWORD WINAPI CardGetFileInfo(__in PCARD_DATA pCardData, __in LPSTR pszDirectoryName, __in LPSTR pszFileName, __in PCARD_FILE_INFO pCardFileInfo)
{
	SCardLog::writeLog("[%s:%d][MD] CardGetFileInfo",__FUNCTION__, __LINE__);
	if (!pCardData) return SCARD_E_INVALID_PARAMETER;
	if (!pszFileName) return SCARD_E_INVALID_PARAMETER;
	if (!strlen(pszFileName)) return SCARD_E_INVALID_PARAMETER;
	if (!pCardFileInfo) return SCARD_E_INVALID_PARAMETER;

	if (pCardFileInfo->dwVersion != CARD_FILE_INFO_CURRENT_VERSION && 
		pCardFileInfo->dwVersion != 0 ) 
		return ERROR_REVISION_MISMATCH;

	pCardFileInfo->AccessCondition = EveryoneReadUserWriteAc;
	if (!pszDirectoryName || !strlen(pszDirectoryName))
	{
		if (!_strcmpi(pszFileName,"cardapps"))
		{
			SCardLog::writeLog("[%s:%d][MD] CardGetFileInfo: cardapps",__FUNCTION__, __LINE__);
			pCardFileInfo->cbFileSize = sizeof( ((cardFiles *)pCardData->pvVendorSpecific)->file_appdir);
			return NO_ERROR;
		}
		if (!_strcmpi(pszFileName,"cardcf"))
		{
			SCardLog::writeLog("[%s:%d][MD] CardGetFileInfo: cardcf",__FUNCTION__, __LINE__);
			pCardFileInfo->cbFileSize = sizeof(((cardFiles *)pCardData->pvVendorSpecific)->file_cardcf);
			return NO_ERROR;
		}
		if (!_strcmpi(pszFileName,"cardid"))
		{
			SCardLog::writeLog("[%s:%d][MD] CardGetFileInfo: cardid",__FUNCTION__, __LINE__);
			pCardFileInfo->cbFileSize = sizeof(((cardFiles *)pCardData->pvVendorSpecific)->file_cardid);
			return NO_ERROR;
		}
		SCardLog::writeLog("[%s:%d][MD] CardGetFileInfo:file not found 0",__FUNCTION__, __LINE__);
		return SCARD_E_FILE_NOT_FOUND;
	}
	if (!_strcmpi(pszDirectoryName,"mscp"))
	{
		if (!_strcmpi(pszFileName,"cmapfile"))
		{
			SCardLog::writeLog("[%s:%d][MD] CardGetFileInfo: cmapfile",__FUNCTION__, __LINE__);
			pCardFileInfo->cbFileSize = sizeof(CONTAINERMAPREC ) * 2;
			return NO_ERROR;
		}
		SCardLog::writeLog("[%s:%d][MD] CardGetFileInfo:file not found 1",__FUNCTION__, __LINE__);
		return SCARD_E_FILE_NOT_FOUND;
	}
	return SCARD_E_DIR_NOT_FOUND;
}

DWORD WINAPI CardReadFile(__in PCARD_DATA pCardData, __in LPSTR pszDirectoryName, __in LPSTR pszFileName, __in DWORD dwFlags, __deref_out_bcount(*pcbData)PBYTE *ppbData, __out PDWORD pcbData)
{
	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	SCardLog::writeLog("[%s:%d][MD] CardReadFile pszDirectoryName=%s, pszFileName=%s, dwFlags=0x%08X",__FUNCTION__, __LINE__, NULLSTR(pszDirectoryName), NULLSTR(pszFileName), dwFlags);

	if (!pszFileName)
		return SCARD_E_INVALID_PARAMETER;
	if (!strlen(pszFileName))
		return SCARD_E_INVALID_PARAMETER;
	if (!ppbData)
		return SCARD_E_INVALID_PARAMETER;
	if (!pcbData)
		return SCARD_E_INVALID_PARAMETER;
	if (dwFlags)
		return SCARD_E_INVALID_PARAMETER;

	if (pszDirectoryName && _strcmpi(pszDirectoryName, "mscp"))
		return SCARD_E_DIR_NOT_FOUND;

	if (!_strcmpi(pszFileName, "cardcf"))
	{
		SCardLog::writeLog("[%s:%d][MD] CardReadFile: Filename cardcf",__FUNCTION__, __LINE__);
		DWORD sz = sizeof(((cardFiles *)pCardData->pvVendorSpecific)->file_cardcf);
		
		PBYTE t = (LPBYTE)(*pCardData->pfnCspAlloc)(sz);
		if (!t)
			return ERROR_NOT_ENOUGH_MEMORY;
		CopyMemory(t,((cardFiles *)pCardData->pvVendorSpecific)->file_cardcf, sz);

		*ppbData = t;
		*pcbData = sz;
		return NO_ERROR;
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
				return SCARD_E_FILE_NOT_FOUND;
			}

			memset(ptr->file_cardid, 0, sizeof(ptr->file_cardid));
			CopyMemory( ptr->file_cardid, id.c_str(), id.length());

			SCardLog::writeLog("[%s:%d][MD] cardid: '%s'",__FUNCTION__, __LINE__, ptr->file_cardid);
		}
		catch (runtime_error &err)
		{
			SCardLog::writeLog("[%s:%d][MD] runtime_error in CardReadFile '%s'",__FUNCTION__, __LINE__, err.what());
			return SCARD_E_FILE_NOT_FOUND;
		}
		DWORD sz = sizeof(ptr->file_cardid);
		PBYTE t = (PBYTE)(*pCardData->pfnCspAlloc)(sz);
		if (!t)
		{
			SCardLog::writeLog("[%s:%d][MD] return ERROR_NOT_ENOUGH_MEMORY;",__FUNCTION__, __LINE__);
			return ERROR_NOT_ENOUGH_MEMORY;
		}
		SCardLog::writeLog("[%s:%d][MD] CopyMemory",__FUNCTION__, __LINE__);
		CopyMemory(t,ptr->file_cardid,sz );

		SCardLog::writeLog("[%s:%d][MD] ppbData",__FUNCTION__, __LINE__);
		*ppbData = t;
		SCardLog::writeLog("[%s:%d][MD] pcbData",__FUNCTION__, __LINE__);
		*pcbData = sz;
		SCardLog::writeLog("[%s:%d][MD] return NO_ERROR;",__FUNCTION__, __LINE__);
		return NO_ERROR;
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
				return SCARD_E_FILE_NOT_FOUND;
			}

			DWORD sz = (DWORD) reply.size();
			PBYTE t = (PBYTE)(*pCardData->pfnCspAlloc)(sz);
			if (!t)
				return ERROR_NOT_ENOUGH_MEMORY;
			CopyMemory(t,&reply[0],sz );

			*ppbData = t;
			*pcbData = sz;
			return NO_ERROR;
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
				return SCARD_E_FILE_NOT_FOUND;
			}

			DWORD sz = (DWORD) reply.size();
			PBYTE t = (PBYTE)(*pCardData->pfnCspAlloc)(sz);
			if (!t)
				return ERROR_NOT_ENOUGH_MEMORY;
			CopyMemory(t,&reply[0],sz );

			*ppbData = t;
			*pcbData = sz;
			return NO_ERROR;
		}

		if (!_strcmpi(pszFileName,"ksc01"))
		{
			SCardLog::writeLog("[%s:%d][MD] CardReadFile: Filename ksc01 [SIGN CERT]",__FUNCTION__, __LINE__);
			if (pCardData->dwVersion < 6 )
			{
				SCardLog::writeLog("[%s:%d][MD] Runtime_error in CardReadFile, reading ksc01,pCardData->dwVersion is %d",__FUNCTION__, __LINE__, pCardData->dwVersion);
				return SCARD_E_FILE_NOT_FOUND;
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
				return SCARD_E_FILE_NOT_FOUND;
			}

			DWORD sz = (DWORD) reply.size();
			PBYTE t = (PBYTE)(*pCardData->pfnCspAlloc)(sz);
			if (!t)
				return ERROR_NOT_ENOUGH_MEMORY;
			CopyMemory(t,&reply[0],sz );

			*ppbData = t;
			*pcbData = sz;
			return NO_ERROR;
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
				return SCARD_E_FILE_NOT_FOUND;
			}

			if (id.length() < MIN_DOCUMENT_ID_LEN || id.length() > MAX_DOCUMENT_ID_LEN)
			{
				SCardLog::writeLog("[%s:%d][MD] Runtime_error in CardReadFile, id.length is '%d'",__FUNCTION__, __LINE__, id.length());
				return SCARD_E_FILE_NOT_FOUND;
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
				return ERROR_NOT_ENOUGH_MEMORY;
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
			return NO_ERROR;
		}
	}

	SCardLog::writeLog("[%s:%d][MD] Returning E_NOFILE",__FUNCTION__, __LINE__);
	return SCARD_E_FILE_NOT_FOUND;
}

DWORD WINAPI CardQueryFreeSpace( __in PCARD_DATA pCardData, __in DWORD dwFlags, __in PCARD_FREE_SPACE_INFO pCardFreeSpaceInfo)
{
	if (!pCardData) 
		return SCARD_E_INVALID_PARAMETER;
	if (!pCardFreeSpaceInfo) 
		return SCARD_E_INVALID_PARAMETER;
	SCardLog::writeLog("[%s:%d][MD] CardWriteFile dwFlags=0x%08X, dwVersion=%u",__FUNCTION__, __LINE__, dwFlags, pCardFreeSpaceInfo->dwVersion );
	if (dwFlags) 
		return SCARD_E_INVALID_PARAMETER;

	if (pCardFreeSpaceInfo->dwVersion != CARD_FREE_SPACE_INFO_CURRENT_VERSION && pCardFreeSpaceInfo->dwVersion != 0)
		return ERROR_REVISION_MISMATCH;

	pCardFreeSpaceInfo->dwVersion = CARD_FREE_SPACE_INFO_CURRENT_VERSION;
	pCardFreeSpaceInfo->dwBytesAvailable = 0;
	pCardFreeSpaceInfo->dwKeyContainersAvailable = 0;
	pCardFreeSpaceInfo->dwMaxKeyContainers = 2;
	return NO_ERROR;
}

DWORD WINAPI CardQueryKeySizes(__in PCARD_DATA pCardData, __in DWORD dwKeySpec, __in DWORD dwFlags, __in PCARD_KEY_SIZES pKeySizes)
{
	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	if (!pKeySizes)
	{
		SCardLog::writeLog("[%s:%d][MD] CardQueryKeySizes NULL pKeySizes",__FUNCTION__, __LINE__);
		return SCARD_E_INVALID_PARAMETER;
	}

	SCardLog::writeLog("[%s:%d][MD] CardQueryKeySizes dwKeySpec=%u, dwFlags=0x%08X, dwVersion=%u",__FUNCTION__, __LINE__,dwKeySpec,dwFlags,pKeySizes->dwVersion );

	if (dwFlags)
		return  SCARD_E_INVALID_PARAMETER;

	if (dwKeySpec > 8 || dwKeySpec == 0)
		return SCARD_E_INVALID_PARAMETER;

	if (dwKeySpec != AT_SIGNATURE && dwKeySpec != AT_KEYEXCHANGE )
		return SCARD_E_UNSUPPORTED_FEATURE;

	if (pKeySizes->dwVersion > CARD_KEY_SIZES_CURRENT_VERSION)
		return ERROR_REVISION_MISMATCH;

	unsigned int key_size = NULL;
	try
	{
		EstEIDManager estEIDManager(pCardData->hSCardCtx, pCardData->hScard);
		key_size  = estEIDManager.getKeySize();
	}
	catch (runtime_error &err )
	{
		SCardLog::writeLog("[%s:%d][MD] runtime_error in CardReadFile '%s'",__FUNCTION__, __LINE__, err.what());
		return SCARD_E_FILE_NOT_FOUND;
	}
	if (!key_size)
		return SCARD_E_UNEXPECTED;

	pKeySizes->dwDefaultBitlen = key_size;
	pKeySizes->dwMaximumBitlen = key_size;
	pKeySizes->dwMinimumBitlen = key_size;
	pKeySizes->dwIncrementalBitlen = 0;

	return NO_ERROR;
}

DWORD WINAPI CardRSADecrypt(__in PCARD_DATA pCardData, __inout PCARD_RSA_DECRYPT_INFO  pInfo)
{
	if (!pCardData) return SCARD_E_INVALID_PARAMETER;
	if (!pInfo) return SCARD_E_INVALID_PARAMETER;
	SCardLog::writeLog("[%s:%d][MD] CardRSADecrypt dwVersion=%u, bContainerIndex=%u, dwKeySpec=%u, cbData=%u",__FUNCTION__, __LINE__, pInfo->dwVersion, pInfo->bContainerIndex, pInfo->dwKeySpec, pInfo->cbData);
	if(pInfo->dwVersion == CARD_RSA_KEY_DECRYPT_INFO_VERSION_TWO)
		SCardLog::writeLog("[%s:%d][MD] CardRSADecrypt dwPaddingType=%u, pPaddingInfo=%s",__FUNCTION__, __LINE__, pInfo->dwPaddingType, pInfo->pPaddingInfo);

	if (pInfo->dwVersion < CARD_RSA_KEY_DECRYPT_INFO_VERSION_ONE)
		return ERROR_REVISION_MISMATCH;
	if(pInfo->dwVersion > CARD_RSA_KEY_DECRYPT_INFO_VERSION_TWO)
		return ERROR_REVISION_MISMATCH;
	if(pInfo->dwKeySpec > AT_SIGNATURE)
		return SCARD_E_INVALID_PARAMETER;

	if(pInfo->dwKeySpec != AT_KEYEXCHANGE)
	{
		if(pInfo->dwKeySpec <= AT_SIGNATURE)
			return SCARD_E_INVALID_PARAMETER;
	}
	if(pInfo->cbData <= 1)
		return SCARD_E_INSUFFICIENT_BUFFER;

	if(!pInfo->cbData)
		return SCARD_E_INSUFFICIENT_BUFFER;
		
	SCardLog::writeLog("[%s:%d][MD] CardRSADecrypt: Check pbData",__FUNCTION__, __LINE__);
	if (!pInfo->pbData)
	{
		SCardLog::writeLog("[%s:%d][MD] CardRSADecrypt: Check pbData failed",__FUNCTION__, __LINE__);
		return SCARD_E_INVALID_PARAMETER;
	}

	SCardLog::writeLog("[%s:%d][MD] CardRSADecrypt: Check dwKeySpec",__FUNCTION__, __LINE__);
	if (pInfo->dwKeySpec > 8 || pInfo->dwKeySpec == 0 ) 
	{
		return SCARD_E_INVALID_PARAMETER;
	}
	SCardLog::writeLog("[%s:%d][MD] CardRSADecrypt: Check AT_SIGNATURE && AT_KEYEXCHANGE",__FUNCTION__, __LINE__);
	if (pInfo->dwKeySpec != AT_SIGNATURE && pInfo->dwKeySpec != AT_KEYEXCHANGE )
	{	
		return SCARD_E_INVALID_PARAMETER;
	}
	SCardLog::writeLog("[%s:%d][MD] CardRSADecrypt: Check AUTH_CONTAINER_INDEX && SIGN_CONTAINER_INDEX",__FUNCTION__, __LINE__);
	if (pInfo->bContainerIndex != AUTH_CONTAINER_INDEX && pInfo->bContainerIndex != SIGN_CONTAINER_INDEX )
	{
		return SCARD_E_NO_KEY_CONTAINER;
	}
	SCardLog::writeLog("[%s:%d][MD] CardRSADecrypt: Check AUTH_CONTAINER_INDEX",__FUNCTION__, __LINE__);
	if (pInfo->bContainerIndex == AUTH_CONTAINER_INDEX)
	{
		if (pInfo->dwKeySpec != AT_KEYEXCHANGE)
		{
			SCardLog::writeLog("[%s:%d][MD] CardRSADecrypt: Check AUTH_CONTAINER_INDEX failed.  Is: %i expected %i",__FUNCTION__, __LINE__, pInfo->bContainerIndex, AUTH_CONTAINER_INDEX);
			return SCARD_E_INVALID_PARAMETER;
		}
	}
	else if (pInfo->dwKeySpec != AT_SIGNATURE)
	{
		SCardLog::writeLog("[%s:%d][MD] CardRSADecrypt: Check AT_SIGNATURE failed",__FUNCTION__, __LINE__);
		return SCARD_E_INVALID_PARAMETER;
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
			return SCARD_E_INSUFFICIENT_BUFFER;
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
			return NTE_BAD_DATA; //fyr digidoc
		}
		else
		{
			SCardLog::writeLog("[%s:%d][MD] CardRSADecrypt: E_NEEDSAUTH",__FUNCTION__, __LINE__);
			return SCARD_W_SECURITY_VIOLATION;
		}
	}
	catch (CardError & err)
	{
		SCardLog::writeLog("[%s:%d][MD] CardError exception thrown: %s SW1=0x%02X SW2=0x%02X",__FUNCTION__, __LINE__, err.what(),
			err.SW1 , err.SW2 );
		if (err.SW1 == 0x64 && err.SW2 == 0 )
			return NTE_BAD_DATA; //fyr digidoc
		else
			return SCARD_E_UNEXPECTED;
	}
	catch (runtime_error & ex)
	{
		SCardLog::writeLog("[%s:%d][MD] runtime_error exception thrown: %s",__FUNCTION__, __LINE__, ex.what());
		return SCARD_E_UNEXPECTED;
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
	return NO_ERROR;
}

DWORD WINAPI CardSignData( __in PCARD_DATA pCardData, __in PCARD_SIGNING_INFO pInfo)
{
	if (!pCardData) return SCARD_E_INVALID_PARAMETER;
	if (!pInfo) return SCARD_E_INVALID_PARAMETER;

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

	if (!pInfo->pbData) return SCARD_E_INVALID_PARAMETER;
	if (pInfo->bContainerIndex != AUTH_CONTAINER_INDEX && pInfo->bContainerIndex != SIGN_CONTAINER_INDEX)
		return SCARD_E_NO_KEY_CONTAINER;
	if (pInfo->dwVersion > 1)
	{
		SCardLog::writeLog("[%s:%d][MD] CardSignData(3) dwPaddingType=%u",__FUNCTION__, __LINE__,pInfo->dwPaddingType);
	}

	if (pInfo->dwVersion != 1 && pInfo->dwVersion != 2) 
	{
		SCardLog::writeLog("[%s:%d][MD] Unsupported version",__FUNCTION__, __LINE__);
		return ERROR_REVISION_MISMATCH;
	}
	if (pInfo->dwKeySpec != AT_KEYEXCHANGE && pInfo->dwKeySpec != AT_SIGNATURE )
	{
		SCardLog::writeLog("[%s:%d][MD] Unsupported dwKeySpec",__FUNCTION__, __LINE__);
		return SCARD_E_INVALID_PARAMETER;
	}

	DWORD dwFlagMask = CARD_PADDING_INFO_PRESENT | CARD_BUFFER_SIZE_ONLY | CARD_PADDING_NONE | CARD_PADDING_PKCS1 | CARD_PADDING_PSS;
	if (pInfo->dwSigningFlags & (~dwFlagMask))
	{
		SCardLog::writeLog("[%s:%d][MD] Bogus dwSigningFlags",__FUNCTION__, __LINE__);
		return SCARD_E_INVALID_PARAMETER;
	}

	if (CARD_PADDING_INFO_PRESENT & pInfo->dwSigningFlags)
	{
		if (CARD_PADDING_PKCS1 != pInfo->dwPaddingType)
		{
			SCardLog::writeLog("[%s:%d][MD] Unsupported paddingtype",__FUNCTION__, __LINE__);
			return SCARD_E_UNSUPPORTED_FEATURE;
		}
		BCRYPT_PKCS1_PADDING_INFO *pinf = (BCRYPT_PKCS1_PADDING_INFO *)pInfo->pPaddingInfo;
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
			return SCARD_E_INVALID_PARAMETER;
		}
		if (hashAlg !=0 && hashAlg != CALG_SSL3_SHAMD5 && hashAlg != CALG_SHA1 && hashAlg != CALG_MD5 && hashAlg != CALG_SHA_256 && hashAlg != CALG_SHA_384 && hashAlg != CALG_SHA_512)
		{
			SCardLog::writeLog("[%s:%d][MD] unsupported aiHashAlg",__FUNCTION__, __LINE__);
			return SCARD_E_UNSUPPORTED_FEATURE;
		}
	}

	if (pInfo->bContainerIndex != AUTH_CONTAINER_INDEX && pInfo->bContainerIndex != SIGN_CONTAINER_INDEX )
	{
		SCardLog::writeLog("[%s:%d][MD] Invalid container index",__FUNCTION__, __LINE__);
		return SCARD_E_NO_KEY_CONTAINER;
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
				SCARD_E_UNSUPPORTED_FEATURE;
			}
			SCardLog::writeLog("[%s:%d][MD] CALG_SHA_256 key size %i",__FUNCTION__, __LINE__, estEIDManager.getKeySize());
			reply = estEIDManager.sign(hash, EstEIDManager::SHA256, pInfo->bContainerIndex == AUTH_CONTAINER_INDEX ? EstEIDManager::AUTH : EstEIDManager::SIGN);
			break;
		case CALG_SHA_384:
			if(estEIDManager.getCardVersion() < EstEIDManager::VER_1_1)
			{
				SCardLog::writeLog("[%s:%d][MD] CALG_SHA_384 key size %i unsupported",__FUNCTION__, __LINE__, estEIDManager.getKeySize());
				SCARD_E_UNSUPPORTED_FEATURE;
			}
			SCardLog::writeLog("[%s:%d][MD] CALG_SHA_384 key size %i",__FUNCTION__, __LINE__, estEIDManager.getKeySize());
			reply = estEIDManager.sign(hash, EstEIDManager::SHA384, pInfo->bContainerIndex == AUTH_CONTAINER_INDEX ? EstEIDManager::AUTH : EstEIDManager::SIGN);
			break;
		case CALG_SHA_512:
			if(estEIDManager.getCardVersion() < EstEIDManager::VER_1_1)
			{
				SCardLog::writeLog("[%s:%d][MD] CALG_SHA_512 key size %i unsupported",__FUNCTION__, __LINE__, estEIDManager.getKeySize());
				SCARD_E_UNSUPPORTED_FEATURE;
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
				return SCARD_E_UNSUPPORTED_FEATURE;
			}
			break;
		default:
			SCardLog::writeLog("[%s:%d][MD] Unsupported hash alogrithm",__FUNCTION__, __LINE__);
			return SCARD_E_UNSUPPORTED_FEATURE;
		}
		if (reply.size() == 0)
		{
			SCardLog::writeLog("[%s:%d][MD] No function to call, hashAlg 0x%08X, container %d",__FUNCTION__, __LINE__,hashAlg,pInfo->bContainerIndex);
			return SCARD_W_SECURITY_VIOLATION;
		}
	}
	catch (AuthError &err)
	{
		SCardLog::writeLog("[%s:%d][MD] SCError exception thrown: %s",__FUNCTION__, __LINE__, err.what());
		return SCARD_W_SECURITY_VIOLATION;
	}
	catch (runtime_error &ex)
	{
		SCardLog::writeLog("[%s:%d][MD] Runtime_error exception thrown:",__FUNCTION__, __LINE__, ex.what());
		return SCARD_E_UNEXPECTED;
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
		if (!pInfo->pbSignedData) return ERROR_NOT_ENOUGH_MEMORY;
		CopyMemory(pInfo->pbSignedData,&reply[0],reply.size());
	}
	return NO_ERROR;
}

DWORD WINAPI CardGetChallenge(__in PCARD_DATA pCardData, __deref_out_bcount(*pcbChallengeData) PBYTE *ppbChallengeData, __out PDWORD pcbChallengeData)
{
	SCardLog::writeLog("[%s:%d][MD] CardGetChallenge. Running in %s mode",__FUNCTION__, __LINE__, TestMode == true ? "TEST MODE" : "USER MODE");
	if(TestMode == true)
	{
		SCardLog::writeLog("[%s:%d][MD] This feature is not supported in test mode: ",__FUNCTION__, __LINE__);
		return SCARD_E_UNSUPPORTED_FEATURE;
	}
	if(NULL == pCardData)
		return SCARD_E_INVALID_PARAMETER;
	if(NULL == ppbChallengeData)
		return SCARD_E_INVALID_PARAMETER;
	if(NULL == pcbChallengeData)
		return SCARD_E_INVALID_PARAMETER;
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
			return ERROR_NOT_ENOUGH_MEMORY;
		CopyMemory(t, &cardChallenge[0], cardChallenge.size());
		*ppbChallengeData = t;
		*pcbChallengeData = (DWORD)cardChallenge.size();
	}
	catch (AuthError &err)
	{
		SCardLog::writeLog("[%s:%d][MD] SCError exception thrown: %s",__FUNCTION__, __LINE__, err.what());
		return SCARD_W_SECURITY_VIOLATION;
	}
	catch (runtime_error &ex)
	{
		SCardLog::writeLog("[%s:%d][MD] Runtime_error exception thrown:",__FUNCTION__, __LINE__, ex.what());
		return SCARD_E_UNEXPECTED;
	}
	return NO_ERROR;
}


DWORD WINAPI CardChangeAuthenticator(__in PCARD_DATA  pCardData, __in LPWSTR pwszUserId, __in_bcount(cbCurrentAuthenticator)PBYTE pbCurrentAuthenticator, __in DWORD cbCurrentAuthenticator,
	__in_bcount(cbNewAuthenticator)PBYTE pbNewAuthenticator, __in DWORD cbNewAuthenticator, __in DWORD cRetryCount, __in DWORD dwFlags, __out_opt PDWORD pcAttemptsRemaining)
{
	SCardLog::writeLog("[%s:%d][MD] CardChangeAuthenticator. Running in %s mode", __FUNCTION__, __LINE__, TestMode == true ? "TEST MODE" : "USER MODE");
	return CardChangeAuthenticatorEx(pCardData, PIN_CHANGE_FLAG_UNBLOCK | CARD_PIN_SILENT_CONTEXT, ROLE_ADMIN, pbCurrentAuthenticator, cbCurrentAuthenticator, ROLE_USER, pbNewAuthenticator, cbNewAuthenticator, cRetryCount, pcAttemptsRemaining);
}

DWORD WINAPI CardChangeAuthenticatorEx(__in PCARD_DATA pCardData, __in DWORD dwFlags, __in PIN_ID dwAuthenticatingPinId, __in_bcount(cbAuthenticatingPinData) PBYTE pbAuthenticatingPinData,
	__in DWORD cbAuthenticatingPinData, __in PIN_ID dwTargetPinId, __in_bcount(cbTargetData)PBYTE pbTargetData, __in DWORD cbTargetData, __in DWORD cRetryCount,
	__out_opt PDWORD pcAttemptsRemaining)
{
	if(!pCardData)
		return SCARD_E_INVALID_PARAMETER;
 	SCardLog::writeLog("[%s:%d][MD] CardChangeAuthenticatorEx. Running in %s mode.  dwVersion=%u, PIN_ID=%i, dwFlags=%s",__FUNCTION__, __LINE__, TestMode == true ? "TEST MODE" : "USER MODE", pCardData->dwVersion, dwAuthenticatingPinId, dwFlags == PIN_CHANGE_FLAG_CHANGEPIN ? "PIN_CHANGE_FLAG_CHANGEPIN" : "PIN_CHANGE_FLAG_UNBLOCK");
	if(TestMode == true)
	{
		SCardLog::writeLog("[%s:%d][MD] This feature is not supported in test mode",__FUNCTION__, __LINE__);
		return SCARD_E_UNSUPPORTED_FEATURE;
	}
	if(dwFlags == NULL)
		return SCARD_E_INVALID_PARAMETER;
	if(dwFlags != PIN_CHANGE_FLAG_CHANGEPIN && dwFlags != PIN_CHANGE_FLAG_UNBLOCK)
		return SCARD_E_INVALID_PARAMETER;
	if(dwAuthenticatingPinId != AUTH_PIN_ID && dwAuthenticatingPinId != SIGN_PIN_ID && dwAuthenticatingPinId != PUKK_PIN_ID)
		return SCARD_E_INVALID_PARAMETER;
	if(dwTargetPinId != AUTH_PIN_ID && dwTargetPinId != SIGN_PIN_ID && dwTargetPinId != PUKK_PIN_ID)
		return SCARD_E_INVALID_PARAMETER;
	if(NULL == pbAuthenticatingPinData)
		return SCARD_E_INVALID_PARAMETER;
	if(NULL == pbTargetData)
		return SCARD_E_INVALID_PARAMETER;

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
					return SCARD_E_INVALID_PARAMETER;
				}
			}
			else if(dwFlags == PIN_CHANGE_FLAG_UNBLOCK)
			{
				SCardLog::writeLog("[%s:%d][MD] Unblocking PIN code",__FUNCTION__, __LINE__);
				if(dwTargetPinId == dwAuthenticatingPinId)
					return SCARD_E_INVALID_PARAMETER;

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
					return SCARD_E_INVALID_PARAMETER;
				}
			}
			else
			{
				SCardLog::writeLog("[%s:%d][MD] Invalid dwFlags",__FUNCTION__, __LINE__);
				return SCARD_E_INVALID_PARAMETER;
			}
		}
		catch (AuthError &err)
		{
			if(err.SW1 == 0x69 && err.SW2 == 0x83)
			{
				SCardLog::writeLog("[%s:%d][MD] PIN code blocked",__FUNCTION__, __LINE__);
				return SCARD_W_CHV_BLOCKED;
			}
			else
			{
				SCardLog::writeLog("[%s:%d][MD] PIN authentication error: %s",__FUNCTION__, __LINE__, err.what());
				return SCARD_W_WRONG_CHV;
			}
		}
		catch (runtime_error &ex)
		{
			SCardLog::writeLog("[%s:%d][MD] Runtime_error exception thrown: %s",__FUNCTION__, __LINE__, ex.what());
			return SCARD_E_UNEXPECTED;
		}
	}
	else
	{
		return SCARD_E_INVALID_PARAMETER;
	}
	return NO_ERROR;
}

DWORD WINAPI CardUnblockPin(__in PCARD_DATA  pCardData, __in LPWSTR pwszUserId, __in_bcount(cbAuthenticationData)PBYTE pbAuthenticationData, __in DWORD cbAuthenticationData,
	__in_bcount(cbNewPinData)PBYTE pbNewPinData, __in DWORD cbNewPinData, __in DWORD cRetryCount, __in DWORD dwFlags)
{
	SCardLog::writeLog("[%s:%d][MD] CardUnblockPin. Running in %s mode",__FUNCTION__, __LINE__, TestMode == true ? "TEST MODE" : "USER MODE");
	if(TestMode == true)
	{
		SCardLog::writeLog("[%s:%d][MD] This feature is not supported in test mode: ",__FUNCTION__, __LINE__);
		return SCARD_E_UNSUPPORTED_FEATURE;
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
			return SCARD_W_CHV_BLOCKED;
		}
		else
		{
			SCardLog::writeLog("[%s:%d][MD] CardUnblockPin: PIN authentication error: %s",__FUNCTION__, __LINE__, err.what());
			return SCARD_W_WRONG_CHV;
		}
	}
	catch (runtime_error &ex)
	{
		SCardLog::writeLog("[%s:%d][MD] CardUnblockPin: Runtime_error exception thrown:",__FUNCTION__, __LINE__, ex.what());
		return SCARD_E_UNEXPECTED;
	}
	
	return NO_ERROR;
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



DECLARE_UNSUPPORTED(CardCreateDirectory(__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName,
	__in CARD_DIRECTORY_ACCESS_CONDITION AccessCondition))
DECLARE_UNSUPPORTED(CardDeleteDirectory(__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName))
DECLARE_UNSUPPORTED(CardCreateFile(__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName,
	__in LPSTR pszFileName,
	__in DWORD cbInitialCreationSize,
	__in CARD_FILE_ACCESS_CONDITION AccessCondition))
DECLARE_UNSUPPORTED(CardWriteFile(__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName,
	__in LPSTR pszFileName,
	__in DWORD dwFlags,
	__in_bcount(cbData) PBYTE pbData,
	__in DWORD cbData))
DECLARE_UNSUPPORTED(CardDeleteFile(__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName,
	__in LPSTR pszFileName,
	__in DWORD dwFlags))
DECLARE_UNSUPPORTED(CspGetDHAgreement(__in PCARD_DATA pCardData,
	__in PVOID hSecretAgreement,
	__out BYTE* pbSecretAgreementIndex,
	__in DWORD dwFlags))
DECLARE_UNSUPPORTED(CardAuthenticateChallenge(__in PCARD_DATA  pCardData,
	__in_bcount(cbResponseData) PBYTE pbResponseData,
	__in DWORD cbResponseData,
	__out_opt PDWORD pcAttemptsRemaining))
DECLARE_UNSUPPORTED(CardDeauthenticate(__in PCARD_DATA pCardData,
	__in LPWSTR pwszUserId,
	__in DWORD dwFlags))
DECLARE_UNSUPPORTED(CardCreateContainer(__in PCARD_DATA pCardData,
	__in BYTE bContainerIndex,
	__in DWORD dwFlags,
	__in DWORD dwKeySpec,
	__in DWORD dwKeySize,
	__in PBYTE pbKeyData))
DECLARE_UNSUPPORTED(CardCreateContainerEx(__in PCARD_DATA  pCardData,
	__in BYTE  bContainerIndex,
	__in DWORD  dwFlags,
	__in DWORD  dwKeySpec,
	__in DWORD  dwKeySize,
	__in PBYTE  pbKeyData,
	__in PIN_ID  PinId))
DECLARE_UNSUPPORTED(CardDeleteContainer(__in PCARD_DATA pCardData,
	__in BYTE bContainerIndex,
	__in DWORD dwReserved))
DECLARE_UNSUPPORTED(CardConstructDHAgreement(__in PCARD_DATA pCardData,
	__in PCARD_DH_AGREEMENT_INFO pAgreementInfo))
DECLARE_UNSUPPORTED(CardDeriveKey(__in PCARD_DATA pCardData,
	__in PCARD_DERIVE_KEY pAgreementInfo))
DECLARE_UNSUPPORTED(CardDestroyDHAgreement(__in PCARD_DATA pCardData,
	__in BYTE bSecretAgreementIndex,
	__in DWORD dwFlags))
DECLARE_UNSUPPORTED(CardDeauthenticateEx(__in PCARD_DATA pCardData,
	__in PIN_SET PinId,
	__in DWORD dwFlags))
DECLARE_UNSUPPORTED(CardGetChallengeEx(__in PCARD_DATA pCardData,
	__in PIN_ID PinId,
	__deref_out_bcount(*pcbChallengeData) PBYTE *ppbChallengeData,
	__out PDWORD pcbChallengeData,
	__in DWORD dwFlags))
DECLARE_UNSUPPORTED(CardSetContainerProperty(__in PCARD_DATA pCardData,
	__in BYTE bContainerIndex,
	__in LPCWSTR wszProperty,
	__in_bcount(cbDataLen) PBYTE pbData,
	__in DWORD cbDataLen,
	__in DWORD dwFlags))
DECLARE_UNSUPPORTED(MDImportSessionKey(__in PCARD_DATA  pCardData,
	__in LPCWSTR  pwszBlobType,
	__in LPCWSTR  pwszAlgId,
	__out PCARD_KEY_HANDLE  phKey,
	__in_bcount(cbInput) PBYTE  pbInput,
	__in DWORD  cbInput))
DECLARE_UNSUPPORTED(MDEncryptData(__in PCARD_DATA  pCardData,
	__in CARD_KEY_HANDLE  hKey,
	__in LPCWSTR  pwszSecureFunction,
	__in_bcount(cbInput) PBYTE  pbInput,
	__in DWORD  cbInput, __in DWORD  dwFlags,
	__deref_out_ecount(*pcEncryptedData) PCARD_ENCRYPTED_DATA  *ppEncryptedData,
	__out PDWORD  pcEncryptedData))
DECLARE_UNSUPPORTED(CardImportSessionKey(__in PCARD_DATA  pCardData,
	__in BYTE  bContainerIndex,
	__in VOID  *pPaddingInfo,
	__in LPCWSTR  pwszBlobType,
	__in LPCWSTR  pwszAlgId,
	__out CARD_KEY_HANDLE  *phKey,
	__in_bcount(cbInput) PBYTE  pbInput,
	__in DWORD  cbInput,
	__in DWORD  dwFlags))
DECLARE_UNSUPPORTED(CardGetSharedKeyHandle(__in PCARD_DATA  pCardData,
	__in_bcount(cbInput) PBYTE  pbInput,
	__in DWORD  cbInput,
	__deref_opt_out_bcount(*pcbOutput)PBYTE  *ppbOutput,
	__out_opt PDWORD  pcbOutput,
	__out PCARD_KEY_HANDLE  phKey))
DECLARE_UNSUPPORTED(CardGetAlgorithmProperty(__in PCARD_DATA  pCardData,
	__in LPCWSTR   pwszAlgId,
	__in LPCWSTR   pwszProperty,
	__out_bcount_part_opt(cbData, *pdwDataLen)PBYTE  pbData,
	__in DWORD  cbData,
	__out PDWORD  pdwDataLen,
	__in DWORD  dwFlags))
DECLARE_UNSUPPORTED(CardGetKeyProperty(__in PCARD_DATA pCardData,
	__in CARD_KEY_HANDLE  hKey,
	__in LPCWSTR  pwszProperty,
	__out_bcount_part_opt(cbData, *pdwDataLen) PBYTE  pbData,
	__in DWORD  cbData,
	__out PDWORD  pdwDataLen,
	__in DWORD  dwFlags))
DECLARE_UNSUPPORTED(CardSetKeyProperty(__in PCARD_DATA pCardData,
	__in CARD_KEY_HANDLE  hKey,
	__in LPCWSTR  pwszProperty,
	__in_bcount(cbInput) PBYTE  pbInput,
	__in DWORD  cbInput,
	__in DWORD  dwFlags))
DECLARE_UNSUPPORTED(CardDestroyKey(__in PCARD_DATA  pCardData,
	__in CARD_KEY_HANDLE hKey))
DECLARE_UNSUPPORTED(CardProcessEncryptedData(__in PCARD_DATA  pCardData,
	__in CARD_KEY_HANDLE  hKey,
	__in LPCWSTR  pwszSecureFunction,
	__in_ecount(cEncryptedData)PCARD_ENCRYPTED_DATA  pEncryptedData,
	__in DWORD  cEncryptedData,
	__out_bcount_part_opt(cbOutput, *pdwOutputLen) PBYTE  pbOutput,
	__in DWORD  cbOutput,
	__out_opt PDWORD  pdwOutputLen,
	__in DWORD  dwFlags))
