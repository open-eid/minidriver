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
#include "notimplemented.h"

DWORD WINAPI CardDeleteContainer(__in PCARD_DATA pCardData,
								 __in BYTE bContainerIndex,
								 __in DWORD dwReserved)
{
	SCardLog::writeLog("[%s:%d] CardDeleteContainer:dummy",__FUNCTION__, __LINE__);
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardCreateDirectory(__in PCARD_DATA pCardData,
								 __in LPSTR pszDirectoryName,
								 __in CARD_DIRECTORY_ACCESS_CONDITION AccessCondition)
{
	SCardLog::writeLog("[%s:%d] CardCreateDirectory:dummy",__FUNCTION__, __LINE__);
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardDeleteDirectory(__in PCARD_DATA pCardData,
								 __in LPSTR pszDirectoryName)
{
	SCardLog::writeLog("[%s:%d] CardDeleteDirectory:dummy",__FUNCTION__, __LINE__);
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardCreateFile(__in PCARD_DATA pCardData,
							__in LPSTR pszDirectoryName,
							__in LPSTR pszFileName,
							__in DWORD cbInitialCreationSize,
							__in CARD_FILE_ACCESS_CONDITION AccessCondition)
{
	SCardLog::writeLog("[%s:%d] CardCreateFile:dummy",__FUNCTION__, __LINE__);
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardDeleteFile(__in PCARD_DATA pCardData,
							__in LPSTR pszDirectoryName,
							__in LPSTR pszFileName,
							__in DWORD dwFlags)
{
	SCardLog::writeLog("[%s:%d] CardDeleteFile:dummy",__FUNCTION__, __LINE__);
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardConstructDHAgreement(__in PCARD_DATA pCardData,
									  __in PCARD_DH_AGREEMENT_INFO pAgreementInfo)
{
	SCardLog::writeLog("[%s:%d] CardConstructDHAgreement:dummy",__FUNCTION__, __LINE__);
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardDeriveKey(__in PCARD_DATA pCardData, 
						   __in PCARD_DERIVE_KEY pAgreementInfo)
{
	SCardLog::writeLog("[%s:%d] CardDeriveKey:dummy",__FUNCTION__, __LINE__);
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardDestroyDHAgreement(__in PCARD_DATA pCardData,
									__in BYTE bSecretAgreementIndex,
									__in DWORD dwFlags)
{
	SCardLog::writeLog("[%s:%d] CardDestroyDHAgreement:dummy",__FUNCTION__, __LINE__);
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CspGetDHAgreement(__in PCARD_DATA pCardData, 
							   __in PVOID hSecretAgreement, 
							   __out BYTE* pbSecretAgreementIndex,
							   __in DWORD dwFlags)
{
	SCardLog::writeLog("[%s:%d] CspGetDHAgreement:dummy",__FUNCTION__, __LINE__);
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardAuthenticateChallenge(__in PCARD_DATA  pCardData,
									   __in_bcount(cbResponseData) PBYTE pbResponseData,
									   __in DWORD cbResponseData,
									   __out_opt PDWORD pcAttemptsRemaining)
{
	SCardLog::writeLog("[%s:%d] CardAuthenticateChallenge:dummy",__FUNCTION__, __LINE__);
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardGetChallengeEx(__in PCARD_DATA pCardData,
								__in PIN_ID PinId,
								__deref_out_bcount(*pcbChallengeData) PBYTE *ppbChallengeData,
								__out PDWORD pcbChallengeData,
								__in DWORD dwFlags )
{
	SCardLog::writeLog("[%s:%d] CardGetChallengeEx:dummy",__FUNCTION__, __LINE__);
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardDeauthenticate(__in PCARD_DATA pCardData,
								__in LPWSTR pwszUserId,
								__in DWORD dwFlags)
{
	SCardLog::writeLog("[%s:%d] CardDeauthenticate:dummy",__FUNCTION__, __LINE__);
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardDeauthenticateEx(__in PCARD_DATA pCardData,
								  __in PIN_SET PinId, 
								  __in DWORD dwFlags)
{
	SCardLog::writeLog("[%s:%d] CardDeauthenticateEx:dummy",__FUNCTION__, __LINE__);
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardGetSharedKeyHandle(__in PCARD_DATA  pCardData,
									__in_bcount(cbInput) PBYTE  pbInput,
									__in DWORD  cbInput,
									__deref_opt_out_bcount(*pcbOutput)PBYTE  *ppbOutput,
									__out_opt PDWORD  pcbOutput,
									__out PCARD_KEY_HANDLE  phKey)
{
	SCardLog::writeLog("[%s:%d] CardGetSharedKeyHandle:dummy",__FUNCTION__, __LINE__);
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardDestroyKey(__in PCARD_DATA  pCardData,
							__in CARD_KEY_HANDLE hKey)
{
	SCardLog::writeLog("[%s:%d] CardDestroyKey:dummy",__FUNCTION__, __LINE__);
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardGetAlgorithmProperty(__in PCARD_DATA  pCardData,
									  __in LPCWSTR   pwszAlgId,
									  __in LPCWSTR   pwszProperty,
									  __out_bcount_part_opt(cbData, *pdwDataLen)PBYTE  pbData,
									  __in DWORD  cbData,
									  __out PDWORD  pdwDataLen,
									  __in DWORD  dwFlags)
{
	SCardLog::writeLog("[%s:%d] CardGetAlgorithmProperty:dummy",__FUNCTION__, __LINE__);
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardGetKeyProperty(__in PCARD_DATA pCardData,
								__in CARD_KEY_HANDLE  hKey,
								__in LPCWSTR  pwszProperty,
								__out_bcount_part_opt(cbData, *pdwDataLen) PBYTE  pbData,
								__in DWORD  cbData,
								__out PDWORD  pdwDataLen,
								__in DWORD  dwFlags)
{
	SCardLog::writeLog("[%s:%d] CardGetKeyProperty:dummy",__FUNCTION__, __LINE__);
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardSetKeyProperty(__in PCARD_DATA pCardData,
								__in CARD_KEY_HANDLE  hKey,
								__in LPCWSTR  pwszProperty,
								__in_bcount(cbInput) PBYTE  pbInput,
								__in DWORD  cbInput,
								__in DWORD  dwFlags)
{
	SCardLog::writeLog("[%s:%d] CardSetKeyProperty:dummy",__FUNCTION__, __LINE__);
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardProcessEncryptedData(__in PCARD_DATA  pCardData,
									  __in CARD_KEY_HANDLE  hKey,
									  __in LPCWSTR  pwszSecureFunction,
									  __in_ecount(cEncryptedData)PCARD_ENCRYPTED_DATA  pEncryptedData,
									  __in DWORD  cEncryptedData,
									  __out_bcount_part_opt(cbOutput, *pdwOutputLen) PBYTE  pbOutput,
									  __in DWORD  cbOutput,
									  __out_opt PDWORD  pdwOutputLen,
									  __in DWORD  dwFlags)
{
	SCardLog::writeLog("[%s:%d] CardProcessEncryptedData:dummy",__FUNCTION__, __LINE__);
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardImportSessionKey(__in PCARD_DATA  pCardData,
								  __in BYTE  bContainerIndex,
								  __in VOID  *pPaddingInfo,
								  __in LPCWSTR  pwszBlobType,
								  __in LPCWSTR  pwszAlgId,
								  __out CARD_KEY_HANDLE  *phKey,
								  __in_bcount(cbInput) PBYTE  pbInput,
								  __in DWORD  cbInput,
								  __in DWORD  dwFlags)
{
	SCardLog::writeLog("[%s:%d] CardImportSessionKey:dummy",__FUNCTION__, __LINE__);
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI MDEncryptData(__in PCARD_DATA  pCardData,
						   __in CARD_KEY_HANDLE  hKey,
						   __in LPCWSTR  pwszSecureFunction,
						   __in_bcount(cbInput) PBYTE  pbInput,
						   __in DWORD  cbInput, __in DWORD  dwFlags,
						   __deref_out_ecount(*pcEncryptedData) PCARD_ENCRYPTED_DATA  *ppEncryptedData,
						   __out PDWORD  pcEncryptedData)
{
	SCardLog::writeLog("[%s:%d] MDEncryptData:dummy",__FUNCTION__, __LINE__);
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI MDImportSessionKey(__in PCARD_DATA  pCardData,
								__in LPCWSTR  pwszBlobType,
								__in LPCWSTR  pwszAlgId,
								__out PCARD_KEY_HANDLE  phKey,
								__in_bcount(cbInput) PBYTE  pbInput,
								__in DWORD  cbInput)
{
	SCardLog::writeLog("[%s:%d] MDImportSessionKey:dummy",__FUNCTION__, __LINE__);
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardCreateContainerEx(__in PCARD_DATA  pCardData,
								   __in BYTE  bContainerIndex,
								   __in DWORD  dwFlags,
								   __in DWORD  dwKeySpec,
								   __in DWORD  dwKeySize,
								   __in PBYTE  pbKeyData,
								   __in PIN_ID  PinId)
{
	SCardLog::writeLog("[%s:%d] CardCreateContainerEx:dummy",__FUNCTION__, __LINE__);
	return SCARD_E_UNSUPPORTED_FEATURE;
}