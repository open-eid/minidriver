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

#ifndef _NOTIMPLEMENTED_H_
#define _NOTIMPLEMENTED_H_

#include <cardmod.h>
#include "esteidcm.h"


DWORD WINAPI CardDeleteContainer(__in PCARD_DATA pCardData, 
								 __in BYTE bContainerIndex, 
								 __in DWORD dwReserved);

DWORD WINAPI CardCreateDirectory(__in PCARD_DATA pCardData, 
								 __in LPSTR pszDirectoryName, 
								 __in CARD_DIRECTORY_ACCESS_CONDITION AccessCondition);

DWORD WINAPI CardDeleteDirectory(__in PCARD_DATA pCardData, 
								 __in LPSTR pszDirectoryName);

DWORD WINAPI CardCreateFile(__in PCARD_DATA pCardData, 
							__in LPSTR pszDirectoryName, 
							__in LPSTR pszFileName, 
							__in DWORD cbInitialCreationSize, 
							__in CARD_FILE_ACCESS_CONDITION AccessCondition);

DWORD WINAPI CardDeleteFile(__in PCARD_DATA pCardData, 
							__in LPSTR pszDirectoryName, 
							__in LPSTR pszFileName, 
							__in DWORD dwFlags);

DWORD WINAPI CardConstructDHAgreement(__in PCARD_DATA pCardData, 
									  __in PCARD_DH_AGREEMENT_INFO pAgreementInfo);

DWORD WINAPI CardDeriveKey(__in PCARD_DATA pCardData, 
						   __in PCARD_DERIVE_KEY pAgreementInfo);

DWORD WINAPI CardDestroyDHAgreement(__in PCARD_DATA pCardData, 
									__in BYTE bSecretAgreementIndex, 
									__in DWORD dwFlags);

DWORD WINAPI CspGetDHAgreement(__in PCARD_DATA pCardData, 
							   __in PVOID hSecretAgreement, 
							   __out BYTE* pbSecretAgreementIndex, 
							   __in DWORD dwFlags);

DWORD WINAPI CardAuthenticateChallenge(__in PCARD_DATA  pCardData, 
									   __in_bcount(cbResponseData) PBYTE pbResponseData, 
									   __in DWORD cbResponseData, 
									   __out_opt PDWORD pcAttemptsRemaining);

DWORD WINAPI CardGetChallengeEx(__in PCARD_DATA pCardData,
								__in PIN_ID PinId,
								__deref_out_bcount(*pcbChallengeData) PBYTE *ppbChallengeData,
								__out PDWORD pcbChallengeData, __in DWORD dwFlags );

DWORD WINAPI CardDeauthenticate(__in PCARD_DATA pCardData,
								__in LPWSTR pwszUserId,
								__in DWORD dwFlags);

DWORD WINAPI CardDeauthenticateEx(__in PCARD_DATA pCardData,
								  __in PIN_SET PinId,
								  __in DWORD dwFlags);

DWORD WINAPI CardGetSharedKeyHandle(__in PCARD_DATA  pCardData,
									__in_bcount(cbInput) PBYTE  pbInput,
									__in DWORD  cbInput,
									__deref_opt_out_bcount(*pcbOutput)PBYTE  *ppbOutput,
									__out_opt PDWORD  pcbOutput,
									__out PCARD_KEY_HANDLE  phKey);

DWORD WINAPI CardDestroyKey(__in PCARD_DATA  pCardData,
							__in CARD_KEY_HANDLE hKey);

DWORD WINAPI CardGetAlgorithmProperty(__in PCARD_DATA  pCardData,
									  __in LPCWSTR   pwszAlgId,
									  __in LPCWSTR   pwszProperty,
									  __out_bcount_part_opt(cbData, *pdwDataLen) PBYTE  pbData,
									  __in DWORD  cbData,
									  __out PDWORD  pdwDataLen,
									  __in DWORD  dwFlags);

DWORD WINAPI CardGetKeyProperty(__in PCARD_DATA pCardData,
								__in CARD_KEY_HANDLE  hKey,
								__in LPCWSTR  pwszProperty,
								__out_bcount_part_opt(cbData, *pdwDataLen) PBYTE  pbData,
								__in DWORD  cbData,
								__out PDWORD  pdwDataLen,
								__in DWORD  dwFlags);

DWORD WINAPI CardSetKeyProperty(__in PCARD_DATA pCardData,
								__in CARD_KEY_HANDLE  hKey,
								__in LPCWSTR  pwszProperty,
								__in_bcount(cbInput) PBYTE  pbInput,
								__in DWORD  cbInput,
								__in DWORD  dwFlags);

DWORD WINAPI CardProcessEncryptedData(__in PCARD_DATA  pCardData,
									  __in CARD_KEY_HANDLE  hKey,
									  __in LPCWSTR  pwszSecureFunction,
									  __in_ecount(cEncryptedData)PCARD_ENCRYPTED_DATA  pEncryptedData,
									  __in DWORD  cEncryptedData,
									  __out_bcount_part_opt(cbOutput, *pdwOutputLen) PBYTE  pbOutput,
									  __in DWORD  cbOutput,
									  __out_opt PDWORD  pdwOutputLen,
									  __in DWORD  dwFlags);

DWORD WINAPI CardImportSessionKey(__in PCARD_DATA  pCardData,
								  __in BYTE  bContainerIndex,
								  __in VOID  *pPaddingInfo,
								  __in LPCWSTR  pwszBlobType,
								  __in LPCWSTR  pwszAlgId, 
								  __out CARD_KEY_HANDLE  *phKey,
								  __in_bcount(cbInput) PBYTE  pbInput,
								  __in DWORD  cbInput,
								  __in DWORD  dwFlags);

DWORD WINAPI MDEncryptData(__in PCARD_DATA  pCardData,
						   __in CARD_KEY_HANDLE  hKey,
						   __in LPCWSTR  pwszSecureFunction,
						   __in_bcount(cbInput) PBYTE  pbInput,
						   __in DWORD  cbInput,
						   __in DWORD  dwFlags, 
						   __deref_out_ecount(*pcEncryptedData) PCARD_ENCRYPTED_DATA  *ppEncryptedData,
						   __out PDWORD  pcEncryptedData);

DWORD WINAPI MDImportSessionKey(__in PCARD_DATA  pCardData,
								__in LPCWSTR  pwszBlobType,
								__in LPCWSTR  pwszAlgId,
								__out PCARD_KEY_HANDLE  phKey,
								__in_bcount(cbInput) PBYTE  pbInput,
								__in DWORD  cbInput);

DWORD WINAPI CardCreateContainerEx(__in PCARD_DATA  pCardData,
								   __in BYTE  bContainerIndex,
								   __in DWORD  dwFlags,
								   __in DWORD  dwKeySpec,
								   __in DWORD  dwKeySize,
								   __in PBYTE  pbKeyData,
								   __in PIN_ID  PinId);

#endif