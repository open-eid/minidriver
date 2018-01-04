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

#include "stdafx.h"

#define AUTH_PIN_ID ROLE_USER
#define SIGN_PIN_ID 3
#define PUKK_PIN_ID ROLE_ADMIN
#define AUTH_CONTAINER_INDEX 0
#define SIGN_CONTAINER_INDEX 1
#define RETURN(X) return logreturn(__FUNCTION__, __FILE__, __LINE__, #X, X)
#define _log(...) log(__FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)
#define DECLARE_UNSUPPORTED(name) DWORD WINAPI name { RETURN(SCARD_E_UNSUPPORTED_FEATURE); }

static const BYTE cardapps[] = { 1, 'm', 's', 'c', 'p', 0, 0, 0, 0 };
static const BYTE cardcf[] = { 0, 0, 0, 0, 0, 0 };

using namespace std;

enum DRIVER_FEATURES {
	FEATURE_VERIFY_PIN_START = 0x01,
	FEATURE_VERIFY_PIN_FINISH = 0x02,
	FEATURE_MODIFY_PIN_START = 0x03,
	FEATURE_MODIFY_PIN_FINISH = 0x04,
	FEATURE_GET_KEY_PRESSED = 0x05,
	FEATURE_VERIFY_PIN_DIRECT = 0x06,
	FEATURE_MODIFY_PIN_DIRECT = 0x07,
	FEATURE_MCT_READER_DIRECT = 0x08,
	FEATURE_MCT_UNIVERSAL = 0x09,
	FEATURE_IFD_PIN_PROPERTIES = 0x0A,
	FEATURE_ABORT = 0x0B,
	FEATURE_SET_SPE_MESSAGE = 0x0C,
	FEATURE_VERIFY_PIN_DIRECT_APP_ID = 0x0D,
	FEATURE_MODIFY_PIN_DIRECT_APP_ID = 0x0E,
	FEATURE_WRITE_DISPLAY = 0x0F,
	FEATURE_GET_KEY = 0x10,
	FEATURE_IFD_DISPLAY_PROPERTIES = 0x11,
	FEATURE_GET_TLV_PROPERTIES = 0x12,
	FEATURE_CCID_ESC_COMMAND = 0x13
};

#pragma pack(push, 1)

typedef struct
{
	uint8_t bTimerOut;
	uint8_t bTimerOut2;
	uint8_t bmFormatString;
	uint8_t bmPINBlockString;
	uint8_t bmPINLengthFormat;
	uint16_t wPINMaxExtraDigit;
	uint8_t bEntryValidationCondition;
	uint8_t bNumberMessage;
	uint16_t wLangId;
	uint8_t bMsgIndex;
	uint8_t bTeoPrologue[3];
	uint32_t ulDataLength;
	uint8_t abData[1];
} PIN_VERIFY_STRUCTURE;

typedef struct
{
	uint8_t bTimerOut;
	uint8_t bTimerOut2;
	uint8_t bmFormatString;
	uint8_t bmPINBlockString;
	uint8_t bmPINLengthFormat;
	uint8_t bInsertionOffsetOld;
	uint8_t bInsertionOffsetNew;
	uint16_t wPINMaxExtraDigit;
	uint8_t bConfirmPIN;
	uint8_t bEntryValidationCondition;
	uint8_t bNumberMessage;
	uint16_t wLangId;
	uint8_t bMsgIndex1;
	uint8_t bMsgIndex2;
	uint8_t bMsgIndex3;
	uint8_t bTeoPrologue[3];
	uint32_t ulDataLength;
	uint8_t abData[1];
} PIN_MODIFY_STRUCTURE;

#pragma pack(pop)

typedef struct
{
	PUBLICKEYSTRUC publickeystruc;
	RSAPUBKEY rsapubkey;
} PUBKEYSTRUCT, *PPUBKEYSTRUCT;

typedef struct
{
	HWND hwndParentWindow, windowHandle;
	PIN_ID pinId;
	LANGID langId;
} EXTERNAL_INFO, *PEXTERNAL_INFO;

struct Files
{
	bool pinpadEnabled = true;
	BYTE cardid[16];
	PCCERT_CONTEXT auth = nullptr, sign = nullptr;
	HWND cp = nullptr;
	map<byte, vector<byte>> dhAgreements;
};

struct Result {
	byte SW1, SW2; vector<byte> data;
	bool operator !() const { return !(SW1 == 0x90 && SW2 == 0x00); }
};

static int32_t ntohl(int32_t source)
{
	return 0
		| ((source & 0x000000ff) << 24)
		| ((source & 0x0000ff00) << 8)
		| ((source & 0x00ff0000) >> 8)
		| ((source & 0xff000000) >> 24);
}

static void log(const char *functionName, const char *fileName, int lineNumber, string message, ...)
{
	static const wstring path = []{
		wstring path(MAX_PATH, 0);
		DWORD size = GetTempPathW(DWORD(path.size()), &path[0]);
		path.resize(size);
		path += L"\\esteidcm.log";
		return path;
	}();

	if (_waccess(path.c_str(), 2) == -1)
		return;
	FILE *log = _wfsopen(path.c_str(), L"a", _SH_DENYNO);
	if (!log)
		return;

	fprintf(log, "[%s:%i] %s() ", fileName, lineNumber, functionName);
	va_list args;
	va_start(args, message);
	vfprintf(log, message.c_str(), args);
	va_end(args);
	fprintf(log, "\n");
	fclose(log);
}

static DWORD logreturn(const char *functionName, const char *fileName, int lineNumber, const char *resultstr, DWORD result)
{
	log(functionName, fileName, lineNumber, "Returning %s", resultstr);
	return result;
}

static string toHex(const vector<byte> &data)
{
	stringstream os;
	os << hex << setfill('0');
	for (const byte &i: data)
		os << setw(2) << static_cast<int>(i);
	return os.str();
}

static Result transfer(const vector<byte> &apdu, SCARDHANDLE card)
{
	vector<byte> data(1024, 0);
	DWORD size = DWORD(data.size());

	DWORD dwProtocol = 0;
	SCardStatus(card, nullptr, nullptr, nullptr, &dwProtocol, nullptr, nullptr);

	_log("> " + toHex(apdu));
	DWORD ret = SCardTransmit(card, dwProtocol == SCARD_PROTOCOL_T0 ? SCARD_PCI_T0 : SCARD_PCI_T1,
		apdu.data(), DWORD(apdu.size()), nullptr, data.data(), &size);
	if (ret != SCARD_S_SUCCESS)
		return{ 0, 0, vector<byte>() };

	Result result = { data[size - 2], data[size - 1], data };
	result.data.resize(size - 2);
	_log("< %02x%02x " + toHex(result.data), result.SW1, result.SW2);
	if (result.SW1 == 0x61)
	{
		Result result2 = transfer({ 0x00, 0xC0, 0x00, 0x00, result.SW2 }, card);
		result2.data.insert(result2.data.begin(), result.data.begin(), result.data.end());
		return result2;
	}
	return result;
}

static map<DRIVER_FEATURES, uint32_t> features(SCARDHANDLE card)
{
	map<DRIVER_FEATURES, uint32_t> result;
	DWORD size = 0;
	BYTE feature[256];
	LONG rv = SCardControl(card, SCARD_CTL_CODE(3400), nullptr, 0, feature, DWORD(sizeof(feature)), &size);
	if (rv != SCARD_S_SUCCESS)
		return result;
	for (BYTE *p = feature; DWORD(p - feature) < size;)
	{
		int tag = *p++, len = *p++, value = 0;
		for (int i = 0; i < len; ++i)
			value |= *p++ << 8 * i;
		result[DRIVER_FEATURES(tag)] = ntohl(value);
	}
	return result;
}

static Result transferCTL(const vector<byte> &apdu, bool verify, uint32_t lang, short minlen, SCARDHANDLE card)
{
	map<DRIVER_FEATURES, uint32_t> f = features(card);
	struct {
		uint16_t wLcdLayout;
		uint8_t bEntryValidationCondition;
		uint8_t bTimeOut2;
	} pin_properties = { 0, 0, 0 };
	DWORD size = sizeof(pin_properties);
	auto ioctl = f.find(FEATURE_IFD_PIN_PROPERTIES);
	if (ioctl != f.cend())
		SCardControl(card, ioctl->second, nullptr, 0, &pin_properties, size, &size);

#define SET(X) \
		X->bTimerOut = 30; \
		X->bTimerOut2 = 30; \
		X->bmFormatString = 0x02; \
		X->bmPINBlockString = 0x00; \
		X->bmPINLengthFormat = 0x00; \
		X->wPINMaxExtraDigit = (minlen << 8) + 12; \
		X->bEntryValidationCondition = 0x02; \
		X->wLangId = lang; \
		X->bTeoPrologue[0] = 0x00; \
		X->bTeoPrologue[1] = 0x00; \
		X->bTeoPrologue[2] = 0x00

	vector<byte> cmd;
	if (verify)
	{
		cmd.resize(sizeof(PIN_VERIFY_STRUCTURE) - 1);
		PIN_VERIFY_STRUCTURE *data = (PIN_VERIFY_STRUCTURE*)cmd.data();
		SET(data);
		data->bNumberMessage = pin_properties.wLcdLayout > 0 ? 0xFF : 0x00;
		data->bMsgIndex = 0x00;
		data->ulDataLength = uint32_t(apdu.size());
	}
	else
	{
		cmd.resize(sizeof(PIN_MODIFY_STRUCTURE) - 1);
		PIN_MODIFY_STRUCTURE *data = (PIN_MODIFY_STRUCTURE*)cmd.data();
		SET(data);
		data->bNumberMessage = pin_properties.wLcdLayout > 0 ? 0x03 : 0x00;
		data->bInsertionOffsetOld = 0x00;
		data->bInsertionOffsetNew = 0x00;
		data->bConfirmPIN = 0x03;
		data->bMsgIndex1 = 0x00;
		data->bMsgIndex2 = 0x01;
		data->bMsgIndex3 = 0x02;
		data->ulDataLength = uint32_t(apdu.size());
	}
	cmd.insert(cmd.cend(), apdu.cbegin(), apdu.cend());

	ioctl = f.find(verify ? FEATURE_VERIFY_PIN_START : FEATURE_MODIFY_PIN_START);
	if (ioctl == f.cend())
		ioctl = f.find(verify ? FEATURE_VERIFY_PIN_DIRECT : FEATURE_MODIFY_PIN_DIRECT);

	_log("> " + toHex(apdu));
	_log("CTL> " + toHex(cmd));
	vector<byte> data(255 + 3, 0);
	size = DWORD(data.size());
	DWORD err = SCardControl(card, ioctl->second, cmd.data(), DWORD(cmd.size()), LPVOID(data.data()), DWORD(data.size()), &size);
	if (err != SCARD_S_SUCCESS)
		return { 0, 0, vector<byte>() };

	ioctl = f.find(verify ? FEATURE_VERIFY_PIN_FINISH : FEATURE_MODIFY_PIN_FINISH);
	if (ioctl != f.cend())
	{
		size = DWORD(data.size());
		err = SCardControl(card, ioctl->second, nullptr, 0, LPVOID(data.data()), DWORD(data.size()), &size);
		if (err != SCARD_S_SUCCESS)
			return{ 0, 0, vector<byte>() };
	}

	Result result = { data[size - 2], data[size - 1], data };
	result.data.resize(size - 2);
	_log("< %02x%02x " + toHex(result.data), result.SW1, result.SW2);
	return result;
}

static PPUBKEYSTRUCT pubKeyRSAStruct(PCARD_DATA pCardData, PCCERT_CONTEXT cer, DWORD &sw, ALG_ID algID)
{
	PCRYPT_BIT_BLOB PublicKey = &cer->pCertInfo->SubjectPublicKeyInfo.PublicKey;
	CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB,
		PublicKey->pbData, PublicKey->cbData, 0, nullptr, &sw);
	PPUBKEYSTRUCT oh = PPUBKEYSTRUCT(pCardData->pfnCspAlloc(sw));
	if (!oh)
		return nullptr;
	CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB,
		PublicKey->pbData, PublicKey->cbData, 0, LPVOID(oh), &sw);
	oh->publickeystruc.aiKeyAlg = algID;
	return oh;
}

static bool isECDSAPubKey(PCCERT_CONTEXT cert)
{
	return strcmp(szOID_ECC_PUBLIC_KEY, cert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId) == 0;
}

static DWORD keySize(PCARD_DATA pCardData, PCCERT_CONTEXT cert)
{
	if (isECDSAPubKey(cert))
		return (cert->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData - 1) * 4;
	else
	{
		DWORD size = 2048;
		DWORD sw = 0;
		PPUBKEYSTRUCT oh = pubKeyRSAStruct(pCardData, cert, sw, 0);
		if (!oh)
			return size;
		size = oh->rsapubkey.bitlen;
		pCardData->pfnCspFree(oh);
		return size;
	}
}

static PBCRYPT_ECCKEY_BLOB pubKeyECStruct(PCARD_DATA pCardData, PCCERT_CONTEXT cert, DWORD &sw, bool ecdsa)
{
	PCRYPT_BIT_BLOB PublicKey = &cert->pCertInfo->SubjectPublicKeyInfo.PublicKey;
	sw = DWORD(sizeof(BCRYPT_ECCKEY_BLOB) + (PublicKey->cbData - 1));
	PBCRYPT_ECCKEY_BLOB oh = PBCRYPT_ECCKEY_BLOB(pCardData->pfnCspAlloc(sw));
	if (!oh)
		return nullptr;
	oh->cbKey = (PublicKey->cbData - 1) / 2;
	oh->dwMagic = ecdsa ? BCRYPT_ECDSA_PUBLIC_P384_MAGIC : BCRYPT_ECDH_PUBLIC_P384_MAGIC;
	CopyMemory(PBYTE(oh) + sizeof(BCRYPT_ECCKEY_BLOB), PublicKey->pbData + 1, PublicKey->cbData - 1);
	return oh;
}

static vector<byte> md5sum(const string &data)
{
	vector<byte> result(16, 0);
	BCRYPT_ALG_HANDLE hAlgorithm = 0;
	BCRYPT_HASH_HANDLE hHash = 0;
	if (BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_MD5_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0) ||
		BCryptCreateHash(hAlgorithm, &hHash, nullptr, 0, nullptr, 0, 0) ||
		BCryptHashData(hHash, PBYTE(data.c_str()), DWORD(data.size()), 0) ||
		BCryptFinishHash(hHash, result.data(), ULONG(result.size()), 0))
		result.clear();
	if (hHash)
		BCryptDestroyHash(hHash);
	if (hAlgorithm)
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	return result;
}

static void getMD5GUID(const string &data, PWCHAR guid)
{
	string result = toHex(md5sum(data));
	for (size_t i = 0; i < result.size(); ++i)
		guid[i] = result[i];
}

static map<uint8_t, vector<byte>> parseFCI(const vector<byte> &data)
{
	map<uint8_t, vector<byte>> result;
	for (vector<byte>::const_iterator i = data.cbegin(); i != data.cend(); ++i)
	{
		uint8_t tag(*i), size(*++i);
		result[tag] = size > 0 ? vector<byte>(i + 1, i + 1 + size) : vector<byte>();
		switch (tag)
		{
		case 0x6F:
		case 0x62:
		case 0x64:
		case 0xA1: continue;
		default: i += size; break;
		}
	}
	return result;
}

static bool isPinPad(PCARD_DATA pCardData)
{
	Files *files = (Files*)pCardData->pvVendorSpecific;
	if (!files->pinpadEnabled)
		return false;
	map<DRIVER_FEATURES, uint32_t> f = features(pCardData->hScard);
	return f.find(FEATURE_VERIFY_PIN_DIRECT) != f.cend() || f.find(FEATURE_VERIFY_PIN_START) != f.cend();
}

DWORD WINAPI CreateProgressBar(LPVOID lpParam)
{
	PEXTERNAL_INFO externalInfo = PEXTERNAL_INFO(lpParam);
	TASKDIALOGCONFIG config = { 0 };
	config.cbSize = sizeof(config);
	config.hwndParent = externalInfo->hwndParentWindow;
	config.hInstance = GetModuleHandle(nullptr);
	config.dwCommonButtons = TDCBF_CANCEL_BUTTON;
	config.pszMainIcon = TD_INFORMATION_ICON;
	config.dwFlags = TDF_EXPAND_FOOTER_AREA | TDF_SHOW_PROGRESS_BAR | TDF_CALLBACK_TIMER;
	config.lpCallbackData = LONG_PTR(externalInfo);
	config.pfCallback = [](HWND hwnd, UINT uNotification, WPARAM wParam, LPARAM lParam, LONG_PTR dwRefData) {
		PEXTERNAL_INFO externalInfo = PEXTERNAL_INFO(dwRefData);
		externalInfo->windowHandle = hwnd;
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
		case TDN_BUTTON_CLICKED:
			SendMessage(hwnd, WM_NCDESTROY, 0, 0);
			return S_FALSE;
		}
		return S_OK;
	};
	switch (PRIMARYLANGID(externalInfo->langId))
	{
	case LANG_ESTONIAN:
		config.pszMainInstruction = L"PIN Pad kaardilugeja";
		config.pszContent = L"Sisestage PIN";
		switch (externalInfo->pinId)
		{
		case AUTH_PIN_ID:
			config.pszContent = L"Palun sisestage autoriseerimise PIN (PIN1)";
			config.pszExpandedInformation = L"Valitud tegevuse jaoks on vaja kasutada isikutuvastuse sertifikaati. Sertifikaadi kasutamiseks sisesta PIN1 kaardilugeja sõrmistikult.";
			break;
		case SIGN_PIN_ID:
			config.pszContent = L"Palun sisestage digiallkirjastamise PIN (PIN2)";
			config.pszExpandedInformation = L"Valitud tegevuse jaoks on vaja kasutada allkirjastamise sertifikaati. Sertifikaadi kasutamiseks sisesta PIN2 kaardilugeja sõrmistikult.";
			break;
		default: break;
		}
		break;
	case LANG_RUSSIAN:
		config.pszMainInstruction = L"PIN Pad считыватель";
		config.pszContent = L"Введите PIN код";
		switch (externalInfo->pinId)
		{
		case AUTH_PIN_ID:
			config.pszContent = L"Введите код PIN для идентификации (PIN 1)";
			config.pszExpandedInformation = L"Данная операция требует сертификат идентификации. Для использования сертификата идентификации введите PIN1 с клавиатуры считывателя.";
			break;
		case SIGN_PIN_ID:
			config.pszContent = L"Введите код PIN для подписи (PIN 2)";
			config.pszExpandedInformation = L"Для данной операцин необходим сертификат подписи. Для использования сертификата подписи введите PIN2 с клавиатуры считывателя.";
			break;
		default: break;
		}
		break;
	default:
		config.pszMainInstruction = L"PIN Pad Reader";
		config.pszContent = L"Enter PIN code";
		switch (externalInfo->pinId)
		{
		case AUTH_PIN_ID:
			config.pszContent = L"Enter PIN for authentication (PIN 1)";
			config.pszExpandedInformation = L"Selected action requires authentication certificate. For using authentication certificate enter PIN1 at the reader.";
			break;
		case SIGN_PIN_ID:
			config.pszContent = L"Enter PIN for digital signature (PIN 2)";
			config.pszExpandedInformation = L"Selected action requires digital signature certificate. For using signature certificate enter PIN2 at the reader.";
			break;
		default: break;
		}
		break;
	}
	_log("Create Progress Dialog");
	DWORD result = 0;
	HMODULE h = LoadLibrary(L"comctl32.dll");
	if (!h)
		return result;
	typedef HRESULT (WINAPI *f_TaskDialogIndirect)(_In_ const TASKDIALOGCONFIG *pTaskConfig,
		_Out_opt_ int *pnButton, _Out_opt_ int *pnRadioButton, _Out_opt_ BOOL *pfVerificationFlagChecked);
	if (f_TaskDialogIndirect f = f_TaskDialogIndirect(GetProcAddress(h, "TaskDialogIndirect")))
		result = f(&config, nullptr, nullptr, nullptr);
	FreeLibrary(h);
	return result;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
#ifdef _WIN64
	_log("Loading esteidcm X64 version %s reason %u", FILE_VERSION_STR, ul_reason_for_call);
#else
	_log("Loading esteidcm X86 version %s reason %u", FILE_VERSION_STR, ul_reason_for_call);
#endif
	return TRUE;
}

DWORD WINAPI CardAcquireContext(__inout PCARD_DATA pCardData, __in DWORD dwFlags)
{
	if (!pCardData)
		RETURN(SCARD_E_INVALID_PARAMETER);
	_log("dwVersion=%u, name=%S, hScard=0x%08X, hSCardCtx=0x%08X", pCardData->dwVersion, pCardData->pwszCardName,
		pCardData->hScard, pCardData->hSCardCtx);
	if (pCardData->dwVersion < CARD_DATA_VERSION_SEVEN)
		RETURN(ERROR_REVISION_MISMATCH);
	if (dwFlags ||
		pCardData->cbAtr == 0 ||
		pCardData->cbAtr == 0xffffffff ||
		!pCardData->pbAtr ||
		!pCardData->pwszCardName ||
		!pCardData->pfnCspAlloc ||
		!pCardData->pfnCspReAlloc ||
		!pCardData->pfnCspFree)
		RETURN(SCARD_E_INVALID_PARAMETER);
	if (!pCardData->hScard)
		RETURN(SCARD_E_INVALID_HANDLE);

	static vector<vector<byte>> atrs{
		{ 0x3B, 0xFE, 0x18, 0x00, 0x00, 0x80, 0x31, 0xFE, 0x45, 0x45, 0x73, 0x74, 0x45, 0x49, 0x44, 0x20, 0x76, 0x65, 0x72, 0x20, 0x31, 0x2E, 0x30, 0xA8 }, /*ESTEID_V3_COLD_DEV1_ATR*/
		{ 0x3B, 0xFE, 0x18, 0x00, 0x00, 0x80, 0x31, 0xFE, 0x45, 0x80, 0x31, 0x80, 0x66, 0x40, 0x90, 0xA4, 0x56, 0x1B, 0x16, 0x83, 0x01, 0x90, 0x00, 0x86 }, /*ESTEID_V3_WARM_DEV1_ATR*/
		{ 0x3B, 0xFE, 0x18, 0x00, 0x00, 0x80, 0x31, 0xFE, 0x45, 0x80, 0x31, 0x80, 0x66, 0x40, 0x90, 0xA4, 0x16, 0x2A, 0x00, 0x83, 0x01, 0x90, 0x00, 0xE1 }, /*ESTEID_V3_WARM_DEV2_ATR*/
		{ 0x3B, 0xFE, 0x18, 0x00, 0x00, 0x80, 0x31, 0xFE, 0x45, 0x80, 0x31, 0x80, 0x66, 0x40, 0x90, 0xA4, 0x16, 0x2A, 0x00, 0x83, 0x0F, 0x90, 0x00, 0xEF }, /*ESTEID_V3_WARM_DEV3_ATR/ESTEID_V35_WARM_ATR*/
		{ 0x3B, 0xFA, 0x18, 0x00, 0x00, 0x80, 0x31, 0xFE, 0x45, 0xFE, 0x65, 0x49, 0x44, 0x20, 0x2F, 0x20, 0x50, 0x4B, 0x49, 0x03 }, /*ESTEID_V35_COLD_ATR*/
	};
	if (!any_of(atrs.cbegin(), atrs.cend(), [&](const vector<byte> &atr){
			return atr.size() == pCardData->cbAtr && equal(atr.cbegin(), atr.cend(), pCardData->pbAtr);
		}))
		RETURN(SCARD_E_UNKNOWN_CARD);

	Result data;
	if (!transfer({ 0x00, 0xA4, 0x00, 0x0C }, pCardData->hScard) ||
		!transfer({ 0x00, 0xA4, 0x01, 0x0C, 0x02, 0xEE, 0xEE }, pCardData->hScard) ||
		!transfer({ 0x00, 0xA4, 0x02, 0x0C, 0x02, 0x50, 0x44 }, pCardData->hScard) ||
		!(data = transfer({ 0x00, 0xB2, 0x08, 0x04, 0x00 }, pCardData->hScard)))
		RETURN(SCARD_E_FILE_NOT_FOUND);

	auto readCert = [](const vector<byte> &file, SCARDHANDLE card) {
		vector<byte> cert;
		Result data;
		if (!(data = transfer(file, card)))
			return cert;
		map<uint8_t, vector<byte>> fci = parseFCI(data.data);
		map<uint8_t, vector<byte>>::const_iterator found = fci.find(0x85);
		size_t size = found != fci.cend() ? found->second[0] << 8 | found->second[1] : 0x0600;
		while (cert.size() < size)
		{
			Result data = transfer({ 0x00, 0xB0, byte(cert.size() >> 8), byte(cert.size()), 0x00 }, card);
			if (!data)
				return cert;
			cert.insert(cert.end(), data.data.begin(), data.data.end());
		}
		return cert;
	};

	string cardid(data.data.cbegin(), data.data.cend());
	vector<byte> auth = readCert({ 0x00, 0xA4, 0x02, 0x00, 0x02, 0xAA, 0xCE }, pCardData->hScard);
	vector<byte> sign = readCert({ 0x00, 0xA4, 0x02, 0x00, 0x02, 0xDD, 0xCE }, pCardData->hScard);
	if (cardid.length() < 8 || cardid.length() > 9 || auth.empty() || sign.empty())
		RETURN(SCARD_E_FILE_NOT_FOUND);
	_log("cardid: " + cardid);

	Files *files = new Files;
	pCardData->pvVendorSpecific = files;
	if (!pCardData->pvVendorSpecific)
		RETURN(ERROR_NOT_ENOUGH_MEMORY);
	files->auth = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, auth.data(), DWORD(auth.size()));
	files->sign = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, sign.data(), DWORD(sign.size()));
	if (!files->auth || !files->sign)
		RETURN(ERROR_NOT_ENOUGH_MEMORY);
	ZeroMemory(files->cardid, sizeof(files->cardid));
	CopyMemory(files->cardid, cardid.c_str(), cardid.size());

	HKEY rootKey = nullptr;
	DWORD lpData = 0;
	DWORD lpSize = sizeof(lpData);
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\RIA\\minidriver", 0, KEY_READ, &rootKey) == ERROR_SUCCESS &&
		RegQueryValueEx(rootKey, L"disablepinpad", 0, nullptr, PBYTE(&lpData), &lpSize) == ERROR_SUCCESS &&
		lpData > 0)
	{
		files->pinpadEnabled = false;
		_log("Disabling pinpad by registry setting");
	}
	if (rootKey)
		RegCloseKey(rootKey);

	pCardData->dwVersion = CARD_DATA_VERSION_SEVEN;
	pCardData->pfnCardDeleteContext = CardDeleteContext;
	pCardData->pfnCardQueryCapabilities = CardQueryCapabilities;
	pCardData->pfnCardDeleteContainer = CardDeleteContainer;
	pCardData->pfnCardCreateContainer = CardCreateContainer;
	pCardData->pfnCardGetContainerInfo = CardGetContainerInfo;
	pCardData->pfnCardAuthenticatePin = CardAuthenticatePin;
	pCardData->pfnCardGetChallenge = CardGetChallenge;
	pCardData->pfnCardAuthenticateChallenge = CardAuthenticateChallenge;
	pCardData->pfnCardUnblockPin = CardUnblockPin;
	pCardData->pfnCardChangeAuthenticator = CardChangeAuthenticator;
	pCardData->pfnCardDeauthenticate = nullptr;
	pCardData->pfnCardCreateDirectory = CardCreateDirectory;
	pCardData->pfnCardDeleteDirectory = CardDeleteDirectory;
	pCardData->pvUnused3 = nullptr;
	pCardData->pvUnused4 = nullptr;
	pCardData->pfnCardCreateFile = CardCreateFile;
	pCardData->pfnCardReadFile = CardReadFile;
	pCardData->pfnCardWriteFile = CardWriteFile;
	pCardData->pfnCardDeleteFile = CardDeleteFile;
	pCardData->pfnCardEnumFiles = CardEnumFiles;
	pCardData->pfnCardGetFileInfo = CardGetFileInfo;
	pCardData->pfnCardQueryFreeSpace = CardQueryFreeSpace;
	pCardData->pfnCardQueryKeySizes = CardQueryKeySizes;

	pCardData->pfnCardSignData = CardSignData;
	pCardData->pfnCardRSADecrypt = CardRSADecrypt;
	pCardData->pfnCardConstructDHAgreement = isECDSAPubKey(files->auth) ? CardConstructDHAgreement : nullptr;

	pCardData->pfnCardDeriveKey = isECDSAPubKey(files->auth) ? CardDeriveKey : nullptr;
	pCardData->pfnCardDestroyDHAgreement = isECDSAPubKey(files->auth) ? CardDestroyDHAgreement : nullptr;
	pCardData->pfnCspGetDHAgreement = nullptr;

	pCardData->pfnCardGetChallengeEx = CardGetChallengeEx;
	pCardData->pfnCardAuthenticateEx = CardAuthenticateEx;
	pCardData->pfnCardChangeAuthenticatorEx = CardChangeAuthenticatorEx;
	pCardData->pfnCardDeauthenticateEx = CardDeauthenticateEx;
	pCardData->pfnCardGetContainerProperty = CardGetContainerProperty;
	pCardData->pfnCardSetContainerProperty = CardSetContainerProperty;
	pCardData->pfnCardGetProperty = CardGetProperty;
	pCardData->pfnCardSetProperty = CardSetProperty;

	//pCardData->pfnCspUnpadData = CspUnpadData;
	pCardData->pfnMDImportSessionKey = MDImportSessionKey;
	pCardData->pfnMDEncryptData = MDEncryptData;
	pCardData->pfnCardImportSessionKey = CardImportSessionKey;
	pCardData->pfnCardGetSharedKeyHandle = CardGetSharedKeyHandle;
	pCardData->pfnCardGetAlgorithmProperty = CardGetAlgorithmProperty;
	pCardData->pfnCardGetKeyProperty = CardGetKeyProperty;
	pCardData->pfnCardSetKeyProperty = CardSetKeyProperty;
	pCardData->pfnCardDestroyKey = CardDestroyKey;
	pCardData->pfnCardProcessEncryptedData = CardProcessEncryptedData;
	pCardData->pfnCardCreateContainerEx = CardCreateContainerEx;
	RETURN(NO_ERROR);
}

DWORD WINAPI CardDeleteContext(__inout PCARD_DATA pCardData)
{
	if (!pCardData)
		RETURN(SCARD_E_INVALID_PARAMETER);
	if (Files *files = (Files*)pCardData->pvVendorSpecific)
	{
		if (files->auth) CertFreeCertificateContext(files->auth);
		if (files->sign) CertFreeCertificateContext(files->sign);
		delete files;
	}
	RETURN(NO_ERROR);
}

DWORD WINAPI CardGetContainerProperty(__in PCARD_DATA pCardData, __in BYTE bContainerIndex, __in LPCWSTR wszProperty,
	__out_bcount_part_opt(cbData, *pdwDataLen) PBYTE pbData, __in DWORD cbData, __out PDWORD pdwDataLen, __in DWORD dwFlags)
{
	if (!pCardData)
		RETURN(SCARD_E_INVALID_PARAMETER);
	_log("bContainerIndex=%u, wszProperty=%S, cbData=%u, dwFlags=0x%08X", bContainerIndex, wszProperty, cbData, dwFlags);
	if (!wszProperty || dwFlags || !pbData || !pdwDataLen)
		RETURN(SCARD_E_INVALID_PARAMETER);

	if (wcscmp(CCP_CONTAINER_INFO, wszProperty) == 0)
	{
		PCONTAINER_INFO p = PCONTAINER_INFO(pbData);
		if (pdwDataLen)
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p))
			RETURN(ERROR_INSUFFICIENT_BUFFER);
		return CardGetContainerInfo(pCardData, bContainerIndex, 0, p);
	}
	if (wcscmp(CCP_PIN_IDENTIFIER, wszProperty) == 0)
	{
		PPIN_ID p = PPIN_ID(pbData);
		if (pdwDataLen)
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p))
			RETURN(ERROR_INSUFFICIENT_BUFFER);
		switch (bContainerIndex)
		{
		case AUTH_CONTAINER_INDEX: *p = AUTH_PIN_ID; break;
		case SIGN_CONTAINER_INDEX: *p = SIGN_PIN_ID; break;
		default: RETURN(SCARD_E_NO_KEY_CONTAINER);
		}
		RETURN(NO_ERROR);
	}
	RETURN(SCARD_E_INVALID_PARAMETER);
}

DWORD WINAPI CardGetProperty(__in PCARD_DATA pCardData, __in LPCWSTR wszProperty,
	__out_bcount_part_opt(cbData, *pdwDataLen) PBYTE pbData, __in DWORD cbData, __out PDWORD pdwDataLen, __in DWORD dwFlags)
{
	_log("wszProperty=%S, cbData=%u, dwFlags=%u", wszProperty, cbData, dwFlags);
	if (!pCardData || !wszProperty || !pbData || !pdwDataLen)
		RETURN(SCARD_E_INVALID_PARAMETER);

	if (wcscmp(CP_CARD_FREE_SPACE, wszProperty) == 0)
	{
		PCARD_FREE_SPACE_INFO p = PCARD_FREE_SPACE_INFO(pbData);
		if (pdwDataLen)
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p) - sizeof(DWORD)) // Ver 0 = 12, 1 = 16
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
		if (dwFlags)
			RETURN(SCARD_E_INVALID_PARAMETER);
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
		if (dwFlags)
			RETURN(SCARD_E_INVALID_PARAMETER);
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
		if (dwFlags)
			RETURN(SCARD_E_INVALID_PARAMETER);
		PDWORD p = PDWORD(pbData);
		if (pdwDataLen)
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p))
			RETURN(SCARD_E_INSUFFICIENT_BUFFER);
		*p = 0;
		RETURN(NO_ERROR);
	}
	if (wcscmp(CP_CARD_GUID, wszProperty) == 0 ||
		wcscmp(CP_CARD_SERIAL_NO, wszProperty) == 0)
	{
		if (dwFlags)
			RETURN(SCARD_E_INVALID_PARAMETER);
		Files *files = (Files *)pCardData->pvVendorSpecific;
		if (pdwDataLen)
			*pdwDataLen = sizeof(files->cardid);
		if (cbData < sizeof(files->cardid))
			RETURN(SCARD_E_INSUFFICIENT_BUFFER);
		CopyMemory(pbData, files->cardid, sizeof(files->cardid));
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
		p->dwFlags = 0;
		p->dwChangePermission = 0;// CREATE_PIN_SET(dwFlags);
		p->dwUnblockPermission = 0; // dwFlags == PUKK_PIN_ID ? CREATE_PIN_SET(PUKK_PIN_ID) : 0;
		p->PinType = isPinPad(pCardData) ? ExternalPinType : AlphaNumericPinType;
		p->PinCachePolicy.dwVersion = PIN_CACHE_POLICY_CURRENT_VERSION;
		p->PinCachePolicy.dwPinCachePolicyInfo = 0;
		p->PinCachePolicy.PinCachePolicyType = dwFlags == AUTH_PIN_ID ? PinCacheNormal : PinCacheNone;
		switch (dwFlags)
		{
		case AUTH_PIN_ID: p->PinPurpose = AuthenticationPin; break;
		case SIGN_PIN_ID: p->PinPurpose = DigitalSignaturePin; break;
		//case PUKK_PIN_ID: p->PinPurpose = UnblockOnlyPin; break;
		default: RETURN(SCARD_E_INVALID_PARAMETER);
		}
		RETURN(NO_ERROR);
	}
	if (wcscmp(CP_CARD_LIST_PINS, wszProperty) == 0)
	{
		if (dwFlags)
			RETURN(SCARD_E_INVALID_PARAMETER);
		PPIN_SET p = PPIN_SET(pbData);
		if (pdwDataLen)
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p))
			RETURN(SCARD_E_INSUFFICIENT_BUFFER);
		SET_PIN(*p, AUTH_PIN_ID);
		SET_PIN(*p, SIGN_PIN_ID);
		//SET_PIN(*p, PUKK_PIN_ID);
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
		*p = CARD_PADDING_NONE | CARD_PADDING_PKCS1;
		RETURN(NO_ERROR);
	}
	RETURN(SCARD_E_UNSUPPORTED_FEATURE);
}

DWORD WINAPI CardSetProperty(__in PCARD_DATA pCardData, __in LPCWSTR wszProperty, __in_bcount(cbDataLen) PBYTE pbData,
	__in DWORD cbDataLen, __in DWORD dwFlags)
{
	if (!pCardData || !wszProperty)
		RETURN(SCARD_E_INVALID_PARAMETER);
	_log("wszProperty=%S, cbDataLen=%u, dwFlags=%u", wszProperty, cbDataLen, dwFlags);

	if (wcscmp(CP_PIN_CONTEXT_STRING, wszProperty) == 0)
		RETURN(NO_ERROR);
	if (!pbData || !cbDataLen)
		RETURN(SCARD_E_INVALID_PARAMETER);
	if (wcscmp(CP_CARD_CACHE_MODE, wszProperty) == 0 ||
		wcscmp(CP_SUPPORTS_WIN_X509_ENROLLMENT, wszProperty) == 0 ||
		wcscmp(CP_CARD_GUID, wszProperty) == 0 ||
		wcscmp(CP_CARD_SERIAL_NO, wszProperty) == 0 ||
		wcscmp(CP_CARD_PIN_STRENGTH_VERIFY, wszProperty) == 0 ||
		wcscmp(CP_CARD_PIN_INFO, wszProperty) == 0)
		RETURN(SCARD_W_SECURITY_VIOLATION);
	if (wcscmp(CP_PARENT_WINDOW, wszProperty) == 0)
	{
		if (dwFlags)
			RETURN(SCARD_E_INVALID_PARAMETER);
		if (cbDataLen != sizeof(pCardData))
			RETURN(SCARD_E_INVALID_PARAMETER);
		HWND cp = *((HWND *) pbData);
		if (cp != 0 && !IsWindow(cp))
			RETURN(SCARD_E_INVALID_PARAMETER);
		Files *files = (Files*)pCardData->pvVendorSpecific;
		files->cp = cp;
		RETURN(NO_ERROR);
	}
	RETURN(SCARD_E_INVALID_PARAMETER);
}


DWORD WINAPI CardQueryCapabilities(__in PCARD_DATA pCardData, __inout PCARD_CAPABILITIES pCardCapabilities)
{
	if (!pCardData || !pCardCapabilities)
		RETURN(SCARD_E_INVALID_PARAMETER);
	if (pCardCapabilities->dwVersion != CARD_CAPABILITIES_CURRENT_VERSION && pCardCapabilities->dwVersion != 0)
		RETURN(ERROR_REVISION_MISMATCH);
	pCardCapabilities->dwVersion = CARD_CAPABILITIES_CURRENT_VERSION;
	_log("dwVersion=%u, fKeyGen=%u, fCertificateCompression=%u", pCardCapabilities->dwVersion,
		pCardCapabilities->fKeyGen, pCardCapabilities->fCertificateCompression);
	pCardCapabilities->fCertificateCompression = TRUE;
	pCardCapabilities->fKeyGen = FALSE;
	RETURN(NO_ERROR);
}

DWORD WINAPI CardGetContainerInfo(__in PCARD_DATA pCardData, __in BYTE bContainerIndex, __in DWORD dwFlags, __inout PCONTAINER_INFO pContainerInfo)
{
	if (!pCardData || !pContainerInfo || dwFlags)
		RETURN(SCARD_E_INVALID_PARAMETER);
	if (pContainerInfo->dwVersion < 0 || pContainerInfo->dwVersion > CONTAINER_INFO_CURRENT_VERSION)
		RETURN(ERROR_REVISION_MISMATCH);
	_log("bContainerIndex=%u, dwFlags=0x%08X, dwVersion=%u", bContainerIndex, dwFlags, pContainerInfo->dwVersion);

	pContainerInfo->dwVersion = CONTAINER_INFO_CURRENT_VERSION;
	pContainerInfo->cbSigPublicKey = 0;
	pContainerInfo->pbSigPublicKey = nullptr;
	pContainerInfo->cbKeyExPublicKey = 0;
	pContainerInfo->pbKeyExPublicKey = nullptr;
	Files *files = (Files*)pCardData->pvVendorSpecific;
	switch (bContainerIndex)
	{
	case AUTH_CONTAINER_INDEX:
	{
		pContainerInfo->pbKeyExPublicKey = isECDSAPubKey(files->auth) ?
			PBYTE(pubKeyECStruct(pCardData, files->auth, pContainerInfo->cbKeyExPublicKey, false)) :
			PBYTE(pubKeyRSAStruct(pCardData, files->auth, pContainerInfo->cbKeyExPublicKey, CALG_RSA_KEYX));
		if (!pContainerInfo->pbKeyExPublicKey)
			RETURN(ERROR_NOT_ENOUGH_MEMORY);
		break;
	}
	case SIGN_CONTAINER_INDEX:
	{
		pContainerInfo->pbSigPublicKey = isECDSAPubKey(files->sign) ?
			PBYTE(pubKeyECStruct(pCardData, files->sign, pContainerInfo->cbSigPublicKey, true)) :
			PBYTE(pubKeyRSAStruct(pCardData, files->sign, pContainerInfo->cbSigPublicKey, CALG_RSA_SIGN));
		if (!pContainerInfo->pbSigPublicKey)
			RETURN(ERROR_NOT_ENOUGH_MEMORY);
		break;
	}
	default:
		RETURN(SCARD_E_NO_KEY_CONTAINER);
	}
	RETURN(NO_ERROR);
}

DWORD WINAPI CardAuthenticatePin(__in PCARD_DATA pCardData, __in LPWSTR pwszUserId, __in_bcount(cbPin) PBYTE pbPin, __in DWORD cbPin, __out_opt PDWORD pcAttemptsRemaining)
{
	_log("pwszUserId=%S", pwszUserId);
	if (!pwszUserId || wcscmp(pwszUserId, wszCARD_USER_USER) != 0 || !pbPin)
		RETURN(SCARD_E_INVALID_PARAMETER);
	return CardAuthenticateEx(pCardData, AUTH_PIN_ID, CARD_PIN_SILENT_CONTEXT, pbPin, cbPin, nullptr, nullptr, pcAttemptsRemaining);
}

DWORD WINAPI CardAuthenticateEx(__in PCARD_DATA pCardData, __in PIN_ID PinId, __in DWORD dwFlags, __in_bcount(cbPinData) PBYTE pbPinData, __in DWORD cbPinData,
	__deref_opt_out_bcount(*pcbSessionPin) PBYTE *ppbSessionPin, __out_opt PDWORD pcbSessionPin, __out_opt PDWORD pcAttemptsRemaining)
{
	_log("PinId=%u, dwFlags=0x%08X, cbPinData=%u, Attempts %s", PinId, dwFlags, cbPinData, pcAttemptsRemaining ? "YES" : "NO");
	if (!pCardData || (PinId != AUTH_PIN_ID && PinId != SIGN_PIN_ID))
		RETURN(SCARD_E_INVALID_PARAMETER);

	Result data;
	BYTE remaining = (!transfer({ 0x00, 0xA4, 0x00, 0x0C, 0x00 }, pCardData->hScard) ||
		!transfer({ 0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x16 }, pCardData->hScard) ||
		!(data = transfer({ 0x00, 0xB2, byte(PinId == AUTH_PIN_ID ? 1 : 2), 0x04, 0x00 }, pCardData->hScard))) ? 3 : data.data[5];

	if (!isPinPad(pCardData))
	{
		_log("Secure connection is not used");
		if (dwFlags == CARD_AUTHENTICATE_GENERATE_SESSION_PIN ||
			dwFlags == CARD_AUTHENTICATE_SESSION_PIN)
			RETURN(SCARD_E_UNSUPPORTED_FEATURE);
		if (dwFlags && dwFlags != CARD_PIN_SILENT_CONTEXT)
			RETURN(SCARD_E_INVALID_PARAMETER);
		if (!pbPinData)
			RETURN(SCARD_E_INVALID_PARAMETER);
		if ((PinId == AUTH_PIN_ID && cbPinData < 4) ||
			(PinId == SIGN_PIN_ID && cbPinData < 5) ||
			cbPinData > 12 ||
			!std::all_of(pbPinData, pbPinData + cbPinData, std::isdigit))
			RETURN(SCARD_W_WRONG_CHV);
		if (remaining == 0)
			RETURN(SCARD_W_CHV_BLOCKED);
		vector<byte> cmd{ 0x00, 0x20, 0x00, byte(PinId == AUTH_PIN_ID ? 0x01 : 0x02), byte(cbPinData) };
		cmd.insert(cmd.end(), pbPinData, pbPinData + cbPinData);
		Result result = transfer(cmd, pCardData->hScard);
		switch ((uint8_t(result.SW1) << 8) + uint8_t(result.SW2))
		{
		case 0x9000: RETURN(NO_ERROR);
		case 0x63C0: //pin retry count 0
			if (pcAttemptsRemaining)
				*pcAttemptsRemaining = 0;
			RETURN(SCARD_W_CHV_BLOCKED);
		case 0x63C1: // Validate error, 1 tries left
		case 0x63C2: // Validate error, 2 tries left
		case 0x63C3: // Validate error, 3 tries left
			--remaining;
			if (pcAttemptsRemaining)
				*pcAttemptsRemaining = remaining;
			RETURN(SCARD_W_WRONG_CHV);
		default:
			RETURN(SCARD_E_INVALID_PARAMETER);
		}
	}
	else
	{
		_log("Using secure connection to card");
		if (dwFlags != CARD_AUTHENTICATE_GENERATE_SESSION_PIN && dwFlags != CARD_AUTHENTICATE_SESSION_PIN && dwFlags != 0)
			RETURN(SCARD_E_INVALID_PARAMETER);

		Files *files = (Files*)pCardData->pvVendorSpecific;
		PWCHAR label = PinId == AUTH_PIN_ID ? L"Authentication error" : L"Signing error";
		if (remaining == 0)
		{
			MessageBox(files->cp, L"PIN code blocked", label, MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
			RETURN(SCARD_W_CHV_BLOCKED);
		}

		EXTERNAL_INFO externalInfo;
		externalInfo.hwndParentWindow = files->cp;
		externalInfo.windowHandle = 0;
		externalInfo.pinId = PinId;
		externalInfo.langId = GetUserDefaultUILanguage();

		while (remaining)
		{
			_log("Authenticating with PinPAD");
			HANDLE thread = CreateThread(nullptr, 0, CreateProgressBar, &externalInfo, 0, nullptr);
			Result result = transferCTL({ 0x00, 0x20, 0x00, byte(PinId == AUTH_PIN_ID ? 1 : 2), 0x00 },
				true, externalInfo.langId, PinId == AUTH_PIN_ID ? 4 : 5, pCardData->hScard);
			SendMessage(externalInfo.windowHandle, WM_NCDESTROY, 0, 0);
			WaitForSingleObject(thread, INFINITE);
			CloseHandle(thread);
			switch ((uint8_t(result.SW1) << 8) + uint8_t(result.SW2))
			{
			case 0x9000: RETURN(NO_ERROR);
			case 0x63C0: //pin retry count 0
				if (PinId == AUTH_PIN_ID)
					MessageBox(files->cp, L"PIN1 blocked.", label, MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
				else
					MessageBox(files->cp, L"PIN2 blocked.", label, MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
				RETURN(SCARD_W_CHV_BLOCKED);
			case 0x63C1: // Validate error, 1 tries left
			case 0x63C2: // Validate error, 2 tries left
			case 0x63C3: // Validate error, 3 tries left
			{
				remaining--;
				WCHAR wcBuffer[512];
				wsprintf(wcBuffer, L"A wrong PIN was presented to the card: %i retries left.", remaining);
				MessageBox(files->cp, wcBuffer, label, MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
				break;
			}
			case 0x6400: // Timeout (SCM)
			case 0x6401: // Cancel (OK, SCM)
				RETURN(SCARD_W_CANCELLED_BY_USER);
			case 0x6403:
				MessageBox(files->cp, PinId == AUTH_PIN_ID ?
					L"PIN1 length has to be between 4 and 12" :
					L"PIN2 length has to be between 5 and 12",
					label, MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
				break;
			default:
				MessageBox(files->cp, L"Unexpected input.", label, MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
				RETURN(SCARD_E_INVALID_PARAMETER);
			}
		}
	}
	RETURN(NO_ERROR);
}

DWORD WINAPI CardEnumFiles(__in PCARD_DATA pCardData, __in_opt LPSTR pszDirectoryName, __deref_out_ecount(*pdwcbFileName) LPSTR *pmszFileNames, __out LPDWORD pdwcbFileName, __in DWORD dwFlags)
{
	if (!pCardData || !pmszFileNames || !pdwcbFileName || dwFlags)
		RETURN(SCARD_E_INVALID_PARAMETER);
	if (!pszDirectoryName || !strlen(pszDirectoryName))
	{
		static const char root_files[] = "cardapps\0" szCACHE_FILE "\0" szCARD_IDENTIFIER_FILE "\0\0";
		*pdwcbFileName = sizeof(root_files) - 1;
		*pmszFileNames = LPSTR(pCardData->pfnCspAlloc(*pdwcbFileName));
		if (!*pmszFileNames)
			RETURN(ERROR_NOT_ENOUGH_MEMORY);
		CopyMemory(*pmszFileNames, root_files, *pdwcbFileName);
		RETURN(NO_ERROR);
	}
	if (!_strcmpi(pszDirectoryName, szBASE_CSP_DIR))
	{
		static const char mscp_files[] = szCONTAINER_MAP_FILE "\0" szUSER_KEYEXCHANGE_CERT_PREFIX "00\0" szUSER_SIGNATURE_CERT_PREFIX "01\0\0";
		*pdwcbFileName = sizeof(mscp_files) - 1;
		*pmszFileNames = LPSTR(pCardData->pfnCspAlloc(*pdwcbFileName));
		if (!*pmszFileNames)
			RETURN(ERROR_NOT_ENOUGH_MEMORY);
		CopyMemory(*pmszFileNames, mscp_files, *pdwcbFileName);
		RETURN(NO_ERROR);
	}
	RETURN(SCARD_E_DIR_NOT_FOUND);
}

DWORD WINAPI CardGetFileInfo(__in PCARD_DATA pCardData, __in_opt LPSTR pszDirectoryName, __in LPSTR pszFileName, __inout PCARD_FILE_INFO pCardFileInfo)
{
	_log("pszDirectoryName='%s', pszFileName='%s'", pszDirectoryName, pszFileName);
	if (!pCardData || !pszFileName || !strlen(pszFileName) || !pCardFileInfo)
		RETURN(SCARD_E_INVALID_PARAMETER);

	if (pCardFileInfo->dwVersion != CARD_FILE_INFO_CURRENT_VERSION && pCardFileInfo->dwVersion != 0)
		RETURN(ERROR_REVISION_MISMATCH);

	pCardFileInfo->AccessCondition = EveryoneReadUserWriteAc;
	if (!pszDirectoryName || !strlen(pszDirectoryName))
	{
		if (!_strcmpi(pszFileName, "cardapps"))
		{
			pCardFileInfo->cbFileSize = sizeof(cardapps);
			RETURN(NO_ERROR);
		}
		if (!_strcmpi(pszFileName, szCACHE_FILE))
		{
			pCardFileInfo->cbFileSize = sizeof(cardcf);
			RETURN(NO_ERROR);
		}
		if (!_strcmpi(pszFileName, szCARD_IDENTIFIER_FILE))
		{
			Files *files = (Files*)pCardData->pvVendorSpecific;
			pCardFileInfo->cbFileSize = sizeof(files->cardid);
			RETURN(NO_ERROR);
		}
		RETURN(SCARD_E_FILE_NOT_FOUND);
	}
	if (!_strcmpi(pszDirectoryName, szBASE_CSP_DIR))
	{
		if (!_strcmpi(pszFileName, szCONTAINER_MAP_FILE))
		{
			pCardFileInfo->cbFileSize = sizeof(CONTAINER_MAP_RECORD) * 2;
			RETURN(NO_ERROR);
		}
		RETURN(SCARD_E_FILE_NOT_FOUND);
	}
	RETURN(SCARD_E_DIR_NOT_FOUND);
}

DWORD WINAPI CardReadFile(__in PCARD_DATA pCardData, __in_opt LPSTR pszDirectoryName, __in LPSTR pszFileName, __in DWORD dwFlags, __deref_out_bcount_opt(*pcbData) PBYTE *ppbData, __out PDWORD pcbData)
{
	_log("pszDirectoryName=%s, pszFileName=%s, dwFlags=0x%08X", pszDirectoryName, pszFileName, dwFlags);
	if (!pCardData || !pszFileName || !strlen(pszFileName) || !ppbData || !pcbData || dwFlags)
		RETURN(SCARD_E_INVALID_PARAMETER);

	Files *files = (Files*)pCardData->pvVendorSpecific;
	if (!_strcmpi(pszFileName, szCACHE_FILE))
	{
		*pcbData = sizeof(cardcf);
		*ppbData = PBYTE(pCardData->pfnCspAlloc(*pcbData));
		if (!*ppbData)
			RETURN(ERROR_NOT_ENOUGH_MEMORY);
		CopyMemory(*ppbData, cardcf, *pcbData);
		RETURN(NO_ERROR);
	}
	if (!_strcmpi(pszFileName, szCARD_IDENTIFIER_FILE))
	{
		*pcbData = sizeof(files->cardid);
		*ppbData = PBYTE(pCardData->pfnCspAlloc(*pcbData));
		if (!*ppbData)
			RETURN(ERROR_NOT_ENOUGH_MEMORY);
		CopyMemory(*ppbData, files->cardid, *pcbData);
		RETURN(NO_ERROR);
	}
	if (pszDirectoryName)
	{
		if (_strcmpi(pszDirectoryName, szBASE_CSP_DIR))
			RETURN(SCARD_E_DIR_NOT_FOUND);
		if (!_strcmpi(pszFileName, szCONTAINER_MAP_FILE))
		{
			*pcbData = sizeof(CONTAINER_MAP_RECORD) * 2;
			*ppbData = PBYTE(pCardData->pfnCspAlloc(*pcbData));
			if (!*ppbData)
				RETURN(ERROR_NOT_ENOUGH_MEMORY);
			ZeroMemory(*ppbData, *pcbData);

			PCONTAINER_MAP_RECORD c1 = PCONTAINER_MAP_RECORD(*ppbData);
			getMD5GUID(string((char*)files->cardid) + "_AUT", c1->wszGuid);
			c1->bFlags = CONTAINER_MAP_VALID_CONTAINER | CONTAINER_MAP_DEFAULT_CONTAINER;
			c1->wKeyExchangeKeySizeBits = WORD(keySize(pCardData, files->auth));

			PCONTAINER_MAP_RECORD c2 = PCONTAINER_MAP_RECORD(*ppbData + sizeof(CONTAINER_MAP_RECORD));
			getMD5GUID(string((char*)files->cardid) + "_SIG", c2->wszGuid);
			c2->bFlags = CONTAINER_MAP_VALID_CONTAINER;
			c2->wSigKeySizeBits = WORD(keySize(pCardData, files->sign));

			RETURN(NO_ERROR);
		}
		if (!_strcmpi(pszFileName, szUSER_KEYEXCHANGE_CERT_PREFIX "00"))
		{
			*pcbData = files->auth->cbCertEncoded;
			*ppbData = PBYTE(pCardData->pfnCspAlloc(*pcbData));
			if (!*ppbData)
				RETURN(ERROR_NOT_ENOUGH_MEMORY);
			CopyMemory(*ppbData, files->auth->pbCertEncoded, *pcbData);
			RETURN(NO_ERROR);
		}
		if (!_strcmpi(pszFileName, szUSER_SIGNATURE_CERT_PREFIX "01"))
		{
			*pcbData = files->sign->cbCertEncoded;
			*ppbData = PBYTE(pCardData->pfnCspAlloc(*pcbData));
			if (!*ppbData)
				RETURN(ERROR_NOT_ENOUGH_MEMORY);
			CopyMemory(*ppbData, files->sign->pbCertEncoded, *pcbData);
			RETURN(NO_ERROR);
		}
	}
	RETURN(SCARD_E_FILE_NOT_FOUND);
}

DWORD WINAPI CardQueryFreeSpace(__in PCARD_DATA pCardData, __in DWORD dwFlags, __inout PCARD_FREE_SPACE_INFO pCardFreeSpaceInfo)
{
	if (!pCardData || !pCardFreeSpaceInfo || dwFlags)
		RETURN(SCARD_E_INVALID_PARAMETER);
	if (pCardFreeSpaceInfo->dwVersion != CARD_FREE_SPACE_INFO_CURRENT_VERSION && pCardFreeSpaceInfo->dwVersion != 0)
		RETURN(ERROR_REVISION_MISMATCH);
	pCardFreeSpaceInfo->dwVersion = CARD_FREE_SPACE_INFO_CURRENT_VERSION;
	pCardFreeSpaceInfo->dwBytesAvailable = 0;
	pCardFreeSpaceInfo->dwKeyContainersAvailable = 0;
	pCardFreeSpaceInfo->dwMaxKeyContainers = 2;
	RETURN(NO_ERROR);
}

DWORD WINAPI CardQueryKeySizes(__in PCARD_DATA pCardData, __in DWORD dwKeySpec, __in DWORD dwFlags, __inout PCARD_KEY_SIZES pKeySizes)
{
	if (!pCardData || !pKeySizes || dwFlags)
		RETURN(SCARD_E_INVALID_PARAMETER);
	_log("dwKeySpec=%u, dwVersion=%u", dwKeySpec, pKeySizes->dwVersion);
	if (pKeySizes->dwVersion > CARD_KEY_SIZES_CURRENT_VERSION)
		RETURN(ERROR_REVISION_MISMATCH);
	Files *files = (Files*)pCardData->pvVendorSpecific;
	switch (dwKeySpec)
	{
	case AT_SIGNATURE:
	case AT_KEYEXCHANGE:
		pKeySizes->dwDefaultBitlen = pKeySizes->dwMaximumBitlen = pKeySizes->dwMinimumBitlen =
			keySize(pCardData, dwKeySpec == AT_KEYEXCHANGE ? files->auth : files->sign);
		pKeySizes->dwIncrementalBitlen = 0;
		break;
	case AT_ECDSA_P384:
	case AT_ECDHE_P384:
		pKeySizes->dwDefaultBitlen = pKeySizes->dwMaximumBitlen = pKeySizes->dwMinimumBitlen =
			keySize(pCardData, files->auth);
		pKeySizes->dwIncrementalBitlen = 1;
		break;
	default:
		RETURN(SCARD_E_INVALID_PARAMETER);
	}
	RETURN(NO_ERROR);
}

DWORD WINAPI CardRSADecrypt(__in PCARD_DATA pCardData, __inout PCARD_RSA_DECRYPT_INFO pInfo)
{
	if (!pCardData || !pInfo)
		RETURN(SCARD_E_INVALID_PARAMETER);
	_log("dwVersion=%u, bContainerIndex=%u, dwKeySpec=%u, cbData=%u", pInfo->dwVersion, pInfo->bContainerIndex, pInfo->dwKeySpec, pInfo->cbData);
	if (pInfo->dwKeySpec != AT_KEYEXCHANGE || !pInfo->pbData)
		RETURN(SCARD_E_INVALID_PARAMETER);
	if (pInfo->dwVersion < CARD_RSA_KEY_DECRYPT_INFO_VERSION_ONE || pInfo->dwVersion > CARD_RSA_KEY_DECRYPT_INFO_VERSION_TWO)
		RETURN(ERROR_REVISION_MISMATCH);
	if (pInfo->bContainerIndex != AUTH_CONTAINER_INDEX && pInfo->bContainerIndex != SIGN_CONTAINER_INDEX)
		RETURN(SCARD_E_NO_KEY_CONTAINER);

	Files *files = (Files*)pCardData->pvVendorSpecific;
	unsigned int key_size = keySize(pCardData, files->auth);
	if (pInfo->cbData < key_size / 8)
		RETURN(SCARD_E_INSUFFICIENT_BUFFER);

	vector<byte> data(pInfo->pbData, pInfo->pbData + pInfo->cbData);
	_log("Data to decrypt: %s with size: %i", toHex(data).c_str(), data.size());
	reverse(data.begin(), data.end());

	vector<byte> decrypt_chain1 = { 0x10, 0x2A, 0x80, 0x86, 0xFF, 0x00 };
	vector<byte> decrypt_chain2 = { 0x00, 0x2A, 0x80, 0x86, 0x02 };
	decrypt_chain1.insert(decrypt_chain1.end(), data.cbegin(), data.cend() - 2);
	decrypt_chain2.insert(decrypt_chain2.end(), data.cend() - 2, data.cend());
	if (!transfer({ 0x00, 0xA4, 0x00, 0x0C }, pCardData->hScard) ||
		!transfer({ 0x00, 0xA4, 0x01, 0x0C, 0x02, 0xEE, 0xEE }, pCardData->hScard) ||
		!transfer({ 0x00, 0x22, 0xF3, 0x06 }, pCardData->hScard) ||
		!transfer({ 0x00, 0x22, 0x41, 0xB8, 0x02, 0x83, 0x00 }, pCardData->hScard) ||
		!transfer(decrypt_chain1, pCardData->hScard))
		RETURN(SCARD_W_SECURITY_VIOLATION);

	Result result = transfer(decrypt_chain2, pCardData->hScard);
	if ((result.SW1 == 0x69 && result.SW2 == 0x88) ||
		(result.SW1 == 0x64 && result.SW2 == 0))
		RETURN(NTE_BAD_DATA);
	if (!result)
		RETURN(SCARD_E_UNEXPECTED);

	reverse(result.data.begin(), result.data.end());
	vector<byte> pB(result.data.begin(), result.data.end());
	if (pInfo->dwVersion == CARD_RSA_KEY_DECRYPT_INFO_VERSION_TWO && pInfo->dwPaddingType == CARD_PADDING_NONE)
	{
		srand((unsigned int)time(0));
		pB.push_back(0);
		//our data comes out in wrong order and needs to be repadded
		for (int psLen = int(key_size / 8 - result.data.size() - 3); psLen > 0; psLen--)
		{
			BYTE br;
			while(0 == (br = LOBYTE(rand())));
				pB.push_back( br );
		}
		pB.push_back(2);
		pB.push_back(0);
	}
	else
		pInfo->cbData = DWORD(pB.size());

	CopyMemory(pInfo->pbData, pB.data(), pB.size());
	RETURN(NO_ERROR);
}

DWORD WINAPI CardSignData(__in PCARD_DATA pCardData, __inout PCARD_SIGNING_INFO pInfo)
{
	if (!pCardData || !pInfo || !pInfo->pbData)
		RETURN(SCARD_E_INVALID_PARAMETER);
	_log("dwVersion=%u, bContainerIndex=%u, dwKeySpec=%u, dwSigningFlags=0x%08X, aiHashAlg=0x%08X, cbData=%u",
		pInfo->dwVersion, pInfo->bContainerIndex, pInfo->dwKeySpec, pInfo->dwSigningFlags, pInfo->aiHashAlg, pInfo->cbData);
	pInfo->cbSignedData = 0;
	if (pInfo->bContainerIndex != AUTH_CONTAINER_INDEX && pInfo->bContainerIndex != SIGN_CONTAINER_INDEX)
		RETURN(SCARD_E_NO_KEY_CONTAINER);
	if (pInfo->dwVersion != CARD_SIGNING_INFO_BASIC_VERSION && pInfo->dwVersion != CARD_SIGNING_INFO_CURRENT_VERSION)
		RETURN(ERROR_REVISION_MISMATCH);
	bool isRSA = true;
	switch (pInfo->dwKeySpec)
	{
	case AT_KEYEXCHANGE:
	case AT_SIGNATURE: break;
	case AT_ECDSA_P384:
	case AT_ECDHE_P384: isRSA = false; break;
	default: RETURN(SCARD_E_INVALID_PARAMETER);
	}	
	DWORD dwFlagMask = CARD_PADDING_INFO_PRESENT | CARD_BUFFER_SIZE_ONLY | CARD_PADDING_NONE | CARD_PADDING_PKCS1;
	if (pInfo->dwSigningFlags & (~dwFlagMask))
		RETURN(SCARD_E_INVALID_PARAMETER);

	ALG_ID hashAlg = pInfo->aiHashAlg;
	if (CARD_PADDING_INFO_PRESENT & pInfo->dwSigningFlags)
	{
		if (CARD_PADDING_PKCS1 != pInfo->dwPaddingType)
			RETURN(SCARD_E_UNSUPPORTED_FEATURE);
		BCRYPT_PKCS1_PADDING_INFO *pinf = (BCRYPT_PKCS1_PADDING_INFO*)pInfo->pPaddingInfo;
		if (!pinf->pszAlgId) hashAlg = CALG_SSL3_SHAMD5;
		else if (wcscmp(pinf->pszAlgId, BCRYPT_MD5_ALGORITHM) == 0) hashAlg = CALG_MD5;
		else if (wcscmp(pinf->pszAlgId, BCRYPT_SHA1_ALGORITHM) == 0) hashAlg = CALG_SHA1;
		else if (wcscmp(pinf->pszAlgId, BCRYPT_SHA256_ALGORITHM) == 0) hashAlg = CALG_SHA_256;
		else if (wcscmp(pinf->pszAlgId, BCRYPT_SHA384_ALGORITHM) == 0) hashAlg = CALG_SHA_384;
		else if (wcscmp(pinf->pszAlgId, BCRYPT_SHA512_ALGORITHM) == 0) hashAlg = CALG_SHA_512;
		else RETURN(SCARD_E_UNSUPPORTED_FEATURE);
	}

	vector<byte> oid;
	switch (hashAlg)
	{
	case CALG_MD5:
		oid = { 0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10 };
		break;
	case CALG_SHA1:
		oid = { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14 };
		break;
	/*case CALG_SHA224:
		oid = { 0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c };
		break;*/
	case CALG_SHA_256:
		oid = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };
		break;
	case CALG_SHA_384:
		oid = { 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30 };
		break;
	case CALG_SHA_512:
		oid = { 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 };
		break;
	case CALG_SSL3_SHAMD5:
	case 0: break;
	default:
		if (GET_ALG_CLASS(hashAlg) != ALG_CLASS_HASH)
			RETURN(SCARD_E_INVALID_PARAMETER);	
		RETURN(SCARD_E_UNSUPPORTED_FEATURE);
	}
	vector<byte> hash(pInfo->pbData, pInfo->pbData + pInfo->cbData);
	if (!(pInfo->dwSigningFlags & CRYPT_NOHASHOID) && isRSA)
		hash.insert(hash.begin(), oid.cbegin(), oid.cend());
	_log("Hash to sign: %s with size: %i", toHex(hash).c_str(), hash.size());

	if (!transfer({ 0x00, 0xA4, 0x00, 0x0C }, pCardData->hScard) ||
		!transfer({ 0x00, 0xA4, 0x01, 0x0C, 0x02, 0xEE, 0xEE }, pCardData->hScard) ||
		!transfer({ 0x00, 0x22, 0xF3, 0x01 }, pCardData->hScard) ||
		!transfer({ 0x00, 0x22, 0x41, 0xB8, 0x02, 0x83, 0x00 }, pCardData->hScard))
		RETURN(SCARD_W_SECURITY_VIOLATION);

	vector<byte> cmd;
	if (pInfo->bContainerIndex == AUTH_CONTAINER_INDEX)
		cmd = { 0x00, 0x88, 0x00, 0x00, byte(hash.size()) };
	else
		cmd = { 0x00, 0x2A, 0x9E, 0x9A, byte(hash.size()) };
	cmd.insert(cmd.end(), hash.cbegin(), hash.cend());
	Result result = transfer(cmd, pCardData->hScard);
	if (!result)
		RETURN(SCARD_W_SECURITY_VIOLATION);

	if (isRSA)
		reverse(result.data.begin(), result.data.end());
	_log("Signed hash: %s with size: %i", toHex(result.data).c_str(), result.data.size());
	pInfo->cbSignedData = DWORD(result.data.size());
	if (!(pInfo->dwSigningFlags & CARD_BUFFER_SIZE_ONLY))
	{
		pInfo->pbSignedData = PBYTE(pCardData->pfnCspAlloc(result.data.size()));
		if (!pInfo->pbSignedData)
			RETURN(ERROR_NOT_ENOUGH_MEMORY);
		CopyMemory(pInfo->pbSignedData, result.data.data(), result.data.size());
	}
	RETURN(NO_ERROR);
}

DWORD WINAPI CardConstructDHAgreement(__in PCARD_DATA pCardData, __inout PCARD_DH_AGREEMENT_INFO pAgreementInfo)
{
	if (!pCardData || !pAgreementInfo || !pAgreementInfo->pbPublicKey)
		RETURN(SCARD_E_INVALID_PARAMETER);
	_log("dwVersion=%u, bContainerIndex=%u, pbData=0x%08X, cbData=%u",
		pAgreementInfo->dwVersion, pAgreementInfo->bContainerIndex, pAgreementInfo->pbPublicKey, pAgreementInfo->dwPublicKey);
	if (pAgreementInfo->bContainerIndex >= 2)
		RETURN(SCARD_E_NO_KEY_CONTAINER);

	vector<byte> data{
		0xA6, // Control Reference Template Tag for Key Agreement (ISO 7816-4:2013 Table 54)
		0x66, // Length of the Control reference Template
		0x7F, // Ephemeral public key Template Tag (ISO 7816-8:2016 Table 3)
		0x49,
		0x63, // Length of ephemeral public key Template
		0x86, // External Public Key
		0x61, // External Public Key Len
		0x04, // Uncompressed
	};
	data.insert(data.end(), pAgreementInfo->pbPublicKey + sizeof(BCRYPT_ECCKEY_BLOB),
		pAgreementInfo->pbPublicKey + pAgreementInfo->dwPublicKey);

	vector<byte> cmd = { 0x00, 0x2A, 0x80, 0x86, byte(data.size()) };
	cmd.insert(cmd.end(), data.cbegin(), data.cend());
	Result result = transfer(cmd, pCardData->hScard);
	if (!result)
		RETURN(SCARD_W_SECURITY_VIOLATION);

	Files *files = (Files*)pCardData->pvVendorSpecific;
	pAgreementInfo->bSecretAgreementIndex = files->dhAgreements.empty() ? 1 : files->dhAgreements.rbegin()->first + 1;
	files->dhAgreements.insert({ pAgreementInfo->bSecretAgreementIndex, result.data });
	_log("Returning bSecretAgreementIndex=%u", pAgreementInfo->bSecretAgreementIndex);
	RETURN(NO_ERROR);
}

DWORD WINAPI CardDeriveKey(__in PCARD_DATA pCardData, __inout PCARD_DERIVE_KEY pAgreementInfo)
{
	if (!pCardData || !pAgreementInfo || !pAgreementInfo->pwszKDF)
		RETURN(SCARD_E_INVALID_PARAMETER);
	_log("dwVersion=%u, pwszKDF=%S, bSecretAgreementIndex=%u, pParameterList=0x%08X, pwszAlgId=%S, dwKeyLen=%u",
		pAgreementInfo->dwVersion, pAgreementInfo->pwszKDF, pAgreementInfo->bSecretAgreementIndex,
		pAgreementInfo->pParameterList, pAgreementInfo->pwszAlgId, pAgreementInfo->dwKeyLen);
	if (pAgreementInfo->dwVersion < CARD_DERIVE_KEY_VERSION)
		RETURN(ERROR_REVISION_MISMATCH);
	Files *files = (Files*)pCardData->pvVendorSpecific;
	auto dhAgreement = files->dhAgreements.find(pAgreementInfo->bSecretAgreementIndex);
	if (dhAgreement == files->dhAgreements.cend())
		RETURN(SCARD_E_INVALID_PARAMETER);

	vector<byte> prepend, append, hmackey, algID, partyUInfo, partyVInfo, suppPubInfo, suppPrivInfo;
	ULONG keyBitLen = 0;
	LPCWSTR algo = nullptr;
	PBCryptBufferDesc params = PBCryptBufferDesc(pAgreementInfo->pParameterList);
	for (ULONG i = 0; i < params->cBuffers; ++i)
	{
		PBCryptBuffer info = &params->pBuffers[i];
		switch (info->BufferType)
		{
		case KDF_HASH_ALGORITHM:
			algo = LPCWSTR(info->pvBuffer);
			if (wcscmp(BCRYPT_SHA1_ALGORITHM, algo) &&
				wcscmp(BCRYPT_SHA256_ALGORITHM, algo) &&
				wcscmp(BCRYPT_SHA384_ALGORITHM, algo) &&
				wcscmp(BCRYPT_SHA512_ALGORITHM, algo))
				RETURN(SCARD_E_INVALID_PARAMETER);
			break;
		case KDF_SECRET_PREPEND: prepend.insert(prepend.cbegin(), PBYTE(info->pvBuffer), PBYTE(info->pvBuffer) + info->cbBuffer); break;
		case KDF_SECRET_APPEND: append.insert(append.cbegin(), PBYTE(info->pvBuffer), PBYTE(info->pvBuffer) + info->cbBuffer); break;
		case KDF_HMAC_KEY: hmackey.assign(PBYTE(info->pvBuffer), PBYTE(info->pvBuffer) + info->cbBuffer); break;
		case KDF_ALGORITHMID: algID.assign(PBYTE(info->pvBuffer), PBYTE(info->pvBuffer) + info->cbBuffer); break;
		case KDF_PARTYUINFO: partyUInfo.assign(PBYTE(info->pvBuffer), PBYTE(info->pvBuffer) + info->cbBuffer); break;
		case KDF_PARTYVINFO: partyVInfo.assign(PBYTE(info->pvBuffer), PBYTE(info->pvBuffer) + info->cbBuffer); break;
		case KDF_SUPPPUBINFO: suppPubInfo.assign(PBYTE(info->pvBuffer), PBYTE(info->pvBuffer) + info->cbBuffer); break;
		case KDF_SUPPPRIVINFO: suppPrivInfo.assign(PBYTE(info->pvBuffer), PBYTE(info->pvBuffer) + info->cbBuffer); break;
#if (NTDDI_VERSION >= NTDDI_WIN8)
		case KDF_KEYBITLENGTH: keyBitLen = *PULONG(info->pvBuffer); break;
#endif
		default: RETURN(SCARD_E_INVALID_PARAMETER);
		}
	}

	if (wcscmp(BCRYPT_KDF_HASH, pAgreementInfo->pwszKDF) == 0 ||
		wcscmp(BCRYPT_KDF_HMAC, pAgreementInfo->pwszKDF) == 0)
	{
		if (pAgreementInfo->dwFlags & KDF_USE_SECRET_AS_HMAC_KEY_FLAG)
			hmackey = dhAgreement->second;
		if ((wcscmp(BCRYPT_KDF_HMAC, pAgreementInfo->pwszKDF) == 0 && hmackey.empty()) ||
			(wcscmp(BCRYPT_KDF_HASH, pAgreementInfo->pwszKDF) == 0 && !hmackey.empty()))
			RETURN(SCARD_E_INVALID_PARAMETER);
		if (!algo)
			algo = BCRYPT_SHA1_ALGORITHM;
	}
	else if (wcscmp(BCRYPT_KDF_SP80056A_CONCAT, pAgreementInfo->pwszKDF) == 0)
	{
		if (!hmackey.empty())
			RETURN(SCARD_E_INVALID_PARAMETER);
		if (algID.empty() || partyUInfo.empty() || partyVInfo.empty())
			RETURN(SCARD_E_INVALID_PARAMETER);
		if (!algo)
		{
			switch (dhAgreement->second.size())
			{
			case 32: algo = BCRYPT_SHA256_ALGORITHM; break;
			case 48: algo = BCRYPT_SHA384_ALGORITHM; break;
			case 65:
			case 66: algo = BCRYPT_SHA512_ALGORITHM; break;
			default: algo = BCRYPT_SHA384_ALGORITHM; break;
			}
		}
	}
	else // if (wcscmp(BCRYPT_KDF_TLS_PRF, pAgreementInfo->pwszKDF) == 0)
		RETURN(SCARD_E_INVALID_PARAMETER);

	BCRYPT_ALG_HANDLE hAlgorithm = 0;
	if (BCryptOpenAlgorithmProvider(&hAlgorithm, algo, MS_PRIMITIVE_PROVIDER, !hmackey.empty() ? BCRYPT_ALG_HANDLE_HMAC_FLAG : 0))
		RETURN(SCARD_E_INVALID_PARAMETER);
	DWORD hashLen = 0;
	DWORD size = sizeof(DWORD);
	if (BCryptGetProperty(hAlgorithm, BCRYPT_HASH_LENGTH, PUCHAR(&hashLen), size, &size, 0))
	{
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		RETURN(SCARD_E_INVALID_PARAMETER);
	}

	if (wcscmp(BCRYPT_KDF_SP80056A_CONCAT, pAgreementInfo->pwszKDF) != 0)
		pAgreementInfo->cbDerivedKey = hashLen;
	else if (keyBitLen)
		pAgreementInfo->cbDerivedKey = (keyBitLen + 7) / 8;
	else
		pAgreementInfo->cbDerivedKey = DWORD(dhAgreement->second.size());
	if (pAgreementInfo->dwFlags & CARD_BUFFER_SIZE_ONLY)
	{
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		RETURN(NO_ERROR);
	}

	vector<byte> key, hash(hashLen, 0);
	vector<byte> *z = &dhAgreement->second;
	if (wcscmp(BCRYPT_KDF_HASH, pAgreementInfo->pwszKDF) == 0 ||
		wcscmp(BCRYPT_KDF_HMAC, pAgreementInfo->pwszKDF) == 0)
	{
		BCRYPT_HASH_HANDLE hHash = 0;
		if (BCryptCreateHash(hAlgorithm, &hHash, nullptr, 0, hmackey.data(), ULONG(hmackey.size()), 0))
		{
			BCryptCloseAlgorithmProvider(hAlgorithm, 0);
			RETURN(SCARD_E_INVALID_PARAMETER);
		}
		if (BCryptHashData(hHash, prepend.data(), ULONG(prepend.size()), 0) ||
			BCryptHashData(hHash, z->data(), ULONG(z->size()), 0) ||
			BCryptHashData(hHash, append.data(), ULONG(append.size()), 0) ||
			BCryptFinishHash(hHash, hash.data(), ULONG(hash.size()), 0))
		{
			BCryptDestroyHash(hHash);
			BCryptCloseAlgorithmProvider(hAlgorithm, 0);
			RETURN(SCARD_E_INVALID_PARAMETER);
		}
		BCryptDestroyHash(hHash);
		key = hash;
	}
	else
	{
		uint32_t reps = uint32_t(ceil(double(pAgreementInfo->cbDerivedKey) / double(hashLen)));
		for (uint32_t i = 1; i <= reps; i++)
		{
			uint32_t intToFourBytes = ntohl(i);
			BCRYPT_HASH_HANDLE hHash = 0;
			if (BCryptCreateHash(hAlgorithm, &hHash, nullptr, 0, nullptr, 0, 0))
			{
				BCryptCloseAlgorithmProvider(hAlgorithm, 0);
				RETURN(SCARD_E_INVALID_PARAMETER);
			}
			if (BCryptHashData(hHash, PUCHAR(&intToFourBytes), 4, 0) ||
				BCryptHashData(hHash, z->data(), ULONG(z->size()), 0) ||
				BCryptHashData(hHash, algID.data(), ULONG(algID.size()), 0) ||
				BCryptHashData(hHash, partyUInfo.data(), ULONG(partyUInfo.size()), 0) ||
				BCryptHashData(hHash, partyVInfo.data(), ULONG(partyVInfo.size()), 0) ||
				BCryptHashData(hHash, suppPubInfo.data(), ULONG(suppPubInfo.size()), 0) ||
				BCryptHashData(hHash, suppPrivInfo.data(), ULONG(suppPrivInfo.size()), 0) ||
				BCryptFinishHash(hHash, hash.data(), ULONG(hash.size()), 0))
			{
				BCryptDestroyHash(hHash);
				BCryptCloseAlgorithmProvider(hAlgorithm, 0);
				RETURN(SCARD_E_INVALID_PARAMETER);
			}
			BCryptDestroyHash(hHash);
			key.insert(key.end(), hash.cbegin(), hash.cend());
		}
	}

	BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	pAgreementInfo->pbDerivedKey = PBYTE(pCardData->pfnCspAlloc(pAgreementInfo->cbDerivedKey));
	if (!pAgreementInfo->pbDerivedKey)
		RETURN(ERROR_NOT_ENOUGH_MEMORY);
	CopyMemory(pAgreementInfo->pbDerivedKey, key.data(), pAgreementInfo->cbDerivedKey);
	RETURN(NO_ERROR);
}

DWORD WINAPI CardDestroyDHAgreement(__in PCARD_DATA pCardData, __in BYTE bSecretAgreementIndex, __in DWORD dwFlags)
{
	if (!pCardData || dwFlags)
		RETURN(SCARD_E_INVALID_PARAMETER);
	_log("bSecretAgreementIndex=%u", bSecretAgreementIndex);
	Files *files = (Files*)pCardData->pvVendorSpecific;
	auto dhAgreement = files->dhAgreements.find(bSecretAgreementIndex);
	if (dhAgreement == files->dhAgreements.cend())
		RETURN(SCARD_E_INVALID_PARAMETER);
	files->dhAgreements.erase(dhAgreement);
	RETURN(NO_ERROR);
}



DECLARE_UNSUPPORTED(CardGetChallenge(__in PCARD_DATA pCardData,
	__deref_out_bcount(*pcbChallengeData) PBYTE *ppbChallengeData,
	__out PDWORD pcbChallengeData))
DECLARE_UNSUPPORTED(CardChangeAuthenticator(__in PCARD_DATA pCardData,
	__in LPWSTR pwszUserId,
	__in_bcount(cbCurrentAuthenticator)PBYTE pbCurrentAuthenticator,
	__in DWORD cbCurrentAuthenticator,
	__in_bcount(cbNewAuthenticator)PBYTE pbNewAuthenticator,
	__in DWORD cbNewAuthenticator,
	__in DWORD cRetryCount,
	__in DWORD dwFlags,
	__out_opt PDWORD pcAttemptsRemaining))
DECLARE_UNSUPPORTED(CardCreateDirectory(__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName,
	__in CARD_DIRECTORY_ACCESS_CONDITION AccessCondition))
DECLARE_UNSUPPORTED(CardDeleteDirectory(__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName))
DECLARE_UNSUPPORTED(CardCreateFile(__in PCARD_DATA pCardData,
	__in_opt LPSTR pszDirectoryName,
	__in LPSTR pszFileName,
	__in DWORD cbInitialCreationSize,
	__in CARD_FILE_ACCESS_CONDITION AccessCondition))
DECLARE_UNSUPPORTED(CardWriteFile(__in PCARD_DATA pCardData,
	__in_opt LPSTR pszDirectoryName,
	__in LPSTR pszFileName,
	__in DWORD dwFlags,
	__in_bcount(cbData) PBYTE pbData,
	__in DWORD cbData))
DECLARE_UNSUPPORTED(CardDeleteFile(__in PCARD_DATA pCardData,
	__in_opt LPSTR pszDirectoryName,
	__in LPSTR pszFileName,
	__in DWORD dwFlags))
DECLARE_UNSUPPORTED(CspGetDHAgreement(__in PCARD_DATA pCardData,
	__in PVOID hSecretAgreement,
	__out BYTE* pbSecretAgreementIndex,
	__in DWORD dwFlags))
DECLARE_UNSUPPORTED(CardAuthenticateChallenge(__in PCARD_DATA pCardData,
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
DECLARE_UNSUPPORTED(CardCreateContainerEx(__in PCARD_DATA pCardData,
	__in BYTE bContainerIndex,
	__in DWORD dwFlags,
	__in DWORD dwKeySpec,
	__in DWORD dwKeySize,
	__in PBYTE pbKeyData,
	__in PIN_ID PinId))
DECLARE_UNSUPPORTED(CardDeleteContainer(__in PCARD_DATA pCardData,
	__in BYTE bContainerIndex,
	__in DWORD dwReserved))
DECLARE_UNSUPPORTED(CardUnblockPin(__in PCARD_DATA pCardData,
	__in LPWSTR pwszUserId,
	__in_bcount(cbAuthenticationData)PBYTE pbAuthenticationData,
	__in DWORD cbAuthenticationData,
	__in_bcount(cbNewPinData)PBYTE pbNewPinData,
	__in DWORD cbNewPinData,
	__in DWORD cRetryCount,
	__in DWORD dwFlags))
DECLARE_UNSUPPORTED(CardChangeAuthenticatorEx(__in PCARD_DATA pCardData,
	__in DWORD dwFlags,
	__in PIN_ID dwAuthenticatingPinId,
	__in_bcount(cbAuthenticatingPinData) PBYTE pbAuthenticatingPinData,
	__in DWORD cbAuthenticatingPinData,
	__in PIN_ID dwTargetPinId,
	__in_bcount(cbTargetData)PBYTE pbTargetData,
	__in DWORD cbTargetData,
	__in DWORD cRetryCount,
	__out_opt PDWORD pcAttemptsRemaining))
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
DECLARE_UNSUPPORTED(MDImportSessionKey(__in PCARD_DATA pCardData,
	__in LPCWSTR pwszBlobType,
	__in LPCWSTR pwszAlgId,
	__out PCARD_KEY_HANDLE phKey,
	__in_bcount(cbInput) PBYTE pbInput,
	__in DWORD cbInput))
DECLARE_UNSUPPORTED(MDEncryptData(__in PCARD_DATA pCardData,
	__in CARD_KEY_HANDLE hKey,
	__in LPCWSTR pwszSecureFunction,
	__in_bcount(cbInput) PBYTE pbInput,
	__in DWORD cbInput, __in DWORD dwFlags,
	__deref_out_ecount(*pcEncryptedData) PCARD_ENCRYPTED_DATA *ppEncryptedData,
	__out PDWORD pcEncryptedData))
DECLARE_UNSUPPORTED(CardImportSessionKey(__in PCARD_DATA pCardData,
	__in BYTE bContainerIndex,
	__in VOID *pPaddingInfo,
	__in LPCWSTR pwszBlobType,
	__in LPCWSTR pwszAlgId,
	__out CARD_KEY_HANDLE *phKey,
	__in_bcount(cbInput) PBYTE pbInput,
	__in DWORD cbInput,
	__in DWORD dwFlags))
DECLARE_UNSUPPORTED(CardGetSharedKeyHandle(__in PCARD_DATA pCardData,
	__in_bcount(cbInput) PBYTE pbInput,
	__in DWORD cbInput,
	__deref_opt_out_bcount(*pcbOutput)PBYTE *ppbOutput,
	__out_opt PDWORD pcbOutput,
	__out PCARD_KEY_HANDLE phKey))
DECLARE_UNSUPPORTED(CardGetAlgorithmProperty(__in PCARD_DATA pCardData,
	__in LPCWSTR pwszAlgId,
	__in LPCWSTR pwszProperty,
	__out_bcount_part_opt(cbData, *pdwDataLen)PBYTE pbData,
	__in DWORD cbData,
	__out PDWORD pdwDataLen,
	__in DWORD dwFlags))
DECLARE_UNSUPPORTED(CardGetKeyProperty(__in PCARD_DATA pCardData,
	__in CARD_KEY_HANDLE hKey,
	__in LPCWSTR pwszProperty,
	__out_bcount_part_opt(cbData, *pdwDataLen) PBYTE pbData,
	__in DWORD cbData,
	__out PDWORD pdwDataLen,
	__in DWORD dwFlags))
DECLARE_UNSUPPORTED(CardSetKeyProperty(__in PCARD_DATA pCardData,
	__in CARD_KEY_HANDLE hKey,
	__in LPCWSTR pwszProperty,
	__in_bcount(cbInput) PBYTE pbInput,
	__in DWORD cbInput,
	__in DWORD dwFlags))
DECLARE_UNSUPPORTED(CardDestroyKey(__in PCARD_DATA pCardData,
	__in CARD_KEY_HANDLE hKey))
DECLARE_UNSUPPORTED(CardProcessEncryptedData(__in PCARD_DATA pCardData,
	__in CARD_KEY_HANDLE hKey,
	__in LPCWSTR pwszSecureFunction,
	__in_ecount(cEncryptedData)PCARD_ENCRYPTED_DATA pEncryptedData,
	__in DWORD cEncryptedData,
	__out_bcount_part_opt(cbOutput, *pdwOutputLen) PBYTE pbOutput,
	__in DWORD cbOutput,
	__out_opt PDWORD pdwOutputLen,
	__in DWORD dwFlags))
