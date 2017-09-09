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

#define NULLSTR(a) (a == NULL ? "<NULL>" : a)
#define NULLWSTR(a) (a == NULL ? L"<NULL>" : a)
#define AUTH_PIN_ID ROLE_USER
#define SIGN_PIN_ID 3
#define PUKK_PIN_ID ROLE_ADMIN
#define AUTH_CONTAINER_INDEX 0
#define SIGN_CONTAINER_INDEX 1
#define RETURN(X) return logreturn(__FUNCTION__, __FILE__, __LINE__, #X, X)
#define _log(...) log(__FUNCTION__, __FILE__, __LINE__, __VA_ARGS__)
#define DECLARE_UNSUPPORTED(name) DWORD WINAPI name { RETURN(SCARD_E_UNSUPPORTED_FEATURE); }
#define CM_IOCTL_GET_FEATURE_REQUEST SCARD_CTL_CODE(3400)

static const BYTE cardapps[] = { 1, 'm', 's', 'c', 'p', 0, 0, 0, 0 };
static const BYTE cardcf[] = { 0, 0, 0, 0, 0, 0 };
HWND cp;

using namespace std;

#if defined(_MSC_VER) 
typedef signed __int8 int8_t;
typedef signed __int16 int16_t;
typedef signed __int32 int32_t;
typedef signed __int64 int64_t;
typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
typedef unsigned __int64 uint64_t;
#endif 

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

typedef struct
{
	PUBLICKEYSTRUC publickeystruc;
	RSAPUBKEY rsapubkey;
} PUBKEYSTRUCT, *PPUBKEYSTRUCT;

typedef struct
{
	HWND hwndParentWindow;
	PIN_ID pinId;
	LANGID langId;
} EXTERNAL_INFO, *PEXTERNAL_INFO;

struct Files
{
	BYTE cardid[16];
	PCCERT_CONTEXT auth, sign;
};

struct Result {
	byte SW1, SW2; vector<byte> data;
	bool operator !() const { return !(SW1 == 0x90 && SW2 == 0x00); }
};

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
	for (vector<byte>::const_iterator i = data.begin(); i != data.end(); ++i)
		os << setw(2) << static_cast<int>(*i);
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
		LPCBYTE(apdu.data()), DWORD(apdu.size()), nullptr, LPBYTE(data.data()), &size);
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
	LONG rv = SCardControl(card, CM_IOCTL_GET_FEATURE_REQUEST, nullptr, 0, feature, DWORD(sizeof(feature)), &size);
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
		PIN_VERIFY_STRUCTURE *data = (PIN_VERIFY_STRUCTURE*)cmd.data();
		SET(data);
		data->bNumberMessage = pin_properties.wLcdLayout > 0 ? 0xFF : 0x00;
		data->bMsgIndex = 0x00;
		data->ulDataLength = uint32_t(apdu.size());
		cmd.resize(sizeof(PIN_VERIFY_STRUCTURE) - 1);
	}
	else
	{
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
		cmd.resize(sizeof(PIN_MODIFY_STRUCTURE) - 1);
	}
	cmd.insert(cmd.cend(), apdu.cbegin(), apdu.cend());

	ioctl = f.find(verify ? FEATURE_VERIFY_PIN_START : FEATURE_MODIFY_PIN_START);
	if (ioctl == f.cend())
		ioctl =  f.find(verify ? FEATURE_VERIFY_PIN_DIRECT : FEATURE_MODIFY_PIN_DIRECT);

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

static PPUBKEYSTRUCT pubKeyStruct(__in PCARD_DATA pCardData, PCCERT_CONTEXT cer, DWORD &sw)
{
	PCRYPT_BIT_BLOB PublicKey = &cer->pCertInfo->SubjectPublicKeyInfo.PublicKey;
	CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB,
		PublicKey->pbData, PublicKey->cbData, 0, nullptr, &sw);
	PPUBKEYSTRUCT oh = PPUBKEYSTRUCT(pCardData->pfnCspAlloc(sw));
	CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB,
		PublicKey->pbData, PublicKey->cbData, 0, LPVOID(oh), &sw);
	return oh;
}

static DWORD keySize(__in PCARD_DATA pCardData, PCCERT_CONTEXT cer)
{
	DWORD size = 2048;
	DWORD sw = 0;
	PPUBKEYSTRUCT oh = pubKeyStruct(pCardData, cer, sw);
	if (!oh)
		return size;
	size = oh->rsapubkey.bitlen;
	pCardData->pfnCspFree(oh);
	return size;
}

static vector<byte> md5sum(const string &data)
{
	vector<byte> result;
	HCRYPTPROV hProv = 0;
	if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		return result;

	HCRYPTHASH hHash = 0;
	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
	{
		CryptReleaseContext(hProv, 0);
		return result;
	}

	if (!CryptHashData(hHash, PBYTE(data.c_str()), DWORD(data.size()), 0))
	{
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		return result;
	}

	DWORD md5size = 16;
	result.resize(md5size);
	if (!CryptGetHashParam(hHash, HP_HASHVAL, PBYTE(result.data()), &md5size, 0))
		result.clear();

	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);

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
	int buttonPressed = 0;
	return TaskDialogIndirect(&config, &buttonPressed, NULL, NULL);
}

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	_log("Reason %u", ul_reason_for_call);
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
    return TRUE;
}

DWORD WINAPI CardAcquireContext(IN PCARD_DATA pCardData, __in DWORD dwFlags)
{
	if (!pCardData)
		RETURN(SCARD_E_INVALID_PARAMETER);
	_log("dwVersion=%u, name=%S"", hScard=0x%08X, hSCardCtx=0x%08X", pCardData->dwVersion, NULLWSTR(pCardData->pwszCardName),
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
		{ 0x3B, 0xFE, 0x94, 0x00, 0xFF, 0x80, 0xB1, 0xFA, 0x45, 0x1F, 0x03, 0x45, 0x73, 0x74, 0x45, 0x49, 0x44, 0x20, 0x76, 0x65, 0x72, 0x20, 0x31, 0x2E, 0x30, 0x43 }, /*ESTEID_V1_COLD_ATR*/
		{ 0x3B, 0x6E, 0x00, 0xFF, 0x45, 0x73, 0x74, 0x45, 0x49, 0x44, 0x20, 0x76, 0x65, 0x72, 0x20, 0x31, 0x2E, 0x30 }, /*ESTEID_V1_WARM_ATR*/
		{ 0x3B, 0xDE, 0x18, 0xFF, 0xC0, 0x80, 0xB1, 0xFE, 0x45, 0x1F, 0x03, 0x45, 0x73, 0x74, 0x45, 0x49, 0x44, 0x20, 0x76, 0x65, 0x72, 0x20, 0x31, 0x2E, 0x30, 0x2B }, /*ESTEID_V1_2007_COLD_ATR*/
		{ 0x3B, 0x5E, 0x11, 0xFF, 0x45, 0x73, 0x74, 0x45, 0x49, 0x44, 0x20, 0x76, 0x65, 0x72, 0x20, 0x31, 0x2E, 0x30 }, /*ESTEID_V1_2007_WARM_ATR*/
		{ 0x3B, 0x6E, 0x00, 0x00, 0x45, 0x73, 0x74, 0x45, 0x49, 0x44, 0x20, 0x76, 0x65, 0x72, 0x20, 0x31, 0x2E, 0x30 }, /*ESTEID_V1_1_COLD_ATR*/
		{ 0x3B, 0xFE, 0x18, 0x00, 0x00, 0x80, 0x31, 0xFE, 0x45, 0x45, 0x73, 0x74, 0x45, 0x49, 0x44, 0x20, 0x76, 0x65, 0x72, 0x20, 0x31, 0x2E, 0x30, 0xA8 }, /*ESTEID_V3_COLD_DEV1_ATR*/
		{ 0x3B, 0xFE, 0x18, 0x00, 0x00, 0x80, 0x31, 0xFE, 0x45, 0x80, 0x31, 0x80, 0x66, 0x40, 0x90, 0xA4, 0x56, 0x1B, 0x16, 0x83, 0x01, 0x90, 0x00, 0x86 }, /*ESTEID_V3_WARM_DEV1_ATR*/
		{ 0x3B, 0xFE, 0x18, 0x00, 0x00, 0x80, 0x31, 0xFE, 0x45, 0x80, 0x31, 0x80, 0x66, 0x40, 0x90, 0xA4, 0x16, 0x2A, 0x00, 0x83, 0x01, 0x90, 0x00, 0xE1 }, /*ESTEID_V3_WARM_DEV2_ATR*/
		{ 0x3B, 0xFE, 0x18, 0x00, 0x00, 0x80, 0x31, 0xFE, 0x45, 0x80, 0x31, 0x80, 0x66, 0x40, 0x90, 0xA4, 0x16, 0x2A, 0x00, 0x83, 0x0F, 0x90, 0x00, 0xEF }, /*ESTEID_V3_WARM_DEV3_ATR*/
		{ 0x3B, 0xF9, 0x18, 0x00, 0x00, 0xC0, 0x0A, 0x31, 0xFE, 0x45, 0x53, 0x46, 0x2D, 0x34, 0x43, 0x43, 0x2D, 0x30, 0x31, 0x81 }, /*ESTEID_V35_COLD_DEV1_ATR*/
		{ 0x3B, 0xF8, 0x13, 0x00, 0x00, 0x81, 0x31, 0xFE, 0x45, 0x4A, 0x43, 0x4F, 0x50, 0x76, 0x32, 0x34, 0x31, 0xB7 }, /*ESTEID_V35_COLD_DEV2_ATR*/
		{ 0x3B, 0xFA, 0x18, 0x00, 0x00, 0x80, 0x31, 0xFE, 0x45, 0xFE, 0x65, 0x49, 0x44, 0x20, 0x2F, 0x20, 0x50, 0x4B, 0x49, 0x03 }, /*ESTEID_V35_COLD_DEV3_ATR*/
		{ 0x3B, 0xFE, 0x18, 0x00, 0x00, 0x80, 0x31, 0xFE, 0x45, 0x80, 0x31, 0x80, 0x66, 0x40, 0x90, 0xA4, 0x16, 0x2A, 0x00, 0x83, 0x0F, 0x90, 0x00, 0xEF }, /*ESTEID_V35_WARM_ATR*/
		{ 0x3B, 0xFE, 0x18, 0x00, 0x00, 0x80, 0x31, 0xFE, 0x45, 0x80, 0x31, 0x80, 0x66, 0x40, 0x90, 0xA5, 0x10, 0x2E, 0x03, 0x83, 0x0F, 0x90, 0x00, 0xEF }, /*UPDATER_TEST_CARDS*/
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

	Files *files = (Files*)(pCardData->pvVendorSpecific = pCardData->pfnCspAlloc(sizeof(Files)));
	if (!pCardData->pvVendorSpecific)
		RETURN(ERROR_NOT_ENOUGH_MEMORY);
	files->auth = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, auth.data(), DWORD(auth.size()));
	files->sign = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, sign.data(), DWORD(sign.size()));
	if (!files->auth || !files->sign)
		RETURN(ERROR_NOT_ENOUGH_MEMORY);
	memcpy(files->cardid, cardid.c_str(), cardid.size());

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
	pCardData->pfnCardConstructDHAgreement = nullptr;

	if (CARD_DATA_VERSION_SEVEN < pCardData->dwVersion)
		pCardData->dwVersion = CARD_DATA_VERSION_SEVEN;
	if (pCardData->dwVersion > 4)
	{
		pCardData->pfnCardDeriveKey = nullptr;
		pCardData->pfnCardDestroyDHAgreement = nullptr;
		pCardData->pfnCspGetDHAgreement = nullptr;
	}
	if (pCardData->dwVersion > 5)
	{
		pCardData->pfnCardGetChallengeEx = CardGetChallengeEx;
		pCardData->pfnCardAuthenticateEx = CardAuthenticateEx;
		pCardData->pfnCardChangeAuthenticatorEx = CardChangeAuthenticatorEx;
		pCardData->pfnCardDeauthenticateEx = CardDeauthenticateEx;
		pCardData->pfnCardGetContainerProperty = CardGetContainerProperty;
		pCardData->pfnCardSetContainerProperty = CardSetContainerProperty;
		pCardData->pfnCardGetProperty = CardGetProperty;
		pCardData->pfnCardSetProperty = CardSetProperty;
	}
	if (pCardData->dwVersion > 6)
	{
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
	}
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
		pCardData->pfnCspFree(pCardData->pvVendorSpecific);
	}
	RETURN(NO_ERROR);
}

DWORD WINAPI CardGetContainerProperty(__in PCARD_DATA pCardData, __in BYTE bContainerIndex, __in LPCWSTR wszProperty,
    __out_bcount_part_opt(cbData, *pdwDataLen) PBYTE pbData, __in DWORD cbData, __out PDWORD pdwDataLen, __in DWORD dwFlags)
{
	if (!pCardData)
		RETURN(SCARD_E_INVALID_PARAMETER);
	_log("bContainerIndex=%u, wszProperty=%S"", cbData=%u, dwFlags=0x%08X", bContainerIndex, NULLWSTR(wszProperty), cbData, dwFlags);
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
	_log("wszProperty=%S, cbData=%u, dwFlags=%u", NULLWSTR(wszProperty), cbData, dwFlags);
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
	if (wcscmp(CP_CARD_GUID, wszProperty) == 0)
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
		map<DRIVER_FEATURES, uint32_t> f = features(pCardData->hScard);
		bool isPinPad = f.find(FEATURE_VERIFY_PIN_DIRECT) != f.cend() || f.find(FEATURE_VERIFY_PIN_START) != f.cend();
		p->dwFlags = 0;
		p->dwChangePermission = 0;// CREATE_PIN_SET(dwFlags);
		p->dwUnblockPermission = 0; // dwFlags == PUKK_PIN_ID ? CREATE_PIN_SET(PUKK_PIN_ID) : 0;
		p->PinType = isPinPad ? ExternalPinType : AlphaNumericPinType;
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
		*p = CARD_PADDING_NONE;
		RETURN(NO_ERROR);
	}
	RETURN(SCARD_E_UNSUPPORTED_FEATURE);
}

DWORD WINAPI CardSetProperty(__in PCARD_DATA pCardData, __in LPCWSTR wszProperty, __in_bcount(cbDataLen) PBYTE pbData,
    __in DWORD cbDataLen, __in DWORD dwFlags)
{
	if (!pCardData || !wszProperty)
		RETURN(SCARD_E_INVALID_PARAMETER);
	_log("wszProperty=%S"", cbDataLen=%u, dwFlags=%u", NULLWSTR(wszProperty), cbDataLen, dwFlags);

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
		cp = *((HWND *) pbData);
		if (cp != 0 && !IsWindow(cp))
		{
			cp = NULL;
			RETURN(SCARD_E_INVALID_PARAMETER);
		}
		RETURN(NO_ERROR);
	}
	RETURN(SCARD_E_INVALID_PARAMETER);
}


DWORD WINAPI CardQueryCapabilities(__in PCARD_DATA pCardData, __in PCARD_CAPABILITIES pCardCapabilities)
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

DWORD WINAPI CardGetContainerInfo(__in PCARD_DATA  pCardData, __in BYTE bContainerIndex, __in DWORD dwFlags, __in PCONTAINER_INFO pContainerInfo)
{
	if (!pCardData || !pContainerInfo || dwFlags)
		RETURN(SCARD_E_INVALID_PARAMETER);
	if (pContainerInfo->dwVersion < 0 || pContainerInfo->dwVersion >  CONTAINER_INFO_CURRENT_VERSION)
		RETURN(ERROR_REVISION_MISMATCH);
	_log("bContainerIndex=%u, dwFlags=0x%08X, dwVersion=%u"", cbSigPublicKey=%u, cbKeyExPublicKey=%u",
		bContainerIndex, dwFlags, pContainerInfo->dwVersion, pContainerInfo->cbSigPublicKey, pContainerInfo->cbKeyExPublicKey);

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
		PPUBKEYSTRUCT oh = pubKeyStruct(pCardData, files->auth, pContainerInfo->cbKeyExPublicKey);
		if (!oh)
			RETURN(ERROR_NOT_ENOUGH_MEMORY);
		oh->publickeystruc.aiKeyAlg = CALG_RSA_KEYX;
		pContainerInfo->pbKeyExPublicKey = PBYTE(oh);
		break;
	}
	case SIGN_CONTAINER_INDEX:
	{
		PPUBKEYSTRUCT oh = pubKeyStruct(pCardData, files->sign, pContainerInfo->cbSigPublicKey);
		if (!oh)
			RETURN(ERROR_NOT_ENOUGH_MEMORY);
		oh->publickeystruc.aiKeyAlg = CALG_RSA_SIGN;
		pContainerInfo->pbSigPublicKey = PBYTE(oh);
		break;
	}
	default:
		RETURN(SCARD_E_NO_KEY_CONTAINER);
	}
	RETURN(NO_ERROR);
}

DWORD WINAPI CardAuthenticatePin(__in PCARD_DATA pCardData, __in LPWSTR pwszUserId, __in_bcount(cbPin) PBYTE pbPin, __in DWORD cbPin, __out_opt PDWORD pcAttemptsRemaining)
{
	_log("pwszUserId=%S", NULLWSTR(pwszUserId));
	if (!pwszUserId || wcscmp(pwszUserId, wszCARD_USER_USER) != 0 || !pbPin)
		RETURN(SCARD_E_INVALID_PARAMETER);
	return CardAuthenticateEx(pCardData, AUTH_PIN_ID, CARD_PIN_SILENT_CONTEXT, pbPin, cbPin, nullptr, nullptr, pcAttemptsRemaining);
}

DWORD WINAPI CardAuthenticateEx(__in PCARD_DATA pCardData, __in PIN_ID PinId, __in DWORD dwFlags, __in PBYTE pbPinData, __in DWORD cbPinData,
    __deref_out_bcount_opt(*pcbSessionPin) PBYTE  *ppbSessionPin, __out_opt PDWORD pcbSessionPin, __out_opt PDWORD pcAttemptsRemaining)
{
	_log("PinId=%u, dwFlags=0x%08X, cbPinData=%u, Attempts %s", PinId, dwFlags, cbPinData, pcAttemptsRemaining ? "YES" : "NO");
	if (!pCardData || (PinId != AUTH_PIN_ID && PinId != SIGN_PIN_ID))
		RETURN(SCARD_E_INVALID_PARAMETER);

	Result data;
	BYTE remaining = (!transfer({ 0x00, 0xA4, 0x00, 0x0C, 0x00 }, pCardData->hScard) ||
		!transfer({ 0x00, 0xA4, 0x02, 0x0C, 0x02, 0x00, 0x16 }, pCardData->hScard) ||
		!(data = transfer({ 0x00, 0xB2, byte(PinId == AUTH_PIN_ID ? 1 : 2), 0x04, 0x00 }, pCardData->hScard))) ? 3 : data.data[5];

	map<DRIVER_FEATURES, uint32_t> f = features(pCardData->hScard);
	bool isPinPad = f.find(FEATURE_VERIFY_PIN_DIRECT) != f.cend() || f.find(FEATURE_VERIFY_PIN_START) != f.cend();
	if (!isPinPad)
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
			cbPinData > 12)
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

		PWCHAR label = PinId == AUTH_PIN_ID ? L"Authentication error" : L"Signing error";
		if (remaining == 0)
		{
			MessageBox(NULL, L"PIN code blocked", label, MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
			RETURN(SCARD_W_CHV_BLOCKED);
		}

		EXTERNAL_INFO externalInfo;
		externalInfo.hwndParentWindow = cp;
		externalInfo.pinId = PinId;
		externalInfo.langId = GetUserDefaultUILanguage();

		while (remaining)
		{
			HANDLE DialogThreadHandle = CreateThread(NULL, 0, DialogThreadEntry, &externalInfo, 0, NULL);
			Result result = transferCTL({ 0x00, 0x20, 0x00, byte(PinId == AUTH_PIN_ID ? 1 : 2), 0x00 },
				true, externalInfo.langId, PinId == AUTH_PIN_ID ? 4 : 5, pCardData->hScard);
			TerminateThread(DialogThreadHandle, ERROR_SUCCESS);
			switch ((uint8_t(result.SW1) << 8) + uint8_t(result.SW2))
			{
			case 0x9000: RETURN(NO_ERROR);
			case 0x63C0: //pin retry count 0
				if (PinId == AUTH_PIN_ID)
					MessageBox(cp, L"PIN1 blocked.", label, MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
				else
					MessageBox(cp, L"PIN2 blocked.", label, MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
				RETURN(SCARD_W_CHV_BLOCKED);
			case 0x63C1: // Validate error, 1 tries left
			case 0x63C2: // Validate error, 2 tries left
			case 0x63C3: // Validate error, 3 tries left
			{
				remaining--;
				WCHAR wcBuffer[512];
				wsprintf(wcBuffer, L"A wrong PIN was presented to the card: %i retries left.", remaining);
				MessageBox(cp, wcBuffer, label, MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
				break;
			}
			case 0x6400: // Timeout (SCM)
				if (PinId == AUTH_PIN_ID)
					MessageBox(cp, L"PIN1 timeout.", label, MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
				else
					MessageBox(cp, L"PIN2 timeout.", label, MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
				RETURN(SCARD_W_CANCELLED_BY_USER);
			case 0x6401: // Cancel (OK, SCM)
				RETURN(SCARD_W_CANCELLED_BY_USER);
			default:
				MessageBox(cp, L"Unexpected input.", label, MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
				RETURN(SCARD_E_INVALID_PARAMETER);
			}
		}
	}
	RETURN(NO_ERROR);
}

DWORD WINAPI CardEnumFiles(__in PCARD_DATA  pCardData, __in LPSTR pszDirectoryName, __out_ecount(*pdwcbFileName)LPSTR *pmszFileNames, __out LPDWORD pdwcbFileName, __in DWORD dwFlags)
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

DWORD WINAPI CardGetFileInfo(__in PCARD_DATA pCardData, __in LPSTR pszDirectoryName, __in LPSTR pszFileName, __in PCARD_FILE_INFO pCardFileInfo)
{
	_log("pszDirectoryName='%s', pszFileName='%s'", NULLSTR(pszDirectoryName), NULLSTR(pszFileName));
	if (!pCardData || !pszFileName || !strlen(pszFileName) || !pCardFileInfo)
		RETURN(SCARD_E_INVALID_PARAMETER);

	if (pCardFileInfo->dwVersion != CARD_FILE_INFO_CURRENT_VERSION && pCardFileInfo->dwVersion != 0)
		RETURN(ERROR_REVISION_MISMATCH);

	pCardFileInfo->AccessCondition = EveryoneReadUserWriteAc;
	if (!pszDirectoryName || !strlen(pszDirectoryName))
	{
		if (!_strcmpi(pszFileName,"cardapps"))
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

DWORD WINAPI CardReadFile(__in PCARD_DATA pCardData, __in LPSTR pszDirectoryName, __in LPSTR pszFileName, __in DWORD dwFlags, __deref_out_bcount(*pcbData)PBYTE *ppbData, __out PDWORD pcbData)
{
	_log("pszDirectoryName=%s, pszFileName=%s, dwFlags=0x%08X", NULLSTR(pszDirectoryName), NULLSTR(pszFileName), dwFlags);
	if (!pCardData || !pszFileName || !strlen(pszFileName) || !ppbData || !pcbData || dwFlags)
		RETURN(SCARD_E_INVALID_PARAMETER);

	Files *files = (Files*)pCardData->pvVendorSpecific;
	if (!_strcmpi(pszFileName, szCACHE_FILE))
	{
		*pcbData = sizeof(cardcf);
		*ppbData = LPBYTE(pCardData->pfnCspAlloc(*pcbData));
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

			CONTAINER_MAP_RECORD *c1 = (CONTAINER_MAP_RECORD*)*ppbData;
			getMD5GUID(string((char*)files->cardid) + "_AUT", c1->wszGuid);
			c1->bFlags = CONTAINER_MAP_VALID_CONTAINER | CONTAINER_MAP_DEFAULT_CONTAINER;
			c1->wKeyExchangeKeySizeBits = WORD(keySize(pCardData, files->auth));

			CONTAINER_MAP_RECORD *c2 = (CONTAINER_MAP_RECORD*)(*ppbData + sizeof(CONTAINER_MAP_RECORD));
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

DWORD WINAPI CardQueryFreeSpace( __in PCARD_DATA pCardData, __in DWORD dwFlags, __in PCARD_FREE_SPACE_INFO pCardFreeSpaceInfo)
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

DWORD WINAPI CardQueryKeySizes(__in PCARD_DATA pCardData, __in DWORD dwKeySpec, __in DWORD dwFlags, __in PCARD_KEY_SIZES pKeySizes)
{
	if (!pCardData || !pKeySizes)
		RETURN(SCARD_E_INVALID_PARAMETER);
	_log("dwKeySpec=%u, dwFlags=0x%08X, dwVersion=%u", dwKeySpec, dwFlags, pKeySizes->dwVersion);
	if (dwFlags || dwKeySpec > 8 || dwKeySpec == 0)
		RETURN(SCARD_E_INVALID_PARAMETER);
	if (dwKeySpec != AT_SIGNATURE && dwKeySpec != AT_KEYEXCHANGE)
		RETURN(SCARD_E_UNSUPPORTED_FEATURE);
	if (pKeySizes->dwVersion > CARD_KEY_SIZES_CURRENT_VERSION)
		RETURN(ERROR_REVISION_MISMATCH);
	Files *files = (Files*)pCardData->pvVendorSpecific;
	DWORD size = keySize(pCardData, dwKeySpec == AT_KEYEXCHANGE ? files->auth : files->sign);
	pKeySizes->dwDefaultBitlen = size;
	pKeySizes->dwMaximumBitlen = size;
	pKeySizes->dwMinimumBitlen = size;
	pKeySizes->dwIncrementalBitlen = 0;
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
	if (pInfo->bContainerIndex != AUTH_CONTAINER_INDEX && pInfo->bContainerIndex != SIGN_CONTAINER_INDEX )
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

DWORD WINAPI CardSignData(__in PCARD_DATA pCardData, __in PCARD_SIGNING_INFO pInfo)
{
	if (!pCardData || !pInfo || !pInfo->pbData)
		RETURN(SCARD_E_INVALID_PARAMETER);
	_log("dwVersion=%u, bContainerIndex=%u, dwKeySpec=%u"", dwSigningFlags=0x%08X, aiHashAlg=0x%08X, cbData=%u",
		pInfo->dwVersion, pInfo->bContainerIndex, pInfo->dwKeySpec, pInfo->dwSigningFlags, pInfo->aiHashAlg, pInfo->cbData);
	pInfo->cbSignedData = 0;
	if (pInfo->bContainerIndex != AUTH_CONTAINER_INDEX && pInfo->bContainerIndex != SIGN_CONTAINER_INDEX)
		RETURN(SCARD_E_NO_KEY_CONTAINER);
	if (pInfo->dwVersion != CARD_SIGNING_INFO_BASIC_VERSION && pInfo->dwVersion != CARD_SIGNING_INFO_CURRENT_VERSION)
		RETURN(ERROR_REVISION_MISMATCH);
	if (pInfo->dwKeySpec != AT_KEYEXCHANGE && pInfo->dwKeySpec != AT_SIGNATURE)
		RETURN(SCARD_E_INVALID_PARAMETER);
	DWORD dwFlagMask = CARD_PADDING_INFO_PRESENT | CARD_BUFFER_SIZE_ONLY | CARD_PADDING_NONE | CARD_PADDING_PKCS1 | CARD_PADDING_PSS;
	if (pInfo->dwSigningFlags & (~dwFlagMask))
		RETURN(SCARD_E_INVALID_PARAMETER);

	ALG_ID hashAlg = pInfo->aiHashAlg;
	if (CARD_PADDING_INFO_PRESENT & pInfo->dwSigningFlags)
	{
		if (CARD_PADDING_PKCS1 != pInfo->dwPaddingType)
			RETURN(SCARD_E_UNSUPPORTED_FEATURE);
		BCRYPT_PKCS1_PADDING_INFO *pinf = (BCRYPT_PKCS1_PADDING_INFO*)pInfo->pPaddingInfo;
		if (!pinf->pszAlgId) hashAlg = CALG_SSL3_SHAMD5;
		else if (wcscmp(pinf->pszAlgId, L"MD5") == 0) hashAlg = CALG_MD5;
		else if (wcscmp(pinf->pszAlgId, L"SHA1") == 0) hashAlg = CALG_SHA1;
		else if (wcscmp(pinf->pszAlgId, L"SHA256") == 0) hashAlg = CALG_SHA_256;
		else if (wcscmp(pinf->pszAlgId, L"SHA384") == 0) hashAlg = CALG_SHA_384;
		else if (wcscmp(pinf->pszAlgId, L"SHA512") == 0) hashAlg = CALG_SHA_512;
		else RETURN(SCARD_E_UNSUPPORTED_FEATURE);
	}
	if (GET_ALG_CLASS(hashAlg) != ALG_CLASS_HASH)
		RETURN(SCARD_E_INVALID_PARAMETER);

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
	default: RETURN(SCARD_E_UNSUPPORTED_FEATURE);
	}
	vector<byte> hash(pInfo->pbData, pInfo->pbData + pInfo->cbData);
	if (!(pInfo->dwSigningFlags & CRYPT_NOHASHOID))
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
	cmd.insert(cmd.end(), hash.data(), hash.data() + hash.size());
	Result result = transfer(cmd, pCardData->hScard);
	if (!result)
		RETURN(SCARD_W_SECURITY_VIOLATION);

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
DECLARE_UNSUPPORTED(CardUnblockPin(__in PCARD_DATA  pCardData,
	__in LPWSTR pwszUserId,
	__in_bcount(cbAuthenticationData)PBYTE pbAuthenticationData,
	__in DWORD cbAuthenticationData,
	__in_bcount(cbNewPinData)PBYTE pbNewPinData,
	__in DWORD cbNewPinData,
	__in DWORD cRetryCount,
	__in DWORD dwFlags))
DECLARE_UNSUPPORTED(CardDestroyDHAgreement(__in PCARD_DATA pCardData,
	__in BYTE bSecretAgreementIndex,
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
