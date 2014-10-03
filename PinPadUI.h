
#ifndef __EXTERNALPINUI_H__
#define __EXTERNALPINUI_H__


typedef struct _EXTERNAL_INFO
{
	HWND			hwndParentWindow;
	int				pinType;
	int				langId;
	
} EXTERNAL_INFO, *PEXTERNAL_INFO;

HRESULT CALLBACK TaskDialogCallbackProcPinEntry(HWND hwnd, UINT uNotification, WPARAM wParam, LPARAM lParam, LONG_PTR dwRefData);
DWORD WINAPI DialogThreadEntry(LPVOID lpParam);

#endif
