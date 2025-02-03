#pragma once

#include <Windows.h>
#include <WinInet.h>

#pragma comment (lib, "Wininet.lib")

BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize);