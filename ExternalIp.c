
/* 
 * NetworkInfoGather
 * Copyright (C) 2023  SecuProject
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <windows.h>
#include <stdio.h>
#include <winhttp.h>

#include "ToolsHTTP.h"
#include "Network.h"
#include "Message.h"

BOOL PrintWanIpAddressTest(LPCWSTR serverName) {
    BOOL  bResults = FALSE;
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    LPCWSTR userAgent = L"Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36";

    hSession = WinHttpOpen(userAgent, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (hSession) {
        hConnect = WinHttpConnect(hSession, serverName, INTERNET_DEFAULT_HTTP_PORT, 0);
        if (hConnect) {
            hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
            if (hRequest) {
                bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
                bResults = WinHttpReceiveResponse(hRequest, NULL);
                if (bResults) {
                    DWORD dwSize = 1;
                    DWORD dwDownloaded = 0;

                    while (dwSize > 0) {
                        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
                            printf("[x] Error %u in WinHttpQueryDataAvailable.\n", GetLastError());
                            return FALSE;
                        }
                        if (!dwSize)
                            return FALSE;
                        char* pszOutBuffer = (char*)malloc(dwSize + 1);
                        if (pszOutBuffer == NULL) {
                            printf("[x] Out of memory\n");
                            free(pszOutBuffer);
                            return FALSE;
                        }
                        ZeroMemory(pszOutBuffer, dwSize + 1);
                        if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded)) {
                            printf("[x] Error %u in WinHttpReadData.\n", GetLastError());
                        } else {
                            printf("[+] The host ip address is %s", pszOutBuffer);
                            free(pszOutBuffer);
                            return TRUE;
                        }
                        free(pszOutBuffer);
                        if (!dwDownloaded)
                            break;
                    }
                } else {
                    printf("[x] Error %d has occurred.\n", GetLastError());
                }
                WinHttpCloseHandle(hRequest);
            }
            WinHttpCloseHandle(hConnect);
        }
        WinHttpCloseHandle(hSession);
    }
    return FALSE;
}

BOOL ExternalIp() {
    const LPCWSTR serverNameList[] = {
        L"checkip.amazonaws.com",
        L"icanhazip.com"
    };
    for (UINT i = 0; i < sizeof(serverNameList) / sizeof(LPCWSTR); i++)
        if (PrintWanIpAddressTest(serverNameList[i]))
            return TRUE;
    return FALSE;
}