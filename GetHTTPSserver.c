
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

#define USER_AGENT_SIZE     100
#define RESOURCE_PATH_SIZE  100
#define REQUEST_TYPE_SIZE   100


HINTERNET WinHttpOpenF(char* userAgent) {
    WCHAR* userAgentW = (WCHAR*)xcalloc(USER_AGENT_SIZE, sizeof(WCHAR));
    if (userAgentW != NULL) {
        HINTERNET hSession;

        if (userAgent == NULL)
            swprintf(userAgentW, USER_AGENT_SIZE, L"%hs", userAgentList[rand() % 5]);
        else
            swprintf(userAgentW, USER_AGENT_SIZE, L"%hs", userAgent);
        // Use WinHttpOpen to obtain a session handle.
        hSession = WinHttpOpen(userAgentW, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        free(userAgentW);
        return hSession;
    }
    return NULL;
}
HINTERNET WinHttpConnectF(HINTERNET hSession,char* ipAddress, int port) {
    WCHAR* ipAddressW = (WCHAR*)xcalloc(IP_ADDRESS_LEN, sizeof(WCHAR));
    if (ipAddressW != NULL) {
        HINTERNET hConnect;

        swprintf(ipAddressW, IP_ADDRESS_LEN, L"%hs", ipAddress);
        hConnect = WinHttpConnect(hSession, ipAddressW, port, 0);
        free(ipAddressW);
        return hConnect;
    }
    return NULL;
}
HINTERNET WinHttpOpenRequestF(HINTERNET hConnect, char* requestType, char* resourcePath) {
    WCHAR* resourcePathW = (WCHAR*)xcalloc(RESOURCE_PATH_SIZE, sizeof(WCHAR));
    if (resourcePathW != NULL) {
        WCHAR* requestTypeW = (WCHAR*)xcalloc(REQUEST_TYPE_SIZE, sizeof(WCHAR));
        if (requestTypeW != NULL) {
            HINTERNET hRequest;

            swprintf(resourcePathW, RESOURCE_PATH_SIZE, L"%hs", resourcePath);
            swprintf(requestTypeW, REQUEST_TYPE_SIZE, L"%hs", requestType);

            hRequest = WinHttpOpenRequest(hConnect, requestTypeW, resourcePathW, L"HTTP/1.1", WINHTTP_NO_REFERER,
                WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
            free(requestTypeW);
            free(resourcePathW);
            return hRequest;
        }
        free(resourcePathW);
    }
    return NULL;
}
BOOL WinHttpSetOptionF(HINTERNET hRequest) {
    //DWORD secureFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    DWORD secureFlags = SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS;
    DWORD redirectionFlags = WINHTTP_DISABLE_REDIRECTS;

    if (!WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, (LPVOID)&secureFlags, sizeof(DWORD)))
        return FALSE;
    if (!WinHttpSetOption(hRequest, WINHTTP_OPTION_DISABLE_FEATURE, (LPVOID)&redirectionFlags, sizeof(DWORD)))
        return FALSE;

    return TRUE;
}


DWORD RequestHeaderSize(char* pServerResponce) {
    const char delim1[] = "\r\n\r\n";
    DWORD requestSize = 0;

    char* ptr1 = strstr(pServerResponce, delim1);
    if (ptr1 == NULL)
        return FALSE;
    requestSize = (DWORD)((ptr1 + sizeof(delim1)) - pServerResponce);
    return requestSize;
}

DWORD RequestHeader(HINTERNET hRequest, char** pServerResponce, FILE* pFile) {
    DWORD dwSize = 0;

    if (!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, NULL,
        &dwSize, WINHTTP_NO_HEADER_INDEX)) {
        DWORD lastError = GetLastError();

        if (lastError == ERROR_INSUFFICIENT_BUFFER) {
            WCHAR* lpOutBuffer;

            *pServerResponce = (char*)malloc(dwSize + (size_t)1);
            if (*pServerResponce == NULL)
                return FALSE;

            lpOutBuffer = (WCHAR*)xcalloc(dwSize, sizeof(WCHAR));
            if (lpOutBuffer == NULL)
                return FALSE;


            if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX,
                lpOutBuffer, &dwSize, WINHTTP_NO_HEADER_INDEX)) {
                sprintf_s(*pServerResponce, dwSize + (size_t)1, "%ws", (WCHAR*)lpOutBuffer);
                free(lpOutBuffer);
                return dwSize;
            } else
                PrintMsgError2("WinHttpQueryHeaders: Error has occurred");
        } else
            PrintMsgError2("WinHttpOpen: Error has occurred");
    } else
        PrintMsgError2("WinHttpQueryHeaders: Error in WinHttpQueryDataAvailable");
    return FALSE;
}
BOOL RequestBody(HINTERNET hRequest, char** serverResponce, FILE* pFile) {
    DWORD dwSize = 0;
    DWORD srvResponseSize; 
    DWORD dwTmp = RequestHeaderSize(*serverResponce);
    if (dwTmp == 0)
        return FALSE;

    srvResponseSize = dwTmp;
    if (WinHttpQueryDataAvailable(hRequest, &dwSize)) {
        while (dwSize > 0) {
            DWORD dwDownloaded = 0;

            srvResponseSize += dwSize;
            *serverResponce = (char*)xrealloc(*serverResponce, srvResponseSize + 1);
            if (*serverResponce == NULL)
                return FALSE;
            if (!WinHttpReadData(hRequest, (LPVOID)((*serverResponce) + dwTmp), dwSize, &dwDownloaded)) {
                PrintOut(pFile, "\t[X] Error %lu in WinHttpReadData.\n", GetLastError());
                return FALSE;
            }
            dwTmp += dwSize;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
                PrintOut(pFile, "\t[X] Error %lu in WinHttpQueryDataAvailable.\n", GetLastError());
                return FALSE;
            }
        }

        (*serverResponce)[srvResponseSize] = 0x00;
        return srvResponseSize;
    } else
        PrintOut(pFile, "\t[X] Error %lu in WinHttpQueryDataAvailable.\n", GetLastError());
    return FALSE;
}

VOID PrintCertInfo(char* title, LPWSTR lpszSubjectInfo, FILE* pFile) {
    LPWSTR pwc = wcschr(lpszSubjectInfo, L'\n');
    if (pwc) {
        INT64 sizeSize = pwc - lpszSubjectInfo;
        PrintOut(pFile, "\t\t[i] %s:\t%.*ws\n", title, (int)sizeSize, lpszSubjectInfo);
        while (pwc != NULL) {
            pwc++;
            LPWSTR pwcTemp = pwc;
            pwc = wcschr(pwc, L'\n');
            if (pwc != NULL) {
                sizeSize = pwc - pwcTemp;
                PrintOut(pFile, "\t\t\t\t%.*ws\n", (int)sizeSize, pwcTemp);
            } else
                PrintOut(pFile, "\t\t\t\t%ws\n", pwcTemp);
        }
    }
}

typedef WINHTTP_CERTIFICATE_INFO* PWINHTTP_CERTIFICATE_INFO;
BOOL GetServerCertInfo(HINTERNET hSession, FILE* pFile) {

    BOOL bResult = FALSE;
    DWORD dwSize = 0;
    PWINHTTP_CERTIFICATE_INFO pCertInfo = NULL;

    WinHttpQueryOption(hSession, WINHTTP_OPTION_SECURITY_CERTIFICATE_STRUCT, NULL, &dwSize);

    if (dwSize > 0) {
        pCertInfo = (PWINHTTP_CERTIFICATE_INFO)malloc(dwSize);
        if (pCertInfo != NULL) {
            if (WinHttpQueryOption(hSession, WINHTTP_OPTION_SECURITY_CERTIFICATE_STRUCT, pCertInfo, &dwSize)) {
                printf("\t[HTTPS] Certificate Chain Information:\n");

                if (pCertInfo->lpszSubjectInfo)
                    PrintCertInfo("Subject",pCertInfo->lpszSubjectInfo,pFile);
                if (pCertInfo->lpszIssuerInfo)
                    PrintCertInfo("Issuer", pCertInfo->lpszIssuerInfo,pFile);
                if (pCertInfo->lpszProtocolName)
                    PrintOut(pFile, "\t\t[i] Protocol:\t%ws\n", pCertInfo->lpszProtocolName);
                if (pCertInfo->lpszSignatureAlgName)
                    PrintOut(pFile, "\t\t[i] Signature Algorithm: %ws\n", pCertInfo->lpszSignatureAlgName);
                if (pCertInfo->lpszEncryptionAlgName)
                    PrintOut(pFile, "\t\t[i] Encryption Algorithm: %ws\n", pCertInfo->lpszEncryptionAlgName);
                PrintOut(pFile, "\t\t[i] Key Size:\t%d\n", pCertInfo->dwKeySize);
                LocalFree(pCertInfo->lpszSubjectInfo);
                LocalFree(pCertInfo->lpszIssuerInfo);
                bResult = TRUE;
            }
            free(pCertInfo);
        }
    }
    return bResult;
}


BOOL WinHttpSetCustomHeader(HINTERNET hRequest, char* customHeader, FILE* pFile) {
    if (customHeader != NULL && customHeader[0] != 0x00) {
        WCHAR* wCustomHeader = (WCHAR*)xcalloc(1042, sizeof(WCHAR));
        if (wCustomHeader == NULL)
            return FALSE;
        int CustHeadSize = swprintf(wCustomHeader, 1042, L"%hs", customHeader);

        if (!WinHttpAddRequestHeaders(hRequest, wCustomHeader, CustHeadSize, WINHTTP_ADDREQ_FLAG_ADD)) {
            printf("\t[-] Fail to set custom header (%lu)!\n", GetLastError());
            free(wCustomHeader);
            return FALSE;
        }
        free(wCustomHeader);
    }
    return TRUE;
}


UINT GetHttpsServer(char* ipAddress, int port, char* requestType, char* resourcePath, char* userAgent, char** serverResponce, char* customHeader, BOOL showInfoCert, FILE* pFile) {
    HINTERNET hSession = WinHttpOpenF(userAgent);
    if (hSession) {
        HINTERNET hConnect = WinHttpConnectF(hSession, ipAddress, port);
        if (hConnect) {
            HINTERNET hRequest = WinHttpOpenRequestF(hConnect, requestType, resourcePath);
            if (hRequest) {
                if (WinHttpSetOptionF(hRequest)) {
                    WinHttpSetCustomHeader(hRequest, customHeader, pFile);
                    
                    // ERROR_WINHTTP_SECURE_FAILURE -> WinHttpSendRequest:Error 12175 has occurred.
                    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
                        if (WinHttpReceiveResponse(hRequest, NULL)) {

                            DWORD srvResponseSize = RequestHeader(hRequest, serverResponce, pFile);


                            // OK FOR DIR ENUM ??? 
                            if (srvResponseSize > 0 && strcmp(requestType, "HEAD") != 0) {
                                if(showInfoCert)
                                    GetServerCertInfo(hRequest, pFile);
                                srvResponseSize = RequestBody(hRequest, serverResponce, pFile);
                            }
                                
                            WinHttpCloseHandle(hRequest);
                            WinHttpCloseHandle(hConnect);
                            WinHttpCloseHandle(hSession);
                            return srvResponseSize;
                        } else 
                            PrintMsgError2("WinHttpReceiveResponse:Error has occurred ");
                    } else {
                        PrintMsgError2("WinHttpSendRequest:Error has occurred ");
                    }
                        
                }else
                    PrintMsgError2("WinHttpSetOption:Error has occurred ");
                WinHttpCloseHandle(hRequest);
            } else
                PrintMsgError2("WinHttpOpenRequest:Error has occurred");
            WinHttpCloseHandle(hConnect);
        } else
            PrintMsgError2("WinHttpConnect:Error has occurred");
        WinHttpCloseHandle(hSession);
    } else
        PrintMsgError2("WinHttpOpen:Error has occurred");
    return FALSE;
}

/*
ERROR_WINHTTP_SECURE_FAILURE
*/