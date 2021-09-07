#include <windows.h>
#include <stdio.h>
#include <winhttp.h>

#include "ToolsHTTP.h"
#include "Network.h"

#define USER_AGENT_SIZE     100
#define IP_ADDRESS_SIZE     16          // TO REMOVE !!!
#define RESOURCE_PATH_SIZE  100
#define REQUEST_TYPE_SIZE   100


HINTERNET WinHttpOpenF(char* userAgent) {
    WCHAR* userAgentW = (WCHAR*)calloc(USER_AGENT_SIZE, sizeof(WCHAR));
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
    WCHAR* ipAddressW = (WCHAR*)calloc(IP_ADDRESS_SIZE, sizeof(WCHAR));
    if (ipAddressW != NULL) {
        HINTERNET hConnect;

        swprintf(ipAddressW, IP_ADDRESS_SIZE, L"%hs", ipAddress);
        hConnect = WinHttpConnect(hSession, ipAddressW, port, 0);
        free(ipAddressW);
        return hConnect;
    }
    return NULL;
}
HINTERNET WinHttpOpenRequestF(HINTERNET hConnect, char* requestType, char* resourcePath) {
    WCHAR* resourcePathW = (WCHAR*)calloc(RESOURCE_PATH_SIZE, sizeof(WCHAR));
    if (resourcePathW != NULL) {
        WCHAR* requestTypeW = (WCHAR*)calloc(REQUEST_TYPE_SIZE, sizeof(WCHAR));
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
    DWORD secureFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
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

            lpOutBuffer = (WCHAR*)calloc(dwSize, sizeof(WCHAR));
            if (lpOutBuffer == NULL)
                return FALSE;


            if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX,
                lpOutBuffer, &dwSize, WINHTTP_NO_HEADER_INDEX)) {
                sprintf_s(*pServerResponce, dwSize + (size_t)1, "%ws", (WCHAR*)lpOutBuffer);
                free(lpOutBuffer);
                return dwSize;
            } else
                printOut(pFile, "\t[X] WinHttpQueryHeaders: Error %d has occurred.\n", lastError);
        } else
            printOut(pFile, "\t[X] WinHttpOpen: Error %d has occurred.\n", lastError);
    } else
        printOut(pFile, "\t[X] WinHttpQueryHeaders: Error %u in WinHttpQueryDataAvailable.\n", GetLastError());
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
            *serverResponce = (char*)realloc(*serverResponce, srvResponseSize + 1);
            if (*serverResponce == NULL)
                return FALSE;
            if (!WinHttpReadData(hRequest, (LPVOID)((*serverResponce) + dwTmp), dwSize, &dwDownloaded)) {
                printOut(pFile, "\t[X] Error %u in WinHttpReadData.\n", GetLastError());
                return FALSE;
            }
            dwTmp += dwSize;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
                printOut(pFile, "\t[X] Error %u in WinHttpQueryDataAvailable.\n", GetLastError());
                return FALSE;
            }
        }

        (*serverResponce)[srvResponseSize] = 0x00;
        return srvResponseSize;
    } else
        printOut(pFile, "\t[X] Error %u in WinHttpQueryDataAvailable.\n", GetLastError());
    return FALSE;
}


typedef WINHTTP_CERTIFICATE_INFO* PWINHTTP_CERTIFICATE_INFO;
BOOL GetServerCertInfo(HINTERNET hSession) {

    BOOL bResult = FALSE;
    DWORD dwSize = 0;
    PWINHTTP_CERTIFICATE_INFO pCertInfo = NULL;

    WinHttpQueryOption(hSession, WINHTTP_OPTION_SECURITY_CERTIFICATE_STRUCT, NULL, &dwSize);

    if (dwSize > 0) {
        pCertInfo = (PWINHTTP_CERTIFICATE_INFO)malloc(dwSize);
        if (pCertInfo != NULL) {
            if (WinHttpQueryOption(hSession, WINHTTP_OPTION_SECURITY_CERTIFICATE_STRUCT, pCertInfo, &dwSize)) {
                printf("\t[+] Certificate Chain Information:\n");

                if (pCertInfo->lpszSubjectInfo)
                    printf("\t\t[i] Subject: %ws\n", pCertInfo->lpszSubjectInfo);
                if (pCertInfo->lpszIssuerInfo)
                    printf("\t\t[i] Issuer: %ws\n", pCertInfo->lpszIssuerInfo);
                if (pCertInfo->lpszProtocolName)
                    printf("\t\t[i] Protocol: %ws\n", pCertInfo->lpszProtocolName);
                if (pCertInfo->lpszSignatureAlgName)
                    printf("\t\t[i] Signature Algorithm: %ws\n", pCertInfo->lpszSignatureAlgName);
                if (pCertInfo->lpszEncryptionAlgName)
                    printf("\t\t[i] Encryption Algorithm: %ws\n", pCertInfo->lpszEncryptionAlgName);
                printf("\t\t[i] Key Size: %d\n", pCertInfo->dwKeySize);
                LocalFree(pCertInfo->lpszSubjectInfo);
                LocalFree(pCertInfo->lpszIssuerInfo);
                bResult = TRUE;
            }
            free(pCertInfo);
        }
    }
    return bResult;
}

UINT GetHttpsServer(char* ipAddress, int port, char* requestType, char* resourcePath, char* userAgent, char** serverResponce, FILE* pFile) {
    HINTERNET hSession = WinHttpOpenF(userAgent);
    if (hSession) {
        HINTERNET hConnect = WinHttpConnectF(hSession, ipAddress, port);
        if (hConnect) {
            HINTERNET hRequest = WinHttpOpenRequestF(hConnect, requestType, resourcePath);
            if (hRequest) {
                if (WinHttpSetOptionF(hRequest)) {

                    

                    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
                        if (WinHttpReceiveResponse(hRequest, NULL)) {

                            DWORD srvResponseSize = RequestHeader(hRequest, serverResponce, pFile);
                            if (srvResponseSize > 0 && strcmp(requestType, "HEAD") != 0) {
                                GetServerCertInfo(hRequest);
                                srvResponseSize = RequestBody(hRequest, serverResponce, pFile);
                            }
                                
                            WinHttpCloseHandle(hRequest);
                            WinHttpCloseHandle(hConnect);
                            WinHttpCloseHandle(hSession);
                            return srvResponseSize;
                        } else
                            printOut(pFile, "\t[X] WinHttpReceiveResponse:Error %d has occurred.\n", GetLastError());
                    } else
                        printOut(pFile, "\t[X] WinHttpSendRequest:Error %d has occurred.\n", GetLastError());



                }else
                    printOut(pFile, "\t[X] WinHttpSetOption:Error %d has occurred.\n", GetLastError());
                WinHttpCloseHandle(hRequest);
            } else
                printOut(pFile, "\t[X] WinHttpOpenRequest:Error %d has occurred.\n", GetLastError());
            WinHttpCloseHandle(hConnect);
        } else
            printOut(pFile, "\t[X] WinHttpConnect:Error %d has occurred.\n", GetLastError());
        WinHttpCloseHandle(hSession);
    } else
        printOut(pFile, "\t[X] WinHttpOpen:Error %d has occurred.\n", GetLastError());
    return FALSE;
}