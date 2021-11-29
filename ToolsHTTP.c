#include <windows.h>
#include <stdio.h>

#include "NetDiscovery.h"
#include "ToolsHTTP.h"
#include "Network.h"
#include "GetHTTPserver.h"
#include "GetHTTPSserver.h"
#include "EnumFRITZBox.h"

#include "HttpWordlist.h"
#include "ToolsHTTP.h"
//#include "wordListCommon.h"

const char* userAgentList[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36",
    "Mozilla/5.0 CK={} (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0"
};
const char* invalideUrlPath[] = {
    "/frjguoijefezhof.php",             // Add rand Str
    "/fezfez-fee-feeeee-vfdfd.txt",     // Add rand Str
    "/testaaaFkefezf.html",             // Add rand Str
};

const StrucStrDev structStrDev[] = {
    //{"\"bluBarTitle\":\"FRITZ!Box "," Cable",FRITZBox} ,
    {"\"bluBarTitle\":\"FRITZ!Box ","\"",FRITZBox} ,
    {"product.trim() === 'TrueNAS'",NULL,TrueNAS} ,
    {"test","Cable",UnknownType} ,
};

UINT GetHttpReturnCode(char* serverResponce) {
    const char delim1[] = "HTTP/1.1 ";
    const char delim2[] = " ";

    char* ptr1 = strstr(serverResponce, delim1);
    if (ptr1 != NULL) {
        char* ptr2;

        ptr1 = ptr1 + sizeof(delim1) - 1;
        ptr2 = strstr(ptr1, delim2);
        if (ptr2 != NULL && ptr2 - ptr1 < SERVER_VERSION_SIZE) {
            char* buffer = (char*)malloc(SERVER_VERSION_SIZE);
            if (buffer == NULL)
                return FALSE;

            UINT responceCode;
            strncpy_s(buffer, SERVER_VERSION_SIZE, ptr1, ptr2 - ptr1);
            responceCode = atoi(buffer);
            free(buffer);
            return responceCode;
        }
    }
    return FALSE;
}

UINT GetHttpContentLen(char* serverResponce) {
    const char delim1[] = "Content-Length: ";
    const char delim2[] = "\r\n";

    char* ptr1 = strstr(serverResponce, delim1);
    if (ptr1 != NULL) {
        char* ptr2;

        ptr1 = ptr1 + sizeof(delim1) - 1;
        ptr2 = strstr(ptr1, delim2);
        if (ptr2 != NULL && ptr2 - ptr1 < SERVER_VERSION_SIZE && ptr2 - ptr1 > 0) {
            char* buffer = (char*)malloc(SERVER_VERSION_SIZE);
            if (buffer == NULL)
                return FALSE;

            UINT contentLen;
            strncpy_s(buffer, SERVER_VERSION_SIZE, ptr1, ptr2 - ptr1);
            contentLen = atoi(buffer);
            free(buffer);
            return contentLen;
        }
    }
    return FALSE;
}

BOOL GetHttpHeaderStr(const char* delim1, int sizeDelim1, char* serverResponce, char* serverVersion, int* bufferSize) {
    const char delim2[] = "\r\n";
    char* ptr1 = strstr(serverResponce, delim1);

    if (ptr1 != NULL) {
        char* ptr2;
        ptr1 = ptr1 + sizeDelim1;
        ptr2 = strstr(ptr1, delim2);
        if (ptr2 != NULL && ptr2 - ptr1 < *bufferSize) {
            strncpy_s(serverVersion, *bufferSize, ptr1, ptr2 - ptr1);
            *bufferSize = (int)(ptr2 - ptr1 + 1);
            return TRUE;
        }
    }
    return FALSE;
}

BOOL GetHttpHeaderServerVersion(PHTTP_STRUC httpStruct) {
    UINT serverVersionSize = SERVER_VERSION_SIZE;
    httpStruct->ServerName = (char*)malloc(SERVER_VERSION_SIZE);
    if (httpStruct->ServerName != NULL) {
        const char delim1[] = "Server:";
        if (GetHttpHeaderStr(delim1, sizeof(delim1), httpStruct->rawData, httpStruct->ServerName, &serverVersionSize)) {
            httpStruct->ServerName = (char*)realloc(httpStruct->ServerName, serverVersionSize);
            if (httpStruct->ServerName == NULL)
                return FALSE;
            return TRUE;
        }
        free(httpStruct->ServerName);
    }
    httpStruct->ServerName = NULL;
    return FALSE;
}
BOOL GetHttpHeaderPowerby(PHTTP_STRUC httpStruct) {
    UINT serverVersionSize = SERVER_VERSION_SIZE;
    httpStruct->poweredBy = (char*)malloc(SERVER_VERSION_SIZE);
    if (httpStruct->poweredBy != NULL) {
        const char delim1[] = "X-Powered-By:";
        if (GetHttpHeaderStr(delim1, sizeof(delim1), httpStruct->rawData, httpStruct->poweredBy, &serverVersionSize)) {
            httpStruct->poweredBy = (char*)realloc(httpStruct->poweredBy, serverVersionSize);
            if (httpStruct->poweredBy == NULL)
                return FALSE;
            return TRUE;
        }
        free(httpStruct->poweredBy);
    }
    httpStruct->poweredBy = NULL;
    return FALSE;
}
BOOL GetHttpHeaderContentType(PHTTP_STRUC httpStruct) {
    UINT serverVersionSize = SERVER_VERSION_SIZE;
    httpStruct->contentType = (char*)malloc(SERVER_VERSION_SIZE);
    if (httpStruct->contentType != NULL) {
        const char delim1[] = "Content-Type:";
        if (GetHttpHeaderStr(delim1, sizeof(delim1), httpStruct->rawData, httpStruct->contentType, &serverVersionSize)) {
            httpStruct->contentType = (char*)realloc(httpStruct->contentType, serverVersionSize);
            if (httpStruct->contentType == NULL)
                return FALSE;
            return TRUE;
        }
        free(httpStruct->contentType);
    }
    httpStruct->contentType = NULL;
    return FALSE;
}
BOOL GetHttpHeaderRedirection(PHTTP_STRUC httpStruct) {
    UINT serverVersionSize = SERVER_VERSION_SIZE;
    httpStruct->redirectionPath = (char*)malloc(SERVER_VERSION_SIZE);
    if (httpStruct->redirectionPath != NULL) {
        const char delim1[] = "Location:";
        if (GetHttpHeaderStr(delim1, sizeof(delim1), httpStruct->rawData, httpStruct->redirectionPath, &serverVersionSize)) {
            httpStruct->redirectionPath = (char*)realloc(httpStruct->redirectionPath, serverVersionSize);
            if (httpStruct->redirectionPath == NULL)
                return FALSE;
            return TRUE;
        }
        free(httpStruct->redirectionPath);
    }
    httpStruct->redirectionPath = NULL;
    return FALSE;
}

BOOL GetHttpBody(PHTTP_STRUC httpStruct) {
    const char delim1[] = "\r\n\r\n";
    char* ptr1 = strstr(httpStruct->rawData, delim1);
    if (ptr1 != NULL) {
        httpStruct->pContent = ptr1 + sizeof(delim1);
        return TRUE;
    }
    return FALSE;
}

BOOL GetHttpRequestInfo(PHTTP_STRUC httpStruct) {

    httpStruct->returnCode = GetHttpReturnCode(httpStruct->rawData);
    httpStruct->contentLen = GetHttpContentLen(httpStruct->rawData);

    GetHttpHeaderServerVersion(httpStruct);
    GetHttpHeaderPowerby(httpStruct);
    GetHttpHeaderContentType(httpStruct);

    /*if(httpStruct->contentLen > 0)
        GetHttpBody(httpStruct);*/
    GetHttpBody(httpStruct);

    if (IS_HTTP_REDIRECTS(httpStruct->returnCode))
        GetHttpHeaderRedirection(httpStruct);
    else
        httpStruct->redirectionPath = NULL;

    return TRUE;
}



PHTTP_STRUC InitPHTTP_STRUC(UINT nbElement) {
    PHTTP_STRUC httpStruct = (PHTTP_STRUC)calloc(nbElement, sizeof(HTTP_STRUC));
    if (httpStruct == NULL)
        return NULL;

    for (UINT i = 0; i < nbElement; i++) {
        httpStruct[i].ServerName = NULL;
        httpStruct[i].poweredBy = NULL;
        httpStruct[i].contentType = NULL;
        httpStruct[i].pContent = NULL;
        httpStruct[i].rawData = NULL;
    }
    return httpStruct;
}

VOID FreePHTTP_STRUC(PHTTP_STRUC pHTTP_STRUC) {
    if (pHTTP_STRUC->rawData != NULL)
        free(pHTTP_STRUC->rawData);
    if (pHTTP_STRUC->ServerName != NULL)
        free(pHTTP_STRUC->ServerName);
    if (pHTTP_STRUC->poweredBy != NULL)
        free(pHTTP_STRUC->poweredBy);
    if (pHTTP_STRUC->contentType != NULL)
        free(pHTTP_STRUC->contentType);
    if (pHTTP_STRUC->redirectionPath != NULL)
        free(pHTTP_STRUC->redirectionPath);
    free(pHTTP_STRUC);
}

PHTTP_STRUC GetHttpRequest(char* ipAddress, int port, char* path, char* requestType, BOOL isSSL, FILE* pFile) {
    PHTTP_STRUC httpStruct = InitPHTTP_STRUC(1);
    if (httpStruct == NULL)
        return NULL;

    httpStruct->requestPath = path;

    if (isSSL)
        httpStruct->responseLen = GetHttpsServer(ipAddress, port, requestType, path, NULL, &(httpStruct->rawData), pFile);
    else
        httpStruct->responseLen = GetHttpServer(ipAddress, port, requestType, path, NULL, &(httpStruct->rawData), pFile); // GET
    if (httpStruct->responseLen == 0) {
        printOut(pFile, "\t[-] Page not available !\n");
        free(httpStruct->rawData);
        free(httpStruct);
        return NULL;
    }
    if (httpStruct->rawData == NULL) {
        printOut(pFile, "\t[-] Response data error !\n");
        free(httpStruct);
        return NULL;
    }



    if (!GetHttpRequestInfo(httpStruct)) {
        printOut(pFile, "\t[-] Fail to retrieve information form the request !\n");
        free(httpStruct->rawData);
        free(httpStruct);
        return NULL;
    }
    return httpStruct;
}
/*PHTTP_STRUC GetHttpRequestHead(char* ipAddress, int port, char* path, FILE* pFile) {
    PHTTP_STRUC httpStruct = InitPHTTP_STRUC(1);
    if (httpStruct == NULL)
        return NULL;

    httpStruct->requestPath = path;
    httpStruct->responseLen = GetHttpServer(ipAddress, port, "HEAD", path, NULL, httpStruct->rawData, pFile);

    if (httpStruct->responseLen == 0) {
        printOut(pFile, "\t[-] Page not available !\n");
        free(httpStruct->rawData);
        free(httpStruct);
        return NULL;
    }
    httpStruct->rawData = (char*)realloc(httpStruct->rawData, GET_REQUEST_SIZE);
    if (httpStruct->rawData == NULL) {
        free(httpStruct);
        return NULL;
    }

    if (!GetHttpRequestInfo(httpStruct)) {
        printOut(pFile, "\t[-] Fail to retrieve information form the request !\n");
        free(httpStruct->rawData);
        free(httpStruct);
        return NULL;
    }
    return httpStruct;
}*/
BOOL TestAllHttpsRedirect(PHTTP_STRUC* pHttpStructInvalide,char* ipAddress, int port,FILE* pFile) {
    // ipAddress, port, (char*)invalideUrlPath[i]
    int match = 0;
    char* tmpPath = (char*)malloc(MAX_PATH);
    if (tmpPath == NULL)
        return TRUE;

    for (int i = 0; i < ARRAY_SIZE_CHAR(invalideUrlPath); i++) {
        sprintf_s(tmpPath, MAX_PATH, "https://%s%s", ipAddress, invalideUrlPath[i]);
        if (strcmp(tmpPath, pHttpStructInvalide[i]->redirectionPath) == 0)
            match++;
        else {
            sprintf_s(tmpPath, MAX_PATH, "https://%s:443%s", ipAddress, invalideUrlPath[i]);
            if (strcmp(tmpPath, pHttpStructInvalide[i]->redirectionPath) == 0)
                match++;
        }
    }

    free(tmpPath);
    if (match == 3)
        printOut(pFile, "\t\tAll requests return https://%s/[PAGE_NAME]\n", ipAddress);
    return match == 3;


    // http://192.168.59.45/.bash_history       301 -  0     -> https://192.168.59.45/.bash_history
}


/*
1. Check if val are the same:
    - returnCode
    - contentLen
2. If returnCode >= 400 && returnCode < 599
    * Use returnCode
3. if returnCode >= 300 && returnCode < 400
    if redirectionPath of all 3 to same but HTTPS
        BASE_NOT_FOUND

    if redirectionPath the same for all 3
        * returnCode >= 300 && returnCode < 400 && default->redirectionPath = new->redirectionPath
4. Request size the same for all 3
    - contentLen
*/
typedef enum {
    BASE_CODE_ERROR_CODE,
    BASE_REDIRECT_CODE,
    BASE_DATA_SIZE_CODE,
    BASE_NOT_FOUND
}ENUM_PAGE_NOT_FOUND;

ENUM_PAGE_NOT_FOUND SetPageNotFound(PHTTP_STRUC pHttpStruct, char* ipAddress, int port, FILE* pFile, BOOL isSSL) {
    PHTTP_STRUC pHttpStructInvalide[3]; // Calloc
    BOOL isReturnCodeSame = TRUE;
    BOOL isContentLenSame = TRUE;
    BOOL isRedirectionSame = TRUE;

    pHttpStruct->redirectionPath = (char*)malloc(100);
    if (pHttpStruct->redirectionPath == NULL) {
        return BASE_NOT_FOUND;
    }

    for (int i = 0; i < ARRAY_SIZE_CHAR(invalideUrlPath); i++) {
        pHttpStructInvalide[i] = GetHttpRequest(ipAddress, port, (char*)invalideUrlPath[i], "HEAD", isSSL, pFile);
        if (pHttpStructInvalide[i] == NULL) {
            return BASE_NOT_FOUND;
        }
    }

    pHttpStruct->returnCode = pHttpStructInvalide[0]->returnCode;
    pHttpStruct->contentLen = pHttpStructInvalide[0]->contentLen;



    if (!IS_HTTP_ERROR(pHttpStruct->returnCode))
        isReturnCodeSame = FALSE;

    if (IS_HTTP_REDIRECTS(pHttpStructInvalide[0]->returnCode)) {
        if (TestAllHttpsRedirect(pHttpStructInvalide, ipAddress, port, pFile))
            return BASE_NOT_FOUND;

        if (pHttpStructInvalide[0]->redirectionPath != NULL)
            strcpy_s(pHttpStruct->redirectionPath, 100, pHttpStructInvalide[0]->redirectionPath);
        else
            strcpy_s(pHttpStruct->redirectionPath, 100, "");
    }

    for (int i = 0; i < ARRAY_SIZE_CHAR(invalideUrlPath); i++) {
        if (pHttpStruct->returnCode != pHttpStructInvalide[i]->returnCode)
            isReturnCodeSame = FALSE;
        if (pHttpStruct->contentLen != pHttpStructInvalide[i]->contentLen)
            isContentLenSame = FALSE;
        // Redirection
        if (IS_HTTP_REDIRECTS(pHttpStructInvalide[i]->returnCode) &&
            pHttpStructInvalide[i]->redirectionPath != NULL &&
            strcmp(pHttpStruct->redirectionPath, pHttpStructInvalide[i]->redirectionPath) != 0)
            isRedirectionSame = FALSE;
    }
    for (int i = ARRAY_SIZE_CHAR(invalideUrlPath) - 1; i > 0; i--)
        free(pHttpStructInvalide[i]);


    if (isReturnCodeSame)
        return BASE_CODE_ERROR_CODE;
    else if (isContentLenSame)
        return BASE_REDIRECT_CODE;
    else if (isRedirectionSame)
        return BASE_DATA_SIZE_CODE;
    return BASE_NOT_FOUND;
}


VOID PrintDirFindRedirect(PHTTP_STRUC pHttpStructPage, char* ipAddress, FILE* pFile, BOOL isSSL) {
    printOut(pFile, "\t\thttp%s://%s%-20s %i -  %-5i -> %s\n",
        isSSL ? "s" : "", ipAddress,
        pHttpStructPage->requestPath, pHttpStructPage->returnCode,
        pHttpStructPage->contentLen, pHttpStructPage->redirectionPath);
}
VOID PrintDirFind(PHTTP_STRUC pHttpStructPage, char* ipAddress, FILE* pFile, BOOL isSSL) {
    printOut(pFile, "\t\thttp%s://%s%-20s %i -  %-5i\n",
        isSSL ? "s" : "", ipAddress,
        pHttpStructPage->requestPath, pHttpStructPage->returnCode,
        pHttpStructPage->contentLen);
}


BOOL HttpDirEnum(char* ipAddress, int port, FILE* pFile, BOOL isSSL) {

    printf("\t[HTTP%s] %s:%i - HTTP%s Directory Enum  \n", isSSL ? "S" : "", ipAddress, port, isSSL ? "S" : "");

    ENUM_PAGE_NOT_FOUND enulPageNotFound;
    PHTTP_STRUC pHttpStructInvalide = InitPHTTP_STRUC(1);

    if (pHttpStructInvalide == NULL)
        return FALSE;

    enulPageNotFound = SetPageNotFound(pHttpStructInvalide, ipAddress, port, pFile, isSSL);
    if (enulPageNotFound == BASE_NOT_FOUND) {
        FreePHTTP_STRUC(pHttpStructInvalide);
        return FALSE;
    }
    printf("\t\tURL\t\t\t\t       Code - Length\tRedirection\n");
    for (int i = 0; i < ARRAY_SIZE_CHAR(wordListCommon); i++) {
        PHTTP_STRUC pHttpStructPage = GetHttpRequest(ipAddress, port, (char*)wordListCommon[i], "HEAD", isSSL, pFile);
        if (pHttpStructPage != NULL) {
            printf("\t\t[i] %i/%u\r", i, (unsigned int)ARRAY_SIZE_CHAR(wordListCommon));
            switch (enulPageNotFound) {
            case BASE_CODE_ERROR_CODE:
                if (!IS_HTTP_ERROR(pHttpStructPage->returnCode)) {
                    if (IS_HTTP_REDIRECTS(pHttpStructPage->returnCode))
                        PrintDirFindRedirect(pHttpStructPage, ipAddress, pFile, isSSL);
                    else
                        PrintDirFind(pHttpStructPage, ipAddress, pFile, isSSL);
                }
                break;
            case BASE_REDIRECT_CODE:
                if (IS_HTTP_REDIRECTS(pHttpStructPage->returnCode) && strcmp(pHttpStructPage->redirectionPath, pHttpStructInvalide->redirectionPath) != 0) {
                    PrintDirFindRedirect(pHttpStructPage, ipAddress, pFile, isSSL);
                }
                break;
            case BASE_DATA_SIZE_CODE:
                if (pHttpStructInvalide->contentLen != pHttpStructPage->contentLen) {
                    if (IS_HTTP_REDIRECTS(pHttpStructPage->returnCode))
                        PrintDirFindRedirect(pHttpStructPage, ipAddress, pFile, isSSL);
                    else
                        PrintDirFind(pHttpStructPage, ipAddress, pFile, isSSL);
                }
                break;
            default:
                break;
            }
            FreePHTTP_STRUC(pHttpStructPage);
        }
    }
    FreePHTTP_STRUC(pHttpStructInvalide);
    return TRUE;
}




BOOL GetHTTPFingerprint(char* serverResponce, PORT_INFO* portInfo) {
    portInfo->version = 0;
    portInfo->deviceType = UnknownType;

    for (int i = 0; i < 3; i++) {
        //for (int i = 0; sizeof(deviceType) / sizeof(StrucStrDev) > i; i++) {
        if (strstr(serverResponce, structStrDev[i].pStart) != NULL) {
            portInfo->deviceType = structStrDev[i].deviceType;
            switch (structStrDev[i].deviceType) {
            case FRITZBox:
                if (FRITZBoxVersionDetection(structStrDev[i], portInfo, serverResponce)) {
                    printf("\t\t[SOFTWARE] FRITZBox %i\n", portInfo->version);
                    return FRITZBoxUserEnum(serverResponce);
                }
            case TrueNAS:
                printf("\t\t[SOFTWARE] TrueNAS Detected!\n");
            default:
                break;
            }
        }
    }
    return FALSE;
}


BOOL GetHttpServerInfo(char* ipAddress, int port, FILE* pFile, BOOL isSSL) {
    printf("\t[HTTP%s] %s:%i - HTTP%s information\n", isSSL ? "S" : "", ipAddress, port, isSSL ? "S" : "");

    PHTTP_STRUC pHttpStructPage = GetHttpRequest(ipAddress, port, "/", "GET", isSSL, pFile);
    //PHTTP_STRUC pHttpStructPage = GetHttpRequest(ipAddress, port, "/ui/", "GET", isSSL, pFile);
    if (pHttpStructPage == NULL)
        return FALSE;


    if (pHttpStructPage->ServerName != NULL)
        printf("\t\t[Server] %s\n", pHttpStructPage->ServerName);

    if (pHttpStructPage->returnCode < 400) {
        if (pHttpStructPage->returnCode >= 300) {
            if (pHttpStructPage->redirectionPath != NULL)
                printf("\t\t[Redirection] %s\n", pHttpStructPage->redirectionPath);
        }
        if (pHttpStructPage->returnCode == 200 && pHttpStructPage->pContent != NULL) {
            PORT_INFO portInfo;
            portInfo.portNumber = port;
            portInfo.banner[0] = 0x00;

            if (GetHTTPFingerprint(pHttpStructPage->pContent, &portInfo))
                printOut(pFile, "\t[HTTP%s] Port %i Fingerprint %i - %i\n", isSSL ? "S" : "", portInfo.portNumber, portInfo.deviceType, portInfo.version); // portInfo.deviceType todo
        }
    }

    FreePHTTP_STRUC(pHttpStructPage);
    return TRUE;
}