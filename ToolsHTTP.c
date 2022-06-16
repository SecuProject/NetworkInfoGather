#include <windows.h>
#include <stdio.h>

#include "NetDiscovery.h"
#include "ToolsHTTP.h"
#include "Network.h"
#include "GetHTTPserver.h"
#include "GetHTTPSserver.h"

// Software
#include "EnumFRITZBox.h"
#include "EnumDeluge.h"

#include "HttpWordlist.h"
#include "ToolsHTTP.h"
#include "DetectHttpBasicAuth.h"
#include "CheckCVE.h"
//#include "wordListCommon.h"
#include "apacheWordList.h"
#include "apacheTomcatWordList.h"
#include "IisWordList.h"

const char* sereverTypeStr[] = {
    "nginx",
    "tomcat",
    "apache",
    "iis",
    "litespeed",
    "nodejs",
    "lighttpd",
    "jigsaw"
};

const char* userAgentList[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36",
    "Mozilla/5.0 CK={} (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0"
};
const char* invalideUrlFilePath[] = {
    "/wnhQ7QgxDu3u6rL22Gq.php",     // Add rand Str
    "/G938Ei7F6QGZc9j47apZ.txt",    // Add rand Str
    "/gy788zk7nC472jha6NnmL.html",  // Add rand Str
};
const char* invalideUrlDirecotryPath[] = {
    "/FaTx3UshB75u498Cn",           // Add rand Str
    "/B24L4U8R9KJesa",              // Add rand Str
    "/SWU4v7887VSthS3BAXs",         // Add rand Str
};

#define REDIRECTION_PATH_SIZE  100

const StrucStrDev structStrDev[] = {
    //{"\"bluBarTitle\":\"FRITZ!Box ","\"",FRITZBox} ,
    {"\"bluBarTitle\":\"FRITZ!","\"",FRITZBox} ,
    {"product.trim() === 'TrueNAS'",NULL,TrueNAS} ,
    {"author: 'Deluge Team',",NULL,Deluge} ,
    {"test","Cable",UnknownType} ,
};


char* StrToLower(char* s) {
    for (char* p = s; *p; p++) *p = tolower(*p);
    return s;
}


BOOL ExtractStrStr(char* data, const char* delim1, const char* delim2, char** ppBuffer, int* bufferLen){
    char* ptr1 = strstr(data, delim1);
    if (ptr1 != NULL){
        size_t strLen;
        char* ptr2;

        ptr1 = ptr1 + strlen(delim1);
        ptr2 = strstr(ptr1, delim2);
        strLen = (size_t)(ptr2 - ptr1);
        if (ptr2 != NULL && strLen > 0){
            char* buffer = (char*)malloc(strLen + (size_t)1);
            if (buffer == NULL)
                return FALSE;
            strncpy_s(buffer, strLen + (size_t)1, ptr1, strLen);
            *ppBuffer = buffer;
            *bufferLen = (int)strLen;
            return TRUE;
        }
    }
    return FALSE;
}
BOOL ExtractStrInt(char* str, int matchStr, char* buffer, int bufferLen){
    char* ptr = strchr(str, matchStr);
    int strLen = (int)(ptr - str);
    if (ptr != NULL && strLen < bufferLen && strLen > 0){
        strncpy_s(buffer, bufferLen, str, strLen);
        return strLen;
    }
    return FALSE;
}



UINT GetHttpReturnCode(char* serverResponce, UINT responceSize){
    const char* delim1[] = {
        "HTTP/0.9 ", // 1991	Obsolete
        "HTTP/1.0 ", // 1996	Obsolete
        "HTTP/1.1 ", // 1997	Standard
        "HTTP/2 ",   // 2015	Standard
        "HTTP/3 "    // 2020	Draft
    };
    const char delim2[] = " ";
    char* buffer;
    int bufferLen;

    for (int i = 0; i < ARRAY_SIZE_CHAR(delim1); i++){
        if (ExtractStrStr(serverResponce, delim1[i], delim2, &buffer, &bufferLen)){
            UINT responceCode;
            responceCode = atoi(buffer);
            free(buffer);
            return responceCode;
        }
    }
    return FALSE;
}

int GetHttpContentLen(char* serverResponce, UINT responceSize) {
    const char delim1[] = "Content-Length: ";
    const char delim2[] = "\r\n";

    char* buffer;
    int bufferLen;

    if (ExtractStrStr(serverResponce, delim1, delim2, &buffer, &bufferLen)){
        int contentLen;
        contentLen = atoi(buffer);
        free(buffer);
        return contentLen;
    } else {
        //printf("[d] Header 'Content-Length' Not found !\n");
        const char delim2[] = "\r\n\r\n";
        char* ptr = strstr(serverResponce, delim2);
        if (ptr != NULL) {
            ptr += strlen(delim2);
            if (responceSize - (ptr - serverResponce) == 0) {
                //printf("[d] The body is empty !\n");
                return 0;
            }
        }
    }
    return -1;
}

BOOL GetHttpHeaderStr(const char* delim1, int sizeDelim1, char* serverResponce, char* serverVersion, int* bufferSize) {
    const char delim2[] = "\r\n";
    char* buffer;
    int bufferLen;

    if (ExtractStrStr(serverResponce, delim1, delim2, &buffer, &bufferLen)){
        strncpy_s(serverVersion, *bufferSize, buffer, bufferLen);
        *bufferSize = bufferLen;
        free(buffer);
        return TRUE;
    }
    return FALSE;
}

BOOL GetHttpHeaderServerVersion(PHTTP_STRUC httpStruct, UINT responceSize) {
    UINT serverVersionSize = responceSize + 1;
    httpStruct->ServerName = (char*)malloc(serverVersionSize);
    if (httpStruct->ServerName != NULL) {
        const char delim1[] = "Server:";
        if (GetHttpHeaderStr(delim1, sizeof(delim1), httpStruct->rawData, httpStruct->ServerName, &serverVersionSize)) {
            httpStruct->ServerName = (char*)xrealloc(httpStruct->ServerName, serverVersionSize + (UINT)1);
            if (httpStruct->ServerName == NULL)
                return FALSE;
            return TRUE;
        }
        free(httpStruct->ServerName);
    }
    httpStruct->ServerName = NULL;
    return FALSE;
}
BOOL GetHttpHeaderPowerby(PHTTP_STRUC httpStruct, UINT responceSize) {
    UINT serverVersionSize = responceSize + 1;
    httpStruct->poweredBy = (char*)malloc(serverVersionSize);
    if (httpStruct->poweredBy != NULL) {
        const char delim1[] = "X-Powered-By:";
        if (GetHttpHeaderStr(delim1, sizeof(delim1), httpStruct->rawData, httpStruct->poweredBy, &serverVersionSize)) {
            httpStruct->poweredBy = (char*)xrealloc(httpStruct->poweredBy, serverVersionSize + (UINT)1);
            if (httpStruct->poweredBy == NULL)
                return FALSE;
            return TRUE;
        }
        free(httpStruct->poweredBy);
    }
    httpStruct->poweredBy = NULL;
    return FALSE;
}

BOOL GetHttpHeaderRedirectby(PHTTP_STRUC httpStruct, UINT responceSize){
    UINT serverVersionSize = responceSize + 1;
    httpStruct->redirectBy = (char*)malloc(serverVersionSize);
    if (httpStruct->redirectBy != NULL){
        const char delim1[] = "	X-Redirect-By:";
        if (GetHttpHeaderStr(delim1, sizeof(delim1), httpStruct->rawData, httpStruct->redirectBy, &serverVersionSize)){
            httpStruct->redirectBy = (char*)xrealloc(httpStruct->redirectBy, serverVersionSize + (UINT)1);
            if (httpStruct->redirectBy == NULL)
                return FALSE;
            return TRUE;
        }
        free(httpStruct->redirectBy);
    }
    httpStruct->redirectBy = NULL;
    return FALSE;
}


BOOL GetHttpHeaderContentType(PHTTP_STRUC httpStruct, UINT responceSize) {
    UINT serverVersionSize = responceSize + 1;
    httpStruct->contentType = (char*)malloc(responceSize + 1);
    if (httpStruct->contentType != NULL) {
        const char delim1[] = "Content-Type:";
        if (GetHttpHeaderStr(delim1, sizeof(delim1), httpStruct->rawData, httpStruct->contentType, &serverVersionSize)) {
            httpStruct->contentType = (char*)xrealloc(httpStruct->contentType, serverVersionSize +1);
            if (httpStruct->contentType == NULL)
                return FALSE;
            return TRUE;
        }
        free(httpStruct->contentType);
    }
    httpStruct->contentType = NULL;
    return FALSE;
}
BOOL GetHttpHeaderRedirection(PHTTP_STRUC httpStruct, UINT responceSize) {
    UINT serverVersionSize = responceSize +1;
    httpStruct->redirectionPath = (char*)malloc(serverVersionSize);
    if (httpStruct->redirectionPath != NULL) {
        const char delim1[] = "Location:";
        if (GetHttpHeaderStr(delim1, sizeof(delim1), httpStruct->rawData, httpStruct->redirectionPath, &serverVersionSize)) {
            httpStruct->redirectionPath = (char*)xrealloc(httpStruct->redirectionPath, serverVersionSize + 1);
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
    if (httpStruct->responseLen == 0) {
        printf("[d] Test response size: %u !!!\n", httpStruct->contentLen);
        return FALSE;
    }

    httpStruct->returnCode = GetHttpReturnCode(httpStruct->rawData, httpStruct->responseLen);
    httpStruct->contentLen = GetHttpContentLen(httpStruct->rawData, httpStruct->responseLen);
    if (httpStruct->contentLen > 0)
        GetHttpBody(httpStruct);
    else if (httpStruct->contentLen == -1)
        httpStruct->pContent = NULL;

    GetHttpHeaderServerVersion(httpStruct, httpStruct->responseLen);
    GetHttpHeaderPowerby(httpStruct, httpStruct->responseLen);
    GetHttpHeaderRedirectby(httpStruct, httpStruct->responseLen);
    GetHttpHeaderContentType(httpStruct, httpStruct->responseLen);

    if (IS_HTTP_REDIRECTS(httpStruct->returnCode)) {

        GetHttpHeaderRedirection(httpStruct, httpStruct->responseLen);
    }else
        httpStruct->redirectionPath = NULL;

    return TRUE;
}



PHTTP_STRUC InitPHTTP_STRUC(UINT nbElement) {
    PHTTP_STRUC httpStruct = (PHTTP_STRUC)calloc(nbElement, sizeof(HTTP_STRUC));
    if (httpStruct == NULL)
        return NULL;

    for (UINT i = 0; i < nbElement; i++) {
        httpStruct[i].AuthHeader = NULL;
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
    if (pHTTP_STRUC->AuthHeader != NULL)
        free(pHTTP_STRUC->AuthHeader);
    free(pHTTP_STRUC);
}

PHTTP_STRUC GetHttpRequest(char* ipAddress, int port, char* path, char* requestType, char* httpAuthHeader, BOOL isSSL, FILE* pFile) {
    PHTTP_STRUC httpStruct = InitPHTTP_STRUC(1);
    if (httpStruct == NULL)
        return NULL;

    httpStruct->requestPath = path;

    if (isSSL)
        httpStruct->responseLen = GetHttpsServer(ipAddress, port, requestType, path, NULL, &(httpStruct->rawData), httpAuthHeader,FALSE, pFile);
    else
        httpStruct->responseLen = GetHttpServer(ipAddress, port, requestType, path, NULL, &(httpStruct->rawData), httpAuthHeader, pFile); // GET
    if (httpStruct->responseLen == 0) {
        //printOut(pFile, "\t\t[x] Page not available !\n");
        if(httpStruct->rawData != NULL)
            free(httpStruct->rawData);
        free(httpStruct);
        return NULL;
    }
    if (httpStruct->rawData == NULL) {
        printOut(pFile, "\t\t[x] Response data error !\n");
        free(httpStruct);
        return NULL;
    }

    if (!GetHttpRequestInfo(httpStruct)) {
        printOut(pFile, "\t\t[x] Fail to retrieve information form the request !\n");
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
    httpStruct->rawData = (char*)xrealloc(httpStruct->rawData, GET_REQUEST_SIZE);
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


typedef struct{
    char protocol[5 + 1];
    char ipAddress[15 + 1];
    int port;
    char urlPath[128];
} URL_STRUCT, * PURL_STRUCT;


VOID InitStructUrl(PURL_STRUCT urlStrcut){
    urlStrcut->protocol[0] = 0x00;
    urlStrcut->ipAddress[0] = 0x00;
    urlStrcut->port = 0x00;
    urlStrcut->urlPath[0] = 0x00;
}

BOOL ParseUrl(char* url, PURL_STRUCT urlStrcut){
    InitStructUrl(urlStrcut);

    int ptr = ExtractStrInt(url, ':', urlStrcut->protocol, sizeof(urlStrcut->protocol));
    if (ptr > 0){
        int tmpPtr;

        // Check if format OK
        if (url[ptr] != ':' || url[ptr + 1] != '/' || url[ptr + 2] != '/')
            return FALSE;
        ptr += 3;

        if (strchr(url + ptr, ':')){
            char portTmp[5 + 1] = "\0";
            tmpPtr = ExtractStrInt(url + ptr, ':', urlStrcut->ipAddress, sizeof(urlStrcut->ipAddress));
            if (tmpPtr){
                ptr += tmpPtr + 1;
            }
            if (strchr(url + ptr, '/')){
                tmpPtr = ExtractStrInt(url + ptr, '/', portTmp, sizeof(portTmp));
                urlStrcut->port = atoi(portTmp);
                if (tmpPtr){
                    ptr += tmpPtr;

                    ExtractStrInt(url + ptr, '\0', urlStrcut->urlPath, sizeof(urlStrcut->urlPath));
                    /*tmpPtr = ExtractStrInt(url + ptr, '\0', urlStrcut->urlPath, sizeof(urlStrcut->urlPath));
                    if (tmpPtr){
                        //ptr += tmpPtr + 1;
                    }*/
                }
            } else{
                ExtractStrInt(url + ptr, '\0', portTmp, sizeof(portTmp));
                /*tmpPtr = ExtractStrInt(url + ptr, '\0', portTmp, sizeof(portTmp));
                urlStrcut->port = atoi(portTmp);
                if (tmpPtr){
                    //ptr += tmpPtr + 1;
                }*/
            }
        } else{
            if (strchr(url + ptr, '/')){
                tmpPtr = ExtractStrInt(url + ptr, '/', urlStrcut->ipAddress, sizeof(urlStrcut->ipAddress));
                if (tmpPtr){
                    ptr += tmpPtr;

                    ExtractStrInt(url + ptr, '\0', urlStrcut->urlPath, sizeof(urlStrcut->urlPath));
                    /*tmpPtr = ExtractStrInt(url + ptr, '\0', urlStrcut->urlPath, sizeof(urlStrcut->urlPath));
                    if (tmpPtr){
                        //ptr += tmpPtr + 1;
                    }*/
                }
            } else{
                ExtractStrInt(url + ptr, '\0', urlStrcut->ipAddress, sizeof(urlStrcut->ipAddress));
                /*tmpPtr = ExtractStrInt(url + ptr, '\0', urlStrcut->ipAddress, sizeof(urlStrcut->ipAddress));
                if (tmpPtr){
                    //ptr += tmpPtr + 1;
                }*/
            }
        }
        return TRUE;
    }
    return FALSE;
}
BOOL TestAllHttpsRedirect(PHTTP_STRUC* pHttpStructInvalide, FILE* pFile){
    int match = 0;
    URL_STRUCT* urlStrcutInvalide = (URL_STRUCT*)malloc(sizeof(URL_STRUCT));
    if (urlStrcutInvalide == NULL)
        return TRUE;

    /// Redirection http[s]://domain/xxx -> http[s]://domain/    x 3
    for (int i = 1; i < ARRAY_SIZE_CHAR(invalideUrlFilePath); i++){
        if (strcmp(pHttpStructInvalide[0]->redirectionPath, pHttpStructInvalide[i]->redirectionPath) == 0)
            match++;
    }
    if (match == 2){
        printf("\t\t[i] All requests return %s\n", pHttpStructInvalide[0]->redirectionPath);
        return TRUE;
    }else
        match = 0;


    /// Redirection http[s]://domain/xxx -> http[s]://domain/xxx
    for (int i = 0; i < ARRAY_SIZE_CHAR(invalideUrlFilePath); i++){
        if (!ParseUrl((char*)pHttpStructInvalide[i]->redirectionPath, urlStrcutInvalide))
            return TRUE;
        if (strcmp(urlStrcutInvalide->urlPath, invalideUrlFilePath[i]) == 0)
            match++;
    }
    if (match == ARRAY_SIZE_CHAR(invalideUrlFilePath)){
        if (urlStrcutInvalide->port != 0)
            printf("\t\t[i] All requests return %s://%s:%i/[PAGE_NAME]\n", urlStrcutInvalide->protocol, urlStrcutInvalide->ipAddress, urlStrcutInvalide->port);
        else
            printf("\t\t[i] All requests return %s://%s/[PAGE_NAME]\n", urlStrcutInvalide->protocol, urlStrcutInvalide->ipAddress); // PORT !!!
    }

    free(urlStrcutInvalide);
    return match == ARRAY_SIZE_CHAR(invalideUrlFilePath);


    // http://192.168.59.45/.bash_history       301 -  0     -> https://192.168.59.45/.bash_history
}


/*
Directory 
1. all invalid dir url return 200 

1. Check if val are the same:
    - returnCode
    - contentLen
2. If returnCode >= 400 && returnCode < 599
    * Use returnCode
3. if returnCode >= 300 && returnCode < 400
    if redirectionPath of all 3 to same but HTTPS
        BASE_NOT_FOUND                               ----   to test

    if redirectionPath the same for all 3
        * returnCode >= 300 && returnCode < 400 && default->redirectionPath = new->redirectionPath
4. Request size the same for all 3
    - contentLen
*/
typedef enum {
    BASE_CODE_ERROR_CODE,
    BASE_REDIRECT_CODE,
    BASE_DATA_SIZE_CODE,
    BASE_CODE_AUTH,
    BASE_INVALID_CODE_LEN_DIR,
    BASE_NOT_FOUND
}ENUM_PAGE_NOT_FOUND;


ENUM_PAGE_NOT_FOUND SetNotFound(PHTTP_STRUC pHttpStruct, RequestInfoStruct requestInfoStruct,FILE* pFile, char* invalideUrlPath[], UINT invalideUrlPathSize) {
    BOOL isReturnCodeSame = TRUE;
    BOOL isContentLenSame = TRUE;
    BOOL isRedirectionSame = TRUE;
    UINT isMatch = 0;
    PHTTP_STRUC pHttpStructInvalide[3]; // Calloc


    /*pHttpStruct->redirectionPath = (char*)malloc(REDIRECTION_PATH_SIZE);
    if (pHttpStruct->redirectionPath == NULL) {
        return BASE_NOT_FOUND;
    }*/

    for (UINT i = 0; i < invalideUrlPathSize; i++) {
        pHttpStructInvalide[i] = GetHttpRequest(requestInfoStruct.ipAddress, requestInfoStruct.port, (char*)invalideUrlPath[i], "HEAD", requestInfoStruct.httpAuthHeader, requestInfoStruct.isSSL, pFile);
        if (pHttpStructInvalide[i] == NULL)
            return BASE_NOT_FOUND;
        if (pHttpStructInvalide[i]->returnCode == STATUS_CODE_OK &&
            pHttpStructInvalide[i]->contentLen == NO_BODY_DATA)
            isMatch++;
    }

    if (isMatch == invalideUrlPathSize) {
        for (int i = invalideUrlPathSize - 1; i > 0; i--)
            free(pHttpStructInvalide[i]);
        return BASE_INVALID_CODE_LEN_DIR;
    }

    if (pHttpStructInvalide == NULL)
        return BASE_CODE_ERROR_CODE;



    pHttpStruct->returnCode = pHttpStructInvalide[0]->returnCode;
    pHttpStruct->contentLen = pHttpStructInvalide[0]->contentLen;

    if (!IS_HTTP_ERROR(pHttpStruct->returnCode)) {
        isReturnCodeSame = BASE_CODE_ERROR_CODE;
    } else {
        if (IS_HTTP_AUTH(pHttpStruct->returnCode)) {
            UINT countCodeAuth = 1;
            for (UINT i = 1; i < invalideUrlPathSize; i++) {
                if (IS_HTTP_AUTH(pHttpStructInvalide[i]->returnCode))
                    countCodeAuth++;
            }
            if (countCodeAuth == 3) {
                for (UINT i = invalideUrlPathSize - 1; i > 0; i--)
                    free(pHttpStructInvalide[i]);
                return BASE_NOT_FOUND;
            }
        }
    }
    if (IS_HTTP_REDIRECTS(pHttpStructInvalide[0]->returnCode)) {
        if (TestAllHttpsRedirect(pHttpStructInvalide, pFile))
            return BASE_NOT_FOUND;

        if (pHttpStructInvalide[0]->redirectionPath != NULL)
            strcpy_s(pHttpStruct->redirectionPath, REDIRECTION_PATH_SIZE, pHttpStructInvalide[0]->redirectionPath);
        else
            strcpy_s(pHttpStruct->redirectionPath, REDIRECTION_PATH_SIZE, "");
    }

    for (UINT i = 0; i < invalideUrlPathSize; i++) {
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
    for (int i = invalideUrlPathSize - 1; i > 0; i--)
        free(pHttpStructInvalide[i]);


    if (isReturnCodeSame)
        return BASE_CODE_ERROR_CODE;
    else if (isContentLenSame)
        return BASE_REDIRECT_CODE;
    else if (isRedirectionSame)
        return BASE_DATA_SIZE_CODE;
    return BASE_NOT_FOUND;

}

ENUM_PAGE_NOT_FOUND SetFileNotFound(PHTTP_STRUC pHttpStruct, RequestInfoStruct requestInfoStruct, FILE* pFile) {
    return SetNotFound(pHttpStruct, requestInfoStruct, pFile, (char**)invalideUrlFilePath, ARRAY_SIZE_CHAR(invalideUrlFilePath));
}

ENUM_PAGE_NOT_FOUND SetDirectoryNotFound(PHTTP_STRUC pHttpStruct, RequestInfoStruct requestInfoStruct, FILE* pFile) {
    return SetNotFound(pHttpStruct, requestInfoStruct, pFile,(char**) invalideUrlDirecotryPath, ARRAY_SIZE_CHAR(invalideUrlDirecotryPath));
}


VOID PrintAllDir(FILE* pFile, char* printBuffer, int printBufferLen) {
    int defaultWidth = 120;
    int strLenNew = printBufferLen + 4;
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    HANDLE stdHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    if (stdHandle != NULL) {
        if (GetConsoleScreenBufferInfo(stdHandle,&csbi)) {
            defaultWidth = csbi.dwSize.X;
            //defaultHeight = csbi.dwSize.Y;
        }
    }
    for(int i = 0;i< printBufferLen;i++){
        // 0x09 -> tab
        if (printBuffer[i] == 0x09)
            strLenNew += 5;
    }
    printOut(pFile, "%s", printBuffer);
    for (int i = 0; i < defaultWidth - strLenNew; i++)
        printf(" ");
    printf("\n");
}
VOID PrintDirFindRedirect(PHTTP_STRUC pHttpStructPage, char* ipAddress, FILE* pFile, BOOL isSSL) {
    char* printBuffer = (char*)malloc(1024);
    if (printBuffer == NULL)
        return;
    int strLen = sprintf_s(printBuffer, 1024, "\t\thttp%s://%s%-20s %i -  %-5i -> %s",
        isSSL ? "s" : "", ipAddress,
        pHttpStructPage->requestPath, 
        pHttpStructPage->returnCode,
        (pHttpStructPage->contentLen > 0) ? pHttpStructPage->contentLen : 0,
        pHttpStructPage->redirectionPath);
    PrintAllDir(pFile, printBuffer, strLen);
}
VOID PrintDirFind(PHTTP_STRUC pHttpStructPage, char* ipAddress, FILE* pFile, BOOL isSSL) {
    char* printBuffer = (char*)malloc(1024);
    if (printBuffer == NULL)
        return ;
    int strLen = sprintf_s(printBuffer, 1024, "\t\thttp%s://%s%-20s %i -  %-5i", isSSL ? "s" : "", ipAddress,
        pHttpStructPage->requestPath, pHttpStructPage->returnCode,
        (pHttpStructPage->contentLen > 0) ? pHttpStructPage->contentLen : 0);
    PrintAllDir(pFile, printBuffer, strLen);

   /* printOut(pFile, "\t\thttp%s://%s%-23s %i -  %-5i                                                   \n",
        isSSL ? "s" : "", ipAddress,
        pHttpStructPage->requestPath, pHttpStructPage->returnCode,
        (pHttpStructPage->contentLen > 0) ? pHttpStructPage->contentLen : 0);*/
}

typedef struct {
    char** tabRedirectionPath;
    int nbRedirectionPath;
}RedirectionStruct;

BOOL StartHttpDirEnum(RequestInfoStruct requestInfoStruct, FILE* pFile, ENUM_PAGE_NOT_FOUND enumPageNotFound, ENUM_PAGE_NOT_FOUND enumDirNotFound, PHTTP_STRUC pHttpStructInvalide, char** wordListCommonFile, UINT wordListCommonSize) {
    for (UINT i = 0; i < wordListCommonSize; i++) {
        PHTTP_STRUC pHttpStructPage = GetHttpRequest(requestInfoStruct.ipAddress, requestInfoStruct.port, (char*)wordListCommonFile[i], "HEAD", requestInfoStruct.httpAuthHeader, requestInfoStruct.isSSL, pFile);
        if (pHttpStructPage != NULL) {
            LoadingBar(i + 1, wordListCommonSize);
            switch (enumPageNotFound) {
            case BASE_CODE_ERROR_CODE:
                if (!IS_HTTP_ERROR(pHttpStructPage->returnCode)) {
                    if (IS_HTTP_REDIRECTS(pHttpStructPage->returnCode)) {
                        PrintDirFindRedirect(pHttpStructPage, requestInfoStruct.ipAddress, pFile, requestInfoStruct.isSSL);
                        // Append to table 
                        // redirectionPath = 0x00000164494a67c0 " xxxaaa.php"
                    }else {
                        BOOL isAntiDir = (enumDirNotFound == BASE_INVALID_CODE_LEN_DIR &&
                            pHttpStructPage->returnCode == STATUS_CODE_OK &&
                            pHttpStructPage->contentLen == NO_BODY_DATA);
                        if(!isAntiDir)
                            PrintDirFind(pHttpStructPage, requestInfoStruct.ipAddress, pFile, requestInfoStruct.isSSL);
                    }
                }
                break;
            case BASE_REDIRECT_CODE:
                if (IS_HTTP_REDIRECTS(pHttpStructPage->returnCode) && strcmp(pHttpStructPage->redirectionPath, pHttpStructInvalide->redirectionPath) != 0) {
                    PrintDirFindRedirect(pHttpStructPage, requestInfoStruct.ipAddress, pFile, requestInfoStruct.isSSL);
                }
                break;
            case BASE_DATA_SIZE_CODE:
                if (pHttpStructInvalide->contentLen != pHttpStructPage->contentLen) {
                    if (IS_HTTP_REDIRECTS(pHttpStructPage->returnCode))
                        PrintDirFindRedirect(pHttpStructPage, requestInfoStruct.ipAddress, pFile, requestInfoStruct.isSSL);
                    else
                        PrintDirFind(pHttpStructPage, requestInfoStruct.ipAddress, pFile, requestInfoStruct.isSSL);
                }
                break;
            default:
                break;
            }
            FreePHTTP_STRUC(pHttpStructPage);
        }
    }
    return TRUE;
}
// HttpDirEnum(ipAddress, portNb, httpAuthHeader, serverType, pFile, isSSL);
//BOOL HttpDirEnum(char* ipAddress, int port,char* httpAuthHeader, ServerType serverType, FILE* pFile, BOOL isSSL) {
BOOL HttpDirEnum(RequestInfoStruct requestInfoStruct, ServerType serverType, FILE* pFile) {

    printf("\t[HTTP%s] %s:%i - HTTP%s Directory Enum  \n", requestInfoStruct.isSSL ? "S" : "", requestInfoStruct.ipAddress, requestInfoStruct.port, requestInfoStruct.isSSL ? "S" : "");

    ENUM_PAGE_NOT_FOUND enumPageNotFound;
    PHTTP_STRUC pHttpStructInvalide = InitPHTTP_STRUC(1);

    if (pHttpStructInvalide == NULL)
        return FALSE;
   
    // if BASE_INVALID_CODE_LEN_DIR disable dir !!!
    ENUM_PAGE_NOT_FOUND enumDirNotFound = SetDirectoryNotFound(pHttpStructInvalide, requestInfoStruct,pFile);
    enumPageNotFound = SetFileNotFound(pHttpStructInvalide, requestInfoStruct,pFile);
    if (enumPageNotFound == BASE_NOT_FOUND) {
        FreePHTTP_STRUC(pHttpStructInvalide);
        return FALSE;
    }

    printf("\t\tURL\t\t\t\t   %s      Code - Length\tRedirection\n", requestInfoStruct.isSSL ? " " : "" );

    StartHttpDirEnum(requestInfoStruct, pFile, enumPageNotFound, enumDirNotFound, pHttpStructInvalide, (char**)wordListCommonFile, ARRAY_SIZE_CHAR(wordListCommonFile));
        
    // temp 
    /*StartHttpDirEnum(ipAddress, port, httpAuthHeader, pFile, isSSL, enumPageNotFound, enumDirNotFound, pHttpStructInvalide, (char**)wordListCommonDir, ARRAY_SIZE_CHAR(wordListCommonDir));*/
    
    switch (serverType) {
    case ApacheHttpd:
        StartHttpDirEnum(requestInfoStruct, pFile, enumPageNotFound, enumDirNotFound, pHttpStructInvalide, (char**)wordListApacheFile, ARRAY_SIZE_CHAR(wordListApacheFile));
        //if (enumDirNotFound != BASE_INVALID_CODE_LEN_DIR)
        StartHttpDirEnum(requestInfoStruct, pFile, enumPageNotFound, enumDirNotFound, pHttpStructInvalide, (char**)wordListApacheDir, ARRAY_SIZE_CHAR(wordListApacheDir));
        break;
    case ApacheTomcat:
        StartHttpDirEnum(requestInfoStruct, pFile, enumPageNotFound, enumDirNotFound, pHttpStructInvalide, (char**)wordListApacheTomcatFile, ARRAY_SIZE_CHAR(wordListApacheTomcatFile));
        //if (enumDirNotFound != BASE_INVALID_CODE_LEN_DIR)
        StartHttpDirEnum(requestInfoStruct, pFile, enumPageNotFound, enumDirNotFound, pHttpStructInvalide, (char**)wordListApacheTomcatDir, ARRAY_SIZE_CHAR(wordListApacheTomcatDir));
        break;
    case WebServerIIS:
        StartHttpDirEnum(requestInfoStruct, pFile, enumPageNotFound, enumDirNotFound, pHttpStructInvalide, (char**)wordListIisFile, ARRAY_SIZE_CHAR(wordListIisFile));
        if (enumDirNotFound != BASE_INVALID_CODE_LEN_DIR)
            StartHttpDirEnum(requestInfoStruct, pFile, enumPageNotFound, enumDirNotFound, pHttpStructInvalide, (char**)wordListIisFDir, ARRAY_SIZE_CHAR(wordListIisFDir));
        break;
    default:
        break;
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
                    printf("\t\t[SOFTWARE] %s\n", portInfo->banner);
                    return FRITZBoxUserEnum(serverResponce);
                }
                printf("\t\t[SOFTWARE] FRITZBox\n");
                return TRUE;
            case TrueNAS:
                printf("\t\t[SOFTWARE] TrueNAS Detected!\n");
                return TRUE;
            case Deluge:
                if (!EnumDeluge(serverResponce, portInfo))
                    printf("\t\t[SOFTWARE] Deluge Detected!\n");
                return TRUE;
            default:
                break;
            }
        }
    }
    return FALSE;
}

BOOL CheckRequerSsl(char* ipAddress, int port, BOOL* isSSL, FILE* pFile){
    PHTTP_STRUC pHttpStructPage = GetHttpRequest(ipAddress, port, "/", "GET", NULL, FALSE, pFile);
    if (pHttpStructPage == NULL){
        pHttpStructPage = GetHttpRequest(ipAddress, port, "/", "GET", NULL, TRUE, pFile);
        if (pHttpStructPage == NULL)
            return FALSE;
        *isSSL = TRUE;
    }else if (IS_HTTP_ERROR(pHttpStructPage->returnCode)){
        // IF fail test in HTTPS
        FreePHTTP_STRUC(pHttpStructPage);


        pHttpStructPage = GetHttpRequest(ipAddress, port, "/", "GET", NULL, TRUE, pFile);
        if (pHttpStructPage == NULL)
            return FALSE;
        if (IS_HTTP_ERROR(pHttpStructPage->returnCode) && pHttpStructPage->returnCode != STATUS_CODE_UNAUTHORIZED){
            FreePHTTP_STRUC(pHttpStructPage);
            return FALSE;
        }            
        *isSSL = TRUE;
    }
    FreePHTTP_STRUC(pHttpStructPage);
    return TRUE;
}

BOOL GetHttpServerInfo(RequestInfoStruct requestInfoStruct, ServerType* serverType, FILE* pFile,BOOL isBruteForce) {
    printf("\t[HTTP%s] %s:%i - HTTP%s information\n", requestInfoStruct.isSSL ? "S" : "", requestInfoStruct.ipAddress, requestInfoStruct.port, requestInfoStruct.isSSL ? "S" : "");
    
    PHTTP_STRUC pHttpStructPage = GetHttpRequest(requestInfoStruct.ipAddress, requestInfoStruct.port, "/", "GET", requestInfoStruct.httpAuthHeader, requestInfoStruct.isSSL, pFile);
    if (pHttpStructPage == NULL)
        return FALSE;


    if (pHttpStructPage->ServerName != NULL)
        printf("\t\t[Server]\t%s\n", pHttpStructPage->ServerName);
    if (pHttpStructPage->poweredBy != NULL)
        printf("\t\t[X-Powered-By]\t%s\n", pHttpStructPage->poweredBy);
    if (pHttpStructPage->redirectBy != NULL)
        printf("\t\t[X-Redirect-By]\t%s\n", pHttpStructPage->redirectBy);

    if (pHttpStructPage->returnCode < 400) {
        if (pHttpStructPage->returnCode >= 300) {
            if (pHttpStructPage->redirectionPath != NULL)
                printf("\t\t[Redirection]\t%s\n", pHttpStructPage->redirectionPath);
        }
        if (pHttpStructPage->returnCode == STATUS_CODE_OK && pHttpStructPage->pContent != NULL) {
            PORT_INFO portInfo;
            portInfo.portNumber = requestInfoStruct.port;
            portInfo.banner[0] = 0x00;
            GetHTTPFingerprint(pHttpStructPage->pContent, &portInfo);

            //if (GetHTTPFingerprint(pHttpStructPage->pContent, &portInfo))
                //printOut(pFile, "\t[HTTP%s] Port %i Fingerprint %i - %i\n", isSSL ? "S" : "", portInfo.portNumber, portInfo.deviceType, portInfo.version); // portInfo.deviceType todo
        }
    } else {
        if (IS_HTTP_AUTH(pHttpStructPage->returnCode)) {
            if (HttpBasicAuth(requestInfoStruct.ipAddress, requestInfoStruct.port, pHttpStructPage, isBruteForce, requestInfoStruct.isSSL)) {
                if (pHttpStructPage->AuthHeader != NULL) {
                    //size_t strSize = strlen(pHttpStructPage->AuthHeader);
                    strcpy_s(requestInfoStruct.httpAuthHeader, 1024, pHttpStructPage->AuthHeader);
                }
            }
        } else{
            FreePHTTP_STRUC(pHttpStructPage);
            return FALSE;
        }
    }

    BOOL isTestEnable = FALSE;
    *serverType = CheckCVE(requestInfoStruct.ipAddress, requestInfoStruct.port, *pHttpStructPage, isTestEnable);

    FreePHTTP_STRUC(pHttpStructPage);
    return TRUE;
}