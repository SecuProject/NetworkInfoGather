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

#include "ToolsHTTP.h"
#include "DetectHttpBasicAuth.h"
#include "CheckCVE.h"

#include "ParseHttpResponse.h"
#include "ParseHttpResponse.h"

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



const StrucStrDev structStrDev[] = {
    //{"\"bluBarTitle\":\"FRITZ!Box ","\"",FRITZBox} ,
    {"\"bluBarTitle\":\"FRITZ!","\"",FRITZBox} ,
    {"product.trim() === 'TrueNAS'",NULL,TrueNAS} ,
    {"author: 'Deluge Team',",NULL,Deluge} ,
    {"test","Cable",UnknownType} ,
};


PHTTP_STRUC GetHttpRequest2(char* ipAddress, int port, char* path, char* requestType, char* httpAuthHeader, BOOL isSSL, FILE* pFile) {
    PHTTP_STRUC httpStruct = InitPHTTP_STRUC(1);
    if (httpStruct == NULL)
        return NULL;

    httpStruct->requestPath = path;

    if (isSSL)
        httpStruct->responseLen = GetHttpsServer(ipAddress, port, requestType, path, NULL, &(httpStruct->rawData), httpAuthHeader, FALSE, pFile);
    else
        httpStruct->responseLen = GetHttpServer(ipAddress, port, requestType, path, NULL, &(httpStruct->rawData), httpAuthHeader, pFile); // GET
    if (httpStruct->responseLen == 0) {
        //PrintOut(pFile, "\t\t[x] Page not available !\n");
        if (httpStruct->rawData != NULL)
            free(httpStruct->rawData);
        free(httpStruct);
        return NULL;
    }
    if (httpStruct->rawData == NULL) {
        PrintOut(pFile, "\t\t[x] Response data error !\n");
        free(httpStruct);
        return NULL;
    }

    if (!GetHttpRequestInfo(httpStruct)) {
        PrintOut(pFile, "\t\t[x] Fail to retrieve information form the request !\n");
        free(httpStruct->rawData);
        free(httpStruct);
        return NULL;
    }
    return httpStruct;
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

/*PHTTP_STRUC GetHttpRequestHead(char* ipAddress, int port, char* path, FILE* pFile) {
    PHTTP_STRUC httpStruct = InitPHTTP_STRUC(1);
    if (httpStruct == NULL)
        return NULL;

    httpStruct->requestPath = path;
    httpStruct->responseLen = GetHttpServer(ipAddress, port, "HEAD", path, NULL, httpStruct->rawData, pFile);

    if (httpStruct->responseLen == 0) {
        PrintOut(pFile, "\t[-] Page not available !\n");
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
        PrintOut(pFile, "\t[-] Fail to retrieve information form the request !\n");
        free(httpStruct->rawData);
        free(httpStruct);
        return NULL;
    }
    return httpStruct;
}*/

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
    PHTTP_STRUC pHttpStructPage = GetHttpRequest2(ipAddress, port, "/", "GET", NULL, FALSE, pFile);
    if (pHttpStructPage == NULL){
        pHttpStructPage = GetHttpRequest2(ipAddress, port, "/", "GET", NULL, TRUE, pFile);
        if (pHttpStructPage == NULL)
            return FALSE;
        *isSSL = TRUE;
    }else if (IS_HTTP_ERROR(pHttpStructPage->returnCode)){
        // IF fail test in HTTPS
        FreePHTTP_STRUC(pHttpStructPage);


        pHttpStructPage = GetHttpRequest2(ipAddress, port, "/", "GET", NULL, TRUE, pFile);
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
    
    PHTTP_STRUC pHttpStructPage = GetHttpRequest2(requestInfoStruct.ipAddress, requestInfoStruct.port, "/", "GET", requestInfoStruct.httpAuthHeader, requestInfoStruct.isSSL, pFile);
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
                //PrintOut(pFile, "\t[HTTP%s] Port %i Fingerprint %i - %i\n", isSSL ? "S" : "", portInfo.portNumber, portInfo.deviceType, portInfo.version); // portInfo.deviceType todo
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