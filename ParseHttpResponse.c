
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

#include "Network.h"
#include "ToolsHTTP.h"
#include "ParseHttpResponse.h"


UINT GetHttpReturnCode(char* serverResponce, UINT responceSize) {
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

    for (int i = 0; i < ARRAY_SIZE_CHAR(delim1); i++) {
        if (ExtractStrStr(serverResponce, delim1[i], delim2, &buffer, &bufferLen)) {
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

    if (ExtractStrStr(serverResponce, delim1, delim2, &buffer, &bufferLen)) {
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

    if (ExtractStrStr(serverResponce, delim1, delim2, &buffer, &bufferLen)) {
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

BOOL GetHttpHeaderRedirectby(PHTTP_STRUC httpStruct, UINT responceSize) {
    UINT serverVersionSize = responceSize + 1;
    httpStruct->redirectBy = (char*)malloc(serverVersionSize);
    if (httpStruct->redirectBy != NULL) {
        const char delim1[] = "	X-Redirect-By:";
        if (GetHttpHeaderStr(delim1, sizeof(delim1), httpStruct->rawData, httpStruct->redirectBy, &serverVersionSize)) {
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
            httpStruct->contentType = (char*)xrealloc(httpStruct->contentType, serverVersionSize + 1);
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
    UINT serverVersionSize = responceSize + 1;
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
    } else
        httpStruct->redirectionPath = NULL;

    return TRUE;
}


PHTTP_STRUC InitPHTTP_STRUC(UINT nbElement) {
    PHTTP_STRUC httpStruct = (PHTTP_STRUC)xcalloc(nbElement, sizeof(HTTP_STRUC));
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