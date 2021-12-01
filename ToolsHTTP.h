#pragma once

#ifndef TOOLS_HTTP_HEADER_H
#define TOOLS_HTTP_HEADER_H

#include "NetDiscovery.h"

#define IS_HTTP_SUCCESSFUL(StatusCode)		(StatusCode >= 200 && StatusCode < 300)
#define IS_HTTP_REDIRECTS(StatusCode)		(StatusCode >= 300 && StatusCode < 400)
#define IS_HTTP_ERROR(StatusCode)			(StatusCode >= 400 && StatusCode < 600)
#define IS_HTTP_ERROR_CLIENT(StatusCode)	(StatusCode >= 400 && StatusCode < 500)
#define IS_HTTP_ERROR_SERVER(StatusCode)	(StatusCode >= 500 && StatusCode < 600)


#define STATUS_CODE_UNAUTHORIZED			401
#define STATUS_CODE_FORBIDDEN				403
#define STATUS_CODE_PROXY_AUTH_REQ			407

#define IS_HTTP_AUTH(StatusCode)			(STATUS_CODE_UNAUTHORIZED == StatusCode || \
											STATUS_CODE_FORBIDDEN == StatusCode || \
											STATUS_CODE_PROXY_AUTH_REQ == StatusCode)
#define IS_HTTP_PROXY_AUTH(StatusCode)		STATUS_CODE_PROXY_AUTH_REQ == StatusCode

#define GET_REQUEST_SIZE    10000
#define GET_RESPONSE_SIZE   10000
#define SERVER_VERSION_SIZE 100


extern const char* userAgentList[];

typedef struct {
	const char* pStart;
	const char* pStop;
	DeviceType deviceType;
}StrucStrDev;

extern const StrucStrDev structStrDev[];


typedef struct {
	UINT returnCode;
	UINT responseLen;
	char* ServerName;
	char* poweredBy;
	char* contentType;
	char* requestPath;

	char* redirectionPath;
	char* rawData;
	char* pContent;

	char* AuthHeader;

	UINT contentLen;
}HTTP_STRUC, * PHTTP_STRUC;

char* StrToLower(char* s);
UINT GetHttpReturnCode(char* serverResponce, UINT responceSize);
BOOL HttpDirEnum(char* ipAddress, int port, char* httpAuthHeader, FILE* pFile, BOOL isSSL);
BOOL GetHttpServerInfo(char* ipAddress, int port, char* httpAuthHeader, FILE* pFile, BOOL isSSL, BOOL isBruteForce);
//UINT GetHttpReturnCode(char* serverResponce, UINT responceSize);

#endif