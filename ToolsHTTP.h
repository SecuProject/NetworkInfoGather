#pragma once

#ifndef TOOLS_HTTP_HEADER_H
#define TOOLS_HTTP_HEADER_H

#include "NetDiscovery.h"

#define IS_HTTP_SUCCESSFUL(StatusCode)		(StatusCode >= 200 && StatusCode < 300)
#define IS_HTTP_REDIRECTS(StatusCode)		(StatusCode >= 300 && StatusCode < 400)
#define IS_HTTP_ERROR(StatusCode)			(StatusCode >= 400 && StatusCode < 600)
#define IS_HTTP_ERROR_CLIENT(StatusCode)	(StatusCode >= 400 && StatusCode < 500)
#define IS_HTTP_ERROR_SERVER(StatusCode)	(StatusCode >= 500 && StatusCode < 600)


#define STATUS_CODE_OK						200
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

#define NO_BODY_DATA		0

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
	char* redirectBy;
	char* contentType;
	char* requestPath;

	char* redirectionPath;
	char* rawData;
	char* pContent;

	char* AuthHeader;

	int contentLen;
}HTTP_STRUC, * PHTTP_STRUC;

typedef enum {
	UnknownServer = -1,
	Nginx = 0,
	ApacheTomcat,
	ApacheHttpd,
	WebServerIIS,
	LiteSpeed,
	NodeJs,
	Lighttpd,
	Jigsaw
}ServerType;

typedef struct {
	char*   ipAddress;
	int     port;
	char*	httpAuthHeader;
	BOOL    isSSL;
}RequestInfoStruct;

extern const char* sereverTypeStr[8];

char* StrToLower(char* s);
BOOL ExtractStrStr(char* data, const char* delim1, const char* delim2, char** ppBuffer, int* bufferLen);

UINT GetHttpReturnCode(char* serverResponce, UINT responceSize);
BOOL HttpDirEnum(RequestInfoStruct requestInfoStruct, ServerType serverType, FILE* pFile);
BOOL GetHttpServerInfo(RequestInfoStruct requestInfoStruct, ServerType *serverType,  FILE* pFile, BOOL isBruteForce);
//UINT GetHttpReturnCode(char* serverResponce, UINT responceSize); UnknownServer
BOOL CheckRequerSsl(char* ipAddress, int port, BOOL* isSSL, FILE* pFile);

#endif