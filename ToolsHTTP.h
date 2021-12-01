#pragma once

#ifndef TOOLS_HTTP_HEADER_H
#define TOOLS_HTTP_HEADER_H

#include "NetDiscovery.h"

#define IS_HTTP_SUCCEFUL(StatusCode)				(StatusCode >= 200 && StatusCode < 300)
#define IS_HTTP_REDIRECTS(StatusCode)				(StatusCode >= 300 && StatusCode < 400)
#define IS_HTTP_ERROR(StatusCode)					(StatusCode >= 400 && StatusCode < 600)
#define IS_HTTP_ERROR_CLIENT(StatusCode)			(StatusCode >= 400 && StatusCode < 500)
#define IS_HTTP_ERROR_SERVER(StatusCode)			(StatusCode >= 500 && StatusCode < 600)

#define IS_HTTP_AUTH(StatusCode)					(401 == StatusCode || 403 == StatusCode || 407 == StatusCode)

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

	UINT contentLen;
}HTTP_STRUC, * PHTTP_STRUC;


BOOL HttpDirEnum(char* ipAddress, int port, FILE* pFile, BOOL isSSL);
BOOL GetHttpServerInfo(char* ipAddress, int port, FILE* pFile, BOOL isSSL);
//UINT GetHttpReturnCode(char* serverResponce, UINT responceSize);

#endif