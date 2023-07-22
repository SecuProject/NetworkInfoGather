
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

#pragma once

#ifndef TOOLS_HTTP_HEADER_H
#define TOOLS_HTTP_HEADER_H

#include "NetDiscovery.h"
#include "ParseHttpResponse.h"

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

extern const char* userAgentList[10];

typedef struct {
	const char* pStart;
	const char* pStop;
	DeviceType deviceType;
}StrucStrDev;

extern const StrucStrDev structStrDev[];




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
BOOL ExtractStrInt(char* str, int matchStr, char* buffer, int bufferLen);

PHTTP_STRUC GetHttpRequest2(char* ipAddress, int port, char* path, char* requestType, char* httpAuthHeader, BOOL isSSL, FILE* pFile);

#endif