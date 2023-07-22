
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



#ifndef PARSE_HTTP_RESPONSE_HEADER_H
#define PARSE_HTTP_RESPONSE_HEADER_H


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


UINT GetHttpReturnCode(char* serverResponce, UINT responceSize);
int GetHttpContentLen(char* serverResponce, UINT responceSize);
BOOL GetHttpHeaderStr(const char* delim1, int sizeDelim1, char* serverResponce, char* serverVersion, int* bufferSize);

BOOL GetHttpHeaderServerVersion(PHTTP_STRUC httpStruct, UINT responceSize);
BOOL GetHttpHeaderPowerby(PHTTP_STRUC httpStruct, UINT responceSize);

BOOL GetHttpHeaderRedirectby(PHTTP_STRUC httpStruct, UINT responceSize);


BOOL GetHttpHeaderContentType(PHTTP_STRUC httpStruct, UINT responceSize);
BOOL GetHttpHeaderRedirection(PHTTP_STRUC httpStruct, UINT responceSize);
BOOL GetHttpBody(PHTTP_STRUC httpStruct);
BOOL GetHttpRequestInfo(PHTTP_STRUC httpStruct);


PHTTP_STRUC InitPHTTP_STRUC(UINT nbElement);
VOID FreePHTTP_STRUC(PHTTP_STRUC pHTTP_STRUC);

#endif