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