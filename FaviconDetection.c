#include <Windows.h>
#include <stdio.h>

#include "md5.h"
#include "GetHTTPSserver.h"
#include "GetHTTPserver.h"
#include "FaviconDatabase.h"
#include "Network.h"
#include "ToolsHTTP.h"


char* GetHttpBody2(char* httpData) {
	const char delim1[] = "\r\n\r\n";
	char* pBody = NULL;

	char* ptr1 = strstr(httpData, delim1);
	if (ptr1 != NULL) {
		pBody = ptr1 + sizeof(delim1) - 1;
	}
	return pBody;
}

UINT GetFavicon(RequestInfoStruct requestInfoStruct, char* requestPath, char** ppDataFavion, char** ppDataFavionBody) {
	char* dataFavion = NULL;
	char* dataFavionBody = NULL;
	UINT faviconSize = 0;

	if (requestInfoStruct.isSSL)
		faviconSize = GetHttpsServer(requestInfoStruct.ipAddress, requestInfoStruct.port, "GET", requestPath, NULL, &dataFavion, requestInfoStruct.httpAuthHeader,TRUE, NULL);
	else
		faviconSize = GetHttpServer(requestInfoStruct.ipAddress, requestInfoStruct.port, "GET", requestPath, NULL, &dataFavion, requestInfoStruct.httpAuthHeader,NULL);
	if (faviconSize == 0)
		return FALSE;

	dataFavionBody = GetHttpBody2(dataFavion);
	if (dataFavionBody == NULL) {
		free(dataFavion);
		return FALSE;
	}

	faviconSize -= (UINT)(dataFavionBody - dataFavion);

	*ppDataFavionBody = dataFavionBody;
	*ppDataFavion = dataFavion;
	return faviconSize;
}

int DatabaseSearch(char* md5Hash) {
	UINT i;
	for (i = 0; i < sizeof(favionStruct) / sizeof(FavionStruct) && strcmp(md5Hash, favionStruct[i].favionMD5) != 0; i++);
	if (i < sizeof(favionStruct) / sizeof(FavionStruct) && strcmp(md5Hash, favionStruct[i].favionMD5) == 0)
		return i;

	return -1;
}

// Call show SSL config ??
BOOL FaviconIdentification(RequestInfoStruct requestInfoStruct, FILE* pFile) {
	char* dataFavion = NULL;
	char* dataFavionBody = NULL;

	const char* tabRequestPath[] = {
		"/favicon.ico",
		//"/phpMyAdmin/favicon.ico",
	};

	UINT faviconSize = GetFavicon(requestInfoStruct, (char*)tabRequestPath[0], &dataFavion, &dataFavionBody);
	if (faviconSize > 0) {
		char* faviconHash = NULL;
		if (MD5Hash(dataFavionBody, faviconSize, &faviconHash)) {
			//printOut(NULL,"\t\t[D] MD5 Hash: %s\n", faviconHash);
			int iFavion = DatabaseSearch(faviconHash);
			if (iFavion >= 0) {
				printOut(NULL,"\t\t[Favicon id] %s\n", favionStruct[iFavion].cmsName);
				free(faviconHash);
				free(dataFavion);
				return TRUE;
			}
			free(faviconHash);
		}
		free(dataFavion);
	}
	return FALSE;
}