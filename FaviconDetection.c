#include <Windows.h>
#include <stdio.h>

#include "md5.h"
#include "GetHTTPSserver.h"
#include "GetHTTPserver.h"
#include "FaviconDatabase.h"
#include "Network.h"


char* GetHttpBody2(char* httpData) {
	const char delim1[] = "\r\n\r\n";
	char* pBody = NULL;

	char* ptr1 = strstr(httpData, delim1);
	if (ptr1 != NULL) {
		pBody = ptr1 + sizeof(delim1) - 1;
	}
	return pBody;
}

UINT GetFavicon(char* ipAddress, int port, char* requestPath, char** ppDataFavion, char** ppDataFavionBody, BOOL isSSL) {
	char* dataFavion = NULL;
	char* dataFavionBody = NULL;
	UINT faviconSize = 0;

	if (isSSL)
		faviconSize = GetHttpsServer(ipAddress, port, "GET", requestPath, NULL, &dataFavion, NULL,TRUE, NULL);
	else
		faviconSize = GetHttpServer(ipAddress, port, "GET", requestPath, NULL, &dataFavion, NULL,NULL);
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
BOOL FaviconIdentification(char* ipAddress, int port, FILE* pFile, BOOL isSSL) {
	char* dataFavion = NULL;
	char* dataFavionBody = NULL;

	const char* tabRequestPath[] = {
		"/favicon.ico",
		//"/phpMyAdmin/favicon.ico",
	};

	UINT faviconSize = GetFavicon(ipAddress, port, (char*)tabRequestPath[0], &dataFavion, &dataFavionBody, isSSL);
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

/*
int main() {
	initWSA();

	FaviconIdentification("192.168.1.10", 80);

	system("pause");
	return FALSE;
}*/