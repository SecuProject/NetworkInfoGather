#include <stdio.h>
#include <Windows.h>

#include "ToolsHTTP.h"
#include "DetectWAF.h"
#include "FaviconDetection.h"


BOOL EnumHTTP(char* ipAddress, int portNb,BOOL isWAfDetection, FILE* pFile, BOOL isSSL, BOOL isBruteForce) {
	char* httpAuthHeader = (char*)malloc(1024);
	if (httpAuthHeader == NULL)
		return FALSE;
	httpAuthHeader[0] = 0x00;

	// Check if http or https 
	if (!isSSL)
		CheckRequerSsl(ipAddress, portNb, &isSSL, pFile);

	if (GetHttpServerInfo(ipAddress, portNb, httpAuthHeader, pFile, isSSL, isBruteForce)) {
		if (isWAfDetection)
			IsHttpWaf(ipAddress, portNb, pFile, isSSL);
		FaviconIdentification(ipAddress, portNb, pFile, isSSL);
		HttpDirEnum(ipAddress, portNb, httpAuthHeader, pFile, isSSL);

		free(httpAuthHeader);
		return TRUE;
	}

	free(httpAuthHeader);
	return FALSE;
}