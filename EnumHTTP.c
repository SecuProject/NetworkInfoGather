#include <stdio.h>
#include <Windows.h>

#include "ToolsHTTP.h"
#include "DetectWAF.h"
#include "FaviconDetection.h"
#include "NetDiscovery.h"


BOOL EnumHTTP(char* ipAddress, int portNb,BOOL isWAfDetection, FILE* pFile, BOOL isSSL, BOOL isBruteForce) {
	ServerType serverType;
	RequestInfoStruct requestInfoStruct = {
		.ipAddress = ipAddress,
		.isSSL = isSSL,
		.port = portNb,
		.httpAuthHeader = (char*)malloc(BUFFER_SIZE)
	};

	if (requestInfoStruct.httpAuthHeader == NULL)
		return FALSE;
	requestInfoStruct.httpAuthHeader[0] = 0x00;

	// Check if http or https 
	if (!isSSL)
		CheckRequerSsl(ipAddress, portNb, &isSSL, pFile);

	if (GetHttpServerInfo(requestInfoStruct, &serverType, pFile, isBruteForce)) {
		if (isWAfDetection)
			IsHttpWaf(requestInfoStruct, pFile);
		FaviconIdentification(requestInfoStruct, pFile);
		HttpDirEnum(requestInfoStruct, serverType, pFile);

		free(requestInfoStruct.httpAuthHeader);
		return TRUE;
	}

	free(requestInfoStruct.httpAuthHeader);
	return FALSE;
}