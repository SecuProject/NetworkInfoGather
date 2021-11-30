#include <stdio.h>
#include <Windows.h>

#include "ToolsHTTP.h"
#include "DetectWAF.h"
#include "FaviconDetection.h"


BOOL EnumHTTP(char* ipAddress, int portNb,BOOL isWAfDetection, FILE* pFile, BOOL isSSL) {
	if (GetHttpServerInfo(ipAddress, portNb, pFile, FALSE)) {
		if (isWAfDetection)
			IsHttpWaf(ipAddress, portNb, pFile, FALSE);
	}
	FaviconIdentification(ipAddress, portNb, pFile, FALSE);
	HttpDirEnum(ipAddress, portNb, pFile, FALSE);
	return TRUE;
}