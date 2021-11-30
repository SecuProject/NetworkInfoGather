#include <stdio.h>
#include <Windows.h>

#include "ToolsHTTP.h"
#include "DetectWAF.h"
#include "FaviconDetection.h"


BOOL EnumHTTP(char* ipAddress, int portNb,BOOL isWAfDetection, FILE* pFile, BOOL isSSL) {
	if (GetHttpServerInfo(ipAddress, portNb, pFile, isSSL)) {
		if (isWAfDetection)
			IsHttpWaf(ipAddress, portNb, pFile, isSSL);
		FaviconIdentification(ipAddress, portNb, pFile, isSSL);
		HttpDirEnum(ipAddress, portNb, pFile, isSSL);
		return TRUE;
	}
	return FALSE;
}