
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