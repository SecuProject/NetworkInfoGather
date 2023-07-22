
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

#include <Windows.h>
#include <stdio.h>

#include "MgArguments.h"
#include "GetHTTPserver.h"
#include "GetHTTPSserver.h"
#include "Network.h"
#include "ToolsHTTP.h"

BOOL WriteToFile(char* filePath, char* dataBuffer, DWORD dwBytesToWrite) {
	HANDLE hFile;

	hFile = CreateFileA(filePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[x] Fail to open file: %s (%u)\n", filePath, GetLastError());
		return FALSE;
	}
	DWORD dwBytesWritten;
	BOOL bErrorFlag = WriteFile(hFile, dataBuffer, dwBytesToWrite, &dwBytesWritten, NULL);
	if (!bErrorFlag) {
		printf("[x] Terminal failure: Unable to write to the file %s (%u)\n", filePath, GetLastError());
		return FALSE;
	}
	return TRUE;
}

RequestInfoStruct GetInfoFromStruct(CurlStruct CurlStruct,char** pBaseAddress) {
	RequestInfoStruct requestInfoStruct = {
		.ipAddress = NULL,
		.isSSL = CurlStruct.isSsl
	}; 
	char* ptr = CurlStruct.hostUrl;
	char* ptr2;
	char* baseAddress = (char*)malloc(MAX_PATH);
	if (baseAddress == NULL)
		return requestInfoStruct;

	if (CurlStruct.isSsl) {
		ptr += 8; // Remove "https://" string
	} else {
		ptr += 7; // Remove "http://" string
	}


	size_t absoluteStrLen;
	char* resourcePath = strchr(ptr, '/');
	if (resourcePath != NULL) {
		size_t hostnameStrLen = resourcePath - ptr;
		if (hostnameStrLen > MAX_PATH)
			hostnameStrLen = MAX_PATH - 1;
		strncpy_s(baseAddress, MAX_PATH, ptr, hostnameStrLen);
		absoluteStrLen = strlen(resourcePath) + (size_t)1;

		*pBaseAddress = (char*)malloc(absoluteStrLen);
		if (*pBaseAddress == NULL) {
			free(resourcePath);
			return requestInfoStruct; // FAIL
		}
		strcpy_s(*pBaseAddress, absoluteStrLen, resourcePath);
	} else {
		strcpy_s(baseAddress, MAX_PATH, ptr);
		*pBaseAddress = (char*)malloc(2);
		strcpy_s(*pBaseAddress,2,"/");
	}

	
	requestInfoStruct.ipAddress = (char*)malloc(IP_ADDRESS_LEN);
	if (requestInfoStruct.ipAddress == NULL) {
		free(*pBaseAddress);
		free(resourcePath);
		return requestInfoStruct;
	}

	// Check port 
	ptr2 = strchr(ptr, ':');
	if (ptr2 != NULL) {
		ptr2[0] = 0x00;
		ptr2++;
		requestInfoStruct.port = atoi(ptr2);
		strcpy_s(requestInfoStruct.ipAddress, IP_ADDRESS_LEN, ptr);
	} else {
		size_t requStrLen = resourcePath - ptr;
		strncpy_s(requestInfoStruct.ipAddress, IP_ADDRESS_LEN, ptr, requStrLen);
		if (requestInfoStruct.isSSL)
			requestInfoStruct.port = PORT_HTTPS;
		else
			requestInfoStruct.port = PORT_HTTP;
	}
	return requestInfoStruct;
}

char* GetHostIpAddress(char* hostUrl, BOOL isVerboseMode) {
	int a, b, c, d;
	char* ipAddress;

	if (sscanf_s(hostUrl, "%i.%i.%i.%i", &a, &b, &c, &d) == 4) {
		ipAddress = (char*)malloc(IP_ADDRESS_LEN);
		if (ipAddress == NULL)
			return NULL;
		strcpy_s(ipAddress, IP_ADDRESS_LEN, hostUrl);
	} else {
		// Resolve host name
		if(HostnameToIp(hostUrl, &ipAddress)){
			if (sscanf_s(ipAddress, "%i.%i.%i.%i", &a, &b, &c, &d) != 4) {
				free(ipAddress);
				return NULL;
			}
		} else
			return NULL;
	}
	PrintVerbose(isVerboseMode, "\t[i] Checking IP address validity: ", ipAddress);
	if (IsIpAddressValid(a, b, c, d)) {
		PrintVerbose(isVerboseMode, "VALID\n");
		PrintVerbose(isVerboseMode, "\t[i] Target host: %s\n", ipAddress);
	} else
		PrintVerbose(isVerboseMode, "INVALID\n");
	return ipAddress;
}

BOOL Curl(CurlStruct CurlStruct) {
	RequestInfoStruct requestInfoStruct;
	char* urlBaseAddress = NULL;
	char* httpMethon = "GET";

	if (CurlStruct.agentInfo) {
		httpMethon = "HEAD";
	} else if (CurlStruct.method != NULL)
		httpMethon = CurlStruct.method;

	PrintVerbose(CurlStruct.isVerbose, "\t[i] Target url: %s\n", CurlStruct.hostUrl);

	requestInfoStruct = GetInfoFromStruct(CurlStruct, &urlBaseAddress);
	if (requestInfoStruct.ipAddress == NULL)
		return FALSE;


	PrintVerbose(CurlStruct.isVerbose, "\t[i] Target Port: %i\n", requestInfoStruct.port);
	PrintVerbose(CurlStruct.isVerbose, "\t[i] TLS status: %s\n", requestInfoStruct.isSSL? "Enable":"Disable");
	PrintVerbose(CurlStruct.isVerbose, "\t[i] Target resource: %s\n", urlBaseAddress);


	char* ipAddress = GetHostIpAddress(requestInfoStruct.ipAddress, CurlStruct.isVerbose);
	if (ipAddress == NULL) {
		// free ..
		return FALSE;
	}
	strcpy_s(requestInfoStruct.ipAddress, IP_ADDRESS_LEN, ipAddress);


	char* httpUserAgent = "curl/7.54.0";
	if (CurlStruct.userAgent)
		httpUserAgent = CurlStruct.userAgent;
	else if (CurlStruct.agentRand) {
		httpUserAgent = (char*)userAgentList[rand() % (10 - 1)]; // to check
	}
	char* serverResponce = NULL;
	UINT responseSize;

	if (!requestInfoStruct.isSSL) {
		responseSize = GetHttpServer(requestInfoStruct.ipAddress, requestInfoStruct.port, httpMethon, urlBaseAddress, httpUserAgent, &serverResponce, requestInfoStruct.httpAuthHeader, NULL);
	} else {
		responseSize = GetHttpsServer(requestInfoStruct.ipAddress, requestInfoStruct.port, httpMethon, urlBaseAddress, httpUserAgent, &serverResponce, requestInfoStruct.httpAuthHeader, CurlStruct.isVerbose, NULL);
	}
	if (responseSize > 0) {
		if (CurlStruct.filePath == NULL) {
			printf("Request ouptput:\n\n%.*s\n", responseSize, serverResponce);
		} else {
			if (WriteToFile(CurlStruct.filePath, serverResponce, responseSize)) {
				printf("[*] Output data in file %s data %2i kb\n", CurlStruct.filePath, responseSize / 100);
			}
		}
	}
	return TRUE;
}


// User agent
// pCurlStruct.userAgent
// pCurlStruct.agentRand
// pCurlStruct.agentRand

// agentRand -> output !!!


/*

	printf("pCurlStruct.filePath %s\n", CurlStruct.filePath);
if (CurlStruct.agentInfo)
	printf("agentInfo\n");
if (CurlStruct.)
	printf("\n");*/
