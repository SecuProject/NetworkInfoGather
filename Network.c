#include <winsock2.h>
#include <iphlpapi.h>
#include <stdio.h>

#include <ws2tcpip.h>   // inet_pton
#include <iphlpapi.h>   // IPAddr

#include "Network.h"
#include "AdapterInformation.h"

void* xrealloc(void* ptr, size_t size) {
	void* newptr;
	if (size == 0 || ptr == NULL)
		return FALSE;

	newptr = realloc(ptr, size);
	if (newptr == NULL) {
		printf("[x] Memory allocation failed. (%lu)\n", GetLastError());
		free(ptr);
		return NULL;
	}
	return newptr;
}

BOOL IsIpAddressValid(int a, int b, int c, int d) {
	return !(a < 0 || a>255 || b < 0 || b>255 || c < 0 || c>255 || d < 0 || d>255);
}

BOOL GetNetworkRange(char* ipAddress, INT32 ipRangeInt32) {
	INT32 ipAddressInt = IPToUInt(ipAddress);
	return ((ipAddressInt - ipRangeInt32) < 256 && (ipAddressInt - ipRangeInt32) >= 0);
}
/*
FORMAT:
- "192.168.1.1"
- "192.168.1.1:80"
*/
BOOL GetIpPortFromArg(char* argv, pBruteforceStruct pBruteforceStruct) {
	UINT a, b, c, d, port;
	int nbData = sscanf_s(argv, "%u.%u.%u.%u:%u", &a, &b, &c, &d, &port);

	switch (nbData) {
	case 4:
		if (IsIpAddressValid(a, b, c, d)) {
			strcpy_s(pBruteforceStruct->ipAddress, IP_ADDRESS_LEN, argv);
			return TRUE;
		}
		break;
	case 5:
		if (IsIpAddressValid(a, b, c, d)) {
			sprintf_s(pBruteforceStruct->ipAddress, IP_ADDRESS_LEN, "%u.%u.%u.%u", a, b, c, d);
			if (port > 0) {
				pBruteforceStruct->port = port;
				return TRUE;
			}
		}
		break;
	default:
		break;
	}
	return FALSE;
}

BOOL printOut(FILE* pFile, const char* format, ...) {
	va_list args;
	va_start(args, format);
	vprintf(format, args);
	if (pFile != NULL)
		vfprintf(pFile, format, args);
	va_end(args);
	return TRUE;
}

DWORD SyncWaitForMultipleObjs(HANDLE* handles, DWORD count) {
	DWORD waitingThreadsCount = count;
	int index = 0;
	DWORD res = 0;
	while (waitingThreadsCount >= MAXIMUM_WAIT_OBJECTS) {
		res = WaitForMultipleObjects(MAXIMUM_WAIT_OBJECTS, &handles[index], TRUE, INFINITE);
		if (res == WAIT_TIMEOUT || res == WAIT_FAILED) {
			printf("\t[x] SyncWaitForMultipleObjs wait Failed.\t");
			return res;
		}

		waitingThreadsCount -= MAXIMUM_WAIT_OBJECTS;
		index += MAXIMUM_WAIT_OBJECTS;
	}

	if (waitingThreadsCount > 0) {
		res = WaitForMultipleObjects(waitingThreadsCount, &handles[index], TRUE, INFINITE);
		if (res == WAIT_TIMEOUT || res == WAIT_FAILED) {
			printf("\t[x] SyncWaitForMultipleObjs wait Failed.\t");
		}
	}

	return res;
}


SOCKADDR_IN InitSockAddr(char* ipAddress, int port) {
	SOCKADDR_IN ssin;
	IPAddr ipAddressF;

	inet_pton(AF_INET, ipAddress, &ipAddressF);
	memset(&ssin, 0, sizeof(SOCKADDR_IN));
	ssin.sin_family = AF_INET;
	ssin.sin_addr.s_addr = ipAddressF;
	ssin.sin_port = htons(port);

	return ssin;
}


BOOL initWSA(FILE* pFile) {
	WSADATA wsa;

	//printOut(pFile,"[i] Initialising Winsock...");
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
		printOut(pFile,"[x] Failed. Error Code : %d", WSAGetLastError());
		return FALSE;
	}
	//printOut(pFile,"Initialised.\n");
	return TRUE;
}