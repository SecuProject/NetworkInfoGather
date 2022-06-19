#include <winsock2.h>
#include <iphlpapi.h>   // IPAddr
#include <stdio.h>
#include <ws2tcpip.h>   // inet_pton

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
void* xcalloc(size_t _Count, size_t _Size){
	if (_Count == 0 || _Size == 0)
		return FALSE;
	char* newptr = calloc(_Count, _Size);
	if (newptr == NULL){
		printf("[x] Memory allocation failed. (%lu)\n", GetLastError());
		return NULL;
	}
	return newptr;
}
void* xmalloc(size_t _Size){
	if (_Size == 0)
		return FALSE;
	char* newptr = malloc(_Size);
	if (newptr == NULL){
		printf("[x] Memory allocation failed. (%lu)\n", GetLastError());
		return NULL;
	}
	return newptr;
}


BOOL InitNetworkPcInfo(NetworkPcInfo** pNetworkPcInfo, PTHREAD_STRUCT_DATA* pThreadStructData, DWORD** pDwThreadIdArray, HANDLE** pThreadArray, int maskSizeInt){
	NetworkPcInfo* networkPcInfo = (NetworkPcInfo*)xcalloc(maskSizeInt, sizeof(NetworkPcInfo));
	if (networkPcInfo != NULL){
		PTHREAD_STRUCT_DATA threadStructData = (PTHREAD_STRUCT_DATA)xcalloc(maskSizeInt, sizeof(THREAD_STRUCT_DATA));
		if (threadStructData != NULL){
			DWORD* dwThreadIdArray = (DWORD*)xcalloc(maskSizeInt, sizeof(DWORD));
			if (dwThreadIdArray != NULL){
				HANDLE* hThreadArray = (HANDLE*)xcalloc(maskSizeInt, sizeof(HANDLE));
				if (hThreadArray != NULL){
					*pNetworkPcInfo = networkPcInfo;
					*pThreadStructData = threadStructData;
					*pDwThreadIdArray = dwThreadIdArray;
					*pThreadArray = hThreadArray;
					return TRUE;
				}
				free(dwThreadIdArray);
			}
			free(threadStructData);
		}
		free(networkPcInfo);
	}
	return FALSE;
}
VOID FreeNetworkPcInfo(PTHREAD_STRUCT_DATA threadStructData, DWORD* dwThreadIdArray, HANDLE threadArray){
	if (threadArray != NULL)
		free(threadArray);
	if (dwThreadIdArray != NULL)
		free(dwThreadIdArray);
	if (threadStructData != NULL)
		free(threadStructData);
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

char* StrToLower(char* s) {
	for (char* p = s; *p; p++) *p = tolower(*p);
	return s;
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
BOOL printVerbose(BOOL isVerbose, const char* format, ...) {
	if (isVerbose) {
		va_list args;
		va_start(args, format);
		vprintf(format, args);
		va_end(args);
	}
	return TRUE;
}

DWORD SyncWaitForMultipleObjs(HANDLE* handles, DWORD count) {
	DWORD waitingThreadsCount = count;
	int index = 0;
	DWORD res = 0;
	while (waitingThreadsCount >= MAXIMUM_WAIT_OBJECTS) {
		res = WaitForMultipleObjects(MAXIMUM_WAIT_OBJECTS, &handles[index], TRUE, INFINITE);
		if (res == WAIT_TIMEOUT) { // || res == WAIT_FAILED
			printf("\t[x] SyncWaitForMultipleObjs wait Failed (%lu).\n", res);
			return res;
		}

		waitingThreadsCount -= MAXIMUM_WAIT_OBJECTS;
		index += MAXIMUM_WAIT_OBJECTS;
	}

	if (waitingThreadsCount > 0) {
		res = WaitForMultipleObjects(waitingThreadsCount, &handles[index], TRUE, INFINITE);
		if (res == WAIT_TIMEOUT){ // || res == WAIT_FAILED
			printf("\t[x] SyncWaitForMultipleObjs wait Failed (%lu).\n", res);
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
SOCKET ConnectTcpServer(char* ipAddress, int port){
	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET)
		return INVALID_SOCKET;
	SOCKADDR_IN ssin = InitSockAddr(ipAddress, port);

	SetOptions(sock);
	//printf("\t[i] Connecting...\n");
	if (connect(sock, (struct sockaddr*)&ssin, sizeof(ssin)) == SOCKET_ERROR){
		printf("\t[x] Connection Error %lu\n", WSAGetLastError());
		closesocket(sock);
		return INVALID_SOCKET;
	}
	return sock;
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

// Set socket time out 2 sec
int SetOptions(SOCKET fd){
	struct timeval timeout;

	timeout.tv_sec = 2;
	timeout.tv_usec = 0;
	return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) != SOCKET_ERROR;
}


BOOL SizeConsole(int* columns, int* rows){
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	HANDLE stdHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	if (stdHandle == INVALID_HANDLE_VALUE)
		return FALSE;

	if (GetConsoleScreenBufferInfo(stdHandle, &csbi)){
		*columns = csbi.srWindow.Right - csbi.srWindow.Left + 1;
		*rows = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
		return TRUE;
	}
	return FALSE;
}
VOID LoadingBar(UINT i, UINT total){
	UINT consoleColumns;
	UINT consolerows;

	if (!SizeConsole(&consoleColumns, &consolerows)){
		consoleColumns = 120 - 16;
		consolerows = 30;
	} else{
		if(consoleColumns > 50)
			consoleColumns -= 16;
	}
	UINT percentDone = (UINT)(((double)i / total) * 100);
	UINT Average = percentDone * (consoleColumns/2) / 100;
	// 1000 / 4000 => 0.25 *100
	printf("\r\t\t[");

	for (UINT j = 0; j < Average; j++)
		printf("#");
	for (UINT j = 0; j < (consoleColumns / 2) - Average; j++)
		printf(" ");
	printf("] %u%% (%lu/%lu)\r", percentDone, i, total);



	if (i >= total-1){
		for (UINT j = 0; j < consoleColumns - 2; j++)
			printf(" ");
	}
	printf("\r");
}
