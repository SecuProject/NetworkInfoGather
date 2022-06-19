
#pragma once
#include "portList.h"
#include "NetDiscovery.h"

#ifndef NETWORK_HEADER_H
#define NETWORK_HEADER_H


#define ARRAY_SIZE_CHAR(charTab)    (UINT)(sizeof(charTab)/sizeof(char*))


#define ACCESS_DENIED   5
#define NO_MORE_FILES   18


#define MAX_NB_ADAPTER	50

#define MASK_NB_BYTE	4

#define OCTE_MAX		0xFF
#define OCTE_SIZE		8
#define BYTE_SIZE		4
#define IP_ADDRESS_LEN	16
#define MASK_SIZE_CHAR	16

#define MAC_ADDRESS_LEN_BYTE	6
#define MAC_ADDRESS_LEN			MAC_ADDRESS_LEN_BYTE * 2 + 5
//#define MAC_ADDRESS_LEN	    MAC_ADDRESS_LEN_BYTE * 2 + 5 + 50   // test

#define IS_PRIVATE_IP(IP_ADDRESS)		(strncmp(IP_ADDRESS, "192.168.", 8) == 0 \
										||strncmp(IP_ADDRESS, "172.16.", 7) == 0 \
										|| strncmp(IP_ADDRESS, "10.", 3) == 0)


typedef struct {
	char ipAddress[IP_ADDRESS_LEN + 1];
	char macAddress[MAC_ADDRESS_LEN + 1];

	// For DNS reuqest
	char* hostname;
	char* serverDnsIp;

	//For Ping
	int computerTTL;

	FILE* pFile;
	BOOL isHostUp;
} THREAD_STRUCT_DATA, * PTHREAD_STRUCT_DATA;


BOOL initWSA(FILE* pFile);
int SetOptions(SOCKET fd);


BOOL IsIpAddressValid(int a, int b, int c, int d);
BOOL GetNetworkRange(char* ipAddress, INT32 ipRangeInt32);
BOOL GetIpPortFromArg(char* argv, pBruteforceStruct pBruteforceStruct);

BOOL printOut(FILE* pFile, const char* format, ...);
BOOL printVerbose(BOOL isVerbose, const char* format, ...);
DWORD SyncWaitForMultipleObjs(HANDLE* handles, DWORD count);


BOOL InitNetworkPcInfo(NetworkPcInfo** pNetworkPcInfo, PTHREAD_STRUCT_DATA* pThreadStructData, DWORD** pDwThreadIdArray, HANDLE** pThreadArray, int maskSizeInt);
VOID FreeNetworkPcInfo(PTHREAD_STRUCT_DATA threadStructData, DWORD* dwThreadIdArray, HANDLE threadArray);

SOCKADDR_IN InitSockAddr(char* ipAddress, int port);	// Test remove !!!
SOCKET ConnectTcpServer(char* ipAddress, int port);

void* xrealloc(void* ptr, size_t size);
void* xcalloc(size_t _Count, size_t _Size);
void* xmalloc(size_t _Size);

VOID LoadingBar(UINT i, UINT total);
char* StrToLower(char* s);

#endif