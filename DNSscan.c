#include <ws2tcpip.h>   // inet_pton
#include <iphlpapi.h>   // IPAddr
#include <Windows.h>
#include <stdio.h>
#include <windns.h>

#include "Network.h"
#include "NetDiscovery.h"

#pragma warning(disable:4996)


#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

void ReverseIP(char* pIP, UINT bufferSize) {
	char seps[] = ".";
	char* token;
	char pIPSec[4][4];
	int i = 0;
	token = strtok(pIP, seps);
	while (token != NULL) {
		/* While there are "." characters in "string" */
		sprintf_s(pIPSec[i], 4, "%s", token);
		/* Get next "." character: */
		token = strtok(NULL, seps);
		i++;
	}
	sprintf_s(pIP, bufferSize, "%s.%s.%s.%s.%s", pIPSec[3], pIPSec[2], pIPSec[1], pIPSec[0], "IN-ADDR.ARPA");
}
BOOL DnsRequest(char* pOwnerName, char* DnsServIp, WORD wType, char** hostname, FILE* pFile) {
	BOOL result = FALSE;
	//DNS_STATUS status;
	PDNS_RECORD pDnsRecord;

	// Allocate memory for IP4_ARRAY structure.

	PIP4_ARRAY pSrvList = (PIP4_ARRAY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(IP4_ARRAY));
	if (pSrvList == NULL) {
		printf("Memory allocation failed \n");
		return FALSE;
	}

	IPAddr ipAddressF;
	inet_pton(AF_INET, DnsServIp, &ipAddressF);

	pSrvList->AddrCount = 1;
	pSrvList->AddrArray[0] = ipAddressF; //DNS server IP address

	//printf("To test: %s (Server:%s)\n", pOwnerName, DnsServIp);
	if (!DnsQuery_A(pOwnerName, wType, DNS_QUERY_STANDARD, pSrvList, &pDnsRecord, NULL)) {
		//printf("The host name is %s\n", (char*)(pDnsRecord->Data.PTR.pNameHost));
		if (pDnsRecord != NULL) {
			size_t bufferSize = strlen((char*)(pDnsRecord->Data.PTR.pNameHost)) + 1;
			*hostname = (char*)malloc(bufferSize);
			if (*hostname != NULL) {
				strcpy_s(*hostname, bufferSize, (char*)(pDnsRecord->Data.PTR.pNameHost));
				result = TRUE;
			}
			DnsRecordListFree(pDnsRecord, freetype);
		}
	}
	HeapFree(GetProcessHeap(), 0, pSrvList);
	return result;
}


BOOL GetDnsServer(char* serverDnsIp, UINT bufferSize) {
	FIXED_INFO* pFixedInfo;
	ULONG ulOutBufLen;
	DWORD dwRetVal;
	//IP_ADDR_STRING* pIPAddr;
	BOOL result = FALSE;

	pFixedInfo = (FIXED_INFO*)MALLOC(sizeof(FIXED_INFO));
	if (pFixedInfo == NULL) {
		printf("Error allocating memory needed to call GetNetworkParams\n");
		return FALSE;
	}
	ulOutBufLen = sizeof(FIXED_INFO);

	if (GetNetworkParams(pFixedInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		FREE(pFixedInfo);
		pFixedInfo = (FIXED_INFO*)MALLOC(ulOutBufLen);
		if (pFixedInfo == NULL) {
			printf("Error allocating memory needed to call GetNetworkParams\n");
			return FALSE;
		}
	}
	dwRetVal = GetNetworkParams(pFixedInfo, &ulOutBufLen);
	if (dwRetVal == NO_ERROR) {
		IP_ADDR_STRING pDnsServerList = pFixedInfo->DnsServerList;

		char* pDnsServer = pDnsServerList.IpAddress.String;
		PIP_ADDR_STRING pNext = pDnsServerList.Next;
		while (!IS_PRIVATE_IP(pDnsServer) && pNext != NULL) {
			pDnsServer = pDnsServerList.IpAddress.String;
			pNext = pNext->Next;
		}
		if (IS_PRIVATE_IP(pDnsServer)) {
			strcpy_s(serverDnsIp, bufferSize, pDnsServer);
			result = TRUE;
		}
	} else {
		printf("GetNetworkParams failed with error: %lu\n", dwRetVal);
		return FALSE;
	}

	if (pFixedInfo)
		FREE(pFixedInfo);
	return result;
}



//BOOL startPinging(char* ipAddress, int* computerTTL, FILE* pFile) {
BOOL StartDnsRequest(char* ipAddress,char* serverDnsIp, char** hostname, FILE* pFile) {
	BOOL detected = FALSE;
	WORD wType = DNS_TYPE_PTR;

	char* dnsBuffer = (char*)malloc(MAX_PATH);
	if (dnsBuffer == NULL)
		return FALSE;

	strcpy_s(dnsBuffer, MAX_PATH, ipAddress);
	ReverseIP(dnsBuffer, MAX_PATH);
	detected = DnsRequest(dnsBuffer, serverDnsIp, wType, hostname,pFile);

	free(dnsBuffer);
	return detected;
}

typedef struct {
	char ipAddress[IP_ADDRESS_LEN + 1];
	//char macAddress[MAC_ADDRESS_LEN + 1];
	char* hostname;
	char* serverDnsIp;
	//int computerTTL;
	FILE* pFile;
	BOOL isHostUp;
} THREAD_STRUCT_DATA_DNS, * PTHREAD_STRUCT_DATA_DNS;


DWORD WINAPI ThreadDnsQueryHost(LPVOID lpParam) {
	PTHREAD_STRUCT_DATA_DNS dnsStructData = (PTHREAD_STRUCT_DATA_DNS)lpParam;
	dnsStructData->isHostUp = StartDnsRequest(dnsStructData->ipAddress, dnsStructData->serverDnsIp, &(dnsStructData->hostname), dnsStructData->pFile);
	return dnsStructData->isHostUp;
}

BOOL DNSdiscoveryMultiThread(int maskSizeInt, NetworkPcInfo** ptrNetworkPcInfo, INT32 ipAddressBc, int* nbDetected, FILE* pFile) {
	NetworkPcInfo* networkPcInfo = (NetworkPcInfo*)calloc(maskSizeInt, sizeof(NetworkPcInfo));

	if (networkPcInfo == NULL) {
		printOut(pFile, "\t[x] Unable to allocate memory\n");
		return FALSE;
	}
	PTHREAD_STRUCT_DATA_DNS* pDataArray = (PTHREAD_STRUCT_DATA_DNS*)calloc(maskSizeInt, sizeof(PTHREAD_STRUCT_DATA_DNS));
	if (pDataArray == NULL) {
		printOut(pFile, "\t[x] Unable to allocate memory\n");
		free(networkPcInfo);
		return FALSE;
	}
	DWORD* dwThreadIdArray = (DWORD*)calloc(maskSizeInt, sizeof(DWORD));
	if (dwThreadIdArray == NULL) {
		printOut(pFile, "\t[x] Unable to allocate memory\n");
		free(pDataArray);
		free(networkPcInfo);
		return FALSE;
	}
	HANDLE* hThreadArray = (HANDLE*)calloc(maskSizeInt, sizeof(HANDLE));
	if (hThreadArray == NULL) {
		printOut(pFile, "\t[x] Unable to allocate memory\n");
		free(dwThreadIdArray);
		free(pDataArray);
		free(networkPcInfo);
		return FALSE;
	}

	char* serverDnsIp = (char*)malloc(IP_ADDRESS_LEN);
	if (serverDnsIp == NULL) {
		printOut(pFile, "\t[x] Unable to allocate memory\n");
		free(hThreadArray);
		free(dwThreadIdArray);
		free(pDataArray);
		free(networkPcInfo);
		return FALSE;
	}

	if (!GetDnsServer(serverDnsIp, IP_ADDRESS_LEN)) {
		printf("\t[x] Server DNS IP address is public !\n");
		free(hThreadArray);
		free(dwThreadIdArray);
		free(pDataArray);
		free(networkPcInfo);
		return FALSE;
	}

	for (int i = 0; i < maskSizeInt; i++) {
		pDataArray[i] = (PTHREAD_STRUCT_DATA_DNS)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(THREAD_STRUCT_DATA_DNS));
		if (pDataArray[i] == NULL) {
			printf("\t[x] Unable to allocate memory\n");
			free(serverDnsIp);
			free(hThreadArray);
			free(dwThreadIdArray);
			free(pDataArray);
			free(networkPcInfo);
			return FALSE;
		}
		pDataArray[i]->pFile = NULL;
		pDataArray[i]->serverDnsIp = serverDnsIp;


		INT32 ipAddress = ipAddressBc + i;
		sprintf_s(pDataArray[i]->ipAddress, IP_ADDRESS_LEN, "%i.%i.%i.%i",
			(ipAddress >> 24) & OCTE_MAX, //  << 24; // (OCTE_SIZE * 4)
			(ipAddress >> OCTE_SIZE * 2) & OCTE_MAX,
			(ipAddress >> OCTE_SIZE) & OCTE_MAX,
			ipAddress & OCTE_MAX);
		hThreadArray[i] = CreateThread(NULL, 0, ThreadDnsQueryHost, pDataArray[i], 0, &dwThreadIdArray[i]);
		if (hThreadArray[i] == NULL) {
			printf("\t[x] Unable to Create Thread\n");
			free(serverDnsIp);
			free(hThreadArray);
			free(dwThreadIdArray);
			free(pDataArray);
			free(networkPcInfo);
			return FALSE;
		}
		Sleep(20);
	}
	SyncWaitForMultipleObjs(hThreadArray, maskSizeInt);
	free(serverDnsIp);


	int nbHostUp = 0;
	//printf("[*] List of hosts:\n");
	for (int i = 0; i < maskSizeInt; i++) {
		if (hThreadArray[i] == NULL)
			CloseHandle(hThreadArray[i]);
		if (pDataArray[i] != NULL) {
			if (pDataArray[i]->isHostUp) {
				networkPcInfo[nbHostUp].ipAddress = (char*)malloc(IP_ADDRESS_LEN);
				if (networkPcInfo[nbHostUp].ipAddress == NULL)
					return FALSE;
				strcpy_s(networkPcInfo[nbHostUp].ipAddress, IP_ADDRESS_LEN, pDataArray[i]->ipAddress);



				size_t hostnameSize = strlen(pDataArray[i]->hostname) + 1;
				networkPcInfo[nbHostUp].hostname = (char*)malloc(hostnameSize);
				if (networkPcInfo[nbHostUp].hostname == NULL)
					return FALSE;
				strcpy_s(networkPcInfo[nbHostUp].hostname, hostnameSize, pDataArray[i]->hostname);


				//printf("The hostname of %s is %s\n", networkPcInfo[nbHostUp].ipAddress, networkPcInfo[nbHostUp].hostname);

				free(pDataArray[i]->hostname);
				nbHostUp++;
			}
			HeapFree(GetProcessHeap(), 0, pDataArray[i]); // ???? -> FREE 
			pDataArray[i] = NULL;    // Ensure address is not reused.
		}

	}

	free(hThreadArray);
	free(dwThreadIdArray);
	free(pDataArray);

	networkPcInfo = (NetworkPcInfo*)xrealloc(networkPcInfo, (nbHostUp + 1) * sizeof(NetworkPcInfo));
	if (networkPcInfo == NULL)
		return FALSE;

	*nbDetected = nbHostUp;
	*ptrNetworkPcInfo = networkPcInfo;
	return TRUE;
}