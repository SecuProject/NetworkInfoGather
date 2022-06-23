#include <ws2tcpip.h>   // inet_pton
#include <iphlpapi.h>   // IPAddr
#include <Windows.h>
#include <stdio.h>
#include <windns.h>

#include "Network.h"
#include "NetDiscovery.h"

#pragma warning(disable:4996)

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
			*hostname = (char*)xmalloc(bufferSize);
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

	pFixedInfo = (FIXED_INFO*)xmalloc(sizeof(FIXED_INFO));
	if (pFixedInfo == NULL) {
		return FALSE;
	}
	ulOutBufLen = sizeof(FIXED_INFO);

	if (GetNetworkParams(pFixedInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		free(pFixedInfo);
		pFixedInfo = (FIXED_INFO*)xmalloc(ulOutBufLen);
		if (pFixedInfo == NULL) {
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
		free(pFixedInfo);
	return result;
}

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

DWORD WINAPI ThreadDnsQueryHost(LPVOID lpParam) {
	PTHREAD_STRUCT_DATA dnsStructData = (PTHREAD_STRUCT_DATA)lpParam;
	dnsStructData->isHostUp = StartDnsRequest(dnsStructData->ipAddress, dnsStructData->serverDnsIp, &(dnsStructData->hostname), dnsStructData->pFile);
	return dnsStructData->isHostUp;
}

BOOL DNSdiscoveryMultiThread(int maskSizeInt, NetworkPcInfo** ptrNetworkPcInfo, INT32 ipAddressBc, int* pNbDetected, FILE* pFile) {
	NetworkPcInfo* networkPcInfo;
	PTHREAD_STRUCT_DATA dnsStructData;
	DWORD* dwThreadIdArray;
	HANDLE* hThreadArray;
	if (InitNetworkPcInfo(&networkPcInfo, &dnsStructData, &dwThreadIdArray, &hThreadArray, maskSizeInt)){
		char* serverDnsIp = (char*)malloc(IP_ADDRESS_LEN);
		if (serverDnsIp != NULL){
			if (GetDnsServer(serverDnsIp, IP_ADDRESS_LEN)){
				int nbDetected = 0;

				for (int i = 0; i < maskSizeInt; i++){
					INT32 ipAddress = ipAddressBc + i;

					dnsStructData[i].pFile = NULL;
					dnsStructData[i].serverDnsIp = serverDnsIp;
					sprintf_s(dnsStructData[i].ipAddress, IP_ADDRESS_LEN, "%i.%i.%i.%i",
						(ipAddress >> 24) & OCTE_MAX, //  << 24; // (OCTE_SIZE * 4)
						(ipAddress >> OCTE_SIZE * 2) & OCTE_MAX,
						(ipAddress >> OCTE_SIZE) & OCTE_MAX,
						ipAddress & OCTE_MAX);
					hThreadArray[i] = CreateThread(NULL, 0, ThreadDnsQueryHost, &(dnsStructData[i]), 0, &dwThreadIdArray[i]);
					if (hThreadArray[i] == NULL){
						printf("\t[x] Unable to Create Thread\n");
						free(serverDnsIp);
						FreeNetworkPcInfo(dnsStructData, dwThreadIdArray, hThreadArray);
						free(networkPcInfo);
						return FALSE;
					}
					Sleep(20);
				}
				SyncWaitForMultipleObjs(hThreadArray, maskSizeInt);
				free(serverDnsIp);

				for (int i = 0; i < maskSizeInt; i++){
					if (hThreadArray[i] != NULL)
						CloseHandle(hThreadArray[i]);
					if (dnsStructData[i].isHostUp){
						strcpy_s(networkPcInfo[nbDetected].ipAddress, IP_ADDRESS_LEN, dnsStructData[i].ipAddress);

						if (dnsStructData[i].hostname != NULL){
							size_t hostnameSize = strlen(dnsStructData[i].hostname) + 1;
							networkPcInfo[nbDetected].hostname = (char*)malloc(hostnameSize);
							if (networkPcInfo[nbDetected].hostname == NULL)
								return FALSE;
							strcpy_s(networkPcInfo[nbDetected].hostname, hostnameSize, dnsStructData[i].hostname);
							free(dnsStructData[i].hostname);
						}
						nbDetected++;
					}

				}

				FreeNetworkPcInfo(dnsStructData, dwThreadIdArray, hThreadArray);
				networkPcInfo = (NetworkPcInfo*)xrealloc(networkPcInfo, (nbDetected + 1) * sizeof(NetworkPcInfo));
				if (networkPcInfo == NULL)
					return FALSE;

				*pNbDetected = nbDetected;
				*ptrNetworkPcInfo = networkPcInfo;
				return TRUE;

			} else
				printf("\t[x] Server DNS IP address is public !\n");
			free(serverDnsIp);
		} else
			PrintOut(pFile, "\t[x] Unable to allocate memory\n");
		

		FreeNetworkPcInfo(dnsStructData, dwThreadIdArray, hThreadArray);
		free(networkPcInfo);
	}
	*pNbDetected = 0;
	*ptrNetworkPcInfo = NULL;
	return FALSE;
}