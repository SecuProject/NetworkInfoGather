#include <Windows.h>
#include <stdio.h>
#include <iphlpapi.h>
#include <icmpapi.h>

#include "Network.h"
#include "NetDiscovery.h"


// set to (rand() % 3) + 3
#define NB_TIME_PING	(rand() % 2) + 3



#define SEND_DATA_SIZE	32

// 0.5s => 5 * 100
#define TIME_OUT_PING   1000
#define SLEEP_TIME		100


/*
	Linux base					64
	Windows						128
	iOS 12.4 (Cisco Routers)	255
*/


int pingFunctionLoop(HANDLE hIcmpFile, IPAddr ipaddr, char* SendData, LPVOID ReplyBuffer, DWORD ReplySize, int* pComputerTTL) {
	int nbReceived = 0;
	int computerTTL = 0;
	int nbTimePing = NB_TIME_PING;
	for (int i = 0; i < nbTimePing; i++) {
		DWORD dwRetVal = IcmpSendEcho(hIcmpFile, ipaddr, SendData, SEND_DATA_SIZE, NULL, ReplyBuffer, ReplySize, TIME_OUT_PING);
		if (dwRetVal != 0) {
			PICMP_ECHO_REPLY pEchoReply = (PICMP_ECHO_REPLY)ReplyBuffer;
			struct in_addr ReplyAddr;
			ReplyAddr.S_un.S_addr = pEchoReply->Address;
			computerTTL += pEchoReply->Options.Ttl;
			if (pEchoReply->Status == 0) {
				nbReceived++;
			}
		} else
			return FALSE;
		Sleep(TIME_OUT_PING);
	}
	*pComputerTTL = (int)(computerTTL / nbTimePing);
	return nbReceived;
}


BOOL startPinging(char* ipAddress, int* computerTTL, FILE* pFile) {
	BOOL detected = FALSE;
	HANDLE hIcmpFile = IcmpCreateFile();

	if (hIcmpFile == INVALID_HANDLE_VALUE) {
		printOut(pFile, "\t[x] Unable to open handle.\n");
		printOut(pFile, "\t[x] IcmpCreatefile returned error: %lu\n", GetLastError());
		return FALSE;
	} else {
		LPVOID ReplyBuffer = NULL;
		DWORD ReplySize = sizeof(ICMP_ECHO_REPLY) + SEND_DATA_SIZE;
		IPAddr ipaddr = inet_addr(ipAddress);

		if (ipaddr == INADDR_NONE) {
			printOut(pFile, "\t[X] Error with inet_addr (ip address) !!!\n");
			return FALSE;
		}


		ReplyBuffer = (VOID*)calloc(ReplySize, 1);
		if (ReplyBuffer == NULL) {
			printOut(pFile, "\t[x] Unable to allocate memory\n");
			return FALSE;
		} else {
			//char SendData[SEND_DATA_SIZE] = "Data Buffer";
			char SendData[SEND_DATA_SIZE + 1] = {
			0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,0x70,
			0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69 };
			detected = pingFunctionLoop(hIcmpFile, ipaddr, SendData, ReplyBuffer, ReplySize, computerTTL) > 1;
			free(ReplyBuffer);
		}
		IcmpCloseHandle(hIcmpFile);
	}
	return detected;
}


DWORD WINAPI ThreadPingHost(LPVOID lpParam) {
	PTHREAD_STRUCT_DATA icmpStructData = (PTHREAD_STRUCT_DATA)lpParam;
	//printf("\t[d] Scanning %s\n", icmpStructData->ipAddress);
	icmpStructData->isHostUp = startPinging(icmpStructData->ipAddress, &(icmpStructData->computerTTL), icmpStructData->pFile);
	return icmpStructData->isHostUp;
}

BOOL ICMPdiscoveryMultiThread(int maskSizeInt, NetworkPcInfo** ptrNetworkPcInfo, INT32 ipAddressBc, int* nbDetected, FILE* pFile) {
	NetworkPcInfo* networkPcInfo = (NetworkPcInfo*)calloc(maskSizeInt, sizeof(NetworkPcInfo));

	if (networkPcInfo == NULL) {
		printOut(pFile, "\t[x] Unable to allocate memory\n");
		return FALSE;
	}
	PTHREAD_STRUCT_DATA* pDataArray = (PTHREAD_STRUCT_DATA*)calloc(maskSizeInt, sizeof(PTHREAD_STRUCT_DATA));
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


	for (int i = 0; i < maskSizeInt; i++) {
		pDataArray[i] = (PTHREAD_STRUCT_DATA)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(THREAD_STRUCT_DATA));
		if (pDataArray[i] == NULL) {
			printf("\t[x] Unable to allocate memory\n");
			free(hThreadArray);
			free(dwThreadIdArray);
			free(pDataArray);
			free(networkPcInfo);
			return FALSE;
		}
		pDataArray[i]->pFile = NULL;


		INT32 ipAddress = ipAddressBc + i;
		sprintf_s(pDataArray[i]->ipAddress, IP_ADDRESS_LEN, "%i.%i.%i.%i",
			(ipAddress >> 24) & OCTE_MAX, //  << 24; // (OCTE_SIZE * 4)
			(ipAddress >> OCTE_SIZE * 2) & OCTE_MAX,
			(ipAddress >> OCTE_SIZE) & OCTE_MAX,
			ipAddress & OCTE_MAX);
		hThreadArray[i] = CreateThread(NULL, 0, ThreadPingHost, pDataArray[i], 0, &dwThreadIdArray[i]);
		if (hThreadArray[i] == NULL) {
			printf("\t[x] Unable to Create Thread\n");
			free(hThreadArray);
			free(dwThreadIdArray);
			free(pDataArray);
			free(networkPcInfo);
			return FALSE;
		}
		Sleep(20);
	}
	SyncWaitForMultipleObjs(hThreadArray, maskSizeInt);

	int nbHostUp = 0;
	//printf("[*] List of hosts:\n");
	for (int i = 0; i < maskSizeInt; i++) {
		if(hThreadArray[i] == NULL)
			CloseHandle(hThreadArray[i]);
		if (pDataArray[i] != NULL) {
			if (pDataArray[i]->isHostUp) {
				networkPcInfo[nbHostUp].ipAddress = (char*)malloc(IP_ADDRESS_LEN);
				if (networkPcInfo[nbHostUp].ipAddress == NULL)
					return FALSE;

				networkPcInfo[nbHostUp].osName = DetectOSBaseTTL(pDataArray[i]->computerTTL);
				//printf("\t[%i] [%s]\t", nbHostUp +1, pDataArray[i]->ipAddress);

				strcpy_s(networkPcInfo[nbHostUp].ipAddress, IP_ADDRESS_LEN, pDataArray[i]->ipAddress);
				nbHostUp++;
			}
			HeapFree(GetProcessHeap(), 0, pDataArray[i]); // ???? -> FREE 
			pDataArray[i] = NULL;    // Ensure address is not reused.
		}

	}

	free(hThreadArray);
	free(dwThreadIdArray);
	free(pDataArray);

	networkPcInfo = (NetworkPcInfo*)realloc(networkPcInfo,(nbHostUp + 1) * sizeof(NetworkPcInfo));
	if (networkPcInfo == NULL)
		return FALSE;

	*nbDetected = nbHostUp;
	*ptrNetworkPcInfo = networkPcInfo;
	return TRUE;
}