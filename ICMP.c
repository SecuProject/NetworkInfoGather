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
		PrintOut(pFile, "\t[x] Unable to open handle.\n");
		PrintOut(pFile, "\t[x] IcmpCreatefile returned error: %lu\n", GetLastError());
		return FALSE;
	} else {
		LPVOID ReplyBuffer = NULL;
		DWORD ReplySize = sizeof(ICMP_ECHO_REPLY) + SEND_DATA_SIZE;
		IPAddr ipaddr = inet_addr(ipAddress);

		if (ipaddr == INADDR_NONE) {
			PrintOut(pFile, "\t[X] Error with inet_addr (ip address) !!!\n");
			return FALSE;
		}


		ReplyBuffer = (VOID*)xcalloc(ReplySize, 1);
		if (ReplyBuffer == NULL) {
			PrintOut(pFile, "\t[x] Unable to allocate memory\n");
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


BOOL UpdateData(int pNbDetected, int nbDetected, NetworkPcInfo* ptrNetworkPcInfo, NetworkPcInfo* networkPcInfo){
	for (int i = 0; i < pNbDetected; i++) {
		for (int j = 0; j < nbDetected; j++) {
			printf("\t[%i/%i] Match ? '%s' == '%s'\n", i, j, networkPcInfo[i].ipAddress, (ptrNetworkPcInfo)[j].ipAddress);



			printf("\t[+] DIFF %i\n", strcmp(networkPcInfo[i].ipAddress, (ptrNetworkPcInfo)[j].ipAddress));
			if (strcmp(networkPcInfo[i].ipAddress, (ptrNetworkPcInfo)[j].ipAddress) == 0) {
				ptrNetworkPcInfo[i].osName = networkPcInfo[j].osName;
				printf("\t\t[+] Match %i\n", (ptrNetworkPcInfo[i]).osName);
				printf("\t\t[+] Match %s == %s\n", networkPcInfo[i].ipAddress, (ptrNetworkPcInfo)[j].ipAddress);
			}
		}
	}
	return TRUE;
}


void print_ip(unsigned int ip) {
	unsigned char bytes[4];
	bytes[0] = ip & 0xFF;
	bytes[1] = (ip >> 8) & 0xFF;
	bytes[2] = (ip >> 16) & 0xFF;
	bytes[3] = (ip >> 24) & 0xFF;
	printf("%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);
}

BOOL ICMPdiscoveryMultiThread(int maskSizeInt, NetworkPcInfo** ptrNetworkPcInfo, INT32 ipAddressBc, int* pNbDetected, FILE* pFile) {
	NetworkPcInfo* networkPcInfo;
	PTHREAD_STRUCT_DATA icmpStructData;
	DWORD* dwThreadIdArray;
	HANDLE* hThreadArray;
	if (*pNbDetected > 0) {
		for (int i = 0;i<*pNbDetected; i++) {
			int computerTTL = 0;
			if(startPinging((*ptrNetworkPcInfo)[i].ipAddress, &computerTTL, pFile))
				(*ptrNetworkPcInfo)[i].osName = DetectOSBaseTTL(computerTTL);

			//PrintOut(pFile, "\t%3i - %15s -> %i", i + 1, (*ptrNetworkPcInfo)[i].ipAddress, computerTTL);
		}
		// (*ptrNetworkPcInfo)[i].osName += computerTTL;
		return TRUE;
	}else if (InitNetworkPcInfo(&networkPcInfo, &icmpStructData, &dwThreadIdArray, &hThreadArray, maskSizeInt)){
		int nbDetected = 0;

		for (int i = 0; i < maskSizeInt; i++){
			UINT ipAddress = ipAddressBc + i + 127;

			sprintf_s(icmpStructData[i].ipAddress, IP_ADDRESS_LEN, "%i.%i.%i.%i",
				(ipAddress >> 24) & OCTE_MAX, //  << 24; // (OCTE_SIZE * 4)
				(ipAddress >> OCTE_SIZE * 2) & OCTE_MAX,
				(ipAddress >> OCTE_SIZE) & OCTE_MAX,
				ipAddress & OCTE_MAX);
			hThreadArray[i] = CreateThread(NULL, 0, ThreadPingHost, &(icmpStructData[i]), 0, &dwThreadIdArray[i]);
			if (hThreadArray[i] == NULL){
				printf("\t[x] Unable to Create Thread\n");
				FreeNetworkPcInfo(icmpStructData, dwThreadIdArray, hThreadArray);
				free(networkPcInfo);
				return FALSE;
			}
			Sleep(20);
		}
		SyncWaitForMultipleObjs(hThreadArray, maskSizeInt);

		for (int i = 0; i < maskSizeInt; i++){
			if (hThreadArray[i] != NULL)
				CloseHandle(hThreadArray[i]);
			if (icmpStructData[i].isHostUp){
				networkPcInfo[nbDetected].osName = DetectOSBaseTTL(icmpStructData[i].computerTTL);
				//printf("\t[%i] [%s]\t", nbHostUp +1, pDataArray[i]->ipAddress);
				strcpy_s(networkPcInfo[nbDetected].ipAddress, IP_ADDRESS_LEN, icmpStructData[i].ipAddress);
				nbDetected++;
			}
		}
		FreeNetworkPcInfo(icmpStructData, dwThreadIdArray, hThreadArray);

		networkPcInfo = (NetworkPcInfo*)xrealloc(networkPcInfo, (nbDetected + 1) * sizeof(NetworkPcInfo));
		if (networkPcInfo == NULL)
			return FALSE;
		*pNbDetected = nbDetected;
		*ptrNetworkPcInfo = networkPcInfo;
		return TRUE;
	}

	*pNbDetected = 0;
	*ptrNetworkPcInfo = NULL;
	return FALSE;
}