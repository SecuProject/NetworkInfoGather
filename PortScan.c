
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

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <time.h>
#include <iphlpapi.h>	// IPAddr
#include <ws2tcpip.h>	// inet_pton()

#include "Network.h"
#include "portList.h"
//#include "EnumHTTP.h"


BOOL scanPortOpenUDP(char* dest_ip, int port, FILE* pFile) {
	SOCKET udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (udp_sock == INVALID_SOCKET) {
		PrintOut(pFile, "\t[X] socket open failed %lu\n", GetLastError());
		closesocket(udp_sock);
		return FALSE;
	} else {
		SOCKADDR_IN server_addr;

		IPAddr AddrIp;
		inet_pton(AF_INET, dest_ip, &AddrIp);
		memset(&server_addr, 0, sizeof(SOCKADDR_IN));
		server_addr.sin_family = AF_INET;
		server_addr.sin_port = htons(port);
		server_addr.sin_addr.s_addr = AddrIp;

		const char msg[] = "TestUdp\n";

		int send_size = sendto(udp_sock, msg, (int)sizeof(msg), 0, (struct sockaddr*)&server_addr, sizeof(SOCKADDR_IN));
		if (send_size != SOCKET_ERROR) {
			int servAddSize = sizeof(server_addr);
			if (SetOptions(udp_sock) != SOCKET_ERROR){
				char buffer[OCTE_MAX];
				if (recvfrom(udp_sock, buffer, OCTE_MAX, 0, (struct sockaddr*)&server_addr, &servAddSize) != SOCKET_ERROR){
					closesocket(udp_sock);
					return TRUE;
				}
			}else
				PrintOut(pFile, "\t[X] Error setting socket options\n");
		}
		closesocket(udp_sock);
	}
	return FALSE;
}
BOOL scanPortOpenTCP(char* ipAddress, int port,FILE* pFile) {
	SOCKET tcp_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (tcp_sock != INVALID_SOCKET){
		SOCKADDR_IN ssin = InitSockAddr(ipAddress, port);
		if (SetOptions(tcp_sock) != SOCKET_ERROR){
			if (connect(tcp_sock, (struct sockaddr*)&ssin, sizeof(SOCKADDR_IN)) != SOCKET_ERROR){
				closesocket(tcp_sock);
				return TRUE;
			}
		}else
			PrintOut(pFile, "\t[X] Error setting socket options\n");
	} else
		PrintOut(pFile, "\t[X] socket open failed %lu\n", GetLastError());
	closesocket(tcp_sock);
	return FALSE;
}

/*void scanPort(NetworkPcInfo* networkPcInfo, int nbDetected, ScanStruct scanStruct) {
	for (int iPC = 0; iPC < nbDetected; iPC++) {
		PrintOut(scanStruct.ouputFile,"[%s] PORT SCAN\n", networkPcInfo[iPC].ipAddress);
		networkPcInfo[iPC].nbOpenPort = 0;
		if (scanStruct.nbPort > 0) {
			for (UINT iPort = 0; iPort < scanStruct.nbPort; iPort++) {
				if (scanPortOpenTCP(networkPcInfo[iPC].ipAddress, scanStruct.portList[iPort], scanStruct.ouputFile)) {
					//PrintOut(scanStruct.ouputFile, "\t[%s] OPEN PORT %i\n", networkPcInfo[iPC].ipAddress, scanStruct.portList[iPort]);
					PrintOut(scanStruct.ouputFile, "\tOPEN PORT %i\n", scanStruct.portList[iPort]);
					networkPcInfo[iPC].port[networkPcInfo[iPC].nbOpenPort].portNumber = scanStruct.portList[iPort];
					networkPcInfo[iPC].nbOpenPort++;
				}//else
					//PrintOut(pFile,"\t[%s] CLOSE PORT %i\n", networkPcInfo[iPC].ipAddress, port[iPort]);
			}
		} else {
			// Scan TCP
			for (UINT iPort = 0; iPort < NB_TAB_PORT_TCP; iPort++) {
				if (scanPortOpenTCP(networkPcInfo[iPC].ipAddress, portTcp[iPort], scanStruct.ouputFile)) {
					//PrintOut(scanStruct.ouputFile, "\t[%s] TCP - OPEN PORT %i\n", networkPcInfo[iPC].ipAddress, portTcp[iPort]);
					PrintOut(scanStruct.ouputFile, "\tOPEN PORT %i\n", portTcp[iPort]);
					networkPcInfo[iPC].port[networkPcInfo[iPC].nbOpenPort].portNumber = portTcp[iPort];
					networkPcInfo[iPC].nbOpenPort++;
				}
			}
			// Scan UDP
			for (UINT iPort = 0; iPort < NB_TAB_PORT_UDP; iPort++) {
				if (scanPortOpenUDP(networkPcInfo[iPC].ipAddress, portUdp[iPort], scanStruct.ouputFile)) {
					//PrintOut(scanStruct.ouputFile, "\t[%s] UDP - OPEN PORT %i\n", networkPcInfo[iPC].ipAddress, portUdp[iPort]);
					PrintOut(scanStruct.ouputFile, "\tOPEN PORT %i\n", portUdp[iPort]);
					networkPcInfo[iPC].port[networkPcInfo[iPC].nbOpenPort].portNumber = portUdp[iPort];
					networkPcInfo[iPC].nbOpenPort++;
				}
			}
		}
	}
	return;
}*/




typedef struct {
	ScanStruct *scanStruct;
	NetworkPcInfo *networkPcInfo;
	int nbPort;
	int portNumber;
} THREAD_STRUCT_PORT_SCAN, * PTHREAD_STRUCT_PORT_SCAN;

typedef struct {
	ScanStruct *scanStruct;
	NetworkPcInfo *networkPcInfo;
	BOOL isTcp;
} THREAD_STRUCT_PC_PORT_SCAN, * PTHREAD_STRUCT_PC_PORT_SCAN;

CRITICAL_SECTION CriticalSection;

DWORD WINAPI ThreadPcPortScanTcp(LPVOID lpParam) {
	PTHREAD_STRUCT_PORT_SCAN pThreadData = (PTHREAD_STRUCT_PORT_SCAN)lpParam;
	NetworkPcInfo* pNetworkPcInfo = pThreadData->networkPcInfo;
	ScanStruct* pscanStruct = pThreadData->scanStruct;

	//printf("- 3 '%i'\n", pThreadData->portNumber);
	if (scanPortOpenTCP(pNetworkPcInfo->ipAddress, pThreadData->portNumber, pscanStruct->ouputFile)) {
		
		EnterCriticalSection(&CriticalSection);
		// Access the shared resource.
		pNetworkPcInfo->port[pNetworkPcInfo->nbOpenPort].portNumber = pThreadData->portNumber;
		pNetworkPcInfo->port[pNetworkPcInfo->nbOpenPort].isTcp = TRUE;
		pNetworkPcInfo->nbOpenPort++;

		LeaveCriticalSection(&CriticalSection);
		
	}
	return TRUE;
}
DWORD WINAPI ThreadPcPortScanUdp(LPVOID lpParam) {
	PTHREAD_STRUCT_PORT_SCAN pThreadData = (PTHREAD_STRUCT_PORT_SCAN)lpParam;
	NetworkPcInfo* pNetworkPcInfo = pThreadData->networkPcInfo;
	ScanStruct* pscanStruct = pThreadData->scanStruct;

	
	if (scanPortOpenUDP(pNetworkPcInfo->ipAddress, pThreadData->portNumber, pscanStruct->ouputFile)) {
		
		EnterCriticalSection(&CriticalSection);
		// Access the shared resource.
		pNetworkPcInfo->port[pNetworkPcInfo->nbOpenPort].portNumber = pThreadData->portNumber;
		pNetworkPcInfo->port[pNetworkPcInfo->nbOpenPort].isTcp = FALSE;
		pNetworkPcInfo->nbOpenPort++;

		LeaveCriticalSection(&CriticalSection);
		
	}
	return TRUE;
}

BOOL CreatePcPortScanTH(DWORD* dwThreadIdArray, HANDLE* hThreadArray, PTHREAD_STRUCT_PORT_SCAN pThreadDataPort, PTHREAD_STRUCT_PC_PORT_SCAN pThreadData, NetworkPcInfo* pNetworkPcInfo, ScanStruct* pscanStruct, int nbPort, int nbThread, int* portList){
	//pNetworkPcInfo->nbOpenPort = 0;
	
	for (int iPort = 0; iPort < nbPort; iPort++) {
		pThreadDataPort[iPort].scanStruct = pscanStruct;
		pThreadDataPort[iPort].networkPcInfo = pNetworkPcInfo;
		pThreadDataPort[iPort].nbPort = nbPort;
		pThreadDataPort[iPort].portNumber = portList[iPort];

		if (pThreadData->isTcp)
			hThreadArray[iPort] = CreateThread(NULL, 0, ThreadPcPortScanTcp, &pThreadDataPort[iPort], 0, &dwThreadIdArray[iPort]);
		else
			hThreadArray[iPort] = CreateThread(NULL, 0, ThreadPcPortScanUdp, &pThreadDataPort[iPort], 0, &dwThreadIdArray[iPort]);

		if (hThreadArray[iPort] == NULL) {
			printf("\t[x] Unable to Create Thread\n");
			free(pThreadDataPort);
			free(hThreadArray);
			free(dwThreadIdArray);
			return FALSE;
		}
		//Sleep(1); // 5   20
	}

	SyncWaitForMultipleObjs(hThreadArray, nbPort);

	for (int iPort = 0; iPort < nbPort; iPort++) {
		if (hThreadArray[iPort] != NULL)
			CloseHandle(hThreadArray[iPort]);
	}
	return TRUE;
}

#define NB_MAX_THREAD 1000


DWORD WINAPI ThreadNetworkPortScan(LPVOID lpParam) {
	PTHREAD_STRUCT_PC_PORT_SCAN pThreadData = (PTHREAD_STRUCT_PC_PORT_SCAN)lpParam;
	NetworkPcInfo* pNetworkPcInfo = pThreadData->networkPcInfo;
	ScanStruct* pscanStruct = pThreadData->scanStruct;

	BOOL isScanFullPort = FALSE;
	int nbPort;
	int nbThread;
	int* portList;

	if (pscanStruct->nbPort > 0) {
		if (pscanStruct->nbPort > NB_MAX_THREAD) {
			// If user set scann all port
			nbPort = pscanStruct->nbPort;
			nbThread = NB_MAX_THREAD;

			portList = xcalloc(NB_MAX_THREAD+1,sizeof(int*));
			if (portList == NULL)
				return FALSE;
			isScanFullPort = TRUE;
		} else {
			// If user set custom port
			nbPort = pscanStruct->nbPort;
			portList = pscanStruct->portList;
			nbThread = nbPort;
		}
	} else {
		//Use default port list
		if (pThreadData->isTcp) {
			portList = (int*)portTcp;
			nbPort = NB_TAB_PORT_TCP;
		} else {
			portList = (int*)portUdp;
			nbPort = NB_TAB_PORT_UDP;
		}
		nbThread = nbPort;
	}

	DWORD* dwThreadIdArray = (DWORD*)xcalloc(nbPort, sizeof(DWORD));
	if (dwThreadIdArray == NULL) {
		return FALSE;
	}
	HANDLE* hThreadArray = (HANDLE*)xcalloc(nbPort, sizeof(HANDLE));
	if (hThreadArray == NULL) {
		free(dwThreadIdArray);
		return FALSE;
	}
	PTHREAD_STRUCT_PORT_SCAN pThreadDataPort = (PTHREAD_STRUCT_PORT_SCAN)xcalloc(nbPort, sizeof(THREAD_STRUCT_PORT_SCAN));
	if (pThreadDataPort == NULL) {
		free(hThreadArray);
		free(dwThreadIdArray);
		return FALSE;
	}
	
	if (isScanFullPort) {
		for (int i = 1; i < nbPort; i += NB_MAX_THREAD) {
			double result = ((double)i / (double)nbPort) * 100;
			printf("\t[i] Port scan: %.2f/100%%\r", result);
			int j = i;
			if (j < NB_MAX_THREAD) {
				for (; j < NB_MAX_THREAD * i; j++)
					portList[j - 1] = j;
			}else {
				for (; j < i + NB_MAX_THREAD; j++)
					portList[j% NB_MAX_THREAD] = j;
			}
				
			if (i < NB_MAX_THREAD) {
				CreatePcPortScanTH(dwThreadIdArray, hThreadArray, pThreadDataPort, pThreadData, pNetworkPcInfo, pscanStruct, NB_MAX_THREAD-1, nbThread, portList);
				i--;
			}else
				CreatePcPortScanTH(dwThreadIdArray, hThreadArray, pThreadDataPort, pThreadData, pNetworkPcInfo, pscanStruct, NB_MAX_THREAD, nbThread, portList);
		}
	}else
		CreatePcPortScanTH(dwThreadIdArray, hThreadArray, pThreadDataPort, pThreadData, pNetworkPcInfo, pscanStruct, NB_MAX_THREAD, nbThread, portList);
	free(pThreadDataPort);
	free(hThreadArray);
	free(dwThreadIdArray);
	return TRUE;
}



BOOL MultiScanPort(NetworkPcInfo* networkPcInfo, int nbDetected, ScanStruct scanStruct, BOOL isTcp) {
	DWORD* dwThreadIdArray = (DWORD*)xcalloc(nbDetected, sizeof(DWORD));
	if (dwThreadIdArray == NULL) {
		return FALSE;
	}
	HANDLE* hThreadArray = (HANDLE*)xcalloc(nbDetected, sizeof(HANDLE));
	if (hThreadArray == NULL) {
		free(dwThreadIdArray);
		return FALSE;
	}

	PTHREAD_STRUCT_PC_PORT_SCAN pThreadData = (PTHREAD_STRUCT_PC_PORT_SCAN)xcalloc(nbDetected, sizeof(THREAD_STRUCT_PC_PORT_SCAN));
	if (pThreadData == NULL) {
		free(hThreadArray);
		free(dwThreadIdArray);
		return FALSE;
	}

	if (!InitializeCriticalSectionAndSpinCount(&CriticalSection, 0x00000400)) {
		free(pThreadData);
		free(hThreadArray);
		free(dwThreadIdArray);
		return FALSE;
	}

	for (int iPC = 0; iPC < nbDetected; iPC++) {
		pThreadData[iPC].scanStruct = &(scanStruct);
		pThreadData[iPC].networkPcInfo = &(networkPcInfo[iPC]);
		pThreadData[iPC].isTcp = isTcp;


		hThreadArray[iPC] = CreateThread(NULL, 0, ThreadNetworkPortScan, &pThreadData[iPC], 0, &dwThreadIdArray[iPC]);
		if (hThreadArray[iPC] == NULL) {
			printf("\t[x] Unable to Create Thread\n");
			free(pThreadData);
			free(hThreadArray);
			free(dwThreadIdArray);
			return FALSE;
		}
		Sleep(20);
	}

	SyncWaitForMultipleObjs(hThreadArray, nbDetected);


	// Release resources used by the critical section object.
	DeleteCriticalSection(&CriticalSection);

	free(pThreadData);

	for (int iPC = 0; iPC < nbDetected; iPC++) {
		CloseHandle(hThreadArray[iPC]);
		PrintOut(scanStruct.ouputFile, "[%s] PORT SCAN - %s\n", networkPcInfo[iPC].ipAddress, isTcp ? "TCP" : "UDP");
		for (int iPort = 0; iPort < networkPcInfo[iPC].nbOpenPort; iPort++) {
			if(isTcp == networkPcInfo[iPC].port[iPort].isTcp)
				PrintOut(scanStruct.ouputFile, "\t%5i - PORT OPEN\n", networkPcInfo[iPC].port[iPort].portNumber);
				//PrintOut(scanStruct.ouputFile, "\t[%s] %s - OPEN PORT %i\n", networkPcInfo[iPC].ipAddress, isTcp ? "TCP" : "UDP", networkPcInfo[iPC].port[iPort].portNumber);
		}
	}
	free(hThreadArray);
	free(dwThreadIdArray);
	return TRUE;
}