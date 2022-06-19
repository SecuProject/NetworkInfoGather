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
		printOut(pFile, "\t[X] socket open failed %lu\n", GetLastError());
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
				printOut(pFile, "\t[X] Error setting socket options\n");
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
			printOut(pFile, "\t[X] Error setting socket options\n");
	} else
		printOut(pFile, "\t[X] socket open failed %lu\n", GetLastError());
	closesocket(tcp_sock);
	return FALSE;
}

/*void scanPort(NetworkPcInfo* networkPcInfo, int nbDetected, ScanStruct scanStruct) {
	for (int iPC = 0; iPC < nbDetected; iPC++) {
		printOut(scanStruct.ouputFile,"[%s] PORT SCAN\n", networkPcInfo[iPC].ipAddress);
		networkPcInfo[iPC].nbOpenPort = 0;
		if (scanStruct.nbPort > 0) {
			for (UINT iPort = 0; iPort < scanStruct.nbPort; iPort++) {
				if (scanPortOpenTCP(networkPcInfo[iPC].ipAddress, scanStruct.portList[iPort], scanStruct.ouputFile)) {
					//printOut(scanStruct.ouputFile, "\t[%s] OPEN PORT %i\n", networkPcInfo[iPC].ipAddress, scanStruct.portList[iPort]);
					printOut(scanStruct.ouputFile, "\tOPEN PORT %i\n", scanStruct.portList[iPort]);
					networkPcInfo[iPC].port[networkPcInfo[iPC].nbOpenPort].portNumber = scanStruct.portList[iPort];
					networkPcInfo[iPC].nbOpenPort++;
				}//else
					//printOut(pFile,"\t[%s] CLOSE PORT %i\n", networkPcInfo[iPC].ipAddress, port[iPort]);
			}
		} else {
			// Scan TCP
			for (UINT iPort = 0; iPort < NB_TAB_PORT_TCP; iPort++) {
				if (scanPortOpenTCP(networkPcInfo[iPC].ipAddress, portTcp[iPort], scanStruct.ouputFile)) {
					//printOut(scanStruct.ouputFile, "\t[%s] TCP - OPEN PORT %i\n", networkPcInfo[iPC].ipAddress, portTcp[iPort]);
					printOut(scanStruct.ouputFile, "\tOPEN PORT %i\n", portTcp[iPort]);
					networkPcInfo[iPC].port[networkPcInfo[iPC].nbOpenPort].portNumber = portTcp[iPort];
					networkPcInfo[iPC].nbOpenPort++;
				}
			}
			// Scan UDP
			for (UINT iPort = 0; iPort < NB_TAB_PORT_UDP; iPort++) {
				if (scanPortOpenUDP(networkPcInfo[iPC].ipAddress, portUdp[iPort], scanStruct.ouputFile)) {
					//printOut(scanStruct.ouputFile, "\t[%s] UDP - OPEN PORT %i\n", networkPcInfo[iPC].ipAddress, portUdp[iPort]);
					printOut(scanStruct.ouputFile, "\tOPEN PORT %i\n", portUdp[iPort]);
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
	int portList;
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

	
	if (scanPortOpenTCP(pNetworkPcInfo->ipAddress, pThreadData->portList, pscanStruct->ouputFile)) {
		
		EnterCriticalSection(&CriticalSection);
		// Access the shared resource.
		pNetworkPcInfo->port[pNetworkPcInfo->nbOpenPort].portNumber = pThreadData->portList;
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

	
	if (scanPortOpenUDP(pNetworkPcInfo->ipAddress, pThreadData->portList, pscanStruct->ouputFile)) {
		
		EnterCriticalSection(&CriticalSection);
		// Access the shared resource.
		pNetworkPcInfo->port[pNetworkPcInfo->nbOpenPort].portNumber = pThreadData->portList;
		pNetworkPcInfo->port[pNetworkPcInfo->nbOpenPort].isTcp = FALSE;
		pNetworkPcInfo->nbOpenPort++;

		LeaveCriticalSection(&CriticalSection);
		
	}
	return TRUE;
}

// portTcp ???
DWORD WINAPI ThreadNetworkPortScan(LPVOID lpParam) {
	PTHREAD_STRUCT_PC_PORT_SCAN pThreadData = (PTHREAD_STRUCT_PC_PORT_SCAN)lpParam;
	NetworkPcInfo* pNetworkPcInfo = pThreadData->networkPcInfo;
	ScanStruct* pscanStruct = pThreadData->scanStruct;

	int nbPort;
	int* portList;
	if (pThreadData->isTcp) {
		portList = (int*)portTcp;
		nbPort = NB_TAB_PORT_TCP;
	} else {
		portList = (int*)portUdp;
		nbPort = NB_TAB_PORT_UDP;
	}
	

	// If user set custom port
	if (pscanStruct->nbPort > 0) {
		nbPort = pscanStruct->nbPort;
		portList = pscanStruct->portList;
	}

	DWORD* dwThreadIdArray = (DWORD*)calloc(nbPort, sizeof(DWORD));
	if (dwThreadIdArray == NULL) {
		return FALSE;
	}
	HANDLE* hThreadArray = (HANDLE*)calloc(nbPort, sizeof(HANDLE));
	if (hThreadArray == NULL) {
		free(dwThreadIdArray);
		return FALSE;
	}
	PTHREAD_STRUCT_PORT_SCAN pThreadDataPort = (PTHREAD_STRUCT_PORT_SCAN)calloc(nbPort, sizeof(THREAD_STRUCT_PORT_SCAN));
	if (pThreadDataPort == NULL) {
		free(hThreadArray);
		free(dwThreadIdArray);
		return FALSE;
	}

	//pNetworkPcInfo->nbOpenPort = 0;
	for (int iPort= 0; iPort < nbPort; iPort++) {
		pThreadDataPort[iPort].scanStruct = pscanStruct;
		pThreadDataPort[iPort].networkPcInfo = pNetworkPcInfo;
		pThreadDataPort[iPort].nbPort = nbPort;
		pThreadDataPort[iPort].portList = portList[iPort];


		if(pThreadData->isTcp)
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
		Sleep(20);
	}

	SyncWaitForMultipleObjs(hThreadArray, nbPort);

	for (int iPort = 0; iPort < nbPort; iPort++) {
		if(hThreadArray[iPort] != NULL)
			CloseHandle(hThreadArray[iPort]);
	}
	free(pThreadDataPort);
	free(hThreadArray);
	free(dwThreadIdArray);
	return TRUE;
}





BOOL MultiScanPort(NetworkPcInfo* networkPcInfo, int nbDetected, ScanStruct scanStruct, BOOL isTcp) {
	DWORD* dwThreadIdArray = (DWORD*)calloc(nbDetected, sizeof(DWORD));
	if (dwThreadIdArray == NULL) {
		return FALSE;
	}
	HANDLE* hThreadArray = (HANDLE*)calloc(nbDetected, sizeof(HANDLE));
	if (hThreadArray == NULL) {
		free(dwThreadIdArray);
		return FALSE;
	}

	PTHREAD_STRUCT_PC_PORT_SCAN pThreadData = (PTHREAD_STRUCT_PC_PORT_SCAN)calloc(nbDetected, sizeof(THREAD_STRUCT_PC_PORT_SCAN));
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
		printOut(scanStruct.ouputFile, "[%s] PORT SCAN - %s\n", networkPcInfo[iPC].ipAddress, isTcp ? "TCP" : "UDP");
		for (int iPort = 0; iPort < networkPcInfo[iPC].nbOpenPort; iPort++) {
			if(isTcp == networkPcInfo[iPC].port[iPort].isTcp)
				printOut(scanStruct.ouputFile, "\t%5i - PORT OPEN\n", networkPcInfo[iPC].port[iPort].portNumber);
				//printOut(scanStruct.ouputFile, "\t[%s] %s - OPEN PORT %i\n", networkPcInfo[iPC].ipAddress, isTcp ? "TCP" : "UDP", networkPcInfo[iPC].port[iPort].portNumber);
		}
	}
	free(hThreadArray);
	free(dwThreadIdArray);
	return TRUE;
}