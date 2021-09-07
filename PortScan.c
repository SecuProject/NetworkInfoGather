#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <time.h>
#include <iphlpapi.h>	// IPAddr
#include <ws2tcpip.h>	// inet_pton()

#include "Network.h"
#include "portList.h"
#include "EnumHTTP.h"


int set_options(SOCKET fd) {
	struct timeval timeout;

	timeout.tv_sec = 2;
	timeout.tv_usec = 0;
	return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) != SOCKET_ERROR; // if setsockopt == fail => return 0;
}

BOOL scanPortOpenTCP(char* dest_ip, int port,FILE* pFile) {
	SOCKET tcp_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (tcp_sock == INVALID_SOCKET) {
		printOut(pFile,"\t[X] socket open failed %ld\n", GetLastError());
		closesocket(tcp_sock);
		return FALSE;
	} else {
		SOCKADDR_IN ssin;
		IPAddr DestIp;

		inet_pton(AF_INET, dest_ip, &DestIp);

		memset(&ssin, 0, sizeof(SOCKADDR_IN));
		ssin.sin_family = AF_INET;
		ssin.sin_port = htons(port);
		ssin.sin_addr.s_addr = DestIp;

		if (!set_options(tcp_sock)) {
			printOut(pFile,"\t[X] Error setting socket options\n");
			closesocket(tcp_sock);
			return FALSE;
		}
		if (connect(tcp_sock, (struct sockaddr*)&ssin, sizeof(SOCKADDR_IN)) != SOCKET_ERROR) {
			closesocket(tcp_sock);
			return TRUE;
		}
	}
	closesocket(tcp_sock);
	return FALSE;
}

void scanPort(NetworkPcInfo* networkPcInfo, int nbDetected, Arguments arguments) {
	for (int iPC = 0; iPC < nbDetected; iPC++) {
		printOut(arguments.ouputFile,"[%s] PORT SCAN\n", networkPcInfo[iPC].ipAddress);
		networkPcInfo[iPC].nbOpenPort = 0;
		if (arguments.nbPort > 0) {
			for (UINT iPort = 0; iPort < arguments.nbPort; iPort++) {
				if (scanPortOpenTCP(networkPcInfo[iPC].ipAddress, arguments.portList[iPort], arguments.ouputFile)) {
					printOut(arguments.ouputFile, "\t[%s] OPEN PORT %i\n", networkPcInfo[iPC].ipAddress, arguments.portList[iPort]);
					networkPcInfo[iPC].port[networkPcInfo[iPC].nbOpenPort].portNumber = arguments.portList[iPort];
					networkPcInfo[iPC].nbOpenPort++;
				}/*else
					printOut(pFile,"\t[%s] CLOSE PORT %i\n", networkPcInfo[iPC].ipAddress, port[iPort]);*/
			}
		} else {
			for (UINT iPort = 0; iPort < NB_TAB_PORT; iPort++) {
				if (scanPortOpenTCP(networkPcInfo[iPC].ipAddress, port[iPort], arguments.ouputFile)) {
					printOut(arguments.ouputFile, "\t[%s] OPEN PORT %i\n", networkPcInfo[iPC].ipAddress, port[iPort]);
					networkPcInfo[iPC].port[networkPcInfo[iPC].nbOpenPort].portNumber = port[iPort];
					networkPcInfo[iPC].nbOpenPort++;
				}/*else
					printOut(pFile,"\t[%s] CLOSE PORT %i\n", networkPcInfo[iPC].ipAddress, port[iPort]);*/
			}
		}
	}
	return;
}




typedef struct {
	Arguments *arguments;
	NetworkPcInfo *networkPcInfo;
	int nbPort;
	int portList;
} THREAD_STRUCT_PORT_SCAN, * PTHREAD_STRUCT_PORT_SCAN;

typedef struct {
	Arguments *arguments;
	NetworkPcInfo *networkPcInfo;
} THREAD_STRUCT_PC_PORT_SCAN, * PTHREAD_STRUCT_PC_PORT_SCAN;

CRITICAL_SECTION CriticalSection;

DWORD WINAPI ThreadPcPortScan(LPVOID lpParam) {
	PTHREAD_STRUCT_PORT_SCAN pThreadData = (PTHREAD_STRUCT_PORT_SCAN)lpParam;
	NetworkPcInfo* pNetworkPcInfo = pThreadData->networkPcInfo;
	Arguments* pArguments = pThreadData->arguments;

	
	if (scanPortOpenTCP(pNetworkPcInfo->ipAddress, pThreadData->portList, pArguments->ouputFile)) {
		
		EnterCriticalSection(&CriticalSection);
		// Access the shared resource.
		pNetworkPcInfo->port[pNetworkPcInfo->nbOpenPort].portNumber = pThreadData->portList;
		pNetworkPcInfo->nbOpenPort++;

		LeaveCriticalSection(&CriticalSection);
		
	}
	return TRUE;
}
DWORD WINAPI ThreadNetworkPortScan(LPVOID lpParam) {
	PTHREAD_STRUCT_PC_PORT_SCAN pThreadData = (PTHREAD_STRUCT_PC_PORT_SCAN)lpParam;
	NetworkPcInfo* pNetworkPcInfo = pThreadData->networkPcInfo;
	Arguments* pArguments = pThreadData->arguments;

	int nbPort = NB_TAB_PORT;
	int* portList = (int*)port;
	// If user set custom port
	if (pArguments->nbPort > 0) {
		nbPort = pArguments->nbPort;
		portList = pArguments->portList;
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

	pNetworkPcInfo->nbOpenPort = 0;
	for (int iPort= 0; iPort < nbPort; iPort++) {
		pThreadDataPort[iPort].arguments = pArguments;
		pThreadDataPort[iPort].networkPcInfo = pNetworkPcInfo;
		pThreadDataPort[iPort].nbPort = nbPort;
		pThreadDataPort[iPort].portList = portList[iPort];

		hThreadArray[iPort] = CreateThread(NULL, 0, ThreadPcPortScan, &pThreadDataPort[iPort], 0, &dwThreadIdArray[iPort]);
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
		CloseHandle(hThreadArray[iPort]);
	}
	free(pThreadDataPort);
	free(hThreadArray);
	free(dwThreadIdArray);
	return TRUE;
}





BOOL MultiScanPort(NetworkPcInfo* networkPcInfo, int nbDetected, Arguments arguments) {
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

	if (!InitializeCriticalSectionAndSpinCount(&CriticalSection, 0x00000400))
		return FALSE;

	for (int iPC = 0; iPC < nbDetected; iPC++) {
		
		pThreadData[iPC].arguments = &(arguments);
		pThreadData[iPC].networkPcInfo = &(networkPcInfo[iPC]);


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
		printOut(arguments.ouputFile, "[%s] PORT SCAN\n", networkPcInfo[iPC].ipAddress);
		for (int iPort = 0; iPort < networkPcInfo[iPC].nbOpenPort; iPort++) {
			printOut(arguments.ouputFile, "\t[%s] OPEN PORT %i\n", networkPcInfo[iPC].ipAddress, networkPcInfo[iPC].port[iPort].portNumber);
		}
	}
	free(hThreadArray);
	free(dwThreadIdArray);
	return TRUE;
}