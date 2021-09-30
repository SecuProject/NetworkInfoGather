#include <Windows.h>
#include <stdio.h>
#include <time.h>

#include "AdapterInformation.h"
#include "NetDiscovery.h"
#include "Network.h"
#include "PortScan.h"
#include "PortFingerPrint.h"
#include "MgArguments.h"
#include "Network.h"

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Mpr.lib") // WNetAddConnection2
#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "Winhttp.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "wininet.lib")

#define MAX_NB_ADAPTER	50

void FreeStrcutNetPcInfo(NetworkPcInfo* networkPcInfo, int nbDetected) {
	if (networkPcInfo == NULL)
		return;

	for (int i = nbDetected - 1; i ; i--) {
		if (networkPcInfo[i].smtpData != NULL)
			free(networkPcInfo[i].smtpData);
		if (networkPcInfo[i].ipAddress != NULL)
			free(networkPcInfo[i].ipAddress);
		if (networkPcInfo[i].vendorName != NULL)
			free(networkPcInfo[i].vendorName);
	}
	free(networkPcInfo);
}

int main(int argc, char* argv[]) {
	Arguments listAgrument;
	ADAPTER_INFO* adapterInfo;
	UINT nbAdapter;


	if (!GetArguments(argc, argv, &listAgrument))
		return FALSE;

	// Disable SMB brute-force for the test !!! 
	listAgrument.bruteforce = FALSE;


	adapterInfo = (ADAPTER_INFO *)calloc(sizeof(ADAPTER_INFO), MAX_NB_ADAPTER);
	if(adapterInfo == NULL)
		return FALSE;
	nbAdapter = getAdapterkInfo(adapterInfo, listAgrument.ouputFile);
	if (nbAdapter == 0) {
		printOut(listAgrument.ouputFile,"[x] No network interface detected !\n");
		free(adapterInfo);
		return FALSE;
	}
	if (!initWSA(listAgrument.ouputFile))
		return FALSE;

	srand((UINT)time(0));

	if (listAgrument.isListInterface || listAgrument.interfaceNb == 0 || listAgrument.interfaceNb > nbAdapter) {
		if (listAgrument.interfaceNb > nbAdapter)
			printf("[x] Invalid number for the adapter !\n\n");
		else if (listAgrument.interfaceNb == 0 && !listAgrument.isListInterface)
			printf("[x] Adapter not set (-i [Adapter Number]) !\n\n");
		for (UINT i = 0; i < nbAdapter; i++) {
			int maskSizeInt = 0;

			ipCalucation(adapterInfo[i].localIP, adapterInfo[i].networkMask, &maskSizeInt);
			printOut(listAgrument.ouputFile,"[ Adapter %i ] GW %s - MASK %s - Local IP %s\n", i + 1, adapterInfo[i].GateWayIp, adapterInfo[i].networkMask, adapterInfo[i].localIP);
		}
	} else if (listAgrument.interfaceNb < nbAdapter  +1) {
		INT32 ipRangeInt32 = 0;
		int maskSizeInt = 0;
		int nbDetected = 0;
		NetworkPcInfo* networkPcInfo = NULL;
		ADAPTER_INFO adapterInfoSelected = adapterInfo[listAgrument.interfaceNb - 1];

		if (listAgrument.ipAddress != NULL)
			ipRangeInt32 = AddIPRange(listAgrument, &maskSizeInt);
		else
			ipRangeInt32 = ipCalucation(adapterInfoSelected.localIP, adapterInfoSelected.networkMask, &maskSizeInt) + 1;

		printOut(listAgrument.ouputFile, "[ Adapter %i ] GW %s - MASK %s - Local IP %s\n\n",  listAgrument.interfaceNb, adapterInfoSelected.GateWayIp, adapterInfoSelected.networkMask, adapterInfoSelected.localIP);

		if (listAgrument.typeOfScan == Disable_Scan && listAgrument.ipAddress == NULL) {
			printf("[!] The target(s) IP address must be define with '-t' if the host discovery is disable !\n\n");
		}else if (NetDiscovery(listAgrument, ipRangeInt32, maskSizeInt, adapterInfoSelected.localIP, &networkPcInfo, &nbDetected, listAgrument.ouputFile)) {
			if (listAgrument.portScan) {
				//scanPort(networkPcInfo, nbDetected, listAgrument);
				MultiScanPort(networkPcInfo, nbDetected, listAgrument);
				if (listAgrument.advancedScan) {
					PortFingerPrint(networkPcInfo, nbDetected, listAgrument.bruteforce, listAgrument.ouputFile); // BOOL
				}
			}

			// FreeStrcutNetPcInfo(networkPcInfo, nbDetected);
		}
	}

	WSACleanup();
	free(adapterInfo);
	if(listAgrument.ipAddress != NULL)
		free(listAgrument.ipAddress);
	return FALSE;
}
