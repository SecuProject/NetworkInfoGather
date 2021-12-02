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

// New
#include "EnumFTP.h"

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Mpr.lib") // WNetAddConnection2
#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "Winhttp.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "Dnsapi.lib")


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




BOOL Scan(ScanStruct scanStruct) {
	ADAPTER_INFO* adapterInfo;
	UINT nbAdapter;

	// Disable SMB brute-force for the test !!! 
	//scanStruct.bruteforce = FALSE;

	adapterInfo = (ADAPTER_INFO*)calloc(sizeof(ADAPTER_INFO), MAX_NB_ADAPTER);
	if (adapterInfo == NULL)
		return FALSE;
	nbAdapter = getAdapterkInfo(adapterInfo, scanStruct.ouputFile);
	if (nbAdapter == 0) {
		printOut(scanStruct.ouputFile, "[x] No network interface detected !\n");
		free(adapterInfo);
		return FALSE;
	}
	

	if (scanStruct.isListInterface || scanStruct.interfaceNb == 0 || scanStruct.interfaceNb > nbAdapter) {
		if (scanStruct.interfaceNb > nbAdapter)
			printOut(scanStruct.ouputFile, "[x] Invalid number for the adapter !\n\n");
		else if (scanStruct.interfaceNb == 0 && !scanStruct.isListInterface)
			printOut(scanStruct.ouputFile, "[x] Adapter not set (-i [Adapter Number]) !\n\n");
		for (UINT i = 0; i < nbAdapter; i++) {
			int maskSizeInt = 0;

			ipCalucation(adapterInfo[i].localIP, adapterInfo[i].networkMask, &maskSizeInt);
			printOut(scanStruct.ouputFile, "[ Adapter %i ] GW %s - MASK %s - Local IP %s\n", i + 1, adapterInfo[i].GateWayIp, adapterInfo[i].networkMask, adapterInfo[i].localIP);
		}
	} else if (scanStruct.interfaceNb < nbAdapter + 1) {
		INT32 ipRangeInt32 = 0;
		int maskSizeInt = 0;
		int nbDetected = 0;
		NetworkPcInfo* networkPcInfo = NULL;
		ADAPTER_INFO adapterInfoSelected = adapterInfo[scanStruct.interfaceNb - 1];

		if (scanStruct.ipAddress != NULL)
			ipRangeInt32 = AddIPRange(scanStruct, &maskSizeInt);
		else
			ipRangeInt32 = ipCalucation(adapterInfoSelected.localIP, adapterInfoSelected.networkMask, &maskSizeInt) + 1;

		printOut(scanStruct.ouputFile, "[ Adapter %i ] GW %s - MASK %s - Local IP %s\n\n", scanStruct.interfaceNb, adapterInfoSelected.GateWayIp, adapterInfoSelected.networkMask, adapterInfoSelected.localIP);

		if (scanStruct.typeOfScan == Disable_Scan && scanStruct.ipAddress == NULL) {
			printOut(scanStruct.ouputFile, "[!] The target(s) IP address must be define with '-t' if the host discovery is disable !\n\n");
		} else if (NetDiscovery(scanStruct, ipRangeInt32, maskSizeInt, adapterInfoSelected.localIP, &networkPcInfo, &nbDetected, scanStruct.ouputFile)) {
			if (scanStruct.portScan) {
				//scanPort(networkPcInfo, nbDetected, scanStruct);
				MultiScanPort(networkPcInfo, nbDetected, scanStruct,TRUE);
				//MultiScanPort(networkPcInfo, nbDetected, scanStruct,FALSE); enable UDP scan
				if (scanStruct.advancedScan) {
					PortFingerPrint(networkPcInfo, nbDetected, scanStruct.bruteforce, scanStruct.ouputFile); // BOOL
				}
			}
			FreeStrcutNetPcInfo(networkPcInfo, nbDetected);
		}
	}
	free(adapterInfo);
	if (scanStruct.ipAddress != NULL)
		free(scanStruct.ipAddress);
	return FALSE;
}
BOOL BruteForce(BruteforceStruct bruteforceStruct) {
	switch (bruteforceStruct.protocol) {
	case LDAP:
		// TODO
		break;
	case SMB:
		//TODO
		break;
	case HTTP_BASIC:
		//TODO
		break;
	case FTP:
		return FtpBruteForce(bruteforceStruct.ipAddress, bruteforceStruct.usernameTab, bruteforceStruct.nbUsername, bruteforceStruct.passwordTab, bruteforceStruct.nbPassword, NULL);
		break;
	}
	return FALSE;
}
BOOL Exploit(ExploitStruct exploitStruct) {
	switch (exploitStruct.exploit) {
	case ZERO_LOGON:
		break;
	}
	return TRUE;
}



/*
Arg manage output file !!!

*/
int main(int argc, char* argv[]) {
	Arguments listAgrument;


	if (GetArguments(argc, argv, &listAgrument)) {

		if (!initWSA(NULL))
			return FALSE;

		srand((UINT)time(0));

		switch (listAgrument.programMode) {
		case ModeScan:
			Scan(listAgrument.scanStruct);
			break;
		case ModeBruteforce:
			BruteForce(listAgrument.bruteforceStruct);
			break;
		case ModeExploit:
			Exploit(listAgrument.exploitStruct);
			break;
		}

		WSACleanup();
	}
	return FALSE;
}