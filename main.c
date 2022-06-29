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
#include "Exploit.h"

// For the brute force
#include "portList.h"
#include "EnumFTP.h"
#include "EnumSMB.h"
#include "EnumRPC.h"
#include "DetectHttpBasicAuth.h"
#include "EnumPort.h"
#include "Curl.h"
#include "AttackDOS.h"
#include "ExternalIp.h"

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

	adapterInfo = (ADAPTER_INFO*)xcalloc(sizeof(ADAPTER_INFO), MAX_NB_ADAPTER);
	if (adapterInfo == NULL)
		return FALSE;
	nbAdapter = getAdapterkInfo(adapterInfo, scanStruct.ouputFile);
	if (nbAdapter == 0) {
		PrintOut(scanStruct.ouputFile, "[x] No network interface detected !\n");
		free(adapterInfo);
		return FALSE;
	}
	
	if (scanStruct.isListInterface || scanStruct.interfaceNb == 0 || scanStruct.interfaceNb > nbAdapter) {
		if (scanStruct.interfaceNb > nbAdapter)
			PrintOut(scanStruct.ouputFile, "[x] Invalid number for the adapter !\n\n");
		else if (scanStruct.interfaceNb == 0 && !scanStruct.isListInterface)
			PrintOut(scanStruct.ouputFile, "[x] Adapter not set (-i [Adapter Number]) !\n\n");
		for (UINT i = 0; i < nbAdapter; i++) {
			int maskSizeInt = 0;


			ipCalucation(adapterInfo[i].localIP, adapterInfo[i].networkMask, &maskSizeInt);
			PrintOut(scanStruct.ouputFile, "[ Adapter %i ] GW %s - MASK %s - Local IP %s\n", i + 1, adapterInfo[i].GateWayIp, adapterInfo[i].networkMask, adapterInfo[i].localIP);
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

		PrintOut(scanStruct.ouputFile, "[ Adapter %i ] GW %s - MASK %s - Local IP %s\n\n", scanStruct.interfaceNb, adapterInfoSelected.GateWayIp, adapterInfoSelected.networkMask, adapterInfoSelected.localIP);

		if (scanStruct.typeOfScan == Disable_Scan && scanStruct.ipAddress == NULL) {
			PrintOut(scanStruct.ouputFile, "[!] The target(s) IP address must be define with '-t' if the host discovery is disable !\n\n");
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


VOID PrintInfoBf(char* protocol, char* ipAddress,int port,UINT nbCreadTry) {
	printf("[-] %s basic authentication brute force:\n", protocol);
	printf("\t[+] Target: %s:%i\n", ipAddress, port);
	printf("\t[+] Number of credential to try: %u\n", nbCreadTry);
}
BOOL BrutForceSmbFunc(BruteforceStruct bruteforceStruct) {
	BOOL result = FALSE;
	size_t serverIpSize = strlen(bruteforceStruct.ipAddress) + 4 + 1;
	char* sharePath = (char*)malloc(serverIpSize);
	if (sharePath == NULL)
		return FALSE;

	sprintf_s(sharePath, serverIpSize, "\\\\%s", bruteforceStruct.ipAddress);


	result = BrutForceSMB(sharePath, bruteforceStruct.structWordList, NULL);

	free(sharePath);
	return result;
}
BOOL BruteForce(BruteforceStruct bruteforceStruct) {
	UINT nbCreadTry = bruteforceStruct.structWordList.nbUsername * bruteforceStruct.structWordList.nbPassword;
	BOOL result = FALSE;
	char* httpAuthHeader = NULL;
	// SET CUSTOM PORT IN ARG !!!

	if (!scanPortOpenTCP(bruteforceStruct.ipAddress, bruteforceStruct.port, NULL)) {
		printf("[-] Port %u is close on %s !\n", bruteforceStruct.port, bruteforceStruct.ipAddress);
		return FALSE;
	}
	
	switch (bruteforceStruct.protocol) {
	case FTP:
		PrintInfoBf("FTP", bruteforceStruct.ipAddress, bruteforceStruct.port, nbCreadTry);
		result = FtpBruteForce(bruteforceStruct.ipAddress, bruteforceStruct.structWordList, NULL, NULL);
		break;
	case HTTP_BASIC:
		PrintInfoBf("HTTP", bruteforceStruct.ipAddress, bruteforceStruct.port, nbCreadTry);
		result = BruteforceBasic(bruteforceStruct,FALSE, FALSE, &httpAuthHeader);
		if (httpAuthHeader != NULL) {
			printf("\t[i] HTTP Header: \n\t\t%s", httpAuthHeader);
			free(httpAuthHeader);
		}
		break;
	case HTTPS_BASIC:
		PrintInfoBf("HTTPS", bruteforceStruct.ipAddress, bruteforceStruct.port, nbCreadTry);
		result = BruteforceBasic(bruteforceStruct, TRUE, FALSE, &httpAuthHeader);
		if (httpAuthHeader != NULL) {
			printf("\t[i] HTTPS Header: \n\t\t%s", httpAuthHeader);
			free(httpAuthHeader);
		}
		break;
	case SMB:
		PrintInfoBf("SMB", bruteforceStruct.ipAddress, bruteforceStruct.port, nbCreadTry);
		result = BrutForceSmbFunc(bruteforceStruct);
		break;
	case RPC:
		PrintInfoBf("RPC", bruteforceStruct.ipAddress, bruteforceStruct.port, nbCreadTry);
		result = RpcAuthBruteForce(bruteforceStruct);
		break;
	/*case LDAP:
		// TODO
		// PrintInfoBf("LDAP", bruteforceStruct.ipAddress, 443, nbCreadTry);

		StructWordList structWordList;
		StructCredentials structCredentials;
		result = BruteForceLDAP(ipAddress, structWordList, structCredentials);
		break;*/
	}
	return result;
}

/*
Argument manage output file !!!

*/
int main(int argc, char* argv[]) {
	Arguments listAgrument;

	if (!initWSA(NULL))
		return FALSE;

	if (GetArguments(argc, argv, &listAgrument)) {

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
		case ModeEnum:
			EnumPort(listAgrument.enumStruct);
			break;
		case ModeCurl:
			Curl(listAgrument.curlStruct);
			break;
		case ModeExternalIp:
			ExternalIp();
			return TRUE;
		case ModeDos:
			AttackDos(listAgrument.dosStruct);
			break;
		}
		WSACleanup();
	}
	return FALSE;
}