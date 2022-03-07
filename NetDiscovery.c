#include <windows.h>
#include <stdio.h>

#include "NetDiscovery.h"
#include "ICMP.h"
#include "ARPQuery.h"
#include "ARPTable.h"
#include "GetMacVendor.h"
#include "PassifPacketSniffing.h"
#include "DNSscan.h"
#include "MgArguments.h"
#include "Network.h"
#include "AdapterInformation.h"



EnumOS DetectOSBaseTTL(UINT computerTTL) {
	if (computerTTL < 64)
		return OsLinux;
	else if (computerTTL < 128)
		return OsWindows;
	else if (computerTTL < 256)
		return OsCisco;
	else
		return OsUnknown;
	return OsUnknown;
}
VOID PrintHostOS(EnumOS hostOs, FILE* pFile) {
	switch (hostOs) {
	case OsLinux:
		printOut(pFile, " - [Linux base]");
		break;
	case OsWindows:
		printOut(pFile, " - [Windows base]");
break;
	case OsCisco:
		printOut(pFile, " - [Cisco base]");
		break;
	default:
		//printf(" - [Unknown OS]");
		break;
	}
}

VOID ScanBanner(TypeOfScan typeOfScan, FILE* pFile) {
	switch (typeOfScan) {
	case Passif_Scan:
		printOut(pFile, "[i] ARP discovery:\n");
		break;
	case Passif_Packet_Sniffing:
		printOut(pFile, "[i] Passive packet sniffing:\n");
		break;
	case ICMP_Scan:
		printOut(pFile, "[i] ICMP discovery:\n");
		break;
	case ARP_Scan:
		printOut(pFile, "[i] ARP Table discovery:\n");
		break;
	case DNS_Scan:
		printOut(pFile, "[i] DNS request discovery:\n");
		break;
	case Disable_Scan:
		printOut(pFile, "[i] Host(s) to scan:\n");
	default:
		break;
	}
}

INT32 AddIPRange(ScanStruct scanStruct, int* maskSizeInt) {
	NetworkPcInfo* pNetworkPcInfo = NULL;
	int nbHostTest = 0;
	int a, b, c, d, ipRange;
	char* pToken;

	if (scanStruct.typeOfScan == Passif_Packet_Sniffing) {
		printf("\t[!] Passif Packet Sniffing with arg '-t' is not supported !\n");
		printf("\t[!] All the IP addresses will be seen has up !\n");
	}
	pToken = strchr(scanStruct.ipAddress, '/');
	if (pToken != NULL){
		// Multiple hosts
		int nbData = sscanf_s(scanStruct.ipAddress, "%i.%i.%i.%i/%i", &a, &b, &c, &d, &ipRange);
		if (nbData != 5 || ipRange <= 0 || ipRange > 32){
			printf("[x] Invalid IP address format !\n");
			return FALSE;
		}
		nbHostTest = (0xFFFFFFFF >> ipRange) + 1;
	} else{
		pToken = strchr(scanStruct.ipAddress, '-');
		if (pToken != NULL){
			// Multiple hosts
			int nbData = sscanf_s(scanStruct.ipAddress, "%i.%i.%i.%i-%i", &a, &b, &c, &d, &ipRange);
			if (ipRange <= 0 || nbData != 5){
				printf("[x] Invalid IP address format !\n");
				return FALSE;
			}
			nbHostTest = ipRange - d + 1;
		} else{
			// Single host
			int nbData = sscanf_s(scanStruct.ipAddress, "%i.%i.%i.%i", &a, &b, &c, &d);
			if (nbData != 4){
				printf("[x] Invalid IP address format !\n");
				return FALSE;
			}
			nbHostTest = 1;
		}
	}

	if (!IsIpAddressValid(a, b, c, d) && nbHostTest > 0) {
		printf("[x] Invalid IP address format !\n");
		return FALSE;
	}
	char ipAddressTemp[IP_ADDRESS_LEN + 1];
	sprintf_s(ipAddressTemp, IP_ADDRESS_LEN + 1, "%i.%i.%i.%i", a, b, c, d);
	*maskSizeInt = nbHostTest;
	return IPToUInt(ipAddressTemp);
}

BOOL AddHostNotScan(int maskSizeInt, NetworkPcInfo** ptrNetworkPcInfo, INT32 ipAddressBc, int* nbDetected, FILE* pFile) {
	NetworkPcInfo* networkPcInfo = (NetworkPcInfo*)calloc(maskSizeInt, sizeof(NetworkPcInfo));
	if (networkPcInfo == NULL) {
		printOut(pFile, "\t[x] Unable to allocate memory\n");
		return FALSE;
	}

	for (int i = 0; i < maskSizeInt; i++) {
		INT32 ipAddress = ipAddressBc + i;
		if ((ipAddress & OCTE_MAX) > 0 && (ipAddress & OCTE_MAX) < 255){
			networkPcInfo[i].ipAddress = (char*)malloc(IP_ADDRESS_LEN + 1);
			if (networkPcInfo[i].ipAddress == NULL)
				return FALSE;

			sprintf_s(networkPcInfo[i].ipAddress, IP_ADDRESS_LEN + 1, "%i.%i.%i.%i",
				(ipAddress >> 24) & OCTE_MAX, //  << 24; // (OCTE_SIZE * 4)
				(ipAddress >> OCTE_SIZE * 2) & OCTE_MAX,
				(ipAddress >> OCTE_SIZE) & OCTE_MAX,
				ipAddress & OCTE_MAX);
			//printf("\t[%i] [%s]\n", i + 1, networkPcInfo[i].ipAddress);
		}
	}
	*ptrNetworkPcInfo = networkPcInfo;
	*nbDetected = maskSizeInt;
	return TRUE;
}

VOID PrintDiscoveredHost(ScanStruct scanStruct, NetworkPcInfo** networkPcInfo, int nbDetected, FILE* pFile) {
	for (int i = 0; i < nbDetected; i++) {
		if ((*networkPcInfo)[i].macAddress == NULL)
			printOut(scanStruct.ouputFile, "\t%3i - %15s", i + 1, (*networkPcInfo)[i].ipAddress);
		else
			printOut(scanStruct.ouputFile, "\t%3i - %15s:%s", i + 1, (*networkPcInfo)[i].ipAddress, (*networkPcInfo)[i].macAddress);
		
		if((*networkPcInfo)[i].vendorName != NULL)
			printOut(scanStruct.ouputFile, " - [%s]",(*networkPcInfo)[i].vendorName);
		if((*networkPcInfo)[i].hostname != NULL)
			printOut(scanStruct.ouputFile, " - [%s]",(*networkPcInfo)[i].hostname);

		PrintHostOS((*networkPcInfo)[i].osName, pFile);

		printOut(scanStruct.ouputFile, "\n");
	}
	return;
}

BOOL NetDiscovery(ScanStruct scanStruct, INT32 ipRangeInt32, int maskSizeInt,char* localIP, NetworkPcInfo** networkPcInfo, int* nbDetected, FILE* pFile) {
	*nbDetected = 0;
	
	ScanBanner(scanStruct.typeOfScan, scanStruct.ouputFile);

	switch (scanStruct.typeOfScan) {
// ------------------------ Passive Attack  ------------------------
	case Passif_Scan:
		if (GetARPTable(networkPcInfo, nbDetected, ipRangeInt32,pFile))
			getMacVendor(*networkPcInfo, *nbDetected);
		break;
	case Passif_Packet_Sniffing:
		PassifPacketSniffing(localIP, scanStruct.psTimeout, networkPcInfo, nbDetected, scanStruct.ouputFile); // 30
		//getMacVendor(*networkPcInfo, *nbDetected);
		break;
// ------------------------ Active Attack ------------------------
	case ICMP_Scan:
		ICMPdiscoveryMultiThread(maskSizeInt, networkPcInfo, ipRangeInt32, nbDetected, pFile);
		break;
	case ARP_Scan:
		if (ARPdiscoveryThread(maskSizeInt, networkPcInfo, ipRangeInt32, nbDetected, pFile))
			getMacVendor(*networkPcInfo, *nbDetected);
		break;
	case DNS_Scan:
		if (DNSdiscoveryMultiThread(maskSizeInt, networkPcInfo, ipRangeInt32, nbDetected, pFile))
			getMacVendor(*networkPcInfo, *nbDetected);
		break;
	case Disable_Scan:
		if(AddHostNotScan(maskSizeInt, networkPcInfo, ipRangeInt32, nbDetected, pFile))
			getMacVendor(*networkPcInfo, *nbDetected);
		break;
	default:
		break;
	}
	if(*nbDetected > 0)
		PrintDiscoveredHost(scanStruct, networkPcInfo, *nbDetected, pFile);

	return *nbDetected > 0;
}