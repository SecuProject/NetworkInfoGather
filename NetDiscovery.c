#include <windows.h>
#include <stdio.h>

#include "NetDiscovery.h"
#include "ICMP.h"
#include "ARPQuery.h"
#include "ARPTable.h"
#include "GetMacVendor.h"
#include "PassifPacketSniffing.h"
#include "MgArguments.h"
#include "Network.h"
#include "AdapterInformation.h"



EnumOS DetectOSBaseTTL(UINT computerTTL) {
	if (computerTTL < 65)
		return OsLinux;
	else if (computerTTL > 64 || computerTTL < 129)
		return OsWindows;
	else if (computerTTL < 256)
		return OsCisco;
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
	case Disable_Scan:
		printOut(pFile, "[i] Host(s) to scan:\n");
	default:
		break;
	}
}

INT32 AddIPRange(Arguments listAgrument, int* maskSizeInt) {
	int nbDetected = 0;
	NetworkPcInfo* pNetworkPcInfo = NULL;
	int nbHostTest = 0;
	int a, b, c, d, ipRange;

	if (listAgrument.typeOfScan == Passif_Packet_Sniffing) {
		printf("\t[!] Passif Packet Sniffing with arg '-t' is not supported !\n");
		printf("\t[!] All the ip address will be seen has up !\n");
	}

	int nbData = sscanf_s(listAgrument.ipAddress, "%i.%i.%i.%i-%i", &a, &b, &c, &d, &ipRange);
	switch (nbData) {
	case 4:
		// Single host
		nbHostTest = 1;
		break;
	case 5:
		// Multiple hosts
		if (ipRange <= 0) {
			printf("[x] Invalid IP address format !\n");
			return FALSE;
		}
		nbHostTest = ipRange - d + 1;
		break;
	default:
		printf("[x] Invalid IP address format !\n");
		return FALSE;
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
	*ptrNetworkPcInfo = networkPcInfo;
	*nbDetected = maskSizeInt;
	return TRUE;
}

VOID PrintDiscoveredHost(Arguments listAgrument, NetworkPcInfo** networkPcInfo, int* nbDetected, FILE* pFile) {
	for (int i = 0; i < *nbDetected; i++) {
		if ((*networkPcInfo)[i].macAddress == NULL)
			printOut(listAgrument.ouputFile, "\t[%i] - [%s]", i + 1, (*networkPcInfo)[i].ipAddress);
		else
			printOut(listAgrument.ouputFile, "\t[%i] - [%s:%s]", i + 1, (*networkPcInfo)[i].ipAddress, (*networkPcInfo)[i].macAddress);
		
		if((*networkPcInfo)[i].vendorName != NULL)
			printOut(listAgrument.ouputFile, " - [%s]",(*networkPcInfo)[i].vendorName);

		PrintHostOS((*networkPcInfo)[i].osName, pFile);

		printOut(listAgrument.ouputFile, "\n");
	}
	return;
}

BOOL NetDiscovery(Arguments listAgrument, INT32 ipRangeInt32, int maskSizeInt,char* localIP, NetworkPcInfo** networkPcInfo, int* nbDetected, FILE* pFile) {
	*nbDetected = 0;
	
	ScanBanner(listAgrument.typeOfScan, listAgrument.ouputFile);

	switch (listAgrument.typeOfScan) {
// ------------------------ Passive Attack  ------------------------
	case Passif_Scan:
		if (GetARPTable(networkPcInfo, nbDetected, ipRangeInt32,pFile)) {
			getMacVendor(*networkPcInfo, *nbDetected);
			PrintDiscoveredHost(listAgrument, networkPcInfo, nbDetected, pFile);
		}
		break;
	case Passif_Packet_Sniffing:
		if (PassifPacketSniffing(localIP, 5, networkPcInfo, nbDetected, listAgrument.ouputFile)) { // 30
			//getMacVendor(*networkPcInfo, *nbDetected);
			PrintDiscoveredHost(listAgrument, networkPcInfo, nbDetected, pFile);
		}
		break;
// ------------------------ Active Attack ------------------------
	case ICMP_Scan:
		if(ICMPdiscoveryMultiThread(maskSizeInt, networkPcInfo, ipRangeInt32, nbDetected, pFile))
			PrintDiscoveredHost(listAgrument, networkPcInfo, nbDetected, pFile);
		break;
	case ARP_Scan:
		if (ARPdiscoveryThread(maskSizeInt, networkPcInfo, ipRangeInt32, nbDetected, pFile)) {
			getMacVendor(*networkPcInfo, *nbDetected);
			PrintDiscoveredHost(listAgrument, networkPcInfo, nbDetected, pFile);
		}
		break;
	case Disable_Scan:
		if(AddHostNotScan(maskSizeInt, networkPcInfo, ipRangeInt32, nbDetected, pFile))
			getMacVendor(*networkPcInfo, *nbDetected);
		break;
	default:
		break;
	}
	return *nbDetected > 0;
}