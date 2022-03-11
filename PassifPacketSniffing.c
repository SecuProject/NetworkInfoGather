#include <stdio.h>
#include <winsock2.h>
#include <time.h>


#include "tcpIpModuel.h"
#include "NetDiscovery.h"
#include "Network.h"

#pragma warning(disable:4996)


/*typedef struct {
	char ipAddress[IP_ADDRESS_LEN];
	int ttlInfo[100];
	int nbTtlTable;
}PC_INFO;*/


BOOL ProcessPacket(char* Buffer, int Size, NetworkPcInfo** ppNetworkPcInfo, int* nbPcInfo, FILE* pFile) {
	char ipAddressSrc[IP_ADDRESS_LEN];
	char ipAddressDst[IP_ADDRESS_LEN];
	struct sockaddr_in source;
	struct sockaddr_in  dest;
	NetworkPcInfo* pNetworkPcInfo = *ppNetworkPcInfo;
	IPV4_HDR* iphdr = (IPV4_HDR*)Buffer;



	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iphdr->ip_srcaddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iphdr->ip_destaddr;

	strcpy_s(ipAddressSrc, IP_ADDRESS_LEN, inet_ntoa(source.sin_addr));
	strcpy_s(ipAddressDst, IP_ADDRESS_LEN, inet_ntoa(dest.sin_addr));

	// remove 192.168.x.255
	if (IS_PRIVATE_IP(ipAddressSrc)) {
		int iSrc;
		for (iSrc = 0; iSrc < *nbPcInfo && strcmp(pNetworkPcInfo[iSrc].ipAddress, ipAddressSrc) != 0; iSrc++);
		if (iSrc == *nbPcInfo) {
			strcpy_s(pNetworkPcInfo[*nbPcInfo].ipAddress, IP_ADDRESS_LEN, ipAddressSrc);
			
			pNetworkPcInfo[*nbPcInfo].macAddress[0] = 0x00;
			//printOut(pFile,"\tSource IP:\t %s\t", ipAddressSrc);
			//printOut(pFile,"\t[%i] - [%s]\t", (*nbPcInfo) +1, ipAddressSrc);
			pNetworkPcInfo[*nbPcInfo].osName = DetectOSBaseTTL(iphdr->ip_ttl);
			(*nbPcInfo)++;
			pNetworkPcInfo = (NetworkPcInfo*)xrealloc(pNetworkPcInfo, ((*nbPcInfo) + 1) * sizeof(NetworkPcInfo));
			if (pNetworkPcInfo == NULL)
				return FALSE;
		}
	}
	if (IS_PRIVATE_IP(ipAddressDst)) {
		int iDst;
		for (iDst = 0; iDst < *nbPcInfo && strcmp(pNetworkPcInfo[iDst].ipAddress, ipAddressDst) != 0; iDst++);
		if (iDst == *nbPcInfo) {
			strcpy_s(pNetworkPcInfo[*nbPcInfo].ipAddress, IP_ADDRESS_LEN, ipAddressDst);
			//pNetworkPcInfo[*nbPcInfo].osName = DetectOSBaseTTL(iphdr->ip_ttl);
			pNetworkPcInfo[*nbPcInfo].osName = OsUnknown;
			pNetworkPcInfo[*nbPcInfo].macAddress[0] = 0x00;
			//printOut(pFile,"\tDestination IP:\t %s\n", ipAddressDst);
			//printOut(pFile, "\t[%i] - [%s]\n", (*nbPcInfo) + 1, ipAddressDst);
			pNetworkPcInfo[*nbPcInfo].osName = DetectOSBaseTTL(iphdr->ip_ttl);
			(*nbPcInfo)++;
			pNetworkPcInfo = (NetworkPcInfo*)xrealloc(pNetworkPcInfo, ((*nbPcInfo) + 1) * sizeof(NetworkPcInfo));
			if (pNetworkPcInfo == NULL)
				return FALSE;
		}
	}

	*ppNetworkPcInfo = pNetworkPcInfo;
	return TRUE;
}

long CheckTimeSniffing(clock_t start, int timeSniffing) {
	return (double)(clock() - start) / CLOCKS_PER_SEC < timeSniffing;
}

BOOL StartSniffing(SOCKET sniffer, int timeSniffing, NetworkPcInfo** ppNetworkPcInfo, int* nbDetected, FILE* pFile) {
	int nbPcInfo = 0;
	clock_t start;
	int mangobyte;
	//char Buffer[PACKET_BUFFER_SIZE]; // heap alloc

	*ppNetworkPcInfo = (NetworkPcInfo*)calloc(sizeof(NetworkPcInfo), 1);
	if (*ppNetworkPcInfo == NULL)
		return FALSE;

	char* Buffer = (char*)HeapAlloc(GetProcessHeap(), 0, PACKET_BUFFER_SIZE);
	if (Buffer == NULL)
		return FALSE;

	mangobyte = recvfrom(sniffer, Buffer, PACKET_BUFFER_SIZE, 0, 0, 0);
	if (mangobyte <= 0){
		HeapFree(GetProcessHeap(), 0, Buffer);
		return FALSE;
	}

	start = clock();
	while (mangobyte > 0 && CheckTimeSniffing(start, timeSniffing) && nbPcInfo < 255) {
		ProcessPacket(Buffer, mangobyte, ppNetworkPcInfo, &nbPcInfo,pFile);
		mangobyte = recvfrom(sniffer, Buffer, PACKET_BUFFER_SIZE, 0, 0, 0);
	}
	*nbDetected = nbPcInfo;
	if (mangobyte <= 0)
		printOut(pFile,"[x] recvfrom() failed.\n");

	if (!HeapFree(GetProcessHeap(), 0, Buffer)) {
		printOut(pFile,"[x] Call to HeapFree has failed (%u)\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}


BOOL initSniffer(char* interfaceIp, SOCKET* sniffer, FILE* pFile) {
	SOCKADDR_IN dest;
	IN_ADDR addr;
	int in;

	char hostname[100];
	struct hostent* local;
	*sniffer = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	if (*sniffer == INVALID_SOCKET) {
		printOut(pFile,"[x] Failed to create raw socket.\n");
		return FALSE;
	}
	//Retrive the local hostname
	if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR) {
		printOut(pFile,"[x] Gethostname failed : %d\n", WSAGetLastError());
		return FALSE;
	}

	//Retrive the available IPs of the local host
	local = gethostbyname(hostname);
	if (local == NULL) {
		printOut(pFile,"[x] Gethostbyname failed: %d.\n", WSAGetLastError());
		return FALSE;
	}
	int i;
	if (local->h_addr_list[0] == 0){ 
		printOut(pFile,"[x] Interface not found !\n");
		return FALSE;
	}

	for (i = 0; local->h_addr_list[i] != 0; i++) {
		memcpy(&addr, local->h_addr_list[i], sizeof(IN_ADDR));
		if (strcmp(inet_ntoa(addr), interfaceIp) == 0)
			break;
	}
	if (strcmp(inet_ntoa(addr), interfaceIp) != 0) {
		printOut(pFile,"[x] The interface was not found !\n");
		return FALSE;
	}

	memset(&dest, 0, sizeof(SOCKADDR_IN));
	memcpy(&dest.sin_addr.s_addr, local->h_addr_list[i], sizeof(ULONG));
	//memcpy(&dest.sin_addr.s_addr, local->h_addr_list[i], sizeof(dest.sin_addr.s_addr));
	dest.sin_family = AF_INET;
	dest.sin_port = 0;

	if (bind(*sniffer, (const SOCKADDR_IN*) &dest, sizeof(SOCKADDR_IN)) == SOCKET_ERROR) {
		printOut(pFile,"[x] bind(%s) failed.\n", inet_ntoa(addr));
		return FALSE;
	}
	int j = 1;
	if (WSAIoctl(*sniffer, SIO_RCVALL, &j, sizeof(int), 0, 0, (LPDWORD)&in, 0, 0) == SOCKET_ERROR) {
		printOut(pFile,"[x] WSAIoctl() failed.\n");
		return FALSE;
	}
	return TRUE;
}


BOOL PassifPacketSniffing(char* interfaceIp, int timeSniffing, NetworkPcInfo** networkPcInfo, int* nbDetected,FILE* pFile){
	SOCKET sniffer;

	if (initSniffer(interfaceIp ,&sniffer,pFile)) {
		StartSniffing(sniffer, timeSniffing, networkPcInfo, nbDetected,pFile); // sniff for 30 second
		closesocket(sniffer);
		return TRUE;
	}
	return FALSE;
}