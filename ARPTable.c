
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <ws2tcpip.h>

//#pragma warning(disable:4996)

#include "Network.h"
#include "AdapterInformation.h"

#define CHECK_IP_STATE(value)	(value == NlnsReachable || value == NlnsStale)


BOOL isDuplicate(NetworkPcInfo* arpTable,int arpTableSize,char* ipAddress) {
	for (int j = 0; j < arpTableSize; j++) {
		if (strcmp(arpTable[j].ipAddress, ipAddress) == 0)
			return TRUE;
	}
	return FALSE;
}


BOOL GetARPTable(NetworkPcInfo** ptrArpTable, int* arpTableSize, INT32 ipRangeInt32, FILE* pFile) {
	PMIB_IPNET_TABLE2 pipTable = NULL;
	int status = GetIpNetTable2(AF_INET, &pipTable);
	
	if (status != NO_ERROR) {
		printOut(pFile,"[x] GetIpNetTable for IPv4 table returned error: %i\n", status);
		return FALSE;
	} else {
		NetworkPcInfo* arpTable = (NetworkPcInfo*)calloc(sizeof(NetworkPcInfo), 1);

		if (arpTable == NULL)
			return FALSE;

		for (int i = 0; (unsigned)i < pipTable->NumEntries; i++) {
			if (CHECK_IP_STATE(pipTable->Table[i].State) && pipTable->Table[i].PhysicalAddressLength == MAC_ADDRESS_LEN_BYTE) {
				char ipAddress[IP_ADDRESS_LEN + 1];
				inet_ntop(AF_INET, &(pipTable->Table[i].Address.Ipv4.sin_addr), ipAddress, IP_ADDRESS_LEN);
				
				if (!isDuplicate(arpTable, *arpTableSize, ipAddress) &&
					isNetworkRange(ipAddress, ipRangeInt32)) {
					// Check Network
					arpTable[*arpTableSize].ipAddress = (char*)calloc(IP_ADDRESS_LEN + 1, 1);
					if (arpTable[*arpTableSize].ipAddress == NULL)
						return FALSE;
					strcpy_s(arpTable[*arpTableSize].ipAddress, IP_ADDRESS_LEN + 1, ipAddress);


					arpTable[*arpTableSize].macAddress = (char*)calloc(MAC_ADDRESS_LEN_BYTE * 3 + 5 + 1, 1);
					if (arpTable[*arpTableSize].macAddress == NULL)
						return FALSE;
					/*for (int j = 0; j < MAC_ADDRESS_LEN_BYTE; j++)
						sprintf_s(arpTable[*arpTableSize].macAddress + (3 * j), MAC_ADDRESS_LEN - (3 * (int)j / 2) + 1, (j == (MAC_ADDRESS_LEN_BYTE - 1)) ? "%.2X" : "%.2X-", (int)pipTable->Table[i].PhysicalAddress[j]);*/
					BYTE* bPhysAddr = pipTable->Table[i].PhysicalAddress;
					sprintf_s(arpTable[*arpTableSize].macAddress, MAC_ADDRESS_LEN + 1, "%.2X%.2X%.2X%.2X%.2X%.2X",
							bPhysAddr[0], bPhysAddr[1], bPhysAddr[2], bPhysAddr[3], bPhysAddr[4], bPhysAddr[5]);

					arpTable = (NetworkPcInfo*)realloc(arpTable, ((*arpTableSize) + 2) * sizeof(NetworkPcInfo));
					if (arpTable == NULL)
						return FALSE;

					(*arpTableSize)++;
				}
			}
		}
		*(ptrArpTable) = arpTable;
	
	}
	FreeMibTable(pipTable);
	pipTable = NULL;
	return TRUE;
}



BOOL IsIpInArpTable(char* ipAddress,char* macAddress, FILE* pFile) {
	PMIB_IPNET_TABLE2 pipTable = NULL;
	int status = GetIpNetTable2(AF_INET, &pipTable);
	
	if (status == NO_ERROR) {
		for (UINT i = 0; i < pipTable->NumEntries; i++) {
			if (CHECK_IP_STATE(pipTable->Table[i].State) && pipTable->Table[i].PhysicalAddressLength == MAC_ADDRESS_LEN_BYTE) {
				char ipAddressTmp[IP_ADDRESS_LEN + 1];
				inet_ntop(AF_INET, &(pipTable->Table[i].Address.Ipv4.sin_addr), ipAddressTmp, IP_ADDRESS_LEN);
				
				if (strcmp(ipAddressTmp, ipAddress) == 0) {
					BYTE* bPhysAddr = pipTable->Table[i].PhysicalAddress;
					sprintf_s(macAddress, MAC_ADDRESS_LEN + 1, "%.2X%.2X%.2X%.2X%.2X%.2X",
						bPhysAddr[0], bPhysAddr[1], bPhysAddr[2], bPhysAddr[3], bPhysAddr[4], bPhysAddr[5]);
					FreeMibTable(pipTable);
					return TRUE;
				}
			}
		}
	} else 
		printOut(pFile, "[x] GetIpNetTable for IPv4 table returned error: %i\n", status);
	FreeMibTable(pipTable);
	return FALSE;
}

