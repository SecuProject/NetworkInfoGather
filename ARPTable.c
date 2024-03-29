
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
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <ws2tcpip.h>


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
		PrintOut(pFile,"[x] GetIpNetTable for IPv4 table returned error: %i\n", status);
		return FALSE;
	} else {
		NetworkPcInfo* arpTable = (NetworkPcInfo*)xcalloc(sizeof(NetworkPcInfo), 1);
		if (arpTable == NULL)
			return FALSE;

		for (int i = 0; (unsigned)i < pipTable->NumEntries; i++) {
			if (CHECK_IP_STATE(pipTable->Table[i].State) && pipTable->Table[i].PhysicalAddressLength == MAC_ADDRESS_LEN_BYTE) {
				char ipAddress[IP_ADDRESS_LEN + 1];
				inet_ntop(AF_INET, &(pipTable->Table[i].Address.Ipv4.sin_addr), ipAddress, IP_ADDRESS_LEN);
				
				if (!isDuplicate(arpTable, *arpTableSize, ipAddress) &&
					GetNetworkRange(ipAddress, ipRangeInt32)) {
					strcpy_s(arpTable[*arpTableSize].ipAddress, IP_ADDRESS_LEN + 1, ipAddress);
					BYTE* bPhysAddr = pipTable->Table[i].PhysicalAddress;
					sprintf_s(arpTable[*arpTableSize].macAddress, MAC_ADDRESS_LEN + 1, "%.2X%.2X%.2X%.2X%.2X%.2X",
							bPhysAddr[0], bPhysAddr[1], bPhysAddr[2], bPhysAddr[3], bPhysAddr[4], bPhysAddr[5]);

					arpTable = (NetworkPcInfo*)xrealloc(arpTable, ((*arpTableSize) + 2) * sizeof(NetworkPcInfo));
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


/*
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
		PrintOut(pFile, "[x] GetIpNetTable for IPv4 table returned error: %i\n", status);
	FreeMibTable(pipTable);
	return FALSE;
}*/

