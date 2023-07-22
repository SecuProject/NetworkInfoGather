
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
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <ws2tcpip.h>

#include "Network.h"

BOOL ArpScan(char* ipAddress, char* macAddress) {
	IPAddr DestIp;
	IPAddr SrcIp = 0;

	ULONG MacAddr[2];
	ULONG PhysAddrLen = MAC_ADDRESS_LEN_BYTE;  /* default to length of six bytes */
	DWORD dwRetVal;

	inet_pton(AF_INET, ipAddress, &DestIp);
	memset(&MacAddr, 0xff, sizeof(MacAddr));
	dwRetVal = SendARP(DestIp, SrcIp, &MacAddr, &PhysAddrLen);

	if (dwRetVal == NO_ERROR) {
		BYTE* bPhysAddr;

		bPhysAddr = (BYTE*)&MacAddr;
		if (PhysAddrLen) {
			sprintf_s(macAddress, MAC_ADDRESS_LEN + 1, "%.2X%.2X%.2X%.2X%.2X%.2X",
				bPhysAddr[0], bPhysAddr[1], bPhysAddr[2], bPhysAddr[3], bPhysAddr[4], bPhysAddr[5]);
			return TRUE;
		}
	}
	// printf("%i\n",dwRetVal);
	return FALSE;
}

DWORD WINAPI ThreadArpHost(LPVOID lpParam) {
	PTHREAD_STRUCT_DATA arpStructData = (PTHREAD_STRUCT_DATA)lpParam;
	arpStructData->isHostUp = ArpScan(arpStructData->ipAddress, arpStructData->macAddress);
	return arpStructData->isHostUp;
}

BOOL ARPdiscoveryThread(int maskSizeInt, NetworkPcInfo** ptrNetworkPcInfo, INT32 ipAddressBc, int* pNbDetected, FILE* pFile) {
	NetworkPcInfo* networkPcInfo;
	PTHREAD_STRUCT_DATA arpStructData;
	DWORD* dwThreadIdArray;
	HANDLE* hThreadArray;
	if (InitNetworkPcInfo(&networkPcInfo,&arpStructData, &dwThreadIdArray,&hThreadArray, maskSizeInt)){
		int nbDetected = 0;

		for (int i = 0; i < maskSizeInt; i++){
			INT32 ipAddress = ipAddressBc + i;
			sprintf_s(arpStructData[i].ipAddress, IP_ADDRESS_LEN + 1, "%i.%i.%i.%i",
				(ipAddress >> 24) & OCTE_MAX, //  << 24; // (OCTE_SIZE * 4)
				(ipAddress >> OCTE_SIZE * 2) & OCTE_MAX,
				(ipAddress >> OCTE_SIZE) & OCTE_MAX,
				ipAddress & OCTE_MAX);

			hThreadArray[i] = CreateThread(NULL, 0, ThreadArpHost, &(arpStructData[i]), 0, &dwThreadIdArray[i]);
			if (hThreadArray[i] == NULL){
				PrintOut(pFile, "\t[x] Unable to Create Thread\n");
				FreeNetworkPcInfo(arpStructData, dwThreadIdArray, hThreadArray);
				free(networkPcInfo);
				return FALSE;
			}
			Sleep(20);
		}
		SyncWaitForMultipleObjs(hThreadArray, maskSizeInt);

		for (int i = 0; i < maskSizeInt; i++){
			if (hThreadArray[i] != NULL)
				CloseHandle(hThreadArray[i]);

			if (arpStructData[i].isHostUp){
				strcpy_s(networkPcInfo[nbDetected].ipAddress, IP_ADDRESS_LEN, arpStructData[i].ipAddress);
				strcpy_s(networkPcInfo[nbDetected].macAddress, MAC_ADDRESS_LEN, arpStructData[i].macAddress);
				nbDetected++;
			}
		}
		FreeNetworkPcInfo(arpStructData, dwThreadIdArray, hThreadArray);

		networkPcInfo = (NetworkPcInfo*)xrealloc(networkPcInfo, (nbDetected + 1) * sizeof(NetworkPcInfo));
		if (networkPcInfo == NULL)
			return FALSE;

		*pNbDetected = nbDetected;
		*ptrNetworkPcInfo = networkPcInfo;

		return TRUE;
	}

	*pNbDetected = 0;
	*ptrNetworkPcInfo = NULL;
	return FALSE;
}



