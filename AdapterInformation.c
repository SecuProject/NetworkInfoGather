
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
#include <math.h>

#include "AdapterInformation.h"
#include "Network.h"

#pragma warning(disable:4996)


int getAdapterkInfo(ADAPTER_INFO* adapterInfo, FILE* pFile) {
	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;
	int nbAdapter = 0;
	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);

	pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL) {
		PrintOut(pFile,"Error allocating memory needed to call GetAdaptersinfo\n");
		return FALSE;
	}

	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
		if (pAdapterInfo == NULL) {
			PrintOut(pFile,"Error allocating memory needed to call GetAdaptersinfo\n");
			return FALSE;
		}
	}

	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
		pAdapter = pAdapterInfo;
		while (pAdapter) {
			if (strcmp(pAdapter->IpAddressList.IpAddress.String, "0.0.0.0") != 0) {
				strcpy_s(adapterInfo[nbAdapter].GateWayIp, MAX_BUFFER, pAdapter->GatewayList.IpAddress.String);
				strcpy_s(adapterInfo[nbAdapter].localIP, MAX_BUFFER, pAdapter->IpAddressList.IpAddress.String);
				strcpy_s(adapterInfo[nbAdapter].networkMask, MAX_BUFFER, pAdapter->IpAddressList.IpMask.String);
				adapterInfo[nbAdapter].InterfaceIndex = pAdapter->ComboIndex;
				nbAdapter++;
			}
			pAdapter = pAdapter->Next;
		}
	}else {
		PrintOut(pFile,"GetAdaptersInfo failed with error: %d\n", dwRetVal);
		free(pAdapterInfo);
		return FALSE;
	}
	free(pAdapterInfo);
	return nbAdapter;
}

INT32 IPToUInt(char* ip) {
	INT32 addr = 0;
	int a, b, c, d;

	if (sscanf_s(ip, "%d.%d.%d.%d", &a, &b, &c, &d) != 4)
		return 0;
	addr = a << 24;
	addr |= b << OCTE_SIZE * 2;
	addr |= c << OCTE_SIZE;
	addr |= d;
	return addr;
}

int getMaskSize(char* networkMask, int* maskSizeBit) {
	char networkMaskBc[MASK_SIZE_CHAR];
	char *pch;
	INT32 MASK = 0;
	int maskSize;

	strcpy_s(networkMaskBc, MASK_SIZE_CHAR, networkMask);
	pch = strtok(networkMaskBc, ".");
	for (int i = 0; i < MASK_NB_BYTE && pch != NULL; i++) {
		MASK = (atoi(pch) ^ OCTE_MAX) << 4 * (3 - i);
		pch = strtok(NULL, ".");
	}
	*maskSizeBit = MASK;
	MASK++;
	for (maskSize = 0; MASK > 1; maskSize++)
		MASK = MASK / 2;
	return maskSize;
}
INT32 getIpRange(char* localIP, int maskSize) {
	INT32 ipRange = IPToUInt(localIP);
	int size = (int)pow(2, maskSize) - 1;

	ipRange |= size;
	ipRange ^= size;

	return ipRange;
}
INT32 ipCalucation(char* localIP, char* networkMask, int* maskSizeInt) {
	int maskSizeBit = getMaskSize(networkMask, maskSizeInt);
	return getIpRange(localIP, maskSizeBit); // (*maskSizeInt)
}