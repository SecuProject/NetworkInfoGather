#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "Network.h"
#include "macDB.h"


BOOL getVendorFormMac(NetworkPcInfo* networkPcInfo) {
	const char vendorName[] = "UNKNOW";
	BOOL returnValue = FALSE;
	int j;
	size_t strLen = sizeof(vendorName) + 1;
	char* pVendorName = (char*)vendorName;

	if (networkPcInfo->macAddress == NULL) {
		networkPcInfo->vendorName = NULL;
		return FALSE;
	}
	
	for (j = 0; j < sizeof(macDataBase) / sizeof(MacDbStruct) && (strncmp(networkPcInfo->macAddress, macDataBase[j].macAddress, strlen(macDataBase[j].macAddress)) != 0); j++);

	if (j < sizeof(macDataBase) / sizeof(MacDbStruct) && (strncmp(networkPcInfo->macAddress, macDataBase[j].macAddress, strlen(macDataBase[j].macAddress)) == 0)) {
		strLen = strlen(macDataBase[j].VendorName) +1;
		pVendorName = macDataBase[j].VendorName;
	}
	networkPcInfo->vendorName = (char*)malloc(strLen);
	if (networkPcInfo->vendorName == NULL)
		return FALSE;
	strcpy_s(networkPcInfo->vendorName, strLen, pVendorName);
	return returnValue;
}




BOOL getMacVendor(NetworkPcInfo* networkPcInfo,int nbDetected) {
	BOOL returnValue = TRUE;

	for (int i = 0; i < nbDetected; i++)
		returnValue = getVendorFormMac(&(networkPcInfo[i]));
	return returnValue;
}
