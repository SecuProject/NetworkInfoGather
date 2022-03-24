#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "Network.h"
#include "macDB.h"


BOOL getVendorFormMac(NetworkPcInfo* networkPcInfo) {
	const char vendorName[] = "UNKNOW";
	
	if (networkPcInfo->macAddress[0] != 0x00){
		int j;
		for (j = 0; j < sizeof(macDataBase) / sizeof(MacDbStruct) && (strncmp(networkPcInfo->macAddress, macDataBase[j].macAddress, strlen(macDataBase[j].macAddress)) != 0); j++);

		if (j < sizeof(macDataBase) / sizeof(MacDbStruct) && (strncmp(networkPcInfo->macAddress, macDataBase[j].macAddress, strlen(macDataBase[j].macAddress)) == 0)){
			int strLen = (int)strlen(macDataBase[j].VendorName);
			networkPcInfo->vendorName = (char*)malloc(strLen + 1);
			if (networkPcInfo->vendorName == NULL)
				return FALSE;
			strcpy_s(networkPcInfo->vendorName, strLen + 1, macDataBase[j].VendorName);
			return TRUE;
		}
	}
	
	networkPcInfo->vendorName = (char*)malloc(sizeof(vendorName) + 1);
	if (networkPcInfo->vendorName == NULL)
		return FALSE;
	strcpy_s(networkPcInfo->vendorName, sizeof(vendorName) + 1, vendorName);
	return FALSE;
}




BOOL getMacVendor(NetworkPcInfo* networkPcInfo,int nbDetected) {
	BOOL returnValue = TRUE;

	for (int i = 0; i < nbDetected; i++)
		returnValue = getVendorFormMac(&(networkPcInfo[i]));
	return returnValue;
}

BOOL GetNetBiosMacVendor(NetworkPcInfo* networkPcInfo){
	BOOL returnValue = getVendorFormMac(networkPcInfo);
	if (returnValue)
		printf("\t\t[i] Mac Vendor:  %s\n", networkPcInfo->vendorName);
	return returnValue;
}