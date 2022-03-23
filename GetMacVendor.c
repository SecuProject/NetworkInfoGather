#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "Network.h"
#include "macDB.h"


BOOL getVendorFormMac(NetworkPcInfo* networkPcInfo) {
	const char vendorName[] = "UNKNOW";
	int j;

	if (networkPcInfo->macAddress[0] == 0x00){
		networkPcInfo->vendorName = (char*)vendorName;
		return FALSE;
	}
	
	for (j = 0; j < sizeof(macDataBase) / sizeof(MacDbStruct) && (strncmp(networkPcInfo->macAddress, macDataBase[j].macAddress, strlen(macDataBase[j].macAddress)) != 0); j++);

	if (j < sizeof(macDataBase) / sizeof(MacDbStruct) && (strncmp(networkPcInfo->macAddress, macDataBase[j].macAddress, strlen(macDataBase[j].macAddress)) == 0)) {
		networkPcInfo->vendorName = macDataBase[j].VendorName;
	} else
		networkPcInfo->vendorName = (char*)vendorName;
	return TRUE;
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
		printf("\t\t[i] Mac Vendor: %s\n", networkPcInfo->vendorName);
	return returnValue;
}