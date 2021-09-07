#pragma once
#include "portList.h"


#ifndef NET_DISCOVERY_HEADER_H
#define NET_DISCOVERY_HEADER_H
#include "MgArguments.h"

#define BANNER_BUFFER_SIZE	50


typedef enum {
	OsUnknown = 0,
	OsWindows = 1,
	OsLinux = 2,
	OsMac = 3,
	OsBSD = 4,
	OsCisco = 5
}EnumOS;

typedef enum {
	UnknownType,
	FRITZBox
}DeviceType;

typedef struct {
	char Name[33];
	BOOL isGroup;
}NETBIOS_R_M_N_TAB;


typedef struct {
	NETBIOS_R_M_N_TAB* netBIOSRemoteMachineNameTab;
	int nbNetBIOSRemoteMachineNameTab;
	char macAddress[40];				// SIZE WTF !!!
}NETBIOS_Info;

typedef struct {
	int portNumber;
	char banner[BANNER_BUFFER_SIZE];
	DeviceType deviceType;
	int version;
}PORT_INFO;

typedef struct {
	// 2. NetDiscovery
	char* ipAddress;
	char* macAddress;
	char* vendorName;

	// 3. PortScan
	int version;
	PORT_INFO port[NB_TAB_PORT];
	int nbOpenPort;

	// 4. FingerPrintInfo
	EnumOS osName;

	NETBIOS_Info* NetbiosInfo;
	// SMTP
	// DNS
	// SMB
	// FTP
	// HTTP/HTTPS
	BOOL isNetbiosInfo;
}NetworkPcInfo;



EnumOS DetectOSBaseTTL(UINT computerTTL);

BOOL NetDiscovery(Arguments listAgrument, INT32 ipRangeInt32, int maskSizeInt, char* localIP, NetworkPcInfo** networkPcInfo, int* nbDetected, FILE* pFile);

INT32 AddIPRange(Arguments listAgrument, int* maskSizeInt);

VOID PrintHostOS(EnumOS hostOs, FILE* pFile);

#endif