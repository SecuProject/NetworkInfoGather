
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

#pragma once

#ifndef NET_DISCOVERY_HEADER_H
#define NET_DISCOVERY_HEADER_H

#include "portList.h"
#include "MgArguments.h"

#define BANNER_BUFFER_SIZE	50
#define BUFFER_SIZE			1024


#ifndef IP_ADDRESS_LEN
#define IP_ADDRESS_LEN	16
#endif
#ifndef MAC_ADDRESS_LEN
#define MAC_ADDRESS_LEN_BYTE	6
#define MAC_ADDRESS_LEN			MAC_ADDRESS_LEN_BYTE * 2 + 5
#endif

#define HOSTNAME_SIZE       15

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
	FRITZBox,
	TrueNAS,
	Deluge
}DeviceType;

// 3. PortScan
typedef struct {
	int portNumber;
	char banner[BANNER_BUFFER_SIZE];
	DeviceType deviceType;
	int version;
	BOOL isTcp;
}PORT_INFO;





typedef struct {
	char Name[HOSTNAME_SIZE +1];
	BOOL isGroup;
}NETBIOS_R_M_N_TAB;


typedef struct {
	NETBIOS_R_M_N_TAB* netBIOSRemoteMachineNameTab;
	int nbNetBIOSRemoteMachineNameTab;
	char macAddress[MAC_ADDRESS_LEN];
}NETBIOS_Info;


// 4. FingerPrintInfo
typedef struct {
	char banner[BUFFER_SIZE];
	char** listUser;
	UINT numUser;
	char* ntlmData;
} SMTP_DATA;

/*
typedef struct {
	int portNumber;
	char banner[BANNER_BUFFER_SIZE];
	union {
		SMTP_DATA* smtpData;
		NETBIOS_Info* smtpData;
	};
	DeviceType deviceType;
	int version;
}PORT_INFO;
*/

typedef struct {
	// 2. NetDiscovery
	char ipAddress[IP_ADDRESS_LEN +1];
	char macAddress[MAC_ADDRESS_LEN +1];
	char* vendorName;
	char* hostname;

	// 3. PortScan
	int version;
	PORT_INFO port[NB_TAB_PORT_TCP + NB_TAB_PORT_UDP];
	int nbOpenPort;

	// 4. FingerPrintInfo
	EnumOS osName;

	NETBIOS_Info* NetbiosInfo;
	SMTP_DATA* smtpData;
	// DNS
	// LDAP
	// SMB
	// FTP
	// HTTP/HTTPS
	BOOL isNetbiosInfo;
}NetworkPcInfo;



EnumOS DetectOSBaseTTL(UINT computerTTL);

BOOL NetDiscovery(ScanStruct listAgrument, INT32 ipRangeInt32, int maskSizeInt, char* localIP, NetworkPcInfo** networkPcInfo, int* nbDetected, FILE* pFile);

INT32 AddIPRange(ScanStruct listAgrument, int* maskSizeInt);

VOID PrintHostOS(EnumOS hostOs, FILE* pFile);

#endif