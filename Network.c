#include <winsock2.h>
#include <iphlpapi.h>
#include <stdio.h>

#include "portList.h"
#include "AdapterInformation.h"


BOOL IsIpAddressValid(int a, int b, int c, int d) {
	return !(a < 0 || a>255 || b < 0 || b>255 || c < 0 || c>255 || d < 0 || d>255);
}

BOOL isNetworkRange(char* ipAddress, INT32 ipRangeInt32) {
	INT32 ipAddressInt = IPToUInt(ipAddress);
	return ((ipAddressInt - ipRangeInt32) < 256 && (ipAddressInt - ipRangeInt32) >= 0);
}

BOOL printOut(FILE* pFile, const char* format, ...) {
	va_list args;
	va_start(args, format);
	vprintf(format, args);
	if (pFile != NULL)
		vfprintf(pFile, format, args);
	va_end(args);
	return TRUE;
}

DWORD SyncWaitForMultipleObjs(HANDLE* handles, DWORD count) {
	DWORD waitingThreadsCount = count;
	int index = 0;
	DWORD res = 0;
	while (waitingThreadsCount >= MAXIMUM_WAIT_OBJECTS) {
		res = WaitForMultipleObjects(MAXIMUM_WAIT_OBJECTS, &handles[index], TRUE, INFINITE);
		if (res == WAIT_TIMEOUT || res == WAIT_FAILED) {
			printf("\t[x] SyncWaitForMultipleObjs wait Failed.\t");
			return res;
		}

		waitingThreadsCount -= MAXIMUM_WAIT_OBJECTS;
		index += MAXIMUM_WAIT_OBJECTS;
	}

	if (waitingThreadsCount > 0) {
		res = WaitForMultipleObjects(waitingThreadsCount, &handles[index], TRUE, INFINITE);
		if (res == WAIT_TIMEOUT || res == WAIT_FAILED) {
			printf("\t[x] SyncWaitForMultipleObjs wait Failed.\t");
		}
	}

	return res;
}

/*
# HTTP
https://192.168.59.89:9090/             prometheus
https://192.168.59.76/                  freenas
https://192.168.59.89:9443/#!/home      portainer
https://192.168.59.89:8112/             deluge
https://192.168.59.89:3000/             Grafana


#define PORT_HTTP_GRAFANA	3000
#define PORT_HTTP_DELUGE		8112
#define PORT_HTTPS_PORTAINER	9443
#define PORT_HTTP_PROMETHEUS	9090

*/

const int portTcp[] = {
	PORT_FTP,
	PORT_SSH,
	PORT_TELNET,
	PORT_SMTP,
	PORT_DNS,
	PORT_HTTP,
	PORT_KERBEROS,
	PORT_NETBIOS_SSN,
	PORT_LDAP,
	PORT_HTTPS,
	PORT_SMB,
	PORT_MSSQL,
	PORT_ORACLEDB,
	PORT_HTTP_GRAFANA,
	PORT_MYSQL,
	PORT_RDP,
	PORT_POSTGRESQL,
	PORT_WINRM,
	PORT_HTTP_PORTAINER,
	PORT_HTTP_TOMCAT,
	PORT_HTTP_PROXY,
	PORT_HTTP_OTHER,
	PORT_HTTP_DELUGE,
	PORT_HTTPS_PORTAINER,
	PORT_HTTP_PROMETHEUS,
};
/*

#define PORT_UDP_DNS	53
#define PORT_UDP_DHCP	67
#define PORT_UDP_DHCP	68
#define PORT_UDP_NTP	123
#define PORT_UDP_SNMP	161
#define PORT_UDP_SNMP	162

67, 68	Dynamic Host Configuration Protocol (DHCP)
*/
const int portUdp[] = {
	PORT_UDP_NETBIOS,
	PORT_UDP_DHCP,
	PORT_UDP_DHCP2,
	PORT_UDP_NTP,
	PORT_UDP_SNMP,
	PORT_UDP_SNMP2,
};




BOOL initWSA(FILE* pFile) {
	WSADATA wsa;

	//printOut(pFile,"[i] Initialising Winsock...");
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
		printOut(pFile,"[x] Failed. Error Code : %d", WSAGetLastError());
		return FALSE;
	}
	//printOut(pFile,"Initialised.\n");
	return TRUE;
}