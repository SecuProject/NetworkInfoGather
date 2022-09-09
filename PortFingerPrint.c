#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <time.h>
#include <ws2tcpip.h>   // inet_pton
#include <iphlpapi.h>   // IPAddr


#include "Network.h"
#include "EnumFTP.h"
#include "EnumHTTP.h"
#include "EnumSMB.h"
#include "CheckSMBv1.h"
#include "EnumNetBios.h"
#include "EnumSMTP.h"
#include "EnumLDAP.h"
#include "EnumRPC.h"
#include "EnumDNS.h"
#include "XorRoutine.h"

#include "GetMacVendor.h"

//Temp
#include "wordlist.h"


#define NO_OFFSET			0
#define MYSQL_OFFSET		5


VOID AddEndLine(char* banner,int bannerSize) {
	int tmpBufferSize = bannerSize + 1;
	char* tmpBuffer = (char*)malloc(tmpBufferSize);

	if (tmpBuffer != NULL) {
		strncpy_s(tmpBuffer, tmpBufferSize, banner, bannerSize);
		char* ptr = strstr(tmpBuffer, "\n");
		if (ptr == NULL)
			printf("\n");
		free(tmpBuffer);
	}
	return;
}

BOOL GrabBanner(char* protocalName, char* ipAddress, unsigned int port, char* buffer, int bufferSize, int offset, FILE* pFile) {
	SOCKET SocketFD = ConnectTcpServer(ipAddress, port);

	if (SocketFD != INVALID_SOCKET){
		int sizeRecv = recv(SocketFD, buffer, bufferSize, 0);
		if (sizeRecv > 0){
			PrintOut(pFile, "\t[%s] Banner %.*s", protocalName, sizeRecv, buffer + offset); // Add sizeRecv to be tested !!!
			AddEndLine(buffer + offset, sizeRecv);
			closesocket(SocketFD);
			return TRUE;
		}
		closesocket(SocketFD);
	}
	return FALSE;
}
BOOL IsHttpPort(char* ipAddress, int portNb) {
	SOCKET sockfd;

	sockfd = ConnectTcpServer(ipAddress, portNb);
	if (sockfd != INVALID_SOCKET) {
		char fullPayload[200];
		char header[] = {
			"GET / HTTP/1.1\r\n"
			// "User-Agent: %s\r\n"            // USER AGENT
			"Host: %s\r\n"
			"Connection: close\r\n\r\n"
		};
		sprintf_s(fullPayload, 100, header, ipAddress);
		send(sockfd, fullPayload, sizeof(fullPayload), 0);

		char buf[1024];
		char pattern[] = "HTTP/1."; // HTTP/0.9  or HTTP/1.0  or HTTP/1.1 
		// char pattern[] = "HTTP/"; // HTTP/0.9  or HTTP/1.0  or HTTP/1.1 
		int byte_count = recv(sockfd, buf, sizeof(buf), 0);

		if (byte_count > sizeof(pattern) - 1) {
			if (strncmp(pattern, buf, sizeof(pattern) - 1) == 0) {
				return TRUE;
			}
		}
	}
	return FALSE;
}



BOOL PortFingerPrint(NetworkPcInfo* networkPcInfo, int nbDetected, BOOL isBruteforce, FILE* pFile) {
	BOOL isWAfDetection = FALSE;

	StructWordList structWordList;
	structWordList.isBruteForce = isBruteforce;

	structWordList.usernameTab = (char**)usernameList;
	structWordList.nbUsername = sizeof(usernameList) / sizeof(char*);

	structWordList.passwordTab = (char**)passwordList;
	structWordList.nbPassword = sizeof(passwordList) / sizeof(char*);


	XorRoutine(SmbNegociateSMB1Xor, sizeof(SmbNegociateSMB1Xor), "1337");

	for (int i = 0; i < nbDetected; i++) {
		char* ipAddress = networkPcInfo[i].ipAddress;
		int nbFPInfo = networkPcInfo[i].nbOpenPort;

		if(nbFPInfo > 0)
			PrintOut(pFile,"[%s] FingerPrint\n", ipAddress);
		for (int j = 0; j < nbFPInfo; j++) {
			int portNb = networkPcInfo[i].port[j].portNumber;
			if(networkPcInfo[i].port[j].isTcp){
				// TCP

				if (IsHttpPort(ipAddress, portNb)) {
					EnumHTTP(ipAddress, portNb, isWAfDetection, pFile, FALSE, isBruteforce);
				} else {
					switch (portNb) {
					case PORT_FTP:
					case PORT_FTP_ALT:
						GrabBanner("FTP", ipAddress, portNb, networkPcInfo[i].port[j].banner, BANNER_BUFFER_SIZE, NO_OFFSET, pFile);
						FtpEnum(ipAddress, isBruteforce, pFile);
						// version 2.3.4 -> Backdoor
						break;
					case PORT_SSH:
					case PORT_SSH_ALT:
						GrabBanner("SSH", ipAddress, portNb, networkPcInfo[i].port[j].banner, BANNER_BUFFER_SIZE, NO_OFFSET, pFile);
						break;
					case PORT_TELNET:
						//TODO
						break;
					case PORT_SMTP:
						EnumSMTP(&(networkPcInfo[i]), PORT_SMTP, pFile);
						break;
					case PORT_DNS:
						EnumDnsServer(ipAddress, PORT_DNS, pFile);
						break;
					case PORT_DNS_ALT:
						EnumDnsServer(ipAddress, PORT_DNS_ALT, pFile);
						break;
					/*case PORT_HTTP:
					case PORT_HTTP_GRAFANA:
					case PORT_HTTP_TOMCAT:
					case PORT_HTTP_PROXY:
					case PORT_HTTP_OTHER:
					case PORT_HTTP_DELUGE:
					case PORT_HTTP_PORTAINER:
					case PORT_HTTP_PROMETHEUS:
						EnumHTTP(ipAddress, portNb, isWAfDetection, pFile, FALSE, isBruteforce);
						break;*/
					case PORT_HTTPS:
					case PORT_HTTPS_PORTAINER:
						EnumHTTP(ipAddress, portNb, isWAfDetection, pFile, TRUE, isBruteforce);
						break;
					case PORT_RPC:
						if (networkPcInfo[i].isNetbiosInfo)
							EnumRPC(ipAddress, networkPcInfo[i].NetbiosInfo->netBIOSRemoteMachineNameTab[0].Name, "", structWordList);
						else
							EnumRPC(ipAddress, networkPcInfo[i].hostname, "", structWordList);
						break;
					case PORT_NETBIOS_SSN:
						if (EnumNetBios(&(networkPcInfo[i])))
							GetNetBiosMacVendor(&(networkPcInfo[i]));
						break;
					case PORT_LDAP:
						EnumLDAP(ipAddress, portNb, structWordList, pFile);// TODO
						break;
					case PORT_SMB:
						SmbEnum(ipAddress, isBruteforce, pFile);
						break;
					case PORT_MSSQL:
						// TODO
						break;
					case PORT_ORACLEDB:
						// TODO
						break;
					case PORT_MYSQL:
						GrabBanner("MYSQL", ipAddress, portNb, networkPcInfo[i].port[j].banner, BANNER_BUFFER_SIZE, MYSQL_OFFSET, pFile);
						break;
					case PORT_RDP:
						// TODO
						break;
					case PORT_POSTGRESQL:
						// TODO
						break;

					default:
						break;
					}
				}
			}else{
				// Port UDP
				switch (portNb) {
				default:
					break;
				}
			}
		}
	}
	return FALSE;
}