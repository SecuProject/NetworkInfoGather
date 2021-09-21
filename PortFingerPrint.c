#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <time.h>

#include "Network.h"
#include "EnumFTP.h"
#include "EnumHTTP.h"
#include "EnumSMB.h"
#include "EnumNetBios.h"
#include "ToolsHTTP.h"
#include "DetectWAF.h"
#include "EnumSMTP.h"

#pragma warning(disable:4996)

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
	SOCKET SocketFD;

	if ((SocketFD = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		return FALSE;
	SOCKADDR_IN ssin;
	memset(&ssin, 0, sizeof(ssin));
	ssin.sin_family = AF_INET;
	ssin.sin_addr.s_addr = inet_addr(ipAddress);
	ssin.sin_port = htons(port);
	if (connect(SocketFD, (LPSOCKADDR)&ssin, sizeof(ssin)) != SOCKET_ERROR) {
		int sizeRecv = recv(SocketFD, buffer, bufferSize, 0);
		if (sizeRecv > 0) {
			printOut(pFile,"\t[%s] Banner %.*s", protocalName,sizeRecv, buffer + offset); // Add sizeRecv to be tested !!!
			AddEndLine(buffer + offset, sizeRecv);
			closesocket(SocketFD);
			return TRUE;
		}
	}
	closesocket(SocketFD);
	return FALSE;
}

BOOL PortFingerPrint(NetworkPcInfo* networkPcInfo, int nbDetected, BOOL isBruteforce, FILE* pFile) {
	BOOL isWAfDetection = FALSE;
	
	for (int i = 0; i < nbDetected; i++) {
		char* ipAddress = networkPcInfo[i].ipAddress;
		int nbFPInfo = networkPcInfo[i].nbOpenPort;

		if(nbFPInfo > 0)
			printOut(pFile,"[%s] FingerPrint\n", ipAddress);
		for (int j = 0; j < nbFPInfo; j++) {
			int portNb = networkPcInfo[i].port[j].portNumber;
			switch (portNb) {
			case PORT_NETBIOS_SSN:
				EnumNetBios(&(networkPcInfo[i]));
				// update mac if not 00-00-00-00-00-00
				break;
			case PORT_SSH:
				GrabBanner("SSH",ipAddress, portNb, networkPcInfo[i].port[j].banner, BANNER_BUFFER_SIZE, NO_OFFSET,pFile);
				break;
			case PORT_FTP:
				GrabBanner("FTP", ipAddress, portNb, networkPcInfo[i].port[j].banner, BANNER_BUFFER_SIZE, NO_OFFSET,pFile);
				FtpEnum(ipAddress, isBruteforce, pFile);
				break;
			case PORT_MYSQL:
				GrabBanner("MYSQL", ipAddress, portNb, networkPcInfo[i].port[j].banner, BANNER_BUFFER_SIZE, MYSQL_OFFSET,pFile);
				break;
			case PORT_HTTP:
			case PORT_HTTP_TOMCAT:
			case PORT_HTTP_PROXY:
			case PORT_HTTP_OTHER:
				if (GetHttpServerInfo(ipAddress, portNb, pFile, FALSE)) {
					if (isWAfDetection)
						IsHttpWaf(ipAddress, portNb, pFile, FALSE);
				}
				HttpDirEnum(ipAddress, portNb, pFile, FALSE);
				break;
			case PORT_HTTPS:
				if (GetHttpServerInfo(ipAddress, portNb, pFile, TRUE)) {
					if (isWAfDetection)
						IsHttpWaf(ipAddress, portNb, pFile, TRUE);
				}
				HttpDirEnum(ipAddress, portNb, pFile, TRUE);
				break;
			case PORT_SMB:
				SmbEnum(ipAddress, isBruteforce,pFile);
				break;
			
			case PORT_SMTP:
				EnumSMTP(&(networkPcInfo[i]), PORT_SMTP, pFile);
				break;

			default:
				break;
			}
		}
	}
	return FALSE;
}