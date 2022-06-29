#include <winsock2.h>
#include <Windows.h>
#include <stdio.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include "NetDiscovery.h"
#include "Network.h"
#include "wordlist.h"


#define SMTP_ERROR -2

typedef struct {
	SOCKET SocketFD;
	char* ipAddress;
	int port;
} NETSOCK_DATA;

SMTP_DATA* InitSmtpData() {
	SMTP_DATA* smtpData = (SMTP_DATA*)xmalloc(sizeof(SMTP_DATA));
	if (smtpData == NULL)
		return NULL;

	smtpData->numUser = 0;
	smtpData->ntlmData = NULL;
	smtpData->listUser = NULL;
	return smtpData;
}
VOID FreeSmtpData(SMTP_DATA* smtpData) {
	if (smtpData == NULL)
		return;
	if (smtpData->listUser == NULL)
		return;

	for (int i = (int)smtpData->numUser - 1; i > 0; i--)
		free(smtpData->listUser[i]);
	if (smtpData->ntlmData != NULL)
		free(smtpData->ntlmData);
	free(smtpData->listUser);
	free(smtpData);
}

BOOL ConnectToSmtp(NETSOCK_DATA* netSockData,FILE* pFile) {
	SOCKET SocketFD = ConnectTcpServer(netSockData->ipAddress, netSockData->port);
	if (SocketFD == INVALID_SOCKET){
		PrintOut(pFile, "\t[SMTP] Fail to connect to server !\n");
		return FALSE;
	}
	netSockData->SocketFD = SocketFD;
	return TRUE;
}
int recvSmtp(NETSOCK_DATA* netSockData, char* recvBuffer, int bufferSize, FILE* pFile) {
	int sizeRecv = recv(netSockData->SocketFD, recvBuffer, bufferSize, 0);
	if (sizeRecv == SOCKET_ERROR) {
		//PrintOut(pFile, "\t[SMTP] Fail to recv data !\n");
		return SOCKET_ERROR;
	}
	if (strstr(recvBuffer, "Error: too many errors") != NULL) {
		closesocket(netSockData->SocketFD);
		if (!ConnectToSmtp(netSockData,pFile))
			return SOCKET_ERROR;
		sizeRecv = recv(netSockData->SocketFD, recvBuffer, bufferSize, 0);
	}
	return sizeRecv; // OK ??
}
int sendSmtp(SOCKET socket,char* data, int dataLen, FILE* pFile){
	const char endLine[] = "\r\n";
	int sizeRecv = send(socket, data, dataLen, 0);
	if (sizeRecv == SOCKET_ERROR){
		PrintOut(pFile, "\t[SMTP] Fail to send data !\n");
		return SOCKET_ERROR;
	}
	if (send(socket, endLine, sizeof(endLine)-1, 0) == SOCKET_ERROR){
		PrintOut(pFile, "\t[SMTP] Fail to send data !\n");
		return SOCKET_ERROR;
	}
	return sizeRecv;
}


BOOL UserEnumRcptFrom(NETSOCK_DATA netSockData, char* recvBuffer, FILE* pFile) {
	const char strMailFrom[] = "\r\nMAIL FROM:test@test.org";

	sendSmtp(netSockData.SocketFD, (char*)strMailFrom, sizeof(strMailFrom)-1, pFile);
	return recvSmtp(&netSockData, recvBuffer, BUFFER_SIZE, pFile) > 0 && (strstr(recvBuffer, "2.1.0 Ok") != NULL);
}

BOOL UserEnumRCPT(NETSOCK_DATA netSockData, SMTP_DATA* smtpData, FILE* pFile) {
	smtpData->listUser = (char**)xcalloc(sizeof(smtpUser) / sizeof(char*), sizeof(char*));
	if (smtpData->listUser == NULL)
		return FALSE;

	char* recvBuffer = (char*)xmalloc(BUFFER_SIZE);
	if (recvBuffer != NULL) {
		char* sendBuffer = (char*)xmalloc(BUFFER_SIZE);
		if (sendBuffer != NULL) {
			if (UserEnumRcptFrom(netSockData, recvBuffer,pFile)) {
				int nbUser = 0;

				for (UINT i = 0; i < sizeof(smtpUser) / sizeof(char*); i++) {
					int sizeSend = sprintf_s(sendBuffer, BUFFER_SIZE, "RCPT TO:%s", smtpUser[i]);
					sendSmtp(netSockData.SocketFD, sendBuffer, sizeSend, pFile);
					int sizeRecv = recvSmtp(&netSockData, recvBuffer, BUFFER_SIZE,pFile);
					if (sizeRecv > 0) {
						if (strstr(recvBuffer, "250 2.1.5") != NULL) {
							size_t userLen = strlen(smtpUser[i]) + 1;

							smtpData->listUser[nbUser] = (char*)xmalloc(userLen);
							if (smtpData->listUser[nbUser] == NULL) {
								free(sendBuffer);
								free(recvBuffer);
								return FALSE;
							}
							strcpy_s(smtpData->listUser[nbUser], userLen, smtpUser[i]);
							nbUser++;

						}
					} else if (sizeRecv == SMTP_ERROR) {
						i--;
						if (!UserEnumRcptFrom(netSockData, recvBuffer,pFile)) {
							free(sendBuffer);
							free(recvBuffer);
							return FALSE;
						}
					}
					printf("\t\t%u/%u\r", i, ARRAY_SIZE_CHAR(smtpUser));
				}
				free(sendBuffer);

				smtpData->listUser = (char**)xrealloc(smtpData->listUser, nbUser * sizeof(char*));
				if (smtpData->listUser == NULL)
					return FALSE;
				smtpData->numUser = nbUser;
				return TRUE;
			}

			free(sendBuffer);
		}
		free(recvBuffer);
	}
	return FALSE;
}
BOOL UserEnumVRFY(NETSOCK_DATA netSockData, SMTP_DATA* smtpData, FILE* pFile) {
	smtpData->numUser = 0;
	smtpData->listUser = (char**)xcalloc(sizeof(smtpUser) / sizeof(char*), sizeof(char*));
	if (smtpData->listUser == NULL)
		return FALSE;

	char* recvBuffer = (char*)xmalloc(BUFFER_SIZE);
	if (recvBuffer != NULL) {
		char* sendBuffer = (char*)xmalloc(BUFFER_SIZE);
		if (sendBuffer != NULL) {
			int nbUser = 0;


			for (UINT i = 0; i < sizeof(smtpUser) / sizeof(char*); i++) {
				int sizeSend = sprintf_s(sendBuffer, BUFFER_SIZE, "VRFY %s", smtpUser[i]);
				sendSmtp(netSockData.SocketFD, sendBuffer, sizeSend, pFile);
				int sizeRecv = recvSmtp(&netSockData, recvBuffer, BUFFER_SIZE,pFile);
				if (sizeRecv > 0 && strstr(recvBuffer, "252 2.0.0") != NULL) {
					size_t userLen = strlen(smtpUser[i]) + 1;
					//printf("\t[SMTP] VRFY %s %.*s", smtpUser[i], sizeRecv, recvBuffer);
					smtpData->listUser[nbUser] = (char*)xmalloc(userLen);
					if (smtpData->listUser[nbUser] == NULL) {
						free(sendBuffer);
						free(recvBuffer);
						return FALSE;
					}
					strcpy_s(smtpData->listUser[nbUser], userLen, smtpUser[i]);
					nbUser++;
				} else if (sizeRecv == SMTP_ERROR)
					i--;	// Retry user after reconnection

				printf("\t\t%u/%u\r", i, ARRAY_SIZE_CHAR(smtpUser));
			}
			free(sendBuffer);
			free(recvBuffer);


			smtpData->listUser = (char**)xrealloc(smtpData->listUser, nbUser * sizeof(char*));
			if (smtpData->listUser == NULL)
				return FALSE;
			smtpData->numUser = nbUser;
			return TRUE;
		}
		free(recvBuffer);
	}
	FreeSmtpData(smtpData);
	return FALSE;
}
BOOL NtlmAuth(NETSOCK_DATA netSockData, SMTP_DATA* smtpData, FILE* pFile) {
	smtpData->ntlmData = NULL;
	char* recvBuffer = (char*)xmalloc(BUFFER_SIZE);
	if (recvBuffer == NULL) {
		return FALSE;
	}
	char* sendBuffer = (char*)xmalloc(BUFFER_SIZE);
	if (sendBuffer == NULL) {
		free(recvBuffer);
		return FALSE;
	}

	int sizeSend = sprintf_s(sendBuffer, BUFFER_SIZE, "AUTH NTLM 334");
	sendSmtp(netSockData.SocketFD, sendBuffer, sizeSend, pFile);
	free(sendBuffer);


	int sizeRecv = recvSmtp(&netSockData, recvBuffer, BUFFER_SIZE,pFile);
	if (sizeRecv > 0) {
		if (strstr(recvBuffer, "NTLM supported") != NULL) {
			PrintOut(pFile, "\t\t[NTLM] AUTH NTLM 334");

			// send anonymous (null) credentials
			const char ntlmAnonymous[] = "TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA=";

			sendSmtp(netSockData.SocketFD, (char*)ntlmAnonymous, sizeof(ntlmAnonymous)-1, pFile);
			sizeRecv = recvSmtp(&netSockData, recvBuffer, BUFFER_SIZE,pFile);
			if (sizeRecv > 0) {
				if (strstr(recvBuffer, "334") != NULL) {
					smtpData->ntlmData = (char*)xmalloc(sizeRecv + 1);
					if (smtpData->ntlmData != NULL) {
						strncpy_s(smtpData->ntlmData, sizeRecv + 1, recvBuffer, sizeRecv);
						PrintOut(pFile, "\t[NTLM] %.*s\n", sizeRecv, recvBuffer);
						return TRUE;
					}
				}
			}
		}
	}
	free(recvBuffer);
	return FALSE;
}
BOOL SmtpUserEnum(NETSOCK_DATA netSockData, SMTP_DATA* smtpData, FILE* pFile) {
	BOOL bResult = FALSE;

	// Detect if VRFY or RCPT is supported
	const char strExtendedHello[] = "EHLO localhost";
	char* recvBuffer = (char*)xmalloc(BUFFER_SIZE);
	if (recvBuffer != NULL) {
		int sizeRecv;

		sendSmtp(netSockData.SocketFD, (char*)strExtendedHello, sizeof(strExtendedHello) - 1, pFile);
		sizeRecv = recv(netSockData.SocketFD, recvBuffer, BUFFER_SIZE, 0);
		if (sizeRecv > 0) {
			if (strstr(recvBuffer, "250-VRFY") != NULL) {
				PrintOut(pFile, "\t[SMTP] VRFY supported\n");
				bResult = UserEnumVRFY(netSockData, smtpData,pFile);
			}
			if (!bResult) {
				if (strstr(recvBuffer, "250-ETRN") != NULL) {  //? OK ??? 
					PrintOut(pFile, "\t[SMTP] RCPT supported\n");
					bResult = UserEnumRCPT(netSockData, smtpData,pFile);
				}
			}
		}
		free(recvBuffer);
	}
	return bResult;
}

BOOL CheckConnectionMsg(char* ConMsg) {
	// e.g.
	// 421 Cannot connect to SMTP server 192.168.59.2 (192.168.59.2:25), connect error 10061
	// 421 Cannot connect to SMTP server 192.168.59.1 (192.168.59.1:25), connect error 10061
	const char errorMsg[] = "421 Cannot connect to SMTP server";
	return strncmp(ConMsg, errorMsg,sizeof(errorMsg) -1);
}

BOOL SmtpEnum(NETSOCK_DATA netSockData, SMTP_DATA* smtpData, FILE* pFile) {
	if (ConnectToSmtp(&netSockData,pFile)) {
		int sizeRecv = recv(netSockData.SocketFD, smtpData->banner, BUFFER_SIZE, 0);
		if (sizeRecv > 0 && sizeRecv < BUFFER_SIZE) {
			const char smtpQuit[] = "QUIT";
			BOOL result = FALSE;

			smtpData->banner[sizeRecv] = 0x00;
			
			if (CheckConnectionMsg(smtpData->banner)) {
				PrintOut(pFile, "\t[SMTP] Banner %s", smtpData->banner);

				if (!SmtpUserEnum(netSockData, smtpData,pFile))
					PrintOut(pFile, "\t[SMTP] Fail to enumerate users !\n");

				NtlmAuth(netSockData, smtpData,pFile);

				result = TRUE;
			} else {
				PrintOut(pFile, "\t[SMTP] Connection fail !\n");
				memset(smtpData->banner, 0x00, sizeRecv);
			}
			sendSmtp(netSockData.SocketFD, (char*)smtpQuit, sizeof(smtpQuit) - 1, pFile);
			closesocket(netSockData.SocketFD);
			return result;
		}
		closesocket(netSockData.SocketFD);
	} else
		PrintOut(pFile, "\t[SMTP] Fail to connect to server !\n");
	return FALSE;

}

BOOL EnumSMTP(NetworkPcInfo* networkPcInfo, int port, FILE* pFile) {

	NETSOCK_DATA netSockData;
	netSockData.ipAddress = networkPcInfo->ipAddress;
	netSockData.port = port;
	netSockData.SocketFD = SOCKET_ERROR;

	networkPcInfo->smtpData = InitSmtpData();

	if (networkPcInfo->smtpData == NULL)
		return FALSE;

	if (SmtpEnum(netSockData, networkPcInfo->smtpData,pFile) && networkPcInfo->smtpData->numUser > 0) {
		PrintOut(pFile, "\t[SMTP] User list:\n");
		for (UINT i = 0; i < networkPcInfo->smtpData->numUser; i++)
			PrintOut(pFile, "\t\t- %s\n", networkPcInfo->smtpData->listUser[i]);
	}
	
	//FreeSmtpData(smtpData);

	return TRUE;
}
