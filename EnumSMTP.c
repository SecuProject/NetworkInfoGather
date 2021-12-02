#include <winsock2.h>
#include <Windows.h>
#include <stdio.h>

#include "NetDiscovery.h"
#include "Network.h"


#define SMTP_ERROR -2

#pragma warning(disable:4996)


const char* smtpUser[] = {
	"adm",
	"admin",
	"apache",
	"at",
	"bb",
	"bin",
	"cron",
	"daemon",
	"db2fenc1",
	"db2inst1",
	"ftp",
	"games",
	"gdm",
	"guest",
	"halt",
	"lp",
	"mail",
	"man",
	"mysql",
	"named",
	"news",
	"nobody",
	"ntp",
	"operator",
	"oracle",
	"oracle8",
	"portage",
	"postfix",
	"postgres",
	"postmaster",
	"public",
	"root",
	"rpc",
	"shutdown",
	"squid",
	"sshd",
	"sync",
	"system",
	"test",
	"toor",
	"user",
	"uucp",
	"websphere",
	"www-data",
};


typedef struct {
	SOCKET SocketFD;
	char* ipAddress;
	int port;
} NETSOCK_DATA;

SMTP_DATA* InitSmtpData() {
	SMTP_DATA* smtpData = (SMTP_DATA*)malloc(sizeof(SMTP_DATA));
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

	for (int i = (int)smtpData->numUser - 1; i > 0; i--)
		free(smtpData->listUser[i]);
	if (smtpData->ntlmData != NULL)
		free(smtpData->ntlmData);
	free(smtpData);
}

BOOL ConnectToSmtp(NETSOCK_DATA* netSockData,FILE* pFile) {
	SOCKET SocketFD;
	SOCKADDR_IN ssin;

	SocketFD = socket(AF_INET, SOCK_STREAM, 0);
	if (SocketFD == INVALID_SOCKET)
		return FALSE;
	

	memset(&ssin, 0, sizeof(ssin));
	ssin.sin_family = AF_INET;
	ssin.sin_addr.s_addr = inet_addr(netSockData->ipAddress);
	ssin.sin_port = htons(netSockData->port);

	if (connect(SocketFD, (LPSOCKADDR)&ssin, sizeof(ssin)) != SOCKET_ERROR) {
		netSockData->SocketFD = SocketFD;
		return TRUE;
	}
	printOut(pFile, "\t[SMTP] Fail to connect to server !\n");
	closesocket(SocketFD);
	return FALSE;
}
int recvSmpt(NETSOCK_DATA* netSockData, char* recvBuffer, int bufferSize, FILE* pFile) {
	int sizeRecv = recv(netSockData->SocketFD, recvBuffer, bufferSize, 0);
	if (sizeRecv == SOCKET_ERROR) {
		printOut(pFile, "\t[SMTP] Fail to recv data !\n");
		return SOCKET_ERROR;
	}
	if (strstr(recvBuffer, "Error: too many errors") != NULL) {
		closesocket(netSockData->SocketFD);
		if (!ConnectToSmtp(netSockData,pFile)) {
			return SOCKET_ERROR;
		}
		sizeRecv = recv(netSockData->SocketFD, recvBuffer, BUFFER_SIZE, 0); // Banner
		return SMTP_ERROR;
	}
	return sizeRecv;
}


BOOL UserEnumRcptFrom(NETSOCK_DATA netSockData, char* recvBuffer, FILE* pFile) {
	const char strMailFrom[] = "\r\nMAIL FROM:test@test.org\r\n";

	send(netSockData.SocketFD, strMailFrom, sizeof(strMailFrom), 0);
	return recvSmpt(&netSockData, recvBuffer, BUFFER_SIZE, pFile) > 0 && (strstr(recvBuffer, "2.1.0 Ok") != NULL);
}

BOOL UserEnumRCPT(NETSOCK_DATA netSockData, SMTP_DATA* smtpData, FILE* pFile) {
	smtpData->listUser = (char**)calloc(sizeof(smtpUser) / sizeof(char*), sizeof(char*));
	if (smtpData->listUser == NULL)
		return FALSE;

	char* recvBuffer = (char*)malloc(BUFFER_SIZE);
	if (recvBuffer != NULL) {
		char* sendBuffer = (char*)malloc(BUFFER_SIZE);
		if (sendBuffer != NULL) {
			if (UserEnumRcptFrom(netSockData, recvBuffer,pFile)) {
				int nbUser = 0;

				for (UINT i = 0; i < sizeof(smtpUser) / sizeof(char*); i++) {
					int sizeSend = sprintf_s(sendBuffer, BUFFER_SIZE, "RCPT TO:%s\r\n", smtpUser[i]);
					send(netSockData.SocketFD, sendBuffer, sizeSend, 0);
					int sizeRecv = recvSmpt(&netSockData, recvBuffer, BUFFER_SIZE,pFile);
					if (sizeRecv > 0) {
						if (strstr(recvBuffer, "250 2.1.5") != NULL) {
							size_t userLen = strlen(smtpUser[i]) + 1;

							smtpData->listUser[nbUser] = (char*)malloc(userLen);
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
				}
				free(sendBuffer);

				smtpData->listUser = (char**)realloc(smtpData->listUser, nbUser * sizeof(char*));
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
	smtpData->listUser = (char**)calloc(sizeof(smtpUser) / sizeof(char*), sizeof(char*));
	if (smtpData->listUser == NULL)
		return FALSE;

	char* recvBuffer = (char*)malloc(BUFFER_SIZE);
	if (recvBuffer != NULL) {
		char* sendBuffer = (char*)malloc(BUFFER_SIZE);
		if (sendBuffer != NULL) {
			int nbUser = 0;


			for (UINT i = 0; i < sizeof(smtpUser) / sizeof(char*); i++) {
				int sizeSend = sprintf_s(sendBuffer, BUFFER_SIZE, "VRFY %s\r\n", smtpUser[i]);
				send(netSockData.SocketFD, sendBuffer, sizeSend, 0);
				int sizeRecv = recvSmpt(&netSockData, recvBuffer, BUFFER_SIZE,pFile);
				if (sizeRecv > 0 && strstr(recvBuffer, "252 2.0.0") != NULL) {
					size_t userLen = strlen(smtpUser[i]) + 1;
					//printf("\t[SMTP] VRFY %s %.*s", smtpUser[i], sizeRecv, recvBuffer);
					smtpData->listUser[nbUser] = (char*)malloc(userLen);
					if (smtpData->listUser[nbUser] == NULL) {
						free(sendBuffer);
						free(recvBuffer);
						return FALSE;
					}
					strcpy_s(smtpData->listUser[nbUser], userLen, smtpUser[i]);
					nbUser++;
				} else if (sizeRecv == SMTP_ERROR)
					i--;	// Retry user after reconnection 

			}
			free(sendBuffer);
			free(recvBuffer);


			smtpData->listUser = (char**)realloc(smtpData->listUser, nbUser * sizeof(char*));
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
	char* recvBuffer = (char*)malloc(BUFFER_SIZE);
	if (recvBuffer == NULL) {
		return FALSE;
	}
	char* sendBuffer = (char*)malloc(BUFFER_SIZE);
	if (sendBuffer == NULL) {
		free(recvBuffer);
		return FALSE;
	}

	int sizeSend = sprintf_s(sendBuffer, BUFFER_SIZE, "AUTH NTLM 334\r\n");
	send(netSockData.SocketFD, sendBuffer, sizeSend, 0);
	free(sendBuffer);


	int sizeRecv = recvSmpt(&netSockData, recvBuffer, BUFFER_SIZE,pFile);
	if (sizeRecv > 0) {
		if (strstr(recvBuffer, "NTLM supported") != NULL) {
			printOut(pFile, "\t[ntlm] AUTH NTLM 334");

			// send anonymous (null) credentials
			const char ntlmAnonymous[] = "TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA=\r\n";

			send(netSockData.SocketFD, ntlmAnonymous, sizeof(ntlmAnonymous), 0);
			sizeRecv = recvSmpt(&netSockData, recvBuffer, BUFFER_SIZE,pFile);
			if (sizeRecv > 0) {
				if (strstr(recvBuffer, "334") != NULL) {
					smtpData->ntlmData = (char*)malloc(sizeRecv + 1);
					if (smtpData->ntlmData != NULL) {
						strncpy_s(smtpData->ntlmData, sizeRecv + 1, recvBuffer, sizeRecv);
						printOut(pFile, "\t[ntlm] %.*s\n", sizeRecv, recvBuffer);
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
	const char strExtendedHello[] = "EHLO localhost\r\n";
	char* recvBuffer = (char*)malloc(BUFFER_SIZE);
	if (recvBuffer != NULL) {
		int sizeRecv;

		send(netSockData.SocketFD, strExtendedHello, sizeof(strExtendedHello), 0);
		sizeRecv = recv(netSockData.SocketFD, recvBuffer, BUFFER_SIZE, 0);
		if (sizeRecv > 0) {
			if (strstr(recvBuffer, "250-VRFY") != NULL) {
				printOut(pFile, "\t[SMTP] VRFY supported\n");
				bResult = UserEnumVRFY(netSockData, smtpData,pFile);
			}
			if (!bResult) {
				if (strstr(recvBuffer, "250-ETRN") != NULL) {  //? OK ??? 
					printOut(pFile, "\t[SMTP] RCPT supported\n");
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
	const char errorMsg[] = "421 Cannot connect to SMTP server";
	
	return strncmp(ConMsg, errorMsg,sizeof(errorMsg)) == 0;
}

BOOL SmtpEnum(NETSOCK_DATA netSockData, SMTP_DATA* smtpData, FILE* pFile) {
	if (ConnectToSmtp(&netSockData,pFile)) {
		int sizeRecv = recv(netSockData.SocketFD, smtpData->banner, BUFFER_SIZE, 0);
		if (sizeRecv > 0 && sizeRecv < BUFFER_SIZE) {
			const char smtpQuit[] = "QUIT\r\n";
			BOOL result = FALSE;

			smtpData->banner[sizeRecv] = 0x00;
			
			if (CheckConnectionMsg(smtpData->banner)) {
				
				printOut(pFile, "\t[SMTP] Banner %s", smtpData->banner);

				if (!SmtpUserEnum(netSockData, smtpData,pFile))
					printOut(pFile, "\t[SMTP] Fail to enumerate users !\n");

				NtlmAuth(netSockData, smtpData,pFile);

				result = TRUE;
			} else {
				printOut(pFile, "\t[SMTP] Connection fail!\n");
				memset(smtpData->banner, 0x00, sizeRecv);
			}
			send(netSockData.SocketFD, smtpQuit, sizeof(smtpQuit), 0);
			
			closesocket(netSockData.SocketFD);
			return result;
		}
		closesocket(netSockData.SocketFD);
	} else
		printOut(pFile, "\t[SMTP] Fail to connect to server !\n");
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

	if (SmtpEnum(netSockData, networkPcInfo->smtpData,pFile)) {
		printOut(pFile, "\t[SMTP] User list:\n");
		for (UINT i = 0; i < networkPcInfo->smtpData->numUser; i++)
			printOut(pFile, "\t\t- %s\n", networkPcInfo->smtpData->listUser[i]);
	}
	
	//FreeSmtpData(smtpData);

	return TRUE;
}
