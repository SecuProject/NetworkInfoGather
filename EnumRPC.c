
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

#include <stdio.h>
#include <windows.h>
#include <ntdsapi.h>

#include "Network.h"
#include "MgArguments.h"
#include "PrintNightmare.h"
#include "MgCredentials.h"

#pragma comment(lib, "Ntdsapi.lib")


VOID RpcErrorMessage(DWORD errorCode) {
	printf("\t\t[x] Error");

	// https://www.seattlepro.com/rpc-error-codes/
	switch (errorCode) {
	case ERROR_ACCESS_DENIED:
		printf(": Access denied");
		break;
	case RPC_S_SERVER_UNAVAILABLE:
		printf(": RPC_S_SERVER_UNAVAILABLE");
		break;
	case ERROR_NO_SUCH_DOMAIN:
		printf(": ERROR_NO_SUCH_DOMAIN");
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
				printf("\t\t[RPC] Connected to %s\n", DomainControllerName);
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
BOOL __RpcAuthBruteForce(char* DomainControllerName, char* domain, StructWordList structWordList, PStructCredentials structCredentials) {
	HANDLE phDS;

	for (UINT i = 0; i < structWordList.nbUsername; i++) {
		for (UINT j = 0; j < structWordList.nbPassword; j++) {
			if (RpcAuthBind(DomainControllerName, DomainControllerName, structWordList.usernameTab[i], domain, structWordList.passwordTab[j], FALSE, &phDS)) {
				printf("\t\t[+] Login: '%s:%s' !\n", structWordList.usernameTab[i], structWordList.passwordTab[j]);


				structCredentials = InitCredStruct(structWordList.usernameTab[i], structWordList.passwordTab[j], NULL);
				if (structCredentials != NULL){
					DsUnBindA(phDS);
					return TRUE;
				}
				DsUnBindA(phDS);
			}
			PrintOut(NULL, "\t\t[i] %i/%i\r", i * structWordList.nbPassword + j + 1,structWordList.nbPassword * structWordList.nbUsername);
				
		}
	}
	printf("\t\t[x] Fail to brute force RPC !\n");
	return FALSE;
}


BOOL GetDomainControllerInfo(HANDLE phDS,char* domainName) {
	DS_DOMAIN_CONTROLLER_INFO_1A* pInfo;
	DWORD pcOut;
	DWORD ret = DsGetDomainControllerInfoA(phDS, domainName, 1, &pcOut, &pInfo);
	if (ret == ERROR_SUCCESS) {
		printf("\t[RCP] Domain Controller Info:\n");
		printf("\t\t[RCP] NetbiosName: %s\n", pInfo->NetbiosName);
		printf("\t\t[RCP] ComputerObjectName: %s\n", pInfo->ComputerObjectName);
		printf("\t\t[RCP] SiteName: %s\n", pInfo->SiteName);
		printf("\t\t[RCP] ServerObjectName: %s\n", pInfo->ServerObjectName);
		printf("\t\t[RCP] DnsHostName: %s\n", pInfo->DnsHostName);
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
int EnumRPC(char* ipAddress, char* NameDC,char* domainName, StructWordList structWordList) {

	HANDLE phDS;

	CheckPrintNightmare(ipAddress,TRUE);

	if (domainName != NULL && domainName[0] != 0x00){

		printf("\t[RPC] Enumeration:\n");
		if (RpcBind(NameDC, NameDC, &phDS)){
			GetDomainControllerInfo(phDS, domainName);
			DsUnBindA(phDS);
		} else{
			if (structWordList.isBruteForce){
				StructCredentials structCredentials;
				if (__RpcAuthBruteForce(NameDC, domainName, structWordList, &structCredentials)){
					if (RpcAuthBind(NameDC, NameDC, structCredentials.username, domainName, structCredentials.password, TRUE, &phDS)){
						GetDomainControllerInfo(phDS, domainName);
						DsUnBindA(phDS);
					}

				}
			}
		}
	}
	return FALSE;
}
