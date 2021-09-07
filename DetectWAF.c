#include <Windows.h>
#include <stdio.h>
#include "Tools.h"
#include "ToolsHTTP.h"
#include "GetHTTPserver.h"
#include "GetHTTPSserver.h"

char* userAgentWaf[] = {
	"Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:007012)",
	"Nikto",
	"sqlmap/1.3.11#stable (http://sqlmap.org)",
	"sqlmap",
	"Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
	"Nmap",
	"Python-urllib/2.5",
	"Wget/1.13.4 (linux-gnu)",
	"Wget",

};

BOOL IsHttpWaf(char* ipAddress, int port, FILE* pFile, BOOL isSSL) {
	printf("[*] %s:%i - Detect HTTP%s WAF\n", ipAddress, port, isSSL ? "S" : "");
	char* path = "/";
	char* serverResponce = (char*)malloc(GET_REQUEST_SIZE);

	if (serverResponce == NULL) {
		printf("\t[x] Alloc fail !\n");
		return FALSE;
	}

	// Default test
	if (isSSL) {
		if (!GetHttpsServer(ipAddress, port, "HEAD", path, (char*)userAgentList[rand() % 5], &serverResponce, pFile)) {
			printf("\t[-] Page not available !\n");
			free(serverResponce);
			return FALSE;
		}
	} else {
		if (!GetHttpServer(ipAddress, port, "HEAD", path, NULL, &serverResponce, pFile)) {
			printf("\t[-] Page not available !\n");
			free(serverResponce);
			return FALSE;
		}
	}

	for (int i = 0; i < ARRAY_SIZE_CHAR(userAgentWaf); i++) {
		if (isSSL) {
			if (!GetHttpsServer(ipAddress, port, "HEAD", path, userAgentWaf[i], &serverResponce, pFile)) {
				printf("\t[-] WAF Detected (Blocked user agent: %s) !\n", userAgentWaf[i]);
				free(serverResponce);
				return FALSE;
			}
		} else {
			if (!GetHttpServer(ipAddress, port, "HEAD", path, userAgentWaf[i], &serverResponce, pFile)) {
				printf("\t[-] WAF Detected (Blocked user agent: %s) !\n", userAgentWaf[i]);
				free(serverResponce);
				return FALSE;
			}
		}
		Sleep(10);
	}
	free(serverResponce);
	printf("\t[i] Not WAF detected !\n");
	return TRUE;
}

