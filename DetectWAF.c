#include <Windows.h>
#include <stdio.h>
#include "ToolsHTTP.h"
#include "GetHTTPserver.h"
#include "GetHTTPSserver.h"
#include "Network.h"

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

BOOL TestUserAgent(char* ipAddress, int port, FILE* pFile, BOOL isSSL) {
	char* path = "/";
	char* serverResponce = (char*)malloc(GET_REQUEST_SIZE);

	if (serverResponce == NULL) {
		printOut(pFile, "\t[x] Alloc fail !\n");
		return FALSE;
	}

	// Default test
	if (isSSL) {
		if (!GetHttpsServer(ipAddress, port, "HEAD", path, (char*)userAgentList[rand() % 5], &serverResponce, pFile)) {
			printOut(pFile, "\t\t[-] Page not available !\n");
			free(serverResponce);
			return FALSE;
		}
	} else {
		if (!GetHttpServer(ipAddress, port, "HEAD", path, NULL, &serverResponce, pFile)) {
			printOut(pFile, "\t\t[-] Page not available !\n");
			free(serverResponce);
			return FALSE;
		}
	}

	for (int i = 0; i < ARRAY_SIZE_CHAR(userAgentWaf); i++) {
		if (isSSL) {
			if (!GetHttpsServer(ipAddress, port, "HEAD", path, userAgentWaf[i], &serverResponce, pFile)) {
				printOut(pFile, "\t\t[-] WAF Detected (Blocked user agent: %s) !\n", userAgentWaf[i]);
				free(serverResponce);
				return FALSE;
			}
		} else {
			if (!GetHttpServer(ipAddress, port, "HEAD", path, userAgentWaf[i], &serverResponce, pFile)) {
				printOut(pFile, "\t\t[-] WAF Detected (Blocked user agent: %s) !\n", userAgentWaf[i]);
				free(serverResponce);
				return FALSE;
			}
		}
		Sleep(100);
	}
	free(serverResponce);
	return TRUE;
}
BOOL TestAttacks(char* ipAddress, int port, FILE* pFile, BOOL isSSL) {
	/*
	* 
	* Source: https://github.com/EnableSecurity/wafw00f/blob/master/wafw00f/main.py
	* 
	xsstring = '<script>alert("XSS");</script>'
	sqlistring = "UNION SELECT ALL FROM information_schema AND ' or SLEEP(5) or '"
	lfistring = '../../../../etc/passwd'
	rcestring = '/bin/cat /etc/passwd; ping 127.0.0.1; curl google.com'
	xxestring = '<!ENTITY xxe SYSTEM "file:///etc/shadow">]><pwn>&hack;</pwn>'
	*/
	//const char* payload[] = "";

	return TRUE;
}


BOOL IsHttpWaf(char* ipAddress, int port, FILE* pFile, BOOL isSSL) {
	printOut(pFile, "[*] %s:%i - Detect HTTP%s WAF\n", ipAddress, port, isSSL ? "S" : "");
	if (TestUserAgent( ipAddress, port, pFile, isSSL))
		return FALSE;
	if (TestAttacks(ipAddress, port, pFile, isSSL))
		return FALSE;
	printOut(pFile,"\t[i] Not WAF detected !\n");
	return TRUE;
}

