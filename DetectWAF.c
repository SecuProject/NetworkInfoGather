
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

BOOL TestUserAgent(RequestInfoStruct requestInfoStruct, FILE* pFile) {
	char* path = "/";
	char* serverResponce = (char*)xmalloc(GET_REQUEST_SIZE);
	if (serverResponce == NULL) {
		return FALSE;
	}

	// Default test
	if (requestInfoStruct.isSSL) {
		if (!GetHttpsServer(requestInfoStruct.ipAddress, requestInfoStruct.port, "HEAD", path, (char*)userAgentList[rand() % 5], &serverResponce, requestInfoStruct.httpAuthHeader,FALSE, pFile)) {
			PrintOut(pFile, "\t\t[-] Page not available !\n");
			free(serverResponce);
			return FALSE;
		}
	} else {
		if (!GetHttpServer(requestInfoStruct.ipAddress, requestInfoStruct.port, "HEAD", path, NULL, &serverResponce, requestInfoStruct.httpAuthHeader, pFile)) {
			PrintOut(pFile, "\t\t[-] Page not available !\n");
			free(serverResponce);
			return FALSE;
		}
	}

	for (int i = 0; i < ARRAY_SIZE_CHAR(userAgentWaf); i++) {
		if (requestInfoStruct.isSSL) {
			if (!GetHttpsServer(requestInfoStruct.ipAddress, requestInfoStruct.port, "HEAD", path, userAgentWaf[i], &serverResponce, NULL, FALSE, pFile)) {
				PrintOut(pFile, "\t\t[-] WAF Detected (Blocked user agent: %s) !\n", userAgentWaf[i]);
				free(serverResponce);
				return FALSE;
			}
		} else {
			if (!GetHttpServer(requestInfoStruct.ipAddress, requestInfoStruct.port, "HEAD", path, userAgentWaf[i], &serverResponce, NULL, pFile)) {
				PrintOut(pFile, "\t\t[-] WAF Detected (Blocked user agent: %s) !\n", userAgentWaf[i]);
				free(serverResponce);
				return FALSE;
			}
		}
		Sleep(100);
	}
	free(serverResponce);
	return TRUE;
}
BOOL TestAttacks(RequestInfoStruct requestInfoStruct, FILE* pFile) {
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


BOOL IsHttpWaf(RequestInfoStruct requestInfoStruct, FILE* pFile) {
	PrintOut(pFile, "[*] %s:%i - Detect HTTP%s WAF\n", requestInfoStruct.ipAddress, requestInfoStruct.port, requestInfoStruct.isSSL ? "S" : "");
	if (TestUserAgent(requestInfoStruct, pFile))
		return FALSE;
	if (TestAttacks(requestInfoStruct, pFile))
		return FALSE;
	PrintOut(pFile,"\t[i] Not WAF detected !\n");
	return TRUE;
}

