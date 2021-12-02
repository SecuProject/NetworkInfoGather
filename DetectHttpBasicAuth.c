#include <stdio.h>
#include <Windows.h>

#include "Base64.h"
#include "GetHTTPSserver.h"
#include "GetHTTPserver.h"
#include "ToolsHTTP.h"
#include "Network.h"
#include "wordlist.h"


typedef enum {
	INVALIDE	= -1,
	BASIC		=  0,
	BEARER,
	DIGEST,
	MUTUAL,
	NEGOTIATE,
	OAUTH,
	AWS4
}AuthScheme;

BOOL GetAuthRealm(char* authData) {
	const char delim1[] = "realm=\"";
	const char delim2[] = "\"";

	char* ptr1 = strstr(authData, delim1);
	if (ptr1 != NULL) {
		char* ptr2;

		ptr1 = ptr1 + sizeof(delim1) - 1;
		ptr2 = strstr(ptr1, delim2);
		if (ptr2 != NULL && ptr2 - ptr1 > 0) {
			printf("\t\t[Realm] %.*s\n", (UINT)(ptr2 - ptr1), ptr1);
			return TRUE;
		}
	}
	return FALSE;
}
AuthScheme GetAuthScheme(char* authData) {
	const char* authSchemeTab[] = {
		"basic",
		"bearer",
		"digest",
		"mutual",
		"negotiate",
		"oauth",
		"aws4-", // AWS4-HMAC-SHA256 ?
	};
	UINT i;

	for (i = 0; i < ARRAY_SIZE_CHAR(authSchemeTab) && strncmp(authSchemeTab[i], authData, strlen(authSchemeTab[i])) != 0; i++);

	if (i < ARRAY_SIZE_CHAR(authSchemeTab) && strncmp(authSchemeTab[i], authData, strlen(authSchemeTab[i])) == 0) {
		GetAuthRealm(authData);
		return i;
	}

	return INVALIDE;
}
AuthScheme GetAuthHeader(char* serverResponce, UINT responceSize, char** ppAuthHerder) {
	const char delim1[] = "www-authenticate: ";
	const char delim2[] = "\r\n";
	char* ptr1;

	if (serverResponce == NULL)
		return INVALIDE;

	StrToLower(serverResponce);
	ptr1 = strstr(serverResponce, delim1);
	if (ptr1 != NULL) {
		char* ptr2;

		ptr1 = ptr1 + sizeof(delim1) - 1;
		ptr2 = strstr(ptr1, delim2);
		if (ptr2 != NULL && (UINT)(ptr2 - ptr1) < responceSize && ptr2 - ptr1 > 0) {
			AuthScheme authScheme;

			char* buffer = (char*)malloc(responceSize + 1);
			if (buffer == NULL)
				return INVALIDE;

			strncpy_s(buffer, responceSize + 1, ptr1, ptr2 - ptr1);
			authScheme = GetAuthScheme(buffer);

			*ppAuthHerder = buffer;
			return authScheme;
		}
	}
	return INVALIDE;
}



BOOL BruteforceBasic(char* ipAddress, int port, BOOL isSsl, BOOL isProxy, const char** usernameTab, UINT usernameTabSize, const char** passwordTab, UINT passwordTabSize,char** httpAuthHead) {
	char* bufCread;
	char* bufEncode64;
	char* bufAuthHead;
	UINT returnCode = STATUS_CODE_UNAUTHORIZED;

	char* pAuthData;
	size_t authDataSize;

	if (isProxy)
		pAuthData = "Proxy-Authorization: Basic %s\r\n";
	else
		pAuthData = "Authorization: Basic %s\r\n";
	authDataSize = strlen(pAuthData);


	bufCread = (char*)malloc(BUFFER_SIZE + 1);
	if (bufCread == NULL)
		return FALSE;
	bufEncode64 = (char*)malloc(BUFFER_SIZE * 3 + 1);
	if (bufEncode64 == NULL) {
		free(bufCread);
		return FALSE;
	}
	UINT i;
	UINT j;
	for (i = 0; i < usernameTabSize && !IS_HTTP_SUCCESSFUL(returnCode); i++) {
		for (j = 0; j < passwordTabSize && !IS_HTTP_SUCCESSFUL(returnCode); j++) {
			sprintf_s(bufCread, BUFFER_SIZE + 1, "%s:%s", usernameTab[i], passwordTab[j]);
			int bufferEncode64Size = Base64Encode(bufCread, bufEncode64);
			bufAuthHead = (char*)malloc(bufferEncode64Size + authDataSize + 1);
			if (bufAuthHead == NULL) {
				free(bufCread);
				free(bufEncode64);
				return FALSE;
			}
			sprintf_s(bufAuthHead, bufferEncode64Size + authDataSize + 1, pAuthData, bufEncode64);
			UINT responceSize;
			char* serverResponce = NULL;
			if (isSsl)
				responceSize = GetHttpsServer(ipAddress, port, "HEAD", "/", NULL, &serverResponce, bufAuthHead,FALSE, NULL);
			else
				responceSize = GetHttpServer(ipAddress, port, "HEAD", "/", NULL, &serverResponce, bufAuthHead, NULL);

			if (responceSize > 0) {
				returnCode = GetHttpReturnCode(serverResponce, responceSize);
				//printf("[d] Responce code: %i - %s:%s\n", returnCode, usernameTab[i], passwordTab[j]);

				if (IS_HTTP_SUCCESSFUL(returnCode)) {
					size_t httpAuthHeadSize = strlen(bufAuthHead) +1;
					printf("\t\t[Credential] %s:%s\n", usernameTab[i], passwordTab[j]);

					*httpAuthHead = (char*)malloc(httpAuthHeadSize);
					if (*httpAuthHead == NULL) {
						free(bufAuthHead);
						free(bufEncode64);
						free(bufCread);
						return FALSE;
					}
					strcpy_s(*httpAuthHead, httpAuthHeadSize, bufAuthHead);

				} else if (IS_HTTP_ERROR_SERVER(returnCode)) {
					printf("\t[d] Critical fail return status code: %u\n", returnCode);
					free(bufAuthHead);
					free(bufEncode64);
					free(bufCread);
					return FALSE;
				}
			} else {
				printf("\t[HTTP%s] BruteforceBasic - Return 0\n", isSsl ? "S" : "");
			}
			free(bufAuthHead);
		}
	}
	free(bufEncode64);
	free(bufCread);
	return IS_HTTP_SUCCESSFUL(returnCode);
}

VOID GetStatusCodeAuth(UINT responceCode) {
	switch (responceCode) {
	case STATUS_CODE_UNAUTHORIZED:
		printf(" - Unauthorized");
		break;
	case STATUS_CODE_FORBIDDEN:
		printf(" - Forbidden");
		break;
	case STATUS_CODE_PROXY_AUTH_REQ:
		printf(" - Proxy Authentication Required");
		break;
	default:
		break;
	}
	printf(" (%u).\n", responceCode);
}


BOOL HttpBasicAuth(char* ipAddress, int port, PHTTP_STRUC pHttpStructPage, BOOL isBruteForce, BOOL isSsl) {
	char* HeaderAuth = NULL;
	char* httpAuthHead = NULL;
	AuthScheme authScheme = GetAuthHeader(pHttpStructPage->rawData, pHttpStructPage->responseLen, &HeaderAuth);

	if (authScheme == INVALIDE) {
		//printf("\t[HTTP%s] Header not found !\n", isSsl ? "S" : "");
		return FALSE;
	}

	printf("\t\t[Auth Basic] Authorization ");
	switch (authScheme) {
	case BASIC:
		printf("Basic");
		GetStatusCodeAuth(pHttpStructPage->returnCode);
		if (isBruteForce)
			if (BruteforceBasic(ipAddress, port, isSsl, IS_HTTP_PROXY_AUTH(pHttpStructPage->returnCode), usernameList, ARRAY_SIZE_CHAR(usernameList), passwordList, ARRAY_SIZE_CHAR(passwordList), &httpAuthHead))
				pHttpStructPage->AuthHeader = httpAuthHead;
		break;
	case BEARER:
		printf("Bearer");
		GetStatusCodeAuth(pHttpStructPage->returnCode);
		break;
	case DIGEST:
		printf("Digest");
		GetStatusCodeAuth(pHttpStructPage->returnCode);
		break;
	case MUTUAL:
		printf("Mutual");
		GetStatusCodeAuth(pHttpStructPage->returnCode);
		break;
	case NEGOTIATE:
		printf("Negotiate");
		GetStatusCodeAuth(pHttpStructPage->returnCode);
		break;
	case OAUTH:
		printf("OAuth");
		GetStatusCodeAuth(pHttpStructPage->returnCode);
		break;
	case AWS4:
		printf("AWS4");
		GetStatusCodeAuth(pHttpStructPage->returnCode);
		break;
	default:
		printf("ERROR");
		GetStatusCodeAuth(pHttpStructPage->returnCode);
		break;
	}

	free(HeaderAuth);
	return TRUE;
}