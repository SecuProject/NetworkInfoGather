#include <Windows.h>
#include <stdio.h>

#include "ChainListUrlRedir.h"
#include "MgArguments.h"

//////////////// PRINT ////////////////
//
BOOL IsProtocolInUrl(char* url) {
    return (MATCHN(url, "https://", 8) || MATCHN(url, "http://", 7));
}
BOOL FormatUrlTrav(char* urlRedirect) {
    return (MATCHN(urlRedirect, "../", 3));
}
/*VOID PrintRedirectionNode(pRedirectionNode headRedirUrl) {
    if (IsProtocolInUrl(headRedirUrl->redirectUrl)) {
        printf("[NODE] %s\n", headRedirUrl->redirectUrl);
    } else {
        if (FormatUrlTrav(headRedirUrl->redirectUrl))
            printf("[NODE] %s/%s\n", headRedirUrl->baseUrl, headRedirUrl->redirectUrl);
        else
            printf("[NODE] %s%s\n", headRedirUrl->baseUrl, headRedirUrl->redirectUrl);
    }
}*/
//
//////////////// PRINT ////////////////


char* AllocUrl(char* url) {
    size_t strLen = strlen(url) + (size_t)1;
    if (strLen > 0) {
        char* strBuffer = (char*)malloc(strLen);
        if (strBuffer != NULL) {
            strcpy_s(strBuffer, strLen, url);
            return strBuffer;
        }
    }
    return NULL;
}

pRedirectionNode InitStructUrlRedirect(char* url,char* baseUrl) {
    printf("[NODE] INIT - Data: %s\n", url);
    pRedirectionNode headRedirUrl = (pRedirectionNode)malloc(sizeof(redirectionNode));
    if (headRedirUrl == NULL)
        return NULL;
    headRedirUrl->next = NULL;
    char* redirectUrl = AllocUrl(url);
    if (redirectUrl != NULL)
        headRedirUrl->redirectUrl = redirectUrl;
    char* pBaseUrl = AllocUrl(baseUrl);
    if (pBaseUrl != NULL)
        headRedirUrl->baseUrl = pBaseUrl;
    return headRedirUrl;
}


pRedirectionNode AppendRedirectNode(pRedirectionNode pTailRedirUrl, char* url, char* baseUrl) {
    printf("[NODE] Append - Data: %s\n", url);
    pRedirectionNode redirUrlNode = (pRedirectionNode)malloc(sizeof(redirectionNode));
    if (redirUrlNode != NULL) {
        pTailRedirUrl->next = redirUrlNode;
        redirUrlNode->next = NULL;
        redirUrlNode->redirectUrl = AllocUrl(url);
        if (redirUrlNode->redirectUrl != NULL) {
            char* pBaseUrl = AllocUrl(baseUrl);
            if (pBaseUrl != NULL) {
                redirUrlNode->baseUrl = pBaseUrl;
                return redirUrlNode;
            }
        }
    }
    return NULL;
}
BOOL ClearRedirectionNode(pRedirectionNode headRedirUrl) {
    pRedirectionNode tmpNode;
    if (headRedirUrl == NULL)
        return FALSE;
    tmpNode = headRedirUrl->next;

    free(headRedirUrl->redirectUrl);
    free(headRedirUrl);

    while (tmpNode->next != NULL) {
        headRedirUrl = tmpNode;
        tmpNode = headRedirUrl->next;

        free(headRedirUrl->redirectUrl);
        free(headRedirUrl);
    }
    return TRUE;
}