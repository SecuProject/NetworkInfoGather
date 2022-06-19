#include <Windows.h>
#include <stdio.h>

#include "ChainListUrlRedir.h"

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

pRedirectionNode InitStructUrlRedirect(char* url) {
    printf("[NODE] INIT - Data: %s\n", url);
    pRedirectionNode headRedirUrl = (pRedirectionNode)malloc(sizeof(redirectionNode));
    if (headRedirUrl == NULL)
        return NULL;
    headRedirUrl->next = NULL;
    char* redirectUrl = AllocUrl(url);
    if (redirectUrl != NULL)
        headRedirUrl->redirectUrl = redirectUrl;
    return headRedirUrl;
}


pRedirectionNode AppendRedirectNode(pRedirectionNode pTailRedirUrl, char* url) {
    printf("[NODE] Append - Data: %s\n", url);
    pRedirectionNode redirUrlNode = (pRedirectionNode)malloc(sizeof(redirectionNode));
    if (redirUrlNode != NULL) {
        pTailRedirUrl->next = redirUrlNode;
        redirUrlNode->next = NULL;
        redirUrlNode->redirectUrl = AllocUrl(url);
        if (redirUrlNode->redirectUrl != NULL)
            return redirUrlNode;
    }
    return NULL;
}
BOOL PrintRedirectionNode(pRedirectionNode headRedirUrl) {
    pRedirectionNode tmpNode = headRedirUrl;
    if (tmpNode == NULL)
        return FALSE;
    printf("[NODE] %s\n", headRedirUrl->redirectUrl);
    while (tmpNode->next != NULL) {
        tmpNode = tmpNode->next;
        printf("[NODE] %s\n", tmpNode->redirectUrl);
    }
    return TRUE;
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