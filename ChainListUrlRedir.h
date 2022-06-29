#pragma once

#ifndef CHAIN_LIST_URL_REDIR_HEADER_H
#define CHAIN_LIST_URL_REDIR_HEADER_H

typedef struct redirectionNode {
    char* redirectUrl;
    char* baseUrl;
    struct redirectionNode* next;
} redirectionNode, * pRedirectionNode;

char* AllocUrl(char* url);
pRedirectionNode InitStructUrlRedirect(char* url, char* baseUrl);
pRedirectionNode AppendRedirectNode(pRedirectionNode pTailRedirUrl, char* url, char* baseUrl);
//BOOL PrintRedirectionNode(pRedirectionNode headRedirUrl);

BOOL ClearRedirectionNode(pRedirectionNode headRedirUrl);

#endif