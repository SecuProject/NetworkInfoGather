#pragma once

#ifndef CHAIN_LIST_URL_REDIR_HEADER_H
#define CHAIN_LIST_URL_REDIR_HEADER_H

typedef struct redirectionNode {
    char* redirectUrl;
    struct redirectionNode* next;
} redirectionNode, * pRedirectionNode;

char* AllocUrl(char* url);
pRedirectionNode InitStructUrlRedirect(char* url);
pRedirectionNode AppendRedirectNode(pRedirectionNode pTailRedirUrl, char* url);
BOOL PrintRedirectionNode(pRedirectionNode headRedirUrl);

BOOL ClearRedirectionNode(pRedirectionNode headRedirUrl);

#endif