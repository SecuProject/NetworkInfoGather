
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