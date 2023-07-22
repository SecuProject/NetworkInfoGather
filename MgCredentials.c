
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

#include "Network.h"
#include "MgCredentials.h"

PStructCredentials InitCredStruct(char* username, char* password, char* domain){
    PStructCredentials pStructCredentials = (PStructCredentials)xmalloc(sizeof(StructCredentials));
    if (pStructCredentials == NULL){
        printf("[-] Error: malloc failed\n");
        return NULL;
    }
    pStructCredentials->username = NULL;
    pStructCredentials->password = NULL;
    pStructCredentials->domain = NULL;


    if (username != NULL && password != NULL){
        size_t strLen = strlen(username) + 1;
        pStructCredentials->username = (char*)xmalloc(strLen);
        if (pStructCredentials->username != NULL){
            strcpy_s(pStructCredentials->username, strLen, username);

            strLen = strlen(password) + 1;
            pStructCredentials->password = (char*)xmalloc(strLen);
            if (pStructCredentials->password == NULL){
                free(pStructCredentials->username);
                free(pStructCredentials);
                return NULL;
            }
            strcpy_s(pStructCredentials->password, strLen, password);

            if (domain != NULL){
                strLen = strlen(domain) + 1;
                pStructCredentials->domain = (char*)xmalloc(strLen);
                if (pStructCredentials->domain == NULL){
                    free(pStructCredentials->password);
                    free(pStructCredentials->username);
                    free(pStructCredentials);
                    return NULL;
                }
                strcpy_s(pStructCredentials->domain, strLen, domain);
            } else
                pStructCredentials->domain = NULL;
            pStructCredentials->isFound = TRUE;
            return pStructCredentials;
        }
    }
    free(pStructCredentials);
    return NULL;
}
BOOL ClearCredStruct(PStructCredentials pStructCredentials){
    if (pStructCredentials == NULL)
        return FALSE;
    if (pStructCredentials->username != NULL)
        free(pStructCredentials->username);
    if (pStructCredentials->password != NULL)
        free(pStructCredentials->password);
    if (pStructCredentials->domain != NULL)
        free(pStructCredentials->domain);
    free(pStructCredentials);
    return TRUE;
}