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