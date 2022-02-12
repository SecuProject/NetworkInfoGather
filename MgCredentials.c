#include <Windows.h>
#include <stdio.h>

#include "MgCredentials.h"

PStructCredentials InitCredStruct(char* username, char* password, char* domain){
    PStructCredentials pStructCredentials = (PStructCredentials)malloc(sizeof(StructCredentials));
    if (pStructCredentials == NULL){
        printf("[-] Error: malloc failed\n");
        return NULL;
    }
    pStructCredentials->username = NULL;
    pStructCredentials->password = NULL;
    pStructCredentials->domain = NULL;


    if (username != NULL){
        size_t strLen = strlen(username) + 1;
        pStructCredentials->username = (char*)malloc(strLen);
        if (pStructCredentials->username == NULL){
            printf("[-] Error: malloc failed\n");
            return NULL;
        }
        strcpy_s(pStructCredentials->username, strLen, username);
    } else{
        free(pStructCredentials);
        return NULL;
    }
    if (password != NULL){
        size_t strLen = strlen(password) + 1;
        pStructCredentials->password = (char*)malloc(strLen);
        if (pStructCredentials->password == NULL){
            printf("[-] Error: malloc failed\n");
            return NULL;
        }
        strcpy_s(pStructCredentials->password, strLen, password);
    } else{
        free(pStructCredentials->username);
        free(pStructCredentials);
        return NULL;
    }
    if (domain != NULL){
        size_t strLen = strlen(domain) + 1;
        pStructCredentials->domain = (char*)malloc(strLen);
        if (pStructCredentials->domain == NULL){
            printf("[-] Error: malloc failed\n");
            return NULL;
        }
        strcpy_s(pStructCredentials->domain, strLen, domain);
    } else
        pStructCredentials->domain = NULL;
    pStructCredentials->isFound = TRUE;
    return pStructCredentials;

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