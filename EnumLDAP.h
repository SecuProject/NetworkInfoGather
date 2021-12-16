#pragma once

#ifndef ENUM_LDAP_HEADER_H
#define ENUM_LDAP_HEADER_H


typedef struct {
    char** usernameList;
    UINT usernameListSize;

    char** passwordList;
    UINT passwordListSize;

    BOOL isBruteForce;
} StructWordList;

typedef struct {
    char* username;
    char* password;

    /*
    char* ipAddress;
    UINT port;
    */
} StructCredentials;

BOOL BruteForceLDAP(char* ipAddress, int port, StructWordList structWordList, StructCredentials* structCredentials);
BOOL EnumLDAP(char* ipAddress, int port, StructWordList structWordList, FILE* pFile);



#endif