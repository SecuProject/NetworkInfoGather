#pragma once

#ifndef ENUM_LDAP_HEADER_H
#define ENUM_LDAP_HEADER_H


typedef struct {
    char** usernameList;
    UINT usernameListSize;

    char** passwordList;
    UINT passwordListSize;

} StructWordList;

typedef struct {
    char* username;
    char* password;

    /*
    char* ipAddress;
    UINT port;
    */
} StructCredentials;

BOOL BruteForceLDAP(char* ipAddress, StructWordList structWordList, StructCredentials structCredentials);
BOOL EnumLDAP(char* ipAddress, int port, BOOL isBurtForce, FILE* pFile);



#endif