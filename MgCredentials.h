#pragma once

#ifndef MG_CREDENTAILS_HEADER_H
#define MG_CREDENTAILS_HEADER_H

typedef struct{
    char* username;
    char* password;
    char* domain;
    BOOL isFound;
} StructCredentials, * PStructCredentials;


PStructCredentials InitCredStruct(char* username, char* password, char* domain);
BOOL ClearCredStruct(PStructCredentials pStructCredentials);

#endif