#pragma once

#ifndef ENUM_LDAP_HEADER_H
#define ENUM_LDAP_HEADER_H

BOOL BruteForceLDAP(char* ipAddress, int port, StructWordList structWordList, StructCredentials* structCredentials);
BOOL EnumLDAP(char* ipAddress, int port, StructWordList structWordList, FILE* pFile);

#endif