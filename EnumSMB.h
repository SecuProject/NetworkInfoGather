#pragma once



#ifndef ENUM_SMB_HEADER_H
#define ENUM_SMB_HEADER_H

BOOL SmbEnum(char* serverIp, BOOL isBruteForce, FILE* pFile);
BOOL BrutForceSMB(char* sharePath, StructWordList structWordList, FILE* pFile);
BOOL LoginSMB(const char* username, const char* password, char* share);

#endif