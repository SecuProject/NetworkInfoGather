#pragma once



#ifndef ENUM_SMB_HEADER_H
#define ENUM_SMB_HEADER_H

BOOL SmbEnum(char* serverIp, BOOL isBurtForce, FILE* pFile);
BOOL BrutForceSMB(char* sharePath, const char** usernameTab, UINT usernameTabSize, const char** passwordTab, UINT passwordTabSize, FILE* pFile);

#endif