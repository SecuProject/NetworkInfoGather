#pragma once

#ifndef ENUM_FTP_HEADER_H
#define ENUM_FTP_HEADER_H

BOOL FtpEnum(char* serverIp, BOOL isBurtForce, FILE* pFile);
BOOL FtpBruteForce(char* serverIp, char** usernameList, UINT usernameListSize, char** passwordList, UINT passwordListSize, FILE* pFile);
#endif