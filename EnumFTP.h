#pragma once

#ifndef ENUM_FTP_HEADER_H
#define ENUM_FTP_HEADER_H

#ifndef INTERNET_PORT
typedef WORD INTERNET_PORT;
#endif // !INTERNET_PORT

#ifndef INTERNET_DEFAULT_FTP_PORT
#define INTERNET_DEFAULT_FTP_PORT       21
#endif // !INTERNET_PORT

#define FTP_PASSWORD_INCORRECT  530
#define FTP_PASSWORD_VALID      1

// INTERNET_DEFAULT_FTP_PORT
BOOL TestPasswordFTP(char* IpAddress, const char* username, const char* password, INTERNET_PORT port, BOOL isVerbose);
BOOL ListCurrentDirectory(char* IpAddress, char* username, char* password, INTERNET_PORT port);
BOOL FtpEnum(char* serverIp, BOOL isBruteForce, FILE* pFile);
BOOL FtpBruteForce(char* serverIp, StructWordList structWordList, FILE* pFile, PStructCredentials credential);
#endif