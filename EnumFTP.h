
/* 
 * NetworkInfoGather
 * Copyright (C) 2023  SecuProject
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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