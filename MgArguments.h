
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


#ifndef MG_ARGUMENTS_HEADER_H
#define MG_ARGUMENTS_HEADER_H

#include <Windows.h>
#include <stdio.h>
#include "MgCredentials.h"

#define MATCH(strA,strB)            (strcmp(strA, strB) == 0)
#define MATCHN(strA,strB,strLen)    (strncmp(strA, strB,strLen) == 0)

#define MAX_BUFFER	128

////////////////////// SCAN ///////////////////////////
//
typedef enum {
    Passif_Scan,
    Passif_Packet_Sniffing,
    ICMP_Scan,
    ARP_Scan,
    DNS_Scan,
    MULTI_Scan,
    Disable_Scan
}TypeOfScan;

typedef struct ScanStruct {
    BOOL isListInterface;
    UINT interfaceNb;
    TypeOfScan typeOfScan;
    BOOL advancedScan;
    BOOL portScan;
    BOOL bruteforce;
    FILE* ouputFile;
    char* ipAddress;
    UINT* portList;
    UINT nbPort;
    UINT psTimeout;
}ScanStruct, * pScanStruct;
//
////////////////////// SCAN ///////////////////////////

/////////////////// Brute Force ///////////////////////
//
typedef struct {
    char** usernameTab;
    UINT nbUsername;

    char** passwordTab;
    UINT nbPassword;

    BOOL isBruteForce;
} StructWordList;

typedef enum {
    SMB,
    FTP,
    LDAP,
    HTTP_BASIC,
    HTTPS_BASIC,
    RPC,
    /*
    SSH,
    RDP,
    VNC,
    TELNET,*/
}EnumProtocol;

typedef struct BruteforceStruct {
    char ipAddress[16];
    UINT port;
    char* domain;
    char* hostname;

    EnumProtocol protocol;

    StructWordList structWordList;
    StructCredentials structCredentials;
    /*UINT nbUsername;
    char** usernameTab;
    UINT nbPassword;
    char** passwordTab;*/
    BOOL continueSuccess;
}BruteforceStruct, * pBruteforceStruct;
//
/////////////////// Brute Force ///////////////////////



///////////////////// Exploit /////////////////////////
//
typedef struct {
    WCHAR serverFQDN[MAX_PATH]; // check if valid FQDN ('.' * 3)
    WCHAR computerName[MAX_PATH];
    BOOL isOnlyCheck;
}ExploitZeroLogon;
typedef struct{
    char ipAddress[16]; // IP_ADDRESS_LEN
}ExploitPrintNightmare;
typedef struct{
    char ipAddress[16]; // IP_ADDRESS_LEN
}ExploitMs17_010;
typedef struct{
    char ipAddress[16]; // IP_ADDRESS_LEN
}ExploitDoublePulsar;

typedef enum {
    ZERO_LOGON,
    PRINT_NIGHTMARE,
    DOUBLE_PULSAR,
    MS17_010
}EnumExploit;

typedef struct ExploitStruct {
    EnumExploit exploit;
    union {
        ExploitZeroLogon        exploitZeroLogon;
        ExploitPrintNightmare   exploitPrintNightmare;
        ExploitMs17_010         exploitMs17_010;
        ExploitDoublePulsar     exploitDoublePulsar;
    };
}ExploitStruct, * pExploitStruct;
//
///////////////////// Exploit /////////////////////////

///////////////////// Enumeration /////////////////////////
//
typedef struct pEnumStruct{
    char* username;
    char* password;
    char* ipAddress;
    UINT port;
    BOOL enumUser;
    BOOL enumShare;

    EnumProtocol protocol;
}EnumStruct, * pEnumStruct;
//
///////////////////// Enumeration /////////////////////////

///////////////////// Curl /////////////////////////
// 
typedef struct pCurlStruct {
    char* hostUrl;
    char* filePath;
    char* userAgent;
    char* method;

    BOOL isVerbose;
    BOOL isSsl;
    BOOL isOutputfile;
    BOOL isFollowRedirect;
    BOOL agentRand;
    BOOL agentInfo;
}CurlStruct, *pCurlStruct;
// 
///////////////////// Curl /////////////////////////

///////////////////// DOS /////////////////////////
//



typedef enum {
    INVALID_FULL,
    TCP_FLOOD_SYN,
    TCP_FLOOD_FULL,
    UDP_FLOOD,
    PING_FLOOD,
    HTTP_FLOOD,
}AttackType;
typedef struct pDosStruct {
    char* ipAddress;
    INT port;
    AttackType attackType;

    UINT dataSize;
    UINT time;
}DosStruct, * pDosStruct;
// 
///////////////////// DOS /////////////////////////


typedef enum {
    ModeScan,
    ModeBruteforce,
    ModeExploit,
    ModeEnum,
    ModeCurl,
    ModeExternalIp,
    ModeDos
}ProgramMode;

typedef struct Argument {
    ProgramMode programMode;
    union {
        ExploitStruct exploitStruct;
        BruteforceStruct bruteforceStruct;
        ScanStruct scanStruct;
        EnumStruct enumStruct;
        CurlStruct curlStruct;
        DosStruct dosStruct;
    };
}Arguments, * pArguments;

BOOL GetArguments(int argc, char* argv[], pArguments listAgrument);
BOOL HostnameToIp(char* hostname, char** ppIpAddress);

#endif