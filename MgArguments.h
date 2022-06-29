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