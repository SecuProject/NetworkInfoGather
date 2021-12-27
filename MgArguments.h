#pragma once


#ifndef MG_ARGUMENTS_HEADER_H
#define MG_ARGUMENTS_HEADER_H

#include <Windows.h>
#include <stdio.h>

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

typedef struct {
    char* username;
    char* password;
    char* domain;
} StructCredentials;

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

typedef enum {
    ZERO_LOGON,
    PRINT_NIGHTMARE
}EnumExploit;

typedef struct ExploitStruct {
    EnumExploit exploit;
    union {
        ExploitZeroLogon exploitZeroLogon;
        ExploitPrintNightmare exploitPrintNightmare;
    };
}ExploitStruct, * pExploitStruct;
//
///////////////////// Exploit /////////////////////////


typedef enum {
    ModeScan,
    ModeBruteforce,
    ModeExploit
}ProgramMode;

typedef struct Argument {
    ProgramMode programMode;
    union {
        ExploitStruct exploitStruct;
        BruteforceStruct bruteforceStruct;
        ScanStruct scanStruct;
    };
}Arguments, * pArguments;

BOOL GetArguments(int argc, char* argv[], pArguments listAgrument);


#endif