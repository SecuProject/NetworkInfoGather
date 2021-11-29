#pragma once

#ifndef MG_ARGUMENTS_HEADER_H
#define MG_ARGUMENTS_HEADER_H

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
typedef enum {
    SMB,
    FTP,
    LDAP,
    /*
    SSH,
    RDP,
    VNC,
    TELNET,*/
}EnumProtocol;

typedef struct BruteforceStruct {
    char ipAddress[16];
    EnumProtocol protocol;
    UINT nbUsername;
    char** usernameTab;
    UINT nbPassword;
    char** passwordTab;
    BOOL continueSuccess;
}BruteforceStruct, * pBruteforceStruct;
//
/////////////////// Brute Force ///////////////////////



///////////////////// Exploit /////////////////////////
//
typedef struct {
    char serverFQDN[MAX_PATH]; // check if valid FQDN ('.' * 3)
    BOOL isOnlyCheck;
}ExploitZeroLogon;


typedef enum {
    ZERO_LOGON,
}EnumExploit;

typedef struct ExploitStruct {
    EnumExploit exploit;
    union {
        ExploitZeroLogon exploitZeroLogon;
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