#pragma once

#ifndef MG_ARGUMENTS_HEADER_H
#define MG_ARGUMENTS_HEADER_H

typedef enum {
	Passif_Scan,
	Passif_Packet_Sniffing,
	ICMP_Scan,
	ARP_Scan,
    Disable_Scan
}TypeOfScan;


typedef struct Argument {
    BOOL isListInterface;
    int interfaceNb;
	TypeOfScan typeOfScan;
    BOOL advancedScan;
    BOOL portScan;
    BOOL bruteforce;
    FILE* ouputFile;
    char* ipAddress;
    int* portList;
    int nbPort;
}Arguments, * pArguments;

BOOL GetArguments(int argc, char* argv[], pArguments listAgrument);


#endif