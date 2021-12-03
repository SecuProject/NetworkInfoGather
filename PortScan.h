#pragma once



#ifndef PORT_SCAN_HEADER_H
#define PORT_SCAN_HEADER_H


//void scanPort(NetworkPcInfo* networkPcInfo, int nbDetected, ScanStruct scanStruct);

//BOOL scanPortOpenUDP(char* dest_ip, int port, FILE* pFile);
BOOL scanPortOpenTCP(char* dest_ip, int port, FILE* pFile);


BOOL MultiScanPort(NetworkPcInfo* networkPcInfo, int nbDetected, ScanStruct scanStruct, BOOL isTcp);

#endif