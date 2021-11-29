#pragma once



#ifndef PORT_SCAN_HEADER_H
#define PORT_SCAN_HEADER_H

// BOOL scanPortOpenUDP(char* dest_ip, int port, FILE* pFile) 

void scanPort(NetworkPcInfo* networkPcInfo, int nbDetected, ScanStruct scanStruct);
BOOL MultiScanPort(NetworkPcInfo* networkPcInfo, int nbDetected, ScanStruct scanStruct, BOOL isTcp);

#endif