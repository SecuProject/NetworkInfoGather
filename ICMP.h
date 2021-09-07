#pragma once

#ifndef ICMP_HEADER_H
#define ICMP_HEADER_H

BOOL ICMPdiscoveryMultiThread(int maskSizeInt, NetworkPcInfo** ptrNetworkPcInfo, INT32 ipAddressBc, int* nbDetected, FILE* pFile);
BOOL ICMPdiscovery(int maskSizeInt, NetworkPcInfo** ptrNetworkPcInfo, INT32 ipAddressBc, int* nbDetected, FILE* pFile);
BOOL startPinging(char* ipAddress, int* computerTTL, FILE* pFile);
#endif