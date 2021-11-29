#pragma once
#ifndef DNS_SCAN_HEADER_H
#define DNS_SCAN_HEADER_H

BOOL DNSdiscoveryMultiThread(int maskSizeInt, NetworkPcInfo** ptrNetworkPcInfo, INT32 ipAddressBc, int* nbDetected, FILE* pFile);

#endif