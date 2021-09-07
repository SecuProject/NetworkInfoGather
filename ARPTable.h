#pragma once

#ifndef ARP_TABLE_HEADER_H
#define ARP_TABLE_HEADER_H

BOOL GetARPTable(NetworkPcInfo** ptrArpTable, int* arpTableSize, INT32 ipRangeInt32, FILE* pFile);
BOOL IsIpInArpTable(char* ipAddress, char* macAddress, FILE* pFile);

#endif