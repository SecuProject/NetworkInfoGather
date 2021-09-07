
#pragma once
#include "portList.h"
#include "NetDiscovery.h"

#ifndef NETWORK_HEADER_H
#define NETWORK_HEADER_H

#define MAX_NB_ADAPTER	50

#define MASK_NB_BYTE	4

#define OCTE_MAX		0xFF
#define OCTE_SIZE		8
#define BYTE_SIZE		4
#define IP_ADDRESS_LEN	16
#define MASK_SIZE_CHAR	16

#define MAC_ADDRESS_LEN_BYTE	6
#define MAC_ADDRESS_LEN			MAC_ADDRESS_LEN_BYTE * 2 + 5
//#define MAC_ADDRESS_LEN	    MAC_ADDRESS_LEN_BYTE * 2 + 5 + 50   // test



const int port[NB_TAB_PORT];

BOOL initWSA(FILE* pFile);

typedef struct {
	char ipAddress[IP_ADDRESS_LEN + 1];
	char macAddress[MAC_ADDRESS_LEN + 1];
	int computerTTL;
	FILE* pFile;
	BOOL isHostUp;
} THREAD_STRUCT_DATA, * PTHREAD_STRUCT_DATA;

#endif