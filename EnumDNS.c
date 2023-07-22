
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

#include <Windows.h>
#include <stdio.h>
#include "Network.h"

#define DEFAULT_BUFLEN 1024

typedef struct {
    USHORT Length;
    USHORT TransactionID;
    USHORT Flags;
    USHORT Questions;
    USHORT AnswerRRs;
    USHORT AuthorityRRs;
    USHORT AdditionalRRs;
}DNS_STRUCT;
typedef struct {
    USHORT Name;
    USHORT Type;
    USHORT Class;
    DWORD TTL;
    USHORT DataLength;
    UCHAR TxtLength;
    UCHAR Txt[];
}DNS_ANSWER_STRUCT;

size_t CraftDnsTxtQuery(char* dnsQueryVersion, size_t querySize, char* dnsBuffer) {
    // Length -> TO update
    DNS_STRUCT dnsStruct = {
        .Length = (USHORT)0x1e00, // (USHORT)30
        .TransactionID = (USHORT)0x0600,
        .Flags = (USHORT)0x0001, // Recursion desired: Do query recursively
        .Questions = (USHORT)0x0100,
        .AnswerRRs = (USHORT)0x0000,
        .AuthorityRRs = (USHORT)0x0000,
        .AdditionalRRs = (USHORT)0x0000,
    };
    size_t offset = 0;

    memcpy(dnsBuffer, (const void*)&dnsStruct, (size_t)sizeof(DNS_STRUCT));
    offset = sizeof(DNS_STRUCT);
    memcpy(dnsBuffer + offset, dnsQueryVersion, querySize);
    offset += querySize;
    // Type
    USHORT queryType = 0x1000; // TXT
    memcpy(dnsBuffer + offset, &queryType, sizeof(USHORT));
    offset += sizeof(USHORT);
    USHORT queryClass = 0x0300; // CH
    memcpy(dnsBuffer + offset, &queryClass, sizeof(USHORT));
    offset += sizeof(USHORT);
    return offset;
}

BOOL SendData(SOCKET SendingSocket, char* payload, int payloadSize) {
    if (send(SendingSocket, payload, payloadSize, 0) == SOCKET_ERROR) {
        printf("[x] Send failed with error: %d\n", WSAGetLastError());
        return FALSE;
    }
    return TRUE;
}
BOOL RecvData(SOCKET SendingSocket, char* recvbuf, int* iResult) {
    memset(recvbuf, 0x00, DEFAULT_BUFLEN);
    *iResult = recv(SendingSocket, recvbuf, DEFAULT_BUFLEN, 0);
    if (*iResult > 0)
        return TRUE;
    else if (*iResult == 0)
        printf("[-] Connection closed\n");
    else
        printf("[x] recv failed with error: %d\n", WSAGetLastError());
    return FALSE;
}


int GetDnsServerVersion(char* ipAddress, int port, char** ppDnsServerVersion) {
    const char dnsQueryVersion[] = {
        "\x07version\x04"
        "bind"
    };
    
    SOCKET SendingSocket = ConnectTcpServer(ipAddress, port);
    if (SendingSocket == INVALID_SOCKET)
        return FALSE;

    char* dnsBuffer = (char*)malloc(DEFAULT_BUFLEN);
    if (dnsBuffer == NULL)
        return FALSE;
    size_t offset = CraftDnsTxtQuery((char*)dnsQueryVersion, sizeof(dnsQueryVersion), dnsBuffer);

    char recvbuf[DEFAULT_BUFLEN];
    int iResult = 0;

    SendData(SendingSocket, dnsBuffer, (int)offset);
    free(dnsBuffer);
    if (RecvData(SendingSocket, recvbuf, &iResult)) {
        if (iResult > 45) {
            DNS_ANSWER_STRUCT* dnsAnswerStruct = (DNS_ANSWER_STRUCT*)(recvbuf + 30);
            char* dnsServerVersion = (char*)malloc(dnsAnswerStruct->TxtLength + 1);
            if (dnsServerVersion != NULL) {
                strncpy_s(dnsServerVersion, dnsAnswerStruct->TxtLength + 1, dnsAnswerStruct->Txt, dnsAnswerStruct->TxtLength);
                *ppDnsServerVersion = dnsServerVersion;
                closesocket(SendingSocket);
                return TRUE;
            }
        } else
            printf("[x] Invalid data received !\n");
    } else
        printf("[x] Fail to receive data !\n");
    closesocket(SendingSocket);
    WSACleanup();

    return 0;
}



int EnumDnsServer(char* ipAddress, int port, FILE* pFile) {
    char* dnsServerVersion = NULL;
    printf("\t[DNS] Enumeration:\n");

    if (GetDnsServerVersion("192.168.1.111", 53, &dnsServerVersion)) {
        printf("\t\t[i] Server DNS version: %s\n", dnsServerVersion);
        free(dnsServerVersion);
    }
	return TRUE;
}