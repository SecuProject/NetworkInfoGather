#include <winsock2.h>
#include <iphlpapi.h>
#include <windows.h>
#include <stdio.h>
#include <ws2tcpip.h>

#include "ToolsHTTP.h"
#include "Network.h"


BOOL SendRequest(SOCKET Socket, char* ipAddress, char* requestType, char* resourcePath, char* userAgent, char* customHeader, FILE* pFile) {
    char* getRequest = (char*)malloc(GET_REQUEST_SIZE);
    if (getRequest != NULL) {
        const char request[] =
            "%s %s HTTP/1.1\r\n"            // REQUEST TYPE & REQUEST PATH
            "User-Agent: %s\r\n"            // USER AGENT
            "Host: %s\r\n"                  // HOST
            "%s"                            // FOR CUSTOM HEADER
            "Connection: close\r\n\r\n";
        int requestSize;
        char* pUserAgent;
        char* pCustomHeader;


        if (userAgent == NULL)
            pUserAgent = (char*)userAgentList[rand() % 5];
        else
            pUserAgent = userAgent;
        if (customHeader == NULL)
            pCustomHeader = "";
        else
            pCustomHeader = customHeader;


        requestSize = sprintf_s(getRequest, GET_REQUEST_SIZE, request,
            requestType, resourcePath, pUserAgent, ipAddress, pCustomHeader);

        if (requestSize > 0) {
            int sendSize = send(Socket, getRequest, requestSize, 0);
            if (sendSize <= 0) {
                printOut(pFile, "\t[X] Send request failed.\n");
                free(getRequest);
                return FALSE;
            }
            if (sendSize != requestSize)
                printOut(pFile, "\t[!] Send request size not match !\n");

            free(getRequest);
            return TRUE;

        } else
            printOut(pFile, "\t[X] Generate Get request failed.\n");
        free(getRequest);
        return TRUE;
    }
    return FALSE;
}

UINT RecvResponce(SOCKET Socket, char** pServerResponce, FILE* pFile) {
    int nDataLength;
    int nDataLengthTmp;
    char* serverResponce = (char*)malloc(GET_RESPONSE_SIZE + 1);
    if (serverResponce == NULL)
        return FALSE;


    nDataLength = recv(Socket, serverResponce, GET_RESPONSE_SIZE, 0);
    nDataLengthTmp = nDataLength;

    for (UINT i = 2; nDataLengthTmp > 0; i++) {
        serverResponce = realloc(serverResponce, (GET_RESPONSE_SIZE * i) +1);
        if (serverResponce == NULL) {
            printOut(pFile, "\t[X] Realloc failed.\n");
            closesocket(Socket);
            return FALSE;
        }
        nDataLengthTmp = recv(Socket, serverResponce + nDataLength, GET_RESPONSE_SIZE, 0);
        nDataLength += nDataLengthTmp;
    }
    if (nDataLengthTmp == SOCKET_ERROR) {
        printOut(pFile, "\t[X] Error receiving data.\n");
        closesocket(Socket);
        return FALSE;
    }
    serverResponce = (char*)realloc(serverResponce, nDataLength + 1);
    if (serverResponce == NULL) {
        printOut(pFile, "\t[X] Realloc failed.\n");
        closesocket(Socket);
        return FALSE;
    }
    //*(serverResponce)[nDataLength] = 0x00; //1086

    *pServerResponce = serverResponce;
    return nDataLength;
}

BOOL SetSocketTimout(SOCKET Socket) {
    struct timeval timeout;
    timeout.tv_sec = 1000;
    timeout.tv_usec = 0;

    return (setsockopt(Socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(struct timeval)) < 0);
}


UINT GetHttpServer(char* ipAddress, int port, char* requestType, char* resourcePath, char* userAgent, char** pServerResponce, char* customHeader, FILE* pFile) {
    SOCKET Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (Socket != INVALID_SOCKET) {
        SOCKADDR_IN SockAddr;
        IPAddr DestIp;

        inet_pton(AF_INET, ipAddress, &DestIp);

        SockAddr.sin_port = htons(port);
        SockAddr.sin_family = AF_INET;
        SockAddr.sin_addr.s_addr = DestIp;

        if (connect(Socket, (SOCKADDR*)(&SockAddr), sizeof(SockAddr)) != SOCKET_ERROR) {

            // set time out 
            //SetSocketTimout(Socket);
            if (SendRequest(Socket, ipAddress, requestType, resourcePath, userAgent, customHeader, pFile)) {
                int nDataLength = RecvResponce(Socket, pServerResponce, pFile);
                closesocket(Socket);
                return nDataLength;
            }
        } else 
            printOut(pFile, "\t[X] Could not connect to the web server.\n");
        closesocket(Socket);
    }else
        printOut(pFile, "\t[X] socket open failed %ld\n", GetLastError());
    return FALSE;
}