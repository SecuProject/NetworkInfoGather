
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
                PrintOut(pFile, "\t\t[X] Send request failed.\n");
                free(getRequest);
                return FALSE;
            }
            if (sendSize != requestSize)
                PrintOut(pFile, "\t\t[!] Send request size not match !\n");

            free(getRequest);
            return TRUE;

        } else
            PrintOut(pFile, "\t\t[X] Generate Get request failed.\n");
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
        serverResponce = xrealloc(serverResponce, (GET_RESPONSE_SIZE * i) +1);
        if (serverResponce == NULL) {
            closesocket(Socket);
            return FALSE;
        }
        nDataLengthTmp = recv(Socket, serverResponce + nDataLength, GET_RESPONSE_SIZE, 0);
        nDataLength += nDataLengthTmp;
    }
    if (nDataLengthTmp == SOCKET_ERROR) {
        //PrintOut(pFile, "\t\t[x] Error receiving data.\n");
        closesocket(Socket);
        return FALSE;
    }
    serverResponce = (char*)xrealloc(serverResponce, (size_t)(nDataLength + 1));
    if (serverResponce == NULL) {
        closesocket(Socket);
        return FALSE;
    }
    //*(serverResponce)[nDataLength] = 0x00; //1086

    *pServerResponce = serverResponce;
    return nDataLength;
}

UINT GetHttpServer(char* ipAddress, int port, char* requestType, char* resourcePath, char* userAgent, char** pServerResponce, char* customHeader, FILE* pFile) {
    SOCKET Socket = ConnectTcpServer(ipAddress, port);
    if (Socket != INVALID_SOCKET){
        // The ipAddress should be the hostname !!!
        if (SendRequest(Socket, ipAddress, requestType, resourcePath, userAgent, customHeader, pFile)){
            UINT nDataLength = RecvResponce(Socket, pServerResponce, pFile);
            closesocket(Socket);
            return nDataLength;
        }
        closesocket(Socket);
    }
    return FALSE;
}