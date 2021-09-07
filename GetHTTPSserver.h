#pragma once

#ifndef GET_HTTPS_SERVER_HEADER_H
#define GET_HTTPS_SERVER_HEADER_H

UINT GetHttpsServer(char* ipAddress, int port, char* requestType, char* resourcePath, char* userAgent, char** serverResponce, FILE* pFile);

#endif