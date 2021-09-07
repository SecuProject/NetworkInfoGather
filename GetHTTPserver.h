#pragma once

#ifndef GET_HTTP_SERVER_HEADER_H
#define GET_HTTP_SERVER_HEADER_H

UINT GetHttpServer(char* ipAddress, int port, char* requestType, char* resourcePath, char* userAgent, char** serverResponce, FILE* pFile);
#endif