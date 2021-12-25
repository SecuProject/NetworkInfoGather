#pragma once


#ifndef DETECT_HTTP_BASIC_AUTH_HEADER_H
#define DETECT_HTTP_BASIC_AUTH_HEADER_H

#include "ToolsHTTP.h"


BOOL BruteforceBasic(BruteforceStruct bruteforceStruct, BOOL isSsl, BOOL isProxy, char** httpAuthHead);
//BOOL HttpBasicAuth(char* ipAddress, int port, char* responceBuffer, int responceSize, UINT responceCode, BOOL isBruteForce, BOOL isSsl);
BOOL HttpBasicAuth(char* ipAddress, int port, PHTTP_STRUC pHttpStructPage, BOOL isBruteForce, BOOL isSsl);


#endif