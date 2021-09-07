#pragma once



#ifndef ENUM_HTTP_HEADER_H
#define ENUM_HTTP_HEADER_H

int EnumHTTP(char* ipAddress, PORT_INFO portInfo, FILE* pFile);
int EnumHTTPS(char* ipAddress, PORT_INFO portInfo, FILE* pFile);

#endif