#pragma once

#ifndef DETECT_WAF_HEADER_H
#define DETECT_WAF_HEADER_H

BOOL IsHttpWaf(char* ipAddress, int port, FILE* pFile, BOOL isSSL);

#endif