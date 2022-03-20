#pragma once

#ifndef CHECK_SMBv1_HEADER_H
#define CHECK_SMBv1_HEADER_H

BOOL CheckSMBv1(char* ipAddress, int port);

extern unsigned char SmbNegociateSMB1Xor[138];

#endif