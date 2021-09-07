#pragma once


#ifndef TOOLS_H
#define TOOLS_H

#define ARRAY_SIZE_CHAR(charTab)    (UINT)(sizeof(charTab)/sizeof(char*))

#define ACCESS_DENIED               5
#define NO_MORE_FILES               18



BOOL IsIpAddressValid(int a, int b, int c, int d);
BOOL isNetworkRange(char* ipAddress, INT32 ipRangeInt32);


BOOL printOut(FILE* pFile, const char* format, ...);
DWORD SyncWaitForMultipleObjs(HANDLE* handles, DWORD count);

#endif