#ifndef ATTACK_DOS_HEADER_H
#define ATTACK_DOS_HEADER_H

#define DEFAULT_BUFLEN 512

typedef struct {
    SOCKADDR_IN ServerAddr;
    char* ipAddress;
    UINT bufferSize;
}THREAD_STRUCT_HTTP_DOS, * PTHREAD_STRUCT_HTTP_DOS;

BOOL CopyRandBuffer(UCHAR* pBuffer, UINT bufferSize);
BOOL CopyRandBufferAlloc(UCHAR** pBuffer, UINT bufferSize);

BOOL AttackDos(DosStruct dosStruct);

#endif