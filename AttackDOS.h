#ifndef ATTACK_DOS_HEADER_H
#define ATTACK_DOS_HEADER_H

BOOL CopyRandBuffer(UCHAR* pBuffer, UINT bufferSize);
BOOL CopyRandBufferAlloc(UCHAR** pBuffer, UINT bufferSize);

BOOL AttackDos(DosStruct dosStruct);

#endif