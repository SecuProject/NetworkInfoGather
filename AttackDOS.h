
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