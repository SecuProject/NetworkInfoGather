
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

#pragma once


#ifndef DETECT_HTTP_BASIC_AUTH_HEADER_H
#define DETECT_HTTP_BASIC_AUTH_HEADER_H

#include "ToolsHTTP.h"


BOOL BruteforceBasic(BruteforceStruct bruteforceStruct, BOOL isSsl, BOOL isProxy, char** httpAuthHead);
//BOOL HttpBasicAuth(char* ipAddress, int port, char* responceBuffer, int responceSize, UINT responceCode, BOOL isBruteForce, BOOL isSsl);
BOOL HttpBasicAuth(char* ipAddress, int port, PHTTP_STRUC pHttpStructPage, BOOL isBruteForce, BOOL isSsl);


#endif