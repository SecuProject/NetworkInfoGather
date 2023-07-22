
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

#include <windows.h>
#include <stdio.h>

#include "NetDiscovery.h"
#include "ToolsHTTP.h"




// <title>Deluge WebUI 2.0.5-0-202112151848-ubuntu20.04.1</title>
BOOL EnumDeluge(char* serverResponce, PORT_INFO* portInfo){
    const char delim1[] = "<title>";
    const char delim2[] = "</title>";
    char* serverVersion;
    int bufferLen = 0;

    if (ExtractStrStr(serverResponce, delim1, delim2, &serverVersion, &bufferLen) && serverVersion != NULL){
        strncpy_s(portInfo->banner, BANNER_BUFFER_SIZE, serverVersion, BANNER_BUFFER_SIZE -1);
        printf("\t\t[SOFTWARE] %s\n", serverVersion);
        free(serverVersion);
        return TRUE;
    }
	return FALSE;
}