
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

#include "EnumFRITZBox.h"
#include "NetDiscovery.h"
#include "ToolsHTTP.h"


BOOL FRITZBoxVersionDetection(StrucStrDev deviceType, PORT_INFO* portInfo, char* serverResponce) {
    char* buffer;
    int bufferLen=0;

    if(ExtractStrStr(serverResponce, deviceType.pStart, deviceType.pStop, &buffer, &bufferLen)){
        char* diviceType = (char*)malloc(100);
        if (diviceType == NULL)
            return FALSE;

        int nbData = sscanf_s(buffer, "%s %i", diviceType, 100, &portInfo->version);
        if (nbData == 2){
            sprintf_s(portInfo->banner, BANNER_BUFFER_SIZE, "FRITZ!%s %i", diviceType, portInfo->version);
            free(diviceType);
            free(buffer);
            return TRUE;
        }
        free(diviceType);
        free(buffer);
    }
    return FALSE;
}
BOOL FRITZBoxUserEnum(char* serverResponce) {
    const char detectionUiViewUser[] = "\"activeUsers\":";
    char* pInit = strstr(serverResponce, detectionUiViewUser);
    BOOL retVal = FALSE;

    if (pInit != NULL) {
        const char delim1[] = "\"value\":\"";
        const char delim2[] = "\"";
        pInit += sizeof(detectionUiViewUser);

        BOOL isNewUser = TRUE;
        char* pStart = strstr(pInit, delim1);
        if (pStart == NULL)
            return FALSE;

        printf("\t[FRITZBox] username: \n"); // Print !!!!
        while (isNewUser && pStart != NULL) {
            char* pStop;

            pStart += sizeof(delim1) -1 ;
            pStop = strstr(pStart, delim2);
            if (pStop != NULL) {
                int usernameSize = (int)(pStop - pStart);
                if (usernameSize > 0 && usernameSize < 50) {
                    char* usernameBuf = (char*) malloc(usernameSize + 1);
                    if (usernameBuf == NULL)
                        return FALSE;
                    strncpy_s(usernameBuf, usernameSize + 1, pStart, usernameSize);
                    printf("\t\t[i] %s\n", usernameBuf);

                    pStart = strstr(pStop, delim1);
                    isNewUser = TRUE;
                    retVal = TRUE;
                    free(usernameBuf);
                }else
                    isNewUser = FALSE;
            }else
                isNewUser = FALSE;
        }
    }
    return retVal;
}