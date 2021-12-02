#include <windows.h>
#include <stdio.h>

#include "EnumFRITZBox.h"
#include "NetDiscovery.h"
#include "ToolsHTTP.h"


BOOL FRITZBoxVersionDetection(StrucStrDev deviceType, PORT_INFO* portInfo, char* serverResponce) {
    char* pStart = strstr(serverResponce, deviceType.pStart);
    if (pStart != NULL) {
        pStart += strlen(deviceType.pStart);
        char* pEnd = strstr(pStart, deviceType.pStop);
        if (pEnd != NULL) {
            char* pEnd2 = strstr(pStart, " ");
            if (pEnd2 != NULL)
                pEnd = pEnd2;

            int dataSize = (int)(pEnd - pStart);
            if (dataSize < BANNER_BUFFER_SIZE) {
                char* tempBuffer = (char*)malloc(BANNER_BUFFER_SIZE);
                if (tempBuffer == NULL)
                    return FALSE;
                strncpy_s(tempBuffer, BANNER_BUFFER_SIZE, pStart, dataSize);
                portInfo->version = atoi(tempBuffer);
                free(tempBuffer);
                return TRUE;
            }
        }
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