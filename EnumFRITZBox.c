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