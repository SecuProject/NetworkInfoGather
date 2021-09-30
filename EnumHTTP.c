#include <windows.h>
#include <stdio.h>

#include "ToolsHTTP.h"
#include "GetHTTPserver.h"
#include "GetHTTPSserver.h"
//#include "Tools.h"
#include "NetDiscovery.h"

/*typedef struct {
    const char* pStart;
    const char* pStop;
    DeviceType deviceType;
}StrucStrDev;*/


const StrucStrDev deviceType[] = {
      {"FRITZ!Box "," Cable",FRITZBox} ,
      {"test","Cable",UnknownType} ,
};


BOOL FRITZBoxVersionDetection(StrucStrDev deviceType, PORT_INFO* portInfo, char* serverResponce) {
    char* pStart, * pStop;

    pStop = strstr(serverResponce, deviceType.pStop);
    if (pStop != NULL) {
        pStart = strstr(pStop - strlen(deviceType.pStart) - 7, deviceType.pStart);
        if (pStart != NULL) {
            int dataSize = pStop - pStart;
            if (dataSize < BANNER_BUFFER_SIZE) {
                char* tempBuffer = (char*)malloc(BANNER_BUFFER_SIZE);
                if (tempBuffer == NULL)
                    return FALSE;
                pStart = pStart + strlen(deviceType.pStart);
                strncpy_s(tempBuffer, BANNER_BUFFER_SIZE, pStart, dataSize);
                portInfo->version = atoi(tempBuffer);
                free(tempBuffer);
                return TRUE;
            }
        }
    }
    return FALSE;
}


BOOL GetHTTPFingerprint(char* serverResponce, PORT_INFO* portInfo) {
    portInfo->version       = 0;
    portInfo->deviceType    = UnknownType;

    for (int i = 0; sizeof(deviceType) / sizeof(StrucStrDev) > i; i++) {
        if (strstr(serverResponce, deviceType[i].pStart) != NULL) {
            portInfo->deviceType = deviceType[i].deviceType;
            switch (deviceType[i].deviceType) {
            case FRITZBox:
                return FRITZBoxVersionDetection(deviceType[i], portInfo, serverResponce);
            default:
                break;
            }
        }
    }
    return FALSE;
}


BOOL AnalizeHTTPResponse(char* serverResponce, char* protocol, PORT_INFO portInfo, FILE* pFile) {
    if (GetHTTPserverVersion(serverResponce, portInfo.banner, BANNER_BUFFER_SIZE)) {
        printOut(pFile, "\t[%s] Port %i Banner %s\n", protocol, portInfo.portNumber, portInfo.banner);
    } else {
        int returnCode = 0;
        if (GetHTTPReturnCode(serverResponce, &returnCode)) {
            printOut(pFile, "\t[%s] Port %i return code %i\n", protocol, portInfo.portNumber, returnCode);
        }
    }
    if (GetHTTPFingerprint(serverResponce, &portInfo)) {
        printOut(pFile, "\t[%s] Port %i Fingerprint %i - %i\n", protocol, portInfo.portNumber, portInfo.deviceType, portInfo.version); // portInfo.deviceType todo
    }
    return FALSE;
}



int EnumHTTP(char* ipAddress, PORT_INFO portInfo, FILE* pFile) {
    char* serverResponce = (char*)malloc(GET_REQUEST_SIZE);
    if (serverResponce == NULL)
        return FALSE;

    if (GetHTTPserver(ipAddress, portInfo.portNumber, serverResponce, "/", pFile))
        AnalizeHTTPResponse(serverResponce, "HTTP", portInfo, pFile);
    else
        printOut(pFile, "\t[HTTP] Port %i Error\n", portInfo.portNumber);
        
    free(serverResponce);
    return TRUE;
}
int EnumHTTPS(char* ipAddress, PORT_INFO portInfo, FILE* pFile) {
    char* serverResponce = (char*)malloc(GET_REQUEST_SIZE);
    if (serverResponce == NULL)
        return FALSE;

    if (GetHTTPSserver(ipAddress, portInfo.portNumber, serverResponce,"/", pFile)) {
        AnalizeHTTPResponse(serverResponce, "HTTPS", portInfo, pFile);
    }
    printOut(pFile, "\t[HTTPS] Port %i Error\n", portInfo.portNumber);
    free(serverResponce);
    return TRUE;
}