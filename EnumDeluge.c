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