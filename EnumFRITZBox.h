#pragma once

#ifndef ENUM_FRITZBOX_H
#define ENUM_FRITZBOX_H

/* #include "NetDiscovery.h"*/

// --------------------------- NetDiscovery ---------------------------
#define BANNER_BUFFER_SIZE	50
typedef enum {
    UnknownType,
    FRITZBox,
    TrueNAS
}DeviceType;

typedef struct {
    int portNumber;
    char banner[BANNER_BUFFER_SIZE];
    DeviceType deviceType;
    int version;
}PORT_INFO;
// --------------------------- NetDiscovery ---------------------------



typedef struct {
    const char* pStart;
    const char* pStop;
    DeviceType deviceType;
}StrucStrDev;

extern const StrucStrDev deviceType[];

BOOL FRITZBoxVersionDetection(StrucStrDev deviceType, PORT_INFO* portInfo, char* serverResponce);
BOOL FRITZBoxUserEnum(char* serverResponce);

#endif


