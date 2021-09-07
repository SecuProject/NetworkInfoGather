#pragma once



#ifndef PORT_SCAN_HEADER_H
#define PORT_SCAN_HEADER_H

void scanPort(NetworkPcInfo* networkPcInfo, int nbDetected, Arguments arguments);
BOOL MultiScanPort(NetworkPcInfo* networkPcInfo, int nbDetected, Arguments arguments);
#endif