#include <Windows.h>
#include <stdio.h>

#include "MgArguments.h"
#include "AttackFloodPing.h"

BOOL AttackDos(DosStruct dosStruct) {
	switch (dosStruct.attackType) {
	case  TCP_FLOOD_SYN:
		printf("[d] Underdevelopment !!!\n\n");
		break;
	case  TCP_FLOOD_FULL:
		printf("[d] Underdevelopment !!!\n\n");
		break;
	case  UDP_FLOOD:
		printf("[d] Underdevelopment !!!\n\n");
		break;
	case  PING_FLOOD:
		AttackFloodPing(dosStruct.ipAddress, dosStruct.dataSize, dosStruct.time);
		break;
	case  HTTP_FLOOD:
		printf("[d] Underdevelopment !!!\n\n");
		break;
	default:
		break;
	}
	return TRUE;
}