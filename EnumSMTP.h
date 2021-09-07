#pragma once


#ifndef ENUM_SMTP_HEADER_H
#define ENUM_SMTP_HEADER_H



BOOL EnumSMTP(NetworkPcInfo* networkPcInfo,int port, FILE* pFile);
VOID FreeSmtpData(SMTP_DATA* smtpData);

#endif