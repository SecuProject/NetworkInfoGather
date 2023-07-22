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

#pragma once

#ifndef NET_LOGON_HEADER_H
#define NET_LOGON_HEADER_H

typedef struct _NETLOGON_CREDENTIAL {
    CHAR data[8];
} NETLOGON_CREDENTIAL, *PNETLOGON_CREDENTIAL;

typedef struct _NETLOGON_AUTHENTICATOR {
    NETLOGON_CREDENTIAL Credential;
    DWORD Timestamp;
} NETLOGON_AUTHENTICATOR, *PNETLOGON_AUTHENTICATOR;

typedef enum _NETLOGON_SECURE_CHANNEL_TYPE {
    NullSecureChannel = 0,
    MsvApSecureChannel = 1,
    WorkstationSecureChannel = 2,
    TrustedDnsDomainSecureChannel = 3,
    TrustedDomainSecureChannel = 4,
    UasServerSecureChannel = 5,
    ServerSecureChannel = 6,
    CdcServerSecureChannel = 7
} NETLOGON_SECURE_CHANNEL_TYPE;

typedef struct _NL_TRUST_PASSWORD {
    WCHAR Buffer[256];
    ULONG Length;
} NL_TRUST_PASSWORD, *PNL_TRUST_PASSWORD;

typedef NTSTATUS(WINAPI* _I_NetServerReqChallenge)(LPWSTR, LPWSTR, PNETLOGON_CREDENTIAL, PNETLOGON_CREDENTIAL);
typedef NTSTATUS(WINAPI* _I_NetServerAuthenticate2)(LPWSTR PrimaryName, LPWSTR AccountName, NETLOGON_SECURE_CHANNEL_TYPE AccountType, LPWSTR ComputerName, PNETLOGON_CREDENTIAL ClientCredential, PNETLOGON_CREDENTIAL ServerCredential, PULONG NegotiatedFlags);
typedef NTSTATUS(WINAPI* _I_NetServerPasswordSet2)(LPWSTR PrimaryName, LPWSTR AccountName, NETLOGON_SECURE_CHANNEL_TYPE AccountType, LPWSTR ComputerName, PNETLOGON_AUTHENTICATOR Authenticator, PNETLOGON_AUTHENTICATOR ReturnAuthenticator, PNL_TRUST_PASSWORD ClearNewPassword);

typedef struct {
    _I_NetServerReqChallenge NetServerReqChallenge;
    _I_NetServerAuthenticate2 NetServerAuthenticate2;
    _I_NetServerPasswordSet2 NetServerPasswordSet2;
} NetLogonAPI;

#endif