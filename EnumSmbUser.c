
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

#ifndef UNICODE
#define UNICODE
#endif
#pragma comment(lib, "netapi32.lib")

#include <stdio.h>
#include <assert.h>
#include <windows.h> 
#include <lm.h>
#pragma comment(lib, "Mpr.lib") // WNetAddConnection2

#include "Network.h"

#define NB_USER_INFO_1  1

// NetUserChangePassword 
//https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netuserchangepassword
// NetUserAdd 
// https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netuseradd
// NetGetDCName 
// https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netgetdcname


// https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-user_info_1
typedef struct _UserStructSAMR{
    char username[UNLEN];
    char password[PWLEN];
    DWORD passwordAge;
    DWORD flags;
    char comment[256];
    char homeDir[PATHLEN];
    char scriptPath[PATHLEN];
    DWORD privLevel;
}UserStructSAMR, * PUserStructSAMR;


// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rap/fbd5159e-ffac-43e1-a146-4aff405d0314
VOID UserPriv(DWORD userPriv){
    printf("\t\t[i] User privilage: ");
    switch (userPriv){
    case USER_PRIV_GUEST:
        printf("GUEST");
        break;
    case USER_PRIV_USER:
        printf("USER");
        break;
    case USER_PRIV_ADMIN:
        printf("ADMIN");
        break;
    default:
        printf("???");
        break;
    }
    printf("\n");
}
VOID UserFlag(DWORD flags){
    if (flags & UF_LOCKOUT)
        printf("\t\t[x] The account is currently locked out. \n");
    if (flags & UF_ACCOUNTDISABLE)
        printf("\t\t[!] The user's account is disabled.\n");
    if (flags & UF_DONT_EXPIRE_PASSWD)
        printf("\t\t[!] The password should never expire on the account.\n");
    if (flags & UF_PASSWD_NOTREQD)
        printf("\t\t[!] No password is required.\n");
    if (flags & UF_NOT_DELEGATED)
        printf("\t\t[!] Marks the account as \"sensitive\".\n");
    if (flags & UF_DONT_REQUIRE_PREAUTH)
        printf("\t\t[!] Vulnerable to AS-REP Roast Attack!\n");
}


DWORD GetNumberUsers(LPWSTR pszServerName){
    LPUSER_INFO_0 pBuf = NULL;
    DWORD dwLevel = 0;
    DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    DWORD dwResumeHandle = 0;

    NET_API_STATUS nStatus = NetUserEnum((LPCWSTR)pszServerName, dwLevel, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&pBuf, dwPrefMaxLen, &dwEntriesRead, &dwTotalEntries, &dwResumeHandle);
    if (!(nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA)){
        if(nStatus == ACCESS_DENIED)
            printf("[x] A system error has occurred: ACCESS_DENIED\n");
        else
            printf("[x] A system error has occurred: %lu\n", nStatus);
        if (pBuf != NULL)
            NetApiBufferFree(pBuf);
        free(pszServerName);
        return FALSE;
    }
    NetApiBufferFree(pBuf);
    return dwTotalEntries;
}

BOOL GetUserSAMR(char* targetIp, PUserStructSAMR* pTabUserFound, UINT* nbUsers){
    LPUSER_INFO_1 pBuf = NULL;
    LPUSER_INFO_1 pTmpBuf;
    DWORD dwLevel = 1;
    DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    DWORD dwResumeHandle = 0;
    DWORD dwTotalCount = 0;
    PUserStructSAMR tabUserFound;
    NET_API_STATUS nStatus = ERROR_MORE_DATA;


    LPWSTR pszServerName = (LPWSTR)xcalloc(MAX_PATH, sizeof(LPWSTR));
    if (pszServerName == NULL)
        return FALSE;

    swprintf_s(pszServerName, MAX_PATH, L"\\\\%hs", targetIp);

    dwTotalEntries = GetNumberUsers(pszServerName);
    if (dwTotalEntries == 0){
        return FALSE;
    }

    tabUserFound = (PUserStructSAMR)xcalloc(dwTotalEntries, sizeof(UserStructSAMR));
    if (tabUserFound == NULL){
        return FALSE;
    }

    //printf("\nUser account on %s:\n", targetIp);
    while (nStatus == ERROR_MORE_DATA){
        nStatus = NetUserEnum((LPCWSTR)pszServerName, dwLevel, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&pBuf, dwPrefMaxLen, &dwEntriesRead, &dwTotalEntries, &dwResumeHandle);

        if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA)){
            if ((pTmpBuf = pBuf) != NULL){
                for (DWORD i = 0; i < dwEntriesRead; i++){
                    assert(pTmpBuf != NULL);
                    if (pTmpBuf == NULL){
                        printf("[x] An access violation has occurred\n");
                        NetApiBufferFree(pBuf);
                        free(pszServerName);
                        return FALSE;
                    }
                    sprintf_s(tabUserFound[dwTotalCount].username, UNLEN, "%ws", pTmpBuf->usri1_name);
                    sprintf_s(tabUserFound[dwTotalCount].password, PWLEN, "%ws", pTmpBuf->usri1_password);
                    sprintf_s(tabUserFound[dwTotalCount].homeDir, PATHLEN, "%ws", pTmpBuf->usri1_home_dir);
                    sprintf_s(tabUserFound[dwTotalCount].scriptPath, PATHLEN, "%ws", pTmpBuf->usri1_script_path);
                    sprintf_s(tabUserFound[dwTotalCount].comment, 256, "%ws", pTmpBuf->usri1_comment);
                    tabUserFound[dwTotalCount].passwordAge = pTmpBuf->usri1_password_age;
                    tabUserFound[dwTotalCount].flags = pTmpBuf->usri1_flags;
                    tabUserFound[dwTotalCount].privLevel = pTmpBuf->usri1_priv;
                    pTmpBuf++;

                    dwTotalCount++;
                }
            }
        } else{
            if(nStatus == ACCESS_DENIED)
                printf("[x] A system error has occurred: ACCESS_DENIED\n");
            else
                printf("[x] A system error has occurred: %lu\n", nStatus);
            if (pBuf != NULL)
                NetApiBufferFree(pBuf);
            free(pszServerName);
            return FALSE;
        }
        if (pBuf != NULL){
            NetApiBufferFree(pBuf);
            pBuf = NULL;
        }
    }while (nStatus == ERROR_MORE_DATA);


    if (pBuf != NULL)
        NetApiBufferFree(pBuf);
    *pTabUserFound = tabUserFound;
    *nbUsers = dwTotalCount;
    free(pszServerName);
    return TRUE;
}

BOOL UserInfo(char* targetIp){
    PUserStructSAMR tabUsers;
    UINT nbUsers = 0;

    if (GetUserSAMR(targetIp, &tabUsers, &nbUsers)){
        printf("[-] Users found on %s:\n", targetIp);
        for (UINT i = 0; i < nbUsers; i++){
            if (!(tabUsers[i].flags & UF_ACCOUNTDISABLE & UF_ACCOUNTDISABLE)){
                printf("\t[-] Username: %s\n", tabUsers[i].username);
                UserPriv(tabUsers[i].privLevel);
                if (tabUsers[i].homeDir[0] != 0)
                    printf("\t\t[i] Home Dir:\t    %s\n", tabUsers[i].homeDir);
                if (tabUsers[i].comment[0] != 0)
                    printf("\t\t[i] Comment:\t    %s\n", tabUsers[i].comment);
                if (strcmp(tabUsers[i].password, "(null)") != 0)
                    printf("\t\t[i] Password:\t    %s\n", tabUsers[i].password);
                if (tabUsers[i].scriptPath[0] != 0)
                    printf("\t\t[i] Script Path:    %s\n", tabUsers[i].scriptPath);
                UserFlag(tabUsers[i].flags);
            }
        }
        printf("\t[i] Total of %u entries enumerated\n", nbUsers);
    }
    return TRUE;
}