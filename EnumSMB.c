#ifndef UNICODE
#define UNICODE
#endif
#include <windows.h>
#include <stdio.h>
#include <lm.h>

#include "wordlist.h"
#include "Network.h"

BOOL PrintfSmbShareInfo(LPTSTR lpszServer, PSHARE_INFO_502 BufPtr, DWORD er, FILE* pFile) {
    PSHARE_INFO_502 p = BufPtr;
    for (DWORD i = 1; i <= er; i++) {
        printOut(pFile,"\t\t%-17S%-30S%ws\n", p->shi502_netname, p->shi502_path, p->shi502_remark);
        /*if (IsValidSecurityDescriptor(BufPtr->shi502_security_descriptor)) {
            printOut(pFile,"%d", p->shi502_permissions);
        }*/
        p++;
    }
    return TRUE;
}

BOOL SmbPublic(LPWSTR lpszServer, FILE* pFile) {
    PSHARE_INFO_502 BufPtr;
    NET_API_STATUS res;
    DWORD er = 0, tr = 0, resume = 0;

    res = NetShareEnum(lpszServer, 502, (LPBYTE*)&BufPtr, MAX_PREFERRED_LENGTH, &er, &tr, &resume);

    switch (res){
    case NERR_Success:
        printOut(pFile, "\t\tShare:           Local Path:                   Descriptor:\n");
        printOut(pFile, "\t\t----------------------------------------------------------\n");

        PrintfSmbShareInfo(lpszServer, BufPtr, er, pFile);
        NetApiBufferFree(BufPtr);

        while (res == ERROR_MORE_DATA) {
            res = NetShareEnum(lpszServer, 502, (LPBYTE*)&BufPtr, MAX_PREFERRED_LENGTH, &er, &tr, &resume);
            if (res == ERROR_SUCCESS || res == ERROR_MORE_DATA) {
                PrintfSmbShareInfo(lpszServer, BufPtr, er, pFile);
                NetApiBufferFree(BufPtr);
            }
            else {
                printOut(pFile, "\t[SMB] Error: %lu\n", res);
            }
        }
        return TRUE;
    case ACCESS_DENIED:
        printOut(pFile, "\t[SMB] Access denied !\n");
        break;
    case ERROR_BAD_NETPATH:
        printOut(pFile, "\t[SMB] ERROR: BAD NETPATH !\n");
        break;
    default:
        printOut(pFile, "\t[SMB] ERROR: %lu\n", res);
        break;
    }
    return FALSE;
}

BOOL LoginSMB(const char* username, const char* password, char* share) {
    NETRESOURCEA resource;
    resource.dwType = RESOURCETYPE_DISK;
    resource.lpLocalName = 0;
    resource.lpRemoteName = share;
    resource.lpProvider = 0;

    DWORD result = WNetAddConnection2A(&resource, password, username, CONNECT_TEMPORARY);
    // ERROR_LOGON_FAILURE == result -> Bruteforce ok 
    return (result == NO_ERROR);
}

BOOL BrutForceSMB(char* sharePath, StructWordList structWordList, FILE* pFile) {
    BOOL isSmbCreadValid = FALSE;

    printOut(pFile,"\t[SMB] Brute Forcing SMB server:\n");
    
    for (UINT i = 0; i < structWordList.nbUsername && !isSmbCreadValid; i++) {
        for (UINT j = 0; j < structWordList.nbPassword && !isSmbCreadValid; j++) {
            printOut(pFile,"\t\t[i] %i/%i\r", i * structWordList.nbPassword + j +1,
                structWordList.nbPassword * structWordList.nbUsername);
            isSmbCreadValid = LoginSMB(structWordList.usernameTab[i], structWordList.passwordTab[j], sharePath);
            if (isSmbCreadValid)
                printOut(pFile,"\t\t[i] VALID: %s:%s\n", structWordList.usernameTab[i], structWordList.passwordTab[j]);
            /*else
                printOut(pFile,"[SMB] FAILED: %s:%s\n", usernameList[i], passwordList[j]);*/
        }
    }
    if (isSmbCreadValid)
        printf("\n");
    return isSmbCreadValid;
}


BOOL SmbEnum(char* serverIp, BOOL isBruteForce, FILE* pFile) {
    size_t serverIpSize = strlen(serverIp) + 1;
    LPWSTR lpszServer = (LPWSTR)calloc(serverIpSize, sizeof(LPWSTR));

    if (lpszServer == NULL)
        return FALSE;

    printOut(pFile, "\t[SMB] Try to enumerate file share\n");

    swprintf_s(lpszServer, serverIpSize, L"%hs", serverIp);

    if (SmbPublic(lpszServer,pFile)) {
        free(lpszServer);
        return TRUE;
    } else {
        char* sharePath = (char*)calloc(serverIpSize + 4, sizeof(char*));
        if (sharePath == NULL){
            free(lpszServer);
            return FALSE;
        }

        sprintf_s(sharePath, serverIpSize + 4 , "\\\\%s", serverIp);
        StructWordList structWordList = { 
            .usernameTab    = (char**)usernameList ,
            .nbUsername     = ARRAY_SIZE_CHAR(usernameList),
            .passwordTab    = (char**)passwordList,
            .nbPassword     = ARRAY_SIZE_CHAR(passwordList),
            .isBruteForce   = isBruteForce
        };

        if (LoginSMB("", "", sharePath) || LoginSMB("guest", "guest", sharePath) || 
            (isBruteForce && BrutForceSMB(sharePath, structWordList, pFile))) {
            if (SmbPublic(lpszServer, pFile)) {
                WNetCancelConnection2A(sharePath, 0, TRUE);
                free(sharePath);
                free(lpszServer);
                return TRUE;
            }
        }
        printOut(pFile,"\t\t[i] Access denied !\n");
        free(sharePath);
    }
    free(lpszServer);
    return FALSE;
}

/*
BOOL SmbEnum(char* serverIp, BOOL isBruteForce, FILE* pFile) {
    int serverIpSize = (int)strlen(serverIp);

    LPTSTR lpszServer = (LPTSTR)calloc(serverIpSize + 1, sizeof(LPTSTR));
    if (lpszServer == NULL)
        return FALSE;
    char* sharePath = (char*)calloc(serverIpSize + 4 + 1, sizeof(char*));
    if (sharePath == NULL)
        return FALSE;

    sprintf_s(sharePath, serverIpSize + 4 + 1, "\\\\%s", serverIp);
    swprintf_s(lpszServer, serverIpSize + 1, L"%hs", serverIp);

    printOut(pFile,"\t[SMB] Try to enumerate file share\n");

    if (SmbPublic(lpszServer,pFile)) {
        WNetCancelConnection2A(sharePath, 0, TRUE);
        free(lpszServer);
        free(sharePath);
        return TRUE;
    } else {
        if (LoginSMB("", "", sharePath) || LoginSMB("guest", "guest", sharePath) || (isBruteForce && BrutForceSMB(sharePath, pFile))) {
            if (SmbPublic(lpszServer,pFile))
                WNetCancelConnection2A(sharePath, 0, TRUE);
            else
                printOut(pFile,"\t\t[SMB] Access denied !\n");
        } else
            printOut(pFile,"\t\t[SMB] Access denied !\n");
    }
    free(lpszServer);
    free(sharePath);

    return FALSE;
}*/
