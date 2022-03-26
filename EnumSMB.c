#ifndef UNICODE
#define UNICODE
#endif
#include <windows.h>
#include <stdio.h>
#include <lm.h>

#include "wordlist.h"
#include "Network.h"
#include "CheckSMBv1.h"

char* GetShareType(DWORD dwShareType){
    char* shareType;
    switch (dwShareType){
    case STYPE_DISKTREE:
        shareType = "Disk drive";
        break;
    case STYPE_PRINTQ:
        shareType = "Print queue";
        break;
    case STYPE_DEVICE:
        shareType = "Communication device";
        break;
    case STYPE_IPC:
        shareType = "Interprocess communication";
        break;
    case STYPE_TEMPORARY:
        shareType = "A temporary share";
        break;
    case STYPE_SPECIAL:
        shareType = "Special share";
        break;
    default:
        shareType = "";
        break;
    }
    return shareType;
}
void GetShareAccess(DWORD dwAccessPerm){
    int nbChar = 0;
    if (dwAccessPerm == 0){
        printf("NONE");
        nbChar += 4;
    }else if (dwAccessPerm & ACCESS_ALL){
        printf("ALL");
        nbChar += 3;
    }else{
        if (dwAccessPerm & ACCESS_READ){
            printf("R");
            nbChar++;
        }
        if (dwAccessPerm & ACCESS_WRITE){
            printf("W");
            nbChar++;
        }
        if (dwAccessPerm & ACCESS_EXEC){
            printf("X");
            nbChar++;
        }
        if (dwAccessPerm & ACCESS_CREATE){
            printf("C");
            nbChar++;
        }
        if (dwAccessPerm & ACCESS_DELETE){
            printf("D");
            nbChar++;
        }
        if (dwAccessPerm & ACCESS_ATRIB){
            printf("E");
            nbChar++;
        }
        if (dwAccessPerm & ACCESS_PERM){
            printf("P");
            nbChar++;
        }
    }
    for (int i = 0; i < 9 - nbChar; i++)
        printf(" ");
}

VOID PrintfSmbShareInfo502(LPTSTR lpszServer, PSHARE_INFO_502 BufPtr, DWORD er, FILE* pFile) {
    printOut(pFile, "\tShare:           Local Path:                                       Access:  Descriptor:\n");
    printOut(pFile, "\t---------------------------------------------------------------------------------------\n");
    PSHARE_INFO_502 p = BufPtr;
    for (DWORD i = 1; i <= er; i++) {
        printOut(pFile,"\t%-17S%-50S", p->shi502_netname, p->shi502_path);
        GetShareAccess(p->shi502_permissions);
        printOut(pFile,"%ws\n", p->shi502_netname, p->shi502_path, p->shi502_remark);

        if (p->shi502_passwd != NULL && p->shi502_passwd[0] != 0x00){
            printf("\t[!] Password of %ws is: %ws\n",p->shi502_netname, p->shi502_passwd);
        }
        /*if (IsValidSecurityDescriptor(BufPtr->shi502_security_descriptor)) {
            printOut(pFile,"%d", p->shi502_permissions);
        }*/
        p++;
    }
}
VOID PrintfSmbShareInfo1(LPTSTR lpszServer, PSHARE_INFO_1 BufPtr, DWORD er, FILE* pFile){
    printOut(pFile, "\tShare:           Type:                      Descriptor:\n");
    printOut(pFile, "\t----------------------------------------------------------\n");
    PSHARE_INFO_1 p = BufPtr;
    for (DWORD i = 1; i <= er; i++){
        char* shareType = GetShareType(p->shi1_type);
        printOut(pFile, "\t%-17S%-27s%ws\n", p->shi1_netname, shareType, p->shi1_remark);
        p++;
    }
}
/*BOOL TestSmbConnection(LPWSTR lpszServer){
    PSHARE_INFO_0 BufPtr;
    NET_API_STATUS res;
    DWORD er = 0, tr = 0, resume = 0;

    res = NetShareEnum(lpszServer, 0, (LPBYTE*)&BufPtr, MAX_PREFERRED_LENGTH, &er, &tr, &resume);

    printf("%ws\n", BufPtr->shi0_netname);
    while (res == ERROR_MORE_DATA){
        res = NetShareEnum(lpszServer, 0, (LPBYTE*)&BufPtr, MAX_PREFERRED_LENGTH, &er, &tr, &resume);
        printf("%ws\n", BufPtr->shi0_netname);
    }

    NetApiBufferFree(BufPtr);
    return res == NERR_Success;
}*/

BOOL SmbPublic502(LPWSTR lpszServer, FILE* pFile) {
    PSHARE_INFO_502 BufPtr;
    NET_API_STATUS res;
    DWORD er = 0, tr = 0, resume = 0;

    res = NetShareEnum(lpszServer, 502, (LPBYTE*)&BufPtr, MAX_PREFERRED_LENGTH, &er, &tr, &resume);

    switch (res){
    case NERR_Success:
        PrintfSmbShareInfo502(lpszServer, BufPtr, er, pFile);
        NetApiBufferFree(BufPtr);

        while (res == ERROR_MORE_DATA) {
            res = NetShareEnum(lpszServer, 502, (LPBYTE*)&BufPtr, MAX_PREFERRED_LENGTH, &er, &tr, &resume);
            if (res == ERROR_SUCCESS || res == ERROR_MORE_DATA) {
                PrintfSmbShareInfo502(lpszServer, BufPtr, er, pFile);
                NetApiBufferFree(BufPtr);
            }else
                printOut(pFile, "\t[SMB] Public502 - ERROR: %lu\n", res);
        }
        return TRUE;
    case ACCESS_DENIED:
        printOut(pFile, "\t[SMB] Public502 - ERROR: Access denied !\n");
        break;
    case ERROR_BAD_NETPATH:
        printOut(pFile, "\t[SMB] Public502 - ERROR: BAD NETPATH !\n");
        break;
    default:
        printOut(pFile, "\t[SMB] Public502 - ERROR: %lu\n", res);
        break;
    }
    return FALSE;
}
BOOL SmbPublic1(LPWSTR lpszServer, FILE* pFile){
    PSHARE_INFO_1 BufPtr;
    NET_API_STATUS res;
    DWORD er = 0, tr = 0, resume = 0;

    res = NetShareEnum(lpszServer, 1, (LPBYTE*)&BufPtr, MAX_PREFERRED_LENGTH, &er, &tr, &resume);

    switch (res){
    case NERR_Success:
        PrintfSmbShareInfo1(lpszServer, BufPtr, er, pFile);
        NetApiBufferFree(BufPtr);

        while (res == ERROR_MORE_DATA){
            res = NetShareEnum(lpszServer, 1, (LPBYTE*)&BufPtr, MAX_PREFERRED_LENGTH, &er, &tr, &resume);
            if (res == ERROR_SUCCESS || res == ERROR_MORE_DATA){
                PrintfSmbShareInfo1(lpszServer, BufPtr, er, pFile);
                NetApiBufferFree(BufPtr);
            } else
                printOut(pFile, "\t[SMB] Public1   - ERROR: %lu\n", res);
        }
        return TRUE;
    case ACCESS_DENIED:
        printOut(pFile, "\t[SMB] Public1   - ERROR: Access denied !\n");
        break;
    case ERROR_BAD_NETPATH:
        printOut(pFile, "\t[SMB] Public1   - ERROR: BAD NETPATH !\n");
        break;
    default:
        printOut(pFile, "\t[SMB] Public1   - ERROR: %lu\n", res);
        break;
    }
    return FALSE;
}
BOOL SmbPublic(LPWSTR lpszServer, FILE* pFile){
    if (!SmbPublic502(lpszServer,pFile)){
        return SmbPublic1(lpszServer, pFile);
    }
    return FALSE;
}



BOOL TestSmbConnection(LPWSTR lpszServer){
    PSHARE_INFO_0 BufPtr;
    NET_API_STATUS res;
    DWORD er = 0, tr = 0, resume = 0;

    res = NetShareEnum(lpszServer, 0, (LPBYTE*)&BufPtr, MAX_PREFERRED_LENGTH, &er, &tr, &resume);
    NetApiBufferFree(BufPtr);
    return res == NERR_Success;
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
    LPWSTR lpszServer;

    if (CheckSMBv1(serverIp, PORT_SMB))
        printOut(pFile, "\t[SMB] SMBv1 is enable !\n");


    lpszServer = (LPWSTR)xcalloc(serverIpSize, sizeof(LPWSTR));
    if (lpszServer == NULL)
        return FALSE;
    swprintf_s(lpszServer, serverIpSize, L"%hs", serverIp);
    if (TestSmbConnection(lpszServer)){
        printOut(pFile, "\t[SMB] Try to enumerate file share\n");
        if (SmbPublic(lpszServer, pFile)){
            free(lpszServer);
            return TRUE;
        }
    } else{
        char* sharePath = (char*)xcalloc(serverIpSize + 4, sizeof(char*));
        if (sharePath == NULL){
            free(lpszServer);
            return FALSE;
        }

        sprintf_s(sharePath, serverIpSize + 4, "\\\\%s", serverIp);
        if (LoginSMB("", "", sharePath) || LoginSMB(usernameGuest, passwordGuest, sharePath)){
            printOut(pFile, "\t[SMB] Try to enumerate file share\n");
            if (SmbPublic(lpszServer, pFile)){
                WNetCancelConnection2A(sharePath, 0, TRUE);
                free(sharePath);
                free(lpszServer);
                return TRUE;
            }

        } else{
            StructWordList structWordList = {
                .usernameTab = (char**)usernameList ,
                .nbUsername = ARRAY_SIZE_CHAR(usernameList),
                .passwordTab = (char**)passwordList,
                .nbPassword = ARRAY_SIZE_CHAR(passwordList),
                .isBruteForce = isBruteForce
            };
            if(isBruteForce && BrutForceSMB(sharePath, structWordList, pFile)){
                printOut(pFile, "\t[SMB] Try to enumerate file share\n");
                if (SmbPublic(lpszServer, pFile)){
                    WNetCancelConnection2A(sharePath, 0, TRUE);
                    free(sharePath);
                    free(lpszServer);
                    return TRUE;
                }
            }
        }

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
