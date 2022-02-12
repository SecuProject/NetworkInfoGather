// FtpEnum(ipAddress, isBruteforce, pFile);
#include "MgArguments.h"
#include "EnumSmbUser.h"
#include "EnumSMB.h"
#include "EnumFTP.h"
#include "wordlist.h"
#include "portList.h"


VOID PrintEnumPortTitle(char* ipAddress,int port){
    printf("[-] Enumeration on %s port %i:\n", ipAddress, port);
}

BOOL EnumPort(EnumStruct enumStruct){
    BOOL retValue = FALSE;
    char *sharePath = (char*)malloc(MAX_PATH);
    if (sharePath == NULL)
        return FALSE;

    sprintf_s(sharePath, MAX_PATH, "\\\\%s", enumStruct.ipAddress);

    switch (enumStruct.protocol){
    case SMB:
        PrintEnumPortTitle(enumStruct.ipAddress, PORT_SMB);
        if (enumStruct.username != NULL && enumStruct.password != NULL){
            if (!LoginSMB(enumStruct.username, enumStruct.password, sharePath)){
                free(sharePath);
                return FALSE;
            }
        }
        if (enumStruct.enumShare){
            printf("[-] SMB share:\n");
            retValue = SmbEnum(enumStruct.ipAddress, FALSE, NULL);
        }

        if (enumStruct.enumUser)
            retValue &= UserInfo(enumStruct.ipAddress);
        break;
    case FTP:
        PrintEnumPortTitle(enumStruct.ipAddress, enumStruct.port);
        if (TestPasswordFTP(enumStruct.ipAddress, enumStruct.username, enumStruct.password, enumStruct.port,TRUE) == FTP_PASSWORD_VALID)
            return ListCurrentDirectory(enumStruct.ipAddress, enumStruct.username, enumStruct.password, enumStruct.port);
        else{
            if (enumStruct.username == NULL)
                enumStruct.username = (char*)usernameAnonymous;
            if (enumStruct.password == NULL)
                enumStruct.password = (char*)passwordAnonymous;

            printf("[x] FTP authentication for on host: %s (%s:%s) !\n", enumStruct.ipAddress, enumStruct.username, enumStruct.password);
        }
    default:
        break;
    }
    free(sharePath);
	return retValue;
}

