#include <Windows.h>
#include <stdio.h>
#include <wininet.h>

#include "wordlist.h"
#include "Network.h"
#include "MgArguments.h"
#include "EnumFTP.h"


#define RESPONSE_INFO_SIZE      1024

#define IS_POSITVE_PRELIMINARY_REPLY(ftpCode)   (ftpCode > 99  && ftpCode < 200)
#define IS_POSITVE_COMPLETION_REPLY(ftpCode)    (ftpCode > 199 && ftpCode < 300)
#define IS_POSITVE_INTERMEDIATE_REPLY(ftpCode)  (ftpCode > 299 && ftpCode < 400)
#define IS_PERMANENT_NEGATIVE_REPLY(ftpCode)    (ftpCode > 399 && ftpCode < 500)
#define IS_PROTECTED_REPLY(ftpCode)             (ftpCode > 499 && ftpCode < 600)

BOOL HandleFtpCode(int ftpCode){
    BOOL isPositive = TRUE;
    printf("\t\t[");
    if (IS_POSITVE_PRELIMINARY_REPLY(ftpCode))
        printf("*");
    else if (IS_POSITVE_COMPLETION_REPLY(ftpCode))
        printf("+");
    else if (IS_POSITVE_INTERMEDIATE_REPLY(ftpCode))
        printf("!");
    else{
        // ERROR
        isPositive = FALSE;
        if (IS_PERMANENT_NEGATIVE_REPLY(ftpCode))
            printf("-");
        else if (IS_PROTECTED_REPLY(ftpCode))
            printf("w");
        else
            printf("???");
    }
    printf("] ");
    return isPositive;
}
INT HandleFtpMsg(BOOL isVerbose){
    DWORD lastError;
    DWORD lastRespInfoLen = RESPONSE_INFO_SIZE;
    INT ftpCode = 0;

    char* lastRespInfo = (char*)malloc(RESPONSE_INFO_SIZE);
    if (lastRespInfo == NULL)
        return FALSE;

    if (InternetGetLastResponseInfoA(&lastError, lastRespInfo, &lastRespInfoLen)){
        char* next_token = NULL;
        const char* delim = "\n";

        char* token = strtok_s(lastRespInfo, delim, &next_token);
        while (token){
            char* tempRespInfo = (char*)malloc(RESPONSE_INFO_SIZE);
            

            if (tempRespInfo == NULL){
                free(lastRespInfo);
                return FALSE;
            }
            if (sscanf_s(token, "%i %[^\t\n\r]", &ftpCode, tempRespInfo, RESPONSE_INFO_SIZE) == 2){
                if (isVerbose){
                    if (HandleFtpCode(ftpCode))
                        printf("%s\n", tempRespInfo);
                    else
                        printf("%s (%i)\n", tempRespInfo, ftpCode);
                }
            } else
                printf("[!] %s\n", token);
            token = strtok_s(NULL, delim, &next_token);
            free(tempRespInfo);
        }
    }

    if (lastError != NO_ERROR)
        printf("\t[x] FTP error: %lu !\n", lastError);


    free(lastRespInfo);
    return ftpCode;
}

INT TestPasswordFTP(char* IpAddress, const char* username, const char* password, INTERNET_PORT port, BOOL isVerbose) {
    const char* userAgent = "Microsoft Internet Explorer";
    INT returnCode;
    HINTERNET hInternet = InternetOpenA(userAgent, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, INTERNET_FLAG_ASYNC);
    if (hInternet == NULL) {
        return FALSE;
    }
    HINTERNET hFtpSession = InternetConnectA(hInternet, IpAddress, port, username, password, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
    if (hFtpSession == NULL) {
        returnCode = HandleFtpMsg(isVerbose);
        InternetCloseHandle(hInternet);
        return returnCode;
    }
    returnCode = HandleFtpMsg(isVerbose);

    InternetCloseHandle(hFtpSession);
    InternetCloseHandle(hInternet);
    return TRUE;
}

BOOL ListCurrentDirectory(char* IpAddress, char* username, char* password, INTERNET_PORT port) {
    printf("\t[FTP] List Current Directory FTP\n");
    const char* userAgent = "Microsoft Internet Explorer";
    HINTERNET hInternet = InternetOpenA(userAgent, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet == NULL) {
        printf("\t[FTP] InternetOpenA failed: %lu\n", GetLastError());
        return FALSE;
    }
    HINTERNET hFtpSession = InternetConnectA(hInternet, IpAddress, port, username, password, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
    if (hFtpSession == NULL) {
        printf("\t[-] InternetConnectA failed: %lu\n", GetLastError());
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    char currentDirectory[MAX_PATH];
    int sizeCurrentDirectory = 0;

    if (FtpGetCurrentDirectoryA(hInternet, currentDirectory, &sizeCurrentDirectory))
        printf("\t[FTP] CurrentDirectory: %s\n", currentDirectory);

    WIN32_FIND_DATAA FileData;
    HINTERNET hFtpFile = FtpFindFirstFileA(hFtpSession, NULL, &FileData, INTERNET_FLAG_NEED_FILE, 0);
    if (hFtpFile == NULL) {
        DWORD lastError = GetLastError();
        if (lastError == NO_MORE_FILES)
            printf("\t\t[-] Directory is empty\n");
        else
            printf("\t\t[-] FtpFindFirstFileA failed: %lu\n", lastError);
        
        InternetCloseHandle(hFtpSession);
        InternetCloseHandle(hInternet);
        return FALSE;
    }
    printf("\tFile Type    File name\n");
    do {
        char typeOfFile = ' ';

        switch (FileData.dwFileAttributes) {
        case FILE_ATTRIBUTE_NORMAL:
            typeOfFile = 'F';
            break;
        case FILE_ATTRIBUTE_DIRECTORY:
            typeOfFile = 'D';
            break;
        case FILE_ATTRIBUTE_ARCHIVE:
            typeOfFile = 'A';
            break;
        default:
            break;
        }

        printf("\t    %c\t\t%s\n", typeOfFile, FileData.cFileName);

        //if(FtpGetFileA(hFtpFile, FileData.cFileName, LC_FILE, FALSE, FILE_ATTRIBUTE_NORMAL, FTP_TRANSFER_TYPE_BINARY, 0))
        //    printf("%s\n", FileData.cFileName);

    } while (InternetFindNextFileA(hFtpFile, &FileData));

    DWORD lastError = GetLastError();
    if (ERROR_NO_MORE_FILES != lastError) {
        printf("\t[-] FtpFindFirstFileA failed: %lu\n", lastError);
        InternetCloseHandle(hFtpFile);
        InternetCloseHandle(hFtpSession);
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    InternetCloseHandle(hFtpFile);
    InternetCloseHandle(hFtpSession);
    InternetCloseHandle(hInternet);
    return TRUE;
}


BOOL FtpBruteForce(char* serverIp, StructWordList structWordList, FILE* pFile, PStructCredentials credential){
    printOut(pFile, "\t[FTP] Brute Forcing FTP server:\n");
    BOOL isFtpCreadValid = FTP_PASSWORD_INCORRECT;
    UINT i, j;


    INT returnCode = TestPasswordFTP(serverIp, usernameAnonymous, passwordAnonymous, INTERNET_DEFAULT_FTP_PORT, TRUE);
    switch (returnCode){
    case FTP_PASSWORD_VALID:
        credential =  InitCredStruct((char*)usernameAnonymous, (char*)passwordAnonymous, NULL);
        if (credential == NULL)
            FALSE;
        break;
    case FTP_PASSWORD_INCORRECT:
        for (i = 0; i < structWordList.nbUsername && isFtpCreadValid != FTP_PASSWORD_VALID; i++){
            for (j = 0; j < structWordList.nbPassword && isFtpCreadValid != FTP_PASSWORD_VALID; j++){
                LoadingBar(i * structWordList.nbPassword + j, structWordList.nbPassword * structWordList.nbUsername);
                isFtpCreadValid = TestPasswordFTP(serverIp, structWordList.usernameTab[i], structWordList.passwordTab[j], INTERNET_DEFAULT_FTP_PORT, FALSE);
            }
        }
        break;
    default:
        break;
    }

    if (isFtpCreadValid == FTP_PASSWORD_VALID){
        credential = InitCredStruct(structWordList.usernameTab[i], structWordList.passwordTab[j], NULL);
        if (credential == NULL)
            FALSE;
    }
    return isFtpCreadValid;
}


BOOL FtpEnum(char* serverIp, BOOL isBruteForce, FILE* pFile) {
    BOOL isFtpCreadValid = FALSE;
    INT returnCode = TestPasswordFTP(serverIp, usernameAnonymous, passwordAnonymous, INTERNET_DEFAULT_FTP_PORT,TRUE);
    if (returnCode == FTP_PASSWORD_VALID) {
        printf("\t[FTP] Test Password\n");
        printf("\t\t[i] VALID: '%s:%s'\n", usernameAnonymous, passwordAnonymous);
        ListCurrentDirectory(serverIp, (char*)usernameAnonymous, (char*)passwordAnonymous, INTERNET_DEFAULT_FTP_PORT);
        isFtpCreadValid = TRUE;
    }else if (isBruteForce && returnCode == FTP_PASSWORD_INCORRECT) {
        StructCredentials credentials;
        StructWordList structWordList;
        structWordList.usernameTab = (char**)usernameList;
        structWordList.nbUsername = ARRAY_SIZE_CHAR(usernameList);
        structWordList.passwordTab = (char**)passwordList;
        structWordList.nbPassword = ARRAY_SIZE_CHAR(passwordList);


        if (FtpBruteForce(serverIp, structWordList, pFile,&credentials)){
            printf("\t\t[i] VALID: '%s:%s'\n", credentials.username, credentials.password);
            isFtpCreadValid = TRUE;
            ListCurrentDirectory(serverIp, credentials.username, credentials.password, INTERNET_DEFAULT_FTP_PORT);
            ClearCredStruct(&credentials);
        }
    }
    return isFtpCreadValid;
}
