#include <Windows.h>
#include <stdio.h>
#include <wininet.h>
#include "wordlist.h"
#include "Tools.h"

#pragma comment(lib, "wininet.lib")



BOOL TestPasswordFTP(char* IpAddress, const char* username, const char* password) {
    const char* userAgent = "Microsoft Internet Explorer";
    HINTERNET hInternet = InternetOpenA(userAgent, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, INTERNET_FLAG_ASYNC);
    if (hInternet == NULL) {
        return FALSE;
    }
    HINTERNET hFtpSession = InternetConnectA(hInternet, IpAddress, INTERNET_DEFAULT_FTP_PORT, username, password, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
    if (hFtpSession == NULL) {
        InternetCloseHandle(hInternet);
        return FALSE;
    }
    printf("\t\t[FTP] VALID: '%s:%s'\n", username, password);
    InternetCloseHandle(hFtpSession);
    InternetCloseHandle(hInternet);
    return TRUE;
}

BOOL ListCurrentDirectory(char* IpAddress, char* username, char* password) {
    printf("\t[FTP] List Current Directory FTP\n");
    const char* userAgent = "Microsoft Internet Explorer";
    HINTERNET hInternet = InternetOpenA(userAgent, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet == NULL) {
        printf("\t[FTP] InternetOpenA failed: %ld\n", GetLastError());
        return FALSE;
    }
    HINTERNET hFtpSession = InternetConnectA(hInternet, IpAddress, INTERNET_DEFAULT_FTP_PORT, username, password, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
    if (hFtpSession == NULL) {
        printf("\t[-] InternetConnectA failed: %ld\n", GetLastError());
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
            printf("\t\t[-] FtpFindFirstFileA failed: %ld\n", lastError);
        
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

    int lastError = GetLastError();
    if (ERROR_NO_MORE_FILES != lastError) {
        printf("\t[-] FtpFindFirstFileA failed: %ld\n", lastError);
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

BOOL FtpEnum(char* serverIp, BOOL isBurtForce, FILE* pFile) {
    char* usernameAnomym = "anonymous";
    char* passwordAnomym = "anonymous";
    BOOL isFtpCreadValid = FALSE;
    printf("\t[FTP] Test Password\n");

    if (TestPasswordFTP(serverIp, usernameAnomym, passwordAnomym)) {
        ListCurrentDirectory(serverIp, usernameAnomym, passwordAnomym);
        isFtpCreadValid = TRUE;
    } else if(isBurtForce){
        printOut(pFile, "\t[FTP] Brute Forcing FTP server:\n");
        for (int i = 0; i < ARRAY_SIZE_CHAR(usernameList) && !isFtpCreadValid; i++) {
            for (int j = 0; j < ARRAY_SIZE_CHAR(passwordList) && !isFtpCreadValid; j++) {
                printOut(pFile, "\t%i/%i\r", i * ARRAY_SIZE_CHAR(usernameList) + j, ARRAY_SIZE_CHAR(passwordList) * ARRAY_SIZE_CHAR(usernameList));
                isFtpCreadValid = TestPasswordFTP(serverIp, usernameList[i], passwordList[j]);
                if (isFtpCreadValid)
                    printOut(pFile, "\t\t[FTP] VALID: %s:%s\n\n", usernameList[i], passwordList[j]);
            }
        }
    }
    return isFtpCreadValid;
}