#include <Windows.h>
#include <stdio.h>


//////////// Word List ////////////
#include "HttpWordlist.h"
#include "apacheWordList.h"
#include "apacheTomcatWordList.h"
#include "IisWordList.h"
#include "backupWordList.h"
//////////// Word List ////////////

#include "ChainListUrlRedir.h"
#include "Network.h"
#include "ToolsHTTP.h"
#include "DirBruteForce.h"
#include "ParseHttpResponse.h"

#define REDIRECTION_PATH_SIZE  100

/*
Directory
1. all invalid directories url return 200

1. Check if val are the same:
    - returnCode
    - contentLen
2. If returnCode >= 400 && returnCode < 599
    * Use returnCode
3. if returnCode >= 300 && returnCode < 400
    if redirectionPath of all 3 to same but HTTPS
        BASE_NOT_FOUND                               ----   to test

    if redirectionPath the same for all 3
        * returnCode >= 300 && returnCode < 400 && default->redirectionPath = new->redirectionPath
4. Request size the same for all 3
    - contentLen
*/
const char* invalideUrlFilePath[] = {
    "/wnhQ7QgxDu3u6rL22Gq.php",     // Add rand strings
    "/G938Ei7F6QGZc9j47apZ.txt",    // Add rand strings
    "/gy788zk7nC472jha6NnmL.html",  // Add rand strings
};
const char* invalideUrlDirecotryPath[] = {
    "/FaTx3UshB75u498Cn",           // Add rand strings
    "/B24L4U8R9KJesa",              // Add rand strings
    "/SWU4v7887VSthS3BAXs",         // Add rand strings
};

typedef enum {
    BASE_CODE_ERROR_CODE,
    BASE_REDIRECT_CODE,
    BASE_DATA_SIZE_CODE,
    BASE_CODE_AUTH,
    BASE_INVALID_CODE_LEN_DIR,
    BASE_NOT_FOUND
}ENUM_PAGE_NOT_FOUND;


ENUM_PAGE_NOT_FOUND SetNotFound(PHTTP_STRUC pHttpStruct, RequestInfoStruct requestInfoStruct, FILE* pFile, char* invalideUrlPath[], UINT invalideUrlPathSize) {
    BOOL isReturnCodeSame = TRUE;
    BOOL isContentLenSame = TRUE;
    BOOL isRedirectionSame = TRUE;
    UINT isMatch = 0;
    PHTTP_STRUC pHttpStructInvalide[3]; // calloc


    /*pHttpStruct->redirectionPath = (char*)malloc(REDIRECTION_PATH_SIZE);
    if (pHttpStruct->redirectionPath == NULL) {

    }*/


    for (UINT i = 0; i < invalideUrlPathSize; i++) {
        pHttpStructInvalide[i] = GetHttpRequest2(requestInfoStruct.ipAddress, requestInfoStruct.port, (char*)invalideUrlPath[i], "HEAD", requestInfoStruct.httpAuthHeader, requestInfoStruct.isSSL, pFile);
        if (pHttpStructInvalide[i] == NULL)
            return BASE_NOT_FOUND;
        if (pHttpStructInvalide[i]->returnCode == STATUS_CODE_OK &&
            pHttpStructInvalide[i]->contentLen == NO_BODY_DATA)
            isMatch++;
    }

    if (isMatch == invalideUrlPathSize) {
        for (int i = invalideUrlPathSize - 1; i > 0; i--)
            free(pHttpStructInvalide[i]);
        return BASE_INVALID_CODE_LEN_DIR;
    }

    if (pHttpStructInvalide == NULL)
        return BASE_CODE_ERROR_CODE;



    pHttpStruct->returnCode = pHttpStructInvalide[0]->returnCode;
    pHttpStruct->contentLen = pHttpStructInvalide[0]->contentLen;

    if (!IS_HTTP_ERROR(pHttpStruct->returnCode)) {
        isReturnCodeSame = BASE_CODE_ERROR_CODE;
    } else {
        if (IS_HTTP_AUTH(pHttpStruct->returnCode)) {
            UINT countCodeAuth = 1;
            for (UINT i = 1; i < invalideUrlPathSize; i++) {
                if (IS_HTTP_AUTH(pHttpStructInvalide[i]->returnCode))
                    countCodeAuth++;
            }
            if (countCodeAuth == 3) {
                for (UINT i = invalideUrlPathSize - 1; i > 0; i--)
                    free(pHttpStructInvalide[i]);
                return BASE_NOT_FOUND;
            }
        }
    }
    if (IS_HTTP_REDIRECTS(pHttpStructInvalide[0]->returnCode)) {
        if (TestAllHttpsRedirect(pHttpStructInvalide, pFile))
            return BASE_NOT_FOUND;

        if (pHttpStructInvalide[0]->redirectionPath != NULL)
            strcpy_s(pHttpStruct->redirectionPath, REDIRECTION_PATH_SIZE, pHttpStructInvalide[0]->redirectionPath);
        else
            strcpy_s(pHttpStruct->redirectionPath, REDIRECTION_PATH_SIZE, "");
    }

    for (UINT i = 0; i < invalideUrlPathSize; i++) {
        if (pHttpStruct->returnCode != pHttpStructInvalide[i]->returnCode)
            isReturnCodeSame = FALSE;
        if (pHttpStruct->contentLen != pHttpStructInvalide[i]->contentLen)
            isContentLenSame = FALSE;
        // Redirection
        if (IS_HTTP_REDIRECTS(pHttpStructInvalide[i]->returnCode) &&
            pHttpStructInvalide[i]->redirectionPath != NULL &&
            strcmp(pHttpStruct->redirectionPath, pHttpStructInvalide[i]->redirectionPath) != 0)
            isRedirectionSame = FALSE;
    }
    for (int i = invalideUrlPathSize - 1; i > 0; i--)
        free(pHttpStructInvalide[i]);


    if (isReturnCodeSame)
        return BASE_CODE_ERROR_CODE;
    else if (isContentLenSame)
        return BASE_REDIRECT_CODE;
    else if (isRedirectionSame)
        return BASE_DATA_SIZE_CODE;
    return BASE_NOT_FOUND;

}

ENUM_PAGE_NOT_FOUND SetFileNotFound(PHTTP_STRUC pHttpStruct, RequestInfoStruct requestInfoStruct, FILE* pFile) {
    return SetNotFound(pHttpStruct, requestInfoStruct, pFile, (char**)invalideUrlFilePath, ARRAY_SIZE_CHAR(invalideUrlFilePath));
}

ENUM_PAGE_NOT_FOUND SetDirectoryNotFound(PHTTP_STRUC pHttpStruct, RequestInfoStruct requestInfoStruct, FILE* pFile) {
    return SetNotFound(pHttpStruct, requestInfoStruct, pFile, (char**)invalideUrlDirecotryPath, ARRAY_SIZE_CHAR(invalideUrlDirecotryPath));
}


VOID PrintAllDir(FILE* pFile, char* printBuffer, int printBufferLen) {
    int defaultWidth = 120;
    int strLenNew = printBufferLen + 4;
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    HANDLE stdHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    if (stdHandle != NULL) {
        if (GetConsoleScreenBufferInfo(stdHandle, &csbi)) {
            defaultWidth = csbi.dwSize.X;
            //defaultHeight = csbi.dwSize.Y;
        }
    }
    for (int i = 0; i < printBufferLen; i++) {
        // 0x09 -> tab
        if (printBuffer[i] == 0x09)
            strLenNew += 5;
    }
    printOut(pFile, "%s", printBuffer);
    for (int i = 0; i < defaultWidth - strLenNew; i++)
        printf(" ");
    printf("\n");
}
VOID PrintDirFindRedirect(PHTTP_STRUC pHttpStructPage, char* ipAddress, FILE* pFile, BOOL isSSL) {
    char* printBuffer = (char*)malloc(1024);
    if (printBuffer == NULL)
        return;
    int strLen = sprintf_s(printBuffer, 1024, "\t\thttp%s://%s%-24s %i  -  %-5i -> %s",
        isSSL ? "s" : "", ipAddress,
        pHttpStructPage->requestPath,
        pHttpStructPage->returnCode,
        (pHttpStructPage->contentLen > 0) ? pHttpStructPage->contentLen : 0,
        pHttpStructPage->redirectionPath);
    PrintAllDir(pFile, printBuffer, strLen);
}
VOID PrintDirFind(PHTTP_STRUC pHttpStructPage, char* ipAddress, FILE* pFile, BOOL isSSL) {
    char* printBuffer = (char*)malloc(1024);
    if (printBuffer == NULL)
        return;
    int strLen = sprintf_s(printBuffer, 1024, "\t\thttp%s://%s%-24s %i  -  %-5i", isSSL ? "s" : "", ipAddress,
        pHttpStructPage->requestPath, pHttpStructPage->returnCode,
        (pHttpStructPage->contentLen > 0) ? pHttpStructPage->contentLen : 0);
    PrintAllDir(pFile, printBuffer, strLen);

    /* printOut(pFile, "\t\thttp%s://%s%-23s %i -  %-5i                                                   \n",
         isSSL ? "s" : "", ipAddress,
         pHttpStructPage->requestPath, pHttpStructPage->returnCode,
         (pHttpStructPage->contentLen > 0) ? pHttpStructPage->contentLen : 0);*/
}


typedef struct {
    char protocol[5 + 1];
    char ipAddress[15 + 1];
    int port;
    char urlPath[128];
} URL_STRUCT, * PURL_STRUCT;


VOID InitStructUrl(PURL_STRUCT urlStrcut) {
    urlStrcut->protocol[0] = 0x00;
    urlStrcut->ipAddress[0] = 0x00;
    urlStrcut->port = 0x00;
    urlStrcut->urlPath[0] = 0x00;
}

BOOL ParseUrl(char* url, PURL_STRUCT urlStrcut) {
    InitStructUrl(urlStrcut);

    int ptr = ExtractStrInt(url, ':', urlStrcut->protocol, sizeof(urlStrcut->protocol));
    if (ptr > 0) {
        int tmpPtr;

        // Check if format OK
        if (url[ptr] != ':' || url[ptr + 1] != '/' || url[ptr + 2] != '/')
            return FALSE;
        ptr += 3;

        if (strchr(url + ptr, ':')) {
            char portTmp[5 + 1] = "\0";
            tmpPtr = ExtractStrInt(url + ptr, ':', urlStrcut->ipAddress, sizeof(urlStrcut->ipAddress));
            if (tmpPtr) {
                ptr += tmpPtr + 1;
            }
            if (strchr(url + ptr, '/')) {
                tmpPtr = ExtractStrInt(url + ptr, '/', portTmp, sizeof(portTmp));
                urlStrcut->port = atoi(portTmp);
                if (tmpPtr) {
                    ptr += tmpPtr;

                    ExtractStrInt(url + ptr, '\0', urlStrcut->urlPath, sizeof(urlStrcut->urlPath));
                    /*tmpPtr = ExtractStrInt(url + ptr, '\0', urlStrcut->urlPath, sizeof(urlStrcut->urlPath));
                    if (tmpPtr){
                        //ptr += tmpPtr + 1;
                    }*/
                }
            } else {
                ExtractStrInt(url + ptr, '\0', portTmp, sizeof(portTmp));
                /*tmpPtr = ExtractStrInt(url + ptr, '\0', portTmp, sizeof(portTmp));
                urlStrcut->port = atoi(portTmp);
                if (tmpPtr){
                    //ptr += tmpPtr + 1;
                }*/
            }
        } else {
            if (strchr(url + ptr, '/')) {
                tmpPtr = ExtractStrInt(url + ptr, '/', urlStrcut->ipAddress, sizeof(urlStrcut->ipAddress));
                if (tmpPtr) {
                    ptr += tmpPtr;

                    ExtractStrInt(url + ptr, '\0', urlStrcut->urlPath, sizeof(urlStrcut->urlPath));
                    /*tmpPtr = ExtractStrInt(url + ptr, '\0', urlStrcut->urlPath, sizeof(urlStrcut->urlPath));
                    if (tmpPtr){
                        //ptr += tmpPtr + 1;
                    }*/
                }
            } else {
                ExtractStrInt(url + ptr, '\0', urlStrcut->ipAddress, sizeof(urlStrcut->ipAddress));
                /*tmpPtr = ExtractStrInt(url + ptr, '\0', urlStrcut->ipAddress, sizeof(urlStrcut->ipAddress));
                if (tmpPtr){
                    //ptr += tmpPtr + 1;
                }*/
            }
        }
        return TRUE;
    }
    return FALSE;
}
BOOL TestAllHttpsRedirect(PHTTP_STRUC* pHttpStructInvalide, FILE* pFile) {
    int match = 0;
    URL_STRUCT* urlStrcutInvalide = (URL_STRUCT*)malloc(sizeof(URL_STRUCT));
    if (urlStrcutInvalide == NULL)
        return TRUE;

    /// Redirection http[s]://domain/xxx -> http[s]://domain/    x 3
    for (int i = 1; i < ARRAY_SIZE_CHAR(invalideUrlFilePath); i++) {
        if (strcmp(pHttpStructInvalide[0]->redirectionPath, pHttpStructInvalide[i]->redirectionPath) == 0)
            match++;
    }
    if (match == 2) {
        printf("\t\t[i] All requests return %s\n", pHttpStructInvalide[0]->redirectionPath);
        return TRUE;
    } else
        match = 0;


    /// Redirection http[s]://domain/xxx -> http[s]://domain/xxx
    for (int i = 0; i < ARRAY_SIZE_CHAR(invalideUrlFilePath); i++) {
        if (!ParseUrl((char*)pHttpStructInvalide[i]->redirectionPath, urlStrcutInvalide))
            return TRUE;
        if (strcmp(urlStrcutInvalide->urlPath, invalideUrlFilePath[i]) == 0)
            match++;
    }
    if (match == ARRAY_SIZE_CHAR(invalideUrlFilePath)) {
        if (urlStrcutInvalide->port != 0)
            printf("\t\t[i] All requests return %s://%s:%i/[PAGE_NAME]\n", urlStrcutInvalide->protocol, urlStrcutInvalide->ipAddress, urlStrcutInvalide->port);
        else
            printf("\t\t[i] All requests return %s://%s/[PAGE_NAME]\n", urlStrcutInvalide->protocol, urlStrcutInvalide->ipAddress); // PORT !!!
    }

    free(urlStrcutInvalide);
    return match == ARRAY_SIZE_CHAR(invalideUrlFilePath);


    // http://192.168.59.45/.bash_history       301 -  0     -> https://192.168.59.45/.bash_history
}
int StartHttpDirEnum(RequestInfoStruct requestInfoStruct, FILE* pFile, ENUM_PAGE_NOT_FOUND enumPageNotFound, ENUM_PAGE_NOT_FOUND enumDirNotFound, PHTTP_STRUC pHttpStructInvalide, char** wordListCommonFile, UINT wordListCommonSize, pRedirectionNode* pHeadRedirUrl, pRedirectionNode* pTailRedirUrl) {
    INT nbFirstMatch = -1;
    for (UINT i = 0; i < wordListCommonSize; i++) {
        PHTTP_STRUC pHttpStructPage = GetHttpRequest2(requestInfoStruct.ipAddress, requestInfoStruct.port, (char*)wordListCommonFile[i], "HEAD", requestInfoStruct.httpAuthHeader, requestInfoStruct.isSSL, pFile);
        if (pHttpStructPage != NULL) {
            LoadingBar(i + 1, wordListCommonSize);
            switch (enumPageNotFound) {
            case BASE_CODE_ERROR_CODE:
                if (!IS_HTTP_ERROR(pHttpStructPage->returnCode)) {
                    if (IS_HTTP_REDIRECTS(pHttpStructPage->returnCode)) {
                        PrintDirFindRedirect(pHttpStructPage, requestInfoStruct.ipAddress, pFile, requestInfoStruct.isSSL);
                        if (nbFirstMatch == -1)
                            nbFirstMatch = i;

                        // TEST
                        // redirectionPath = 0x00000164494a67c0 " xxxaaa.php"
                        /*if (AppendRedirectNode(pHeadRedirUrl, pTailRedirUrl, pHttpStructPage->redirectionPath))
                            printf("[AppendRedirectNode] %s !!!\n", pHttpStructPage->redirectionPath);*/


                            /*if (*pHeadRedirUrl == NULL) {
                                *pHeadRedirUrl = InitStructUrlRedirect(pHttpStructPage->redirectionPath);
                                if (*pHeadRedirUrl == NULL)
                                    return FALSE;
                                *pTailRedirUrl = *pHeadRedirUrl;
                            } else
                                *pTailRedirUrl = AppendRedirectNode(*pTailRedirUrl, pHttpStructPage->redirectionPath);*/
                    } else {
                        BOOL isAntiDir = (enumDirNotFound == BASE_INVALID_CODE_LEN_DIR &&
                            pHttpStructPage->returnCode == STATUS_CODE_OK &&
                            pHttpStructPage->contentLen == NO_BODY_DATA);
                        if (!isAntiDir)
                            PrintDirFind(pHttpStructPage, requestInfoStruct.ipAddress, pFile, requestInfoStruct.isSSL);
                        if (nbFirstMatch == -1)
                            nbFirstMatch = i;
                    }
                }
                break;
            case BASE_REDIRECT_CODE:
                if (IS_HTTP_REDIRECTS(pHttpStructPage->returnCode) && strcmp(pHttpStructPage->redirectionPath, pHttpStructInvalide->redirectionPath) != 0) {
                    PrintDirFindRedirect(pHttpStructPage, requestInfoStruct.ipAddress, pFile, requestInfoStruct.isSSL);
                    if (nbFirstMatch == -1)
                        nbFirstMatch = i;
                }
                break;
            case BASE_DATA_SIZE_CODE:
                if (pHttpStructInvalide->contentLen != pHttpStructPage->contentLen) {
                    if (IS_HTTP_REDIRECTS(pHttpStructPage->returnCode)) {
                        PrintDirFindRedirect(pHttpStructPage, requestInfoStruct.ipAddress, pFile, requestInfoStruct.isSSL);
                        if (nbFirstMatch == -1)
                            nbFirstMatch = i;
                    } else {
                        PrintDirFind(pHttpStructPage, requestInfoStruct.ipAddress, pFile, requestInfoStruct.isSSL);
                        if (nbFirstMatch == -1)
                            nbFirstMatch = i;
                    }
                }
                break;
            default:
                break;
            }
            FreePHTTP_STRUC(pHttpStructPage);
        }
    }
    return nbFirstMatch;
}



char** CreateTableBackup(UINT numIndexFile, UINT* nbLineListBackup) {
    char** wordListBackupFile = (char**)calloc(ARRAY_SIZE_CHAR(wordListBackupAppendFile), sizeof(char*));
    if (wordListBackupFile == NULL)
        return NULL;

    for (int i = 0; i < ARRAY_SIZE_CHAR(wordListBackupAppendFile); i++) {
        //printf("%s%s\n", wordListIndexFile[numIndexFile], strToAppend[i]);

        wordListBackupFile[i] = (char*)malloc(MAX_PATH);
        if (wordListBackupFile[i] == NULL)
            return FALSE;
        sprintf_s(wordListBackupFile[i], MAX_PATH, "%s%s", wordListIndexFile[numIndexFile], wordListBackupAppendFile[i]);

        (*nbLineListBackup)++;
    }
    return wordListBackupFile;
}
VOID ClearTableBackup(char** wordListBackupFile, UINT nbLineListBackup) {
    for (UINT i = nbLineListBackup; nbLineListBackup != 0; i++)
        free(wordListBackupFile[i]);
    free(wordListBackupFile);
}

#define DEBUG_TEST 1

BOOL HttpDirEnum(RequestInfoStruct requestInfoStruct, ServerType serverType, FILE* pFile) {

    printf("\t[HTTP%s] %s:%i - HTTP%s Directory Enumeration\n", requestInfoStruct.isSSL ? "S" : "", requestInfoStruct.ipAddress, requestInfoStruct.port, requestInfoStruct.isSSL ? "S" : "");

    ENUM_PAGE_NOT_FOUND enumPageNotFound;
    PHTTP_STRUC pHttpStructInvalide = InitPHTTP_STRUC(1);
    pRedirectionNode headRedirUrl = NULL, tailRedirUrl = NULL;

    if (pHttpStructInvalide == NULL)
        return FALSE;

    // if BASE_INVALID_CODE_LEN_DIR disable directories !!!
    ENUM_PAGE_NOT_FOUND enumDirNotFound = SetDirectoryNotFound(pHttpStructInvalide, requestInfoStruct, pFile);
    enumPageNotFound = SetFileNotFound(pHttpStructInvalide, requestInfoStruct, pFile);
    if (enumPageNotFound == BASE_NOT_FOUND) {
        FreePHTTP_STRUC(pHttpStructInvalide);
        return FALSE;
    }

    printf("\t\tURL\t\t\t\t   %s      Code - Length\tRedirection\n", requestInfoStruct.isSSL ? " " : "");

    // Word List - Git
    if (StartHttpDirEnum(requestInfoStruct, pFile, enumPageNotFound, enumDirNotFound, pHttpStructInvalide, (char**)wordListGitFile, ARRAY_SIZE_CHAR(wordListGitFile), &headRedirUrl, &tailRedirUrl)) {

        printf("\t\t[!] Github file exposed !!!\n");
    }

    // Word List - Index
    int numIndexFile = StartHttpDirEnum(requestInfoStruct, pFile, enumPageNotFound, enumDirNotFound, pHttpStructInvalide, (char**)wordListIndexFile, ARRAY_SIZE_CHAR(wordListIndexFile), &headRedirUrl, &tailRedirUrl);

    // Word List - Backup
    if (numIndexFile != -1) {
        UINT nbLineListBackup = 0;
        char** wordListBackupFile = CreateTableBackup(numIndexFile, &nbLineListBackup);
        StartHttpDirEnum(requestInfoStruct, pFile, enumPageNotFound, enumDirNotFound, pHttpStructInvalide, (char**)wordListBackupFile, nbLineListBackup, &headRedirUrl, &tailRedirUrl);
    }



    StartHttpDirEnum(requestInfoStruct, pFile, enumPageNotFound, enumDirNotFound, pHttpStructInvalide, (char**)wordListCommonFile, ARRAY_SIZE_CHAR(wordListCommonFile), &headRedirUrl, &tailRedirUrl);




#if !DEBUG_TEST
    //StartHttpDirEnum(ipAddress, port, httpAuthHeader, pFile, isSSL, enumPageNotFound, enumDirNotFound, pHttpStructInvalide, (char**)wordListCommonDir, ARRAY_SIZE_CHAR(wordListCommonDir), &headRedirUrl, &tailRedirUrl);
    StartHttpDirEnum(requestInfoStruct, pFile, enumPageNotFound, enumDirNotFound, pHttpStructInvalide, (char**)wordListCommonDir, ARRAY_SIZE_CHAR(wordListCommonDir), &headRedirUrl, &tailRedirUrl);

    // TO add wordListBackUpFile
    // StartHttpDirEnum(requestInfoStruct, pFile, enumPageNotFound, enumDirNotFound, pHttpStructInvalide, (char**)wordListBackUpFile, ARRAY_SIZE_CHAR(wordListBackUpFile), &headRedirUrl, &tailRedirUrl);
#endif


    switch (serverType) {
    case ApacheHttpd:
        StartHttpDirEnum(requestInfoStruct, pFile, enumPageNotFound, enumDirNotFound, pHttpStructInvalide, (char**)wordListApacheFile, ARRAY_SIZE_CHAR(wordListApacheFile), &headRedirUrl, &tailRedirUrl);
        StartHttpDirEnum(requestInfoStruct, pFile, enumPageNotFound, enumDirNotFound, pHttpStructInvalide, (char**)wordListApacheDir, ARRAY_SIZE_CHAR(wordListApacheDir), &headRedirUrl, &tailRedirUrl);
        break;
    case ApacheTomcat:
        StartHttpDirEnum(requestInfoStruct, pFile, enumPageNotFound, enumDirNotFound, pHttpStructInvalide, (char**)wordListApacheTomcatFile, ARRAY_SIZE_CHAR(wordListApacheTomcatFile), &headRedirUrl, &tailRedirUrl);
        StartHttpDirEnum(requestInfoStruct, pFile, enumPageNotFound, enumDirNotFound, pHttpStructInvalide, (char**)wordListApacheTomcatDir, ARRAY_SIZE_CHAR(wordListApacheTomcatDir), &headRedirUrl, &tailRedirUrl);
        break;
    case WebServerIIS:
        StartHttpDirEnum(requestInfoStruct, pFile, enumPageNotFound, enumDirNotFound, pHttpStructInvalide, (char**)wordListIisFile, ARRAY_SIZE_CHAR(wordListIisFile), &headRedirUrl, &tailRedirUrl);
        if (enumDirNotFound != BASE_INVALID_CODE_LEN_DIR)
            StartHttpDirEnum(requestInfoStruct, pFile, enumPageNotFound, enumDirNotFound, pHttpStructInvalide, (char**)wordListIisFDir, ARRAY_SIZE_CHAR(wordListIisFDir), &headRedirUrl, &tailRedirUrl);
        break;
    default:
        break;
    }

    StartHttpDirEnum(requestInfoStruct, pFile, enumPageNotFound, enumDirNotFound, pHttpStructInvalide, (char**)wordListIisFile, ARRAY_SIZE_CHAR(wordListIisFile), &headRedirUrl, &tailRedirUrl);

    /*PrintRedirectionNode(headRedirUrl);


    printf("\t[HTTP%s] %s:%i - HTTP%s Backup Enumeration\n", requestInfoStruct.isSSL ? "S" : "", requestInfoStruct.ipAddress, requestInfoStruct.port, requestInfoStruct.isSSL ? "S" : "");
    StartHttpDirEnum(requestInfoStruct, pFile, enumPageNotFound, enumDirNotFound, pHttpStructInvalide, (char**)wordListBackupFile, ARRAY_SIZE_CHAR(wordListBackupFile), &headRedirUrl, &tailRedirUrl);
    ClearRedirectionNode(headRedirUrl);*/

    FreePHTTP_STRUC(pHttpStructInvalide);
    return TRUE;
}