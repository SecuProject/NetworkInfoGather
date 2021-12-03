#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "MgArguments.h"
#include "wordlist.h"
#include "Network.h"

/*
TARGET_IP -> IP of the target

TARGET_RANGE_IP -> Range of IPs to scan ????

*/
BOOL GetPortList(char* portListRaw, pScanStruct pScanStruct) {
    char* next_token = NULL;
    size_t maxNbPort = strlen(portListRaw) / 2;
    char* portList = strtok_s(portListRaw, ",", &next_token);
    pScanStruct->nbPort = 0;

    // Check if only one port
    if (portList == NULL) {
        int* portListInt = (int*)calloc(1, sizeof(int));
        if (portListInt == NULL)
            return FALSE;
        portListInt[0] = atoi(portListRaw);
        if (portListInt[0] < 0 || portListInt[0] > 65535) {
            printf("[-] Invalid port number: %d\n", portListInt[0]);
            free(portListInt);
            return FALSE;
        }
        pScanStruct->portList = portListInt;
        pScanStruct->nbPort = 1;
    } else {
        int* portListInt = (int*)calloc(maxNbPort, sizeof(int));
        if (portListInt == NULL)
            return FALSE;
        int countPort = 0;
        for (countPort = 0; portList != NULL; countPort++) {
            portListInt[countPort] = atoi(portList);
            if (portListInt[countPort] < 0 || portListInt[countPort] > 65535) {
                printf("[-] Invalid port number: %d\n", portListInt[countPort]);
                free(portListInt);
                return FALSE;
            }
            portList = strtok_s(NULL, ",", &next_token);
        }
        portListInt = (int*)xrealloc(portListInt, (countPort + 1) * sizeof(int));
        if (portListInt == NULL)
            return FALSE;

        pScanStruct->portList = portListInt;
        pScanStruct->nbPort = countPort;
    }
    return TRUE;
}

// t.t.com
BOOL CheckFQDN(char* fqdn) {
    //const char* invalidChar = "& '~|";
    char* nextTokent = NULL;
    UINT i;
    char* pch;

    if (strlen(fqdn) < 7)
        return FALSE;

    pch = strchr(fqdn, '.');
    for (i = 0; pch != NULL; i++) {
        //printf("%s\n", pch);
        pch = strchr(pch + 1, '.');
    }
    return i == 2;
}

VOID PrintMenuBruteForce() {
    printf("NetworkInfoGather.exe bf PROTOCOL TARGET_IP[:PORT] [-u username/-U usernameFile.lst] [-p password/-P passwordFile.lst] [--continue-success]\n\n");
    
    printf("PROTOCOL:\n");
    printf("\tftp\n");
    printf("\thttp\n");
    printf("\thttps\n\n");
    /*printf("\tldap\n\n");
    printf("\tsmb\n\n");
    printf("\tssh\n\n");
    printf("\ttelnet\n\n");
    printf("\trdp\n\n");
    printf("\trdp\n\n");*/


    printf("TARGET_IP:\n");
    printf("\tTarget IP Address and port (if port not set the default port will be used).\n");
    printf("\t\te.g. '192.168.1.1' or '192.168.1.1:80'\n\n");   


    printf("Optional parameter:\n");
    printf("\t-u username\t\tThe username of the targeted account\n");
    printf("\t-p password\t\tThe password of the targeted account\n");
    printf("\t-U usernameFile.lst\tThe word list of the targeted account\n");
    printf("\t-P passwordFile.lst\tThe word list of the targeted account\n");
    printf("\t--continue-success\tContinues authentication attempts even after successes\n\n");


    printf("Note:\n");
    printf("If the username and password are not set the tool will use is internal wordlist.\n\n");
    return;
}
VOID PrintMenuExploit() {
    printf("NetworkInfoGather.exe exploit EXPLOIT_NAME\n\n");

    printf("EXPLOIT_NAME:\n");
    printf("\tzeroLogon [-c/-e] -d dc1.domain.local\n");
    printf("\t\t-d\tServer FQDN [REQUIRED]\n");
    printf("\t\t-c\tCheck if server is vulnerable [DEFAULT]\n");
    printf("\t\t-e\tExploit vulnerable and set DC password to NULL\n");
    return;
}
VOID PrintMenuScan() {
    printf("\n\nNetworkInfoGather.exe scan -l\n");
    printf("NetworkInfoGather.exe scan -i INTERFACE_NB [-sD/-sI/-sA/-sP/-sT]|[-t IP_ADDRESS] [-A/-sV/-b] [-p PORTS/-ps] [-o FILEPATH] \n\n");

    printf("Select interface:\n");
    printf("\t-l\t\tList interfaces\n");
    printf("\t-i INTERFACE_NB Select the interface\n\n");

    printf("Select host scan:\n");
    printf("\t-sD\t\tDisable host scan (Must be used with -t).\n");
    printf("\t-sI\t\tSelect ICMP scan.\n");
    printf("\t-sA\t\tSelect ARP scan [DEFAULT].\n");
    printf("\t-sN\t\tSelect DNS scan.\n");
    printf("\t-sP\t\tSelect passif mode (Require Administrator privilege).\n");
    printf("\t\t\t\t-tt TIME   Define the time to sniff packets (default: 5s).\n");
    printf("\t-sT\t\tSelect passif mode (Will grab the list of host from the ARP table of the system).\n\n");

    printf("Select option:\n");
    printf("\t-h\t\tPrint help menu\n");
    printf("\t-t IP_ADDRESS\tTarget IP Address or range. Allowed formats:\n");
    printf("\t\t\t\te.g. '192.168.1.1' or '192.168.1.1-5'\n");
    printf("\t-ps\t\tEnable port scan\n");
    printf("\t-p [PORT_NB]\tUse custom port list port scan (If not set will use default list)\n");
    printf("\t\t\t\te.g. -p 80,443,8080\n");
    printf("\t-b\t\tEnable brute force enable\n");
    printf("\t-A\t\tAggressive scan (grab banner and brute force enable)\n");
    printf("\t-sV\t\tScan for service version\n");
    printf("\t-o FILEPATH\tOutput into a file\n");
    return;
}

VOID PrintMenu() {
    printf("\n\nNetworkInfoGather.exe {scan,bf,exploit} [-h]\n\n");
    printf("OPTION:\n");
    printf("\tscan\tWill scan the network\n");
    printf("\tbf\tbrute force protocol\n");
    printf("\texploit\tExploit vulnerability\n");
    return;
}

BOOL SetArgSolo(pScanStruct* pScanStruct, char* charArg) {
    switch (charArg[1]) {
    case 'A':
        (*pScanStruct)->portScan = TRUE;
        (*pScanStruct)->advancedScan = TRUE;
        (*pScanStruct)->bruteforce = TRUE;
        break;
    case 'b':
        (*pScanStruct)->bruteforce = TRUE;
        break;
    case 'H':
    case 'h':
    case '?':
        PrintMenu();
        return FALSE;
        break;
    default:
        printf("[!] Unknown argument %s\n", charArg);
        break;
    }
    return TRUE;
}

BOOL ParseScanArg(int argc, char* argv[], pScanStruct pScanStruct) {
    pScanStruct->isListInterface = FALSE;
    pScanStruct->interfaceNb = 0;
    pScanStruct->typeOfScan = ARP_Scan;
    pScanStruct->advancedScan = FALSE;
    pScanStruct->portScan = FALSE;
    pScanStruct->bruteforce = FALSE;
    pScanStruct->ouputFile = NULL;
    pScanStruct->ipAddress = NULL;
    pScanStruct->portList = NULL;
    pScanStruct->nbPort = 0;
    pScanStruct->psTimeout = 5;

    if (argc == 3 && (strcmp(argv[2], "-l") == 0)) {
        pScanStruct->isListInterface = TRUE;
        return TRUE;
    } else {
        for (int count = 2; count < argc; count++) {
            size_t argLen = strlen(argv[count]);
            if ((argv[count][0] == '-' || argv[count][0] == '/') && argLen > 1) {
                if (argLen == 2) {
                    BOOL nextNotNull = (argc > count + 1);
                    if (nextNotNull) {
                        size_t strSize;
                        switch (argv[count][1]) {
                        case 'o':
                            if (fopen_s(&pScanStruct->ouputFile, argv[count + 1], "a") != 0) {
                                printf("[x] Fail to open file %s\n", argv[count + 1]);
                                return FALSE;
                            }
                            count++;
                            break;
                        case 't':
                            strSize = strlen(argv[count + 1]);
                            pScanStruct->ipAddress = (char*)calloc(strSize + 1, 1);
                            if(pScanStruct->ipAddress == NULL)
                                return FALSE;
                            strcpy_s(pScanStruct->ipAddress, strSize + 1, argv[count + 1]);
                            count++;
                            break;
                        case 'i':
                            pScanStruct->interfaceNb = atoi(argv[count + 1]);
                            count++;
                            break;
                        case 'p':
                            pScanStruct->portScan = TRUE;
                            GetPortList(argv[count + 1], pScanStruct); // check error
                            count++;
                            break;
                        default:
                            if (!SetArgSolo(&pScanStruct, argv[count]))
                                return FALSE;
                            break;
                        }
                    } else {
                        if (!SetArgSolo(&pScanStruct, argv[count]))
                            return FALSE;
                    }
                } else if (argLen == 3) {
                    if (argv[count][1] == 's' && strlen(argv[count]) == 3){
                        switch (argv[count][2]) {
                        case 'D':
                            pScanStruct->typeOfScan = Disable_Scan;
                            break;
                        case 'I':
                            pScanStruct->typeOfScan = ICMP_Scan;
                            break;
                        case 'A':
                            pScanStruct->typeOfScan = ARP_Scan;
                            break;
                        case 'P':
                            pScanStruct->typeOfScan = Passif_Packet_Sniffing;
                            break;
                        case 'N':
                            pScanStruct->typeOfScan = DNS_Scan;
                            break;
                        case 'T':
                            pScanStruct->typeOfScan = Passif_Scan;
                            break;
                        case 'V':
                            pScanStruct->portScan = TRUE;
                            pScanStruct->advancedScan = TRUE;
                            break;
                        default:
                            break;
                        }
                    } else if (argv[count][1] == 'p' && argv[count][2] == 's') {
                        pScanStruct->portScan = TRUE;
                    } else if (argv[count][1] == 't' && argv[count][2] == 't' && argc > count + 1) {
                        pScanStruct->psTimeout = atoi(argv[count+1]);
                        count++;
                    } else
                        printf("[!] Unknown argument %s\n", argv[count]);
                } else if (strcmp(argv[count], "--help") == 0) {
                    PrintMenu();
                    return FALSE;
                } else
                    printf("[!] Unknown argument %s\n", argv[count]);
            } else {
                printf("[!] Unknown 2 argument %s\n", argv[count]);
            }
        }
    }
    return TRUE;
}



FILE* OpenFileF(char* fileName) {
    FILE* pFile;
    if (fopen_s(&pFile, fileName, "r") != 0) {
        printf("[x] Fail to open the file %s\n", fileName);
        return NULL;
    }
    return pFile;
}
UINT CountFileLineF(FILE* pFile) {
    int count = 1;
    char temp;

    while (fscanf_s(pFile, "%c", &temp, (int)sizeof(char)) != EOF) {
        if (temp == 10)
            count++;
    }
    fseek(pFile, 0L, SEEK_SET);
    return count;
}
UINT LoadWordList(char* filePath, char*** pOutputTab) {
    UINT nbUsername = 0;
    char** userTab;

    FILE* pFile = OpenFileF(filePath);
    if (pFile != NULL) {
        nbUsername = CountFileLineF(pFile);
        userTab = (char**)calloc(nbUsername, sizeof(char*));
        if (userTab == NULL) {
            printf("[!] Fail to allocate memory !\n");
            return FALSE;
        }

        char tempBuffer[MAX_PATH];
        for (UINT iLine = 0; fgets(tempBuffer, MAX_PATH, pFile) != NULL && nbUsername > iLine; iLine++) {
            size_t stringSize = strlen(tempBuffer) + 1;
            userTab[iLine] = (char*)malloc(stringSize);
            if (userTab[iLine] == NULL) {
                printf("[!] Fail to allocate memory !\n");
                return FALSE;
            }
            strncpy_s(userTab[iLine], stringSize, tempBuffer, stringSize - 2);
        }
        fclose(pFile);


        printf("[i] Loaded %i lines from %s\n", nbUsername, filePath);
        *pOutputTab = userTab;
        return nbUsername;
    }
    return FALSE;
}
/*
VOID LoadFileEG(){
    char** userTab = NULL;
    char* filePath = "username.lst";

    UINT nbUsername = LoadWordList(filePath, &userTab);
    if (nbUsername > 0) {
        for (UINT i = 0; nbUsername > i; i++)
                printf("[%i] '%s'\n",i+1, userTab[i]);
    }


    for (UINT i = nbUsername -1; i; i--)
        free(userTab[i]);
    free(userTab);
}
*/




BOOL ParseBruteForceArg(int argc, char* argv[], pBruteforceStruct pBruteforceStruct) {
    pBruteforceStruct->nbUsername = 0;
    pBruteforceStruct->usernameTab = NULL;
    pBruteforceStruct->nbPassword = 0;
    pBruteforceStruct->passwordTab = NULL;
    pBruteforceStruct->continueSuccess = FALSE;
    pBruteforceStruct->port = 0;

    if (argc < 4) {
        PrintMenuBruteForce();
        return FALSE;
    }
    if (strcmp(argv[2], "ftp") == 0) {
        pBruteforceStruct->protocol = FTP;
        pBruteforceStruct->port = PORT_FTP;
    } else if (strcmp(argv[2], "http") == 0) {
        pBruteforceStruct->protocol = HTTP_BASIC;
        pBruteforceStruct->port = PORT_HTTP;
    } else if (strcmp(argv[2], "https") == 0) {
        pBruteforceStruct->protocol = HTTPS_BASIC;
        pBruteforceStruct->port = PORT_HTTPS;
    /* } else if (strcmp(argv[2], "ldap") == 0) {
        pBruteforceStruct->protocol = LDAP;
        pBruteforceStruct->port = PORT_LDAP;
    } else if (strcmp(argv[2], "smb") == 0) {
        pBruteforceStruct->protocol = SMB;
        pBruteforceStruct->port = PORT_SMB;*/
    } else {
        printf("[!] Invalid protocol !!!\n");
        PrintMenuBruteForce();
        return FALSE;
    }

    // Parse IP address and port (FORMATE: 1.1.1.1 or 1.1.1.1:53)
    if (!GetIpPortFromArg(argv[3], pBruteforceStruct)) {
        printf("[!] Invalid format for the ip address '%s'\n", argv[3]);
        printf("[i] Valid format: 192.168.1.1 or 192.168.1.1:80\n");
        return FALSE;
    }

    if (argc > 4) {
        for (int count = 4; count < argc; count++) {
            size_t argLen = strlen(argv[count]);
            if ((argv[count][0] == '-' || argv[count][0] == '/') && argLen == 2) {
                BOOL nextNotNull = (argc > count + 1);
                if (argv[count][1] == 'u' && nextNotNull) {
                    size_t stringSize = strlen(argv[count + 1]) + 1;
                    pBruteforceStruct->usernameTab = (char**)calloc(1, sizeof(char*));
                    if (pBruteforceStruct->usernameTab == NULL) {
                        printf("[!] Fail to allocate 'usernameTab' in memory !\n");
                        return FALSE;
                    }
                    pBruteforceStruct->usernameTab[0] = (char*)malloc(stringSize);
                    if (pBruteforceStruct->usernameTab[0] == NULL) {
                        free(pBruteforceStruct->usernameTab);
                        return FALSE;
                    }
                    strcpy_s(pBruteforceStruct->usernameTab[0], stringSize, argv[count + 1]);
                } else if (argv[count][1] == 'p' && nextNotNull) {
                    size_t stringSize = strlen(argv[count + 1]) + 1;
                    pBruteforceStruct->passwordTab = (char**)calloc(1, sizeof(char*));
                    if (pBruteforceStruct->passwordTab == NULL) {
                        printf("[!] Fail to allocate 'passwordTab' in memory !\n");
                        return FALSE;
                    }
                    pBruteforceStruct->passwordTab[0] = (char*)malloc(stringSize);
                    if (pBruteforceStruct->passwordTab[0] == NULL) {
                        printf("[!] Fail to allocate 'passwordTab' in memory !\n");
                        return FALSE;
                    }
                    strcpy_s(pBruteforceStruct->passwordTab[0], stringSize, argv[count + 1]);
                } else if (argv[count][1] == 'U' && nextNotNull) {
                    pBruteforceStruct->nbUsername = LoadWordList(argv[count + 1], &(pBruteforceStruct->usernameTab));
                    if (pBruteforceStruct->nbUsername == 0) {
                        printf("[x] Fail to open file !\n");
                        return FALSE;
                    }
                } else if (argv[count][1] == 'P' && nextNotNull) {
                    pBruteforceStruct->nbPassword = LoadWordList(argv[count + 1], &(pBruteforceStruct->passwordTab));
                    if (pBruteforceStruct->nbPassword == 0) {
                        printf("[x] Fail to open file !\n");
                        return FALSE;
                    }
                } else {
                    printf("[x] Error !\n");
                    return FALSE;
                }
            } else if (strcmp(argv[count], "--continueSuccess") == 0) {
                pBruteforceStruct->continueSuccess = TRUE;
            }/* else {
                printf("[x] Error !\n");
                return FALSE;
            }*/
        }
    }

    if (pBruteforceStruct->nbUsername == 0) {
        // Load default wordlist
        pBruteforceStruct->usernameTab = (char**)usernameList;
        pBruteforceStruct->nbUsername = sizeof(usernameList) / sizeof(char*);
    }
    if (pBruteforceStruct->nbPassword == 0) {
        // Load default wordlist
        pBruteforceStruct->passwordTab = (char**)passwordList;
        pBruteforceStruct->nbPassword = sizeof(passwordList) / sizeof(char*);
    }

    return TRUE;
}
// program exploit zerologon -d dc.domain.local
BOOL ParseExploitArg(int argc, char* argv[], pExploitStruct pExploitStruct) {
    if (strcmp(argv[2], "zerologon") == 0 && argc > 4) {
        UINT checkArgValidity = 0;

        pExploitStruct->exploit = ZERO_LOGON;
        pExploitStruct->exploitZeroLogon.isOnlyCheck = TRUE;
        strcpy_s(pExploitStruct->exploitZeroLogon.serverFQDN, MAX_PATH, "");

        for (int count = 2; count < argc; count++) {
            size_t argLen = strlen(argv[count]);
            if ((argv[count][0] == '-' || argv[count][0] == '/') && argLen == 2) {
                BOOL nextNotNull = (argc > count + 1);

                if (argv[count][1] == 'd' && nextNotNull) {
                    if (!CheckFQDN(pExploitStruct->exploitZeroLogon.serverFQDN)) {
                        printf("[!] Invalid FQDN %s\n", pExploitStruct->exploitZeroLogon.serverFQDN);
                        return FALSE;
                    }
                    strcpy_s(pExploitStruct->exploitZeroLogon.serverFQDN, MAX_PATH, argv[count + 1]);
                } else if (argv[count][1] == 'e') {
                    pExploitStruct->exploitZeroLogon.isOnlyCheck = FALSE;
                    checkArgValidity++;
                } else if (argv[count][1] == 'c') { // Default     
                    checkArgValidity++;
                } else
                    printf("[X] Unknown argument: '%s'\n !", argv[count]);
            }
        }
        if (checkArgValidity > 1) {
            PrintMenuExploit();
            return FALSE;
        }
    } else {
        PrintMenuExploit();
        return FALSE;
    }
    return TRUE;
}

BOOL GetArguments(int argc, char* argv[], pArguments pListAgrument) {
    if (argc == 1) {
        PrintMenu();
        return FALSE;
    } else if (argc == 2) {
        if (strcmp(argv[1], "scan") == 0) {
            PrintMenuScan();
            return FALSE;
        } else if (strcmp(argv[1], "bf") == 0) {
            PrintMenuBruteForce();
            return FALSE;
        } else if (strcmp(argv[1], "exploit") == 0) {
            PrintMenuExploit();
            return FALSE;
        } else {
            PrintMenu();
            return FALSE;
        }
    } else {
        if (strcmp(argv[1], "scan") == 0) {
            pListAgrument->programMode = ModeScan;
            return ParseScanArg(argc, argv, &(pListAgrument->scanStruct));
        } else if (strcmp(argv[1], "bf") == 0) {
            pListAgrument->programMode = ModeBruteforce;
            return ParseBruteForceArg(argc, argv, &(pListAgrument->bruteforceStruct));
        } else if (strcmp(argv[1], "exploit") == 0) {
            pListAgrument->programMode = ModeExploit;
            return ParseExploitArg(argc, argv, &(pListAgrument->exploitStruct));
        } else {
            PrintMenu();
            return FALSE;
        }
    }

    return TRUE;
}