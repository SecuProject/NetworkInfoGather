#include <winsock2.h>
#include <ws2tcpip.h>

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <lm.h>

#include "MgArguments.h"
#include "EnumFtp.h"
#include "wordlist.h"
#include "Network.h"


// InetPton(AF_INET, _T("192.168.1.1"), &RecvAddr.sin_addr.s_addr);
#pragma warning(disable:4996) 


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
        int* portListInt = (int*)xcalloc(1, sizeof(int));
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
        int* portListInt = (int*)xcalloc(maxNbPort, sizeof(int));
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
DWORD CheckFQDN(char* fqdn) {
    //const char* invalidChar = "& '~|";
    WCHAR* nextTokent = NULL;
    UINT i;
    char* pch;
    DWORD pComputerName;

    if (strlen(fqdn) < 7)
        return FALSE;

    pch = strchr(fqdn, '.');
    if (pch != NULL)
        pComputerName = (DWORD)(pch - fqdn);

    for (i = 0; pch != NULL; i++) {
        //printf("%s\n", pch);
        pch = strchr(pch + 1, '.');
    }
    if (i == 2)
        return pComputerName;

    return FALSE;
}

VOID PrintMenuBruteForce() {
    printf("NetworkInfoGather.exe bf PROTOCOL HOSTNAME/TARGET_IP[:PORT] [-u username/-U usernameFile.lst] [-p password/-P passwordFile.lst] [-d domain] [--continue-success]\n\n");
    
    printf("PROTOCOL:\n");
    printf("\tftp\n");
    printf("\thttp\n");
    printf("\thttps\n");
    printf("\tsmb\n");
    printf("\trpc\n\n");
    /*printf("\tldap\n\n");
    printf("\tssh\n\n");
    printf("\ttelnet\n\n");
    printf("\trdp\n\n");
    printf("\trdp\n\n");*/


    printf("HOSTNAME:\n");
    printf("\tThis is required only for RPC brute force !\n\n");
    printf("TARGET_IP:\n");
    printf("\tTarget IP Address and port (if port not set the default port will be used).\n");
    printf("\t\te.g. '192.168.1.1' or '192.168.1.1:80'\n\n");   


    printf("Optional parameter:\n");
    printf("\t-u username\t\tThe username of the targeted account\n");
    printf("\t-p password\t\tThe password of the targeted account\n");
    printf("\t-d domain\t\tThe domain name of the targeted account\n");
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
    printf("\tzerologon [-c/-e] -d dc1.domain.local\n");
    printf("\t\t-d [FQDN]\tServer FQDN [REQUIRED]\n");
    printf("\t\t-c\t\tCheck if server is vulnerable [DEFAULT]\n");
    printf("\t\t-e\t\tExploit vulnerable and set DC password to NULL\n\n");
    printf("\tms17 IP_ADDRESS\n");
    printf("\t\tNote: check for vulnerable ms17-010 (eternalblue)\n");
    printf("\tdoublep IP_ADDRESS\n");
    printf("\t\tNote: check for vulnerable Double Pulsar backdoor\n");
    printf("\tprintnightmare IP_ADDRESS\n");
    printf("\t\tNote: check for vulnerable CVE-2021-1675/CVE-2021-34527\n\n");
    printf("IP_ADDRESS:\n");
    printf("\te.g. '192.168.1.1'\n\n");
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

    printf("Select option(s):\n");
    printf("\t-h\t\tPrint help menu\n");
    printf("\t-t IP_ADDRESS\tTarget IP Address or range. Allowed formats:\n");
    printf("\t\t\t\te.g. '192.168.1.1' or '192.168.1.1-5' or '192.168.1.0/24'\n");
    printf("\t-ps\t\tEnable port scan\n");
    printf("\t-p [PORT_NB]\tUse custom port list port scan (If not set will use default list)\n");
    printf("\t\t\t\te.g. -p 80,443,8080 or -p- for all ports\n");
    printf("\t-sV\t\tScan for service version\n");
    printf("\t-b\t\tEnable brute force enable\n");
    printf("\t-A\t\tAggressive scan (grab banner and brute force enable)\n");
    printf("\t-o FILEPATH\tOutput into a file\n");
    return;
}
VOID PrintMenuEnum(){
    printf("NetworkInfoGather.exe enum PROTOCOL IP_ADDRESS [-u USERNAME] [-p PASSWORD]\n\n");
    printf("NetworkInfoGather.exe enum smb IP_ADDRESS [-u USERNAME] [-p PASSWORD] [-S] [-U]\n");
    printf("NetworkInfoGather.exe enum ftp IP_ADDRESS [-u USERNAME] [-p PASSWORD] [-P PORT]\n\n");

    printf("PROTOCOL:\n");
    //printf("\thttp\n");
    //printf("\thttps\n");
    printf("\tsmb\tShare enumeration / User enumeration\n");
    printf("\t\t-U\tShare enumeration\n");
    printf("\t\t-S\tUser enumeration\n");
    printf("\tftp\tEnumerate File Transfer Server\n\n");
    printf("\t\t-P PORT\tSet custom port (default: 21)\n");
    //printf("\trpc\n\n");


    printf("IP_ADDRESS:\n");
    printf("\tTarget IP Address\n");

    printf("OPTIONS:\n");
    printf("\t-u USERNAME\t\tThe username of the targeted account\n");
    printf("\t-p PASSWORD\t\tThe password of the targeted account\n");
    return;
}
VOID PrintMenuCurl() {
    printf("NetworkInfoGather.exe curl [http|https]://IP_ADDRESS/resource [-v] [-o FILE] [-X GET] []\n\n");
    printf("URL:\n");
    printf("\tProtocol\n");
    printf("\tTarget IP Address\n");
    printf("\tPort number\n");
    printf("OPTIONS:\n");
    printf("\t-v\t\tEnable verbose mode\n");
    printf("\t-I\t\tSet method to HEAD and print header\n");
    printf("\t-a\t\tSet random user agent\n");

    printf("\t-A USER_AGENT\tSet specific user agent\n");
    printf("\t-o PATH\t\tWrite to file instead of stdout\n");
    printf("\t-X METHOD\tSpecify request method to use\n\n");

    //printf("\t-L\t\tFollow redirection\n");
    //printf("\t-k\t\t...\n\n");
}
VOID PrintMenuDos() {
    printf("NetworkInfoGather.exe dos -t IP_ADDERSS -p PORT [-aS|-aC|-aU|-aP|-aH] [-d data] [-t time]\n\n");
    printf("REQUIRED:\n");
    printf("-t IP_ADDERSS\tIP address of the target\n");
    printf("-p PORT\t\tPort to target\n\n");


    printf("OPTIONS:\n");
    printf("-d DATA\t\tSet the amount of data to send (default: 5 Kb)\n");
    printf("-T time\t\tSet the amount of time in sec (default: 5 sec)\n\n");
    //printf("-n Thread\tSet the number of thread to run\n");
   // printf("-s data\tSet the task schedule\n");

    printf("OPTIONS - TYPE OF ATTACK:\n");
    printf("-aS\t\tTCP flood (SYN) attack\n");
    printf("-aC\t\tTCP flood (Full connection)\n");
    printf("-aU\t\tUDP flood (Full connection)\n");
    printf("-aP\t\tPing flood\n");
    printf("-aH\t\tHTTP flood (KeepAlive -> slowloris)\n\n");
}
VOID PrintMenu() {
    printf("\n\nNetworkInfoGather.exe {scan,bf,exploit,enum,dos,WAN,curl}\n\n");
    printf("OPTION:\n");
    printf("\tscan\tWill scan the network\n");
    printf("\tbf\tbrute force protocol\n");
    printf("\texploit\tExploit vulnerability\n");
    printf("\tenum\tPerform enumeration\n");
    printf("\tdos\tDenial of service attack\n");
    printf("\tWAN\tPrint external IP address of the system\n");
    printf("\tcurl\tWeb request\n");
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
                            pScanStruct->ipAddress = (char*)xcalloc(strSize + 1, 1);
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
                    if (argv[count][1] == 's'){
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
                    } else if (argv[count][1] == 'p' && argv[count][2] == '-') {
                        pScanStruct->portScan = TRUE;
                        pScanStruct->nbPort = 65535;
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
                printf("[!] Unknown argument %s\n", argv[count]);
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
        userTab = (char**)xcalloc(nbUsername, sizeof(char*));
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


BOOL HostnameToIp(char* hostname, char** ppIpAddress){
    struct hostent* he;
    struct in_addr** addr_list;
    *ppIpAddress = (char*)malloc(IP_ADDRESS_LEN + 1);
    if (*ppIpAddress == NULL)
        return FALSE;

    he = gethostbyname(hostname);
    if (he == NULL){
        printf("[x] Fail to resolve the hostname (%i)!\n", WSAGetLastError());
        free(*ppIpAddress);
        return FALSE;
    }
    addr_list = (struct in_addr**)he->h_addr_list;
    strcpy_s(*ppIpAddress, IP_ADDRESS_LEN + 1, inet_ntoa(*addr_list[0]));
    printf("[i] %s resolved to %s\n", hostname, *ppIpAddress);
    return TRUE;
}



BOOL AddStrToStruct(char* name, char* argData, char** structData){
    size_t stringSize = strlen(argData) + 1;
    *structData = (char*)malloc(stringSize);
    if (*structData == NULL){
        printf("[!] Fail to allocate '%s' in memory !\n", name);
        return FALSE;
    }
    strcpy_s(*structData, stringSize, argData);
    return TRUE;
}
BOOL ParseBruteForceArg(int argc, char* argv[], pBruteforceStruct pBruteforceStruct) {
    StructWordList structWordList;
    structWordList.nbUsername = 0;
    structWordList.usernameTab = NULL;
    structWordList.nbPassword = 0;
    structWordList.passwordTab = NULL;
    pBruteforceStruct->domain = NULL;
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
    } else if (strcmp(argv[2], "smb") == 0) {
        pBruteforceStruct->protocol = SMB;
        pBruteforceStruct->port = PORT_SMB;
    } else if (strcmp(argv[2], "rpc") == 0) {
        pBruteforceStruct->protocol = RPC;
        pBruteforceStruct->port = PORT_RPC;
    /* } else if (strcmp(argv[2], "ldap") == 0) {
        pBruteforceStruct->protocol = LDAP;
        pBruteforceStruct->port = PORT_LDAP;*/
    } else {
        printf("[!] Invalid protocol !!!\n");
        PrintMenuBruteForce();
        return FALSE;
    }

    // Parse IP address and port (FORMATE: 1.1.1.1 or 1.1.1.1:53)
    if (!GetIpPortFromArg(argv[3], pBruteforceStruct)) {
        char* ipAddress = NULL;
        if (!HostnameToIp(argv[3], &ipAddress) ||
            !GetIpPortFromArg(ipAddress, pBruteforceStruct)){
            printf("[!] Invalid format for the ip address '%s'\n", argv[3]);
            printf("[i] Valid format: 192.168.1.1 or 192.168.1.1:80\n");
            return FALSE;
        }
        if (!AddStrToStruct("hostname", argv[3], &(pBruteforceStruct->hostname))){
            free(ipAddress);
            return FALSE;
        }
        free(ipAddress);
    }

    if (argc > 4) {
        for (int count = 4; count < argc; count++) {
            size_t argLen = strlen(argv[count]);
            if ((argv[count][0] == '-' || argv[count][0] == '/') && argLen == 2) {
                BOOL nextNotNull = (argc > count + 1);
                if (nextNotNull) {
                    size_t stringSize;
                    switch (argv[count][1]){
                    case 'd':
                        if (!AddStrToStruct("domain", argv[count + 1], &(pBruteforceStruct->domain)))
                            return FALSE;
                        break;
                    case 'u':
                        if (!AddStrToStruct("domain", argv[count + 1], &(pBruteforceStruct->domain)))
                            return FALSE;
                        stringSize = strlen(argv[count + 1]) + 1;
                        structWordList.usernameTab = (char**)malloc(sizeof(char*));
                        if (structWordList.usernameTab == NULL) {
                            printf("[!] Fail to allocate 'usernameTab' in memory !\n");
                            return FALSE;
                        }
                        structWordList.usernameTab[0] = (char*)malloc(stringSize);
                        if (structWordList.usernameTab[0] == NULL) {
                            free(structWordList.usernameTab);
                            return FALSE;
                        }
                        strcpy_s(structWordList.usernameTab[0], stringSize, argv[count + 1]);
                        structWordList.nbUsername = 1;
                        break;
                    case 'p':
                        stringSize = strlen(argv[count + 1]) + 1;
                        structWordList.passwordTab = (char**)malloc(sizeof(char*));
                        if (structWordList.passwordTab == NULL) {
                            printf("[!] Fail to allocate 'passwordTab' in memory !\n");
                            return FALSE;
                        }
                        structWordList.passwordTab[0] = (char*)malloc(stringSize);
                        if (structWordList.passwordTab[0] == NULL) {
                            printf("[!] Fail to allocate 'passwordTab[0]' in memory !\n");
                            return FALSE;
                        }
                        strcpy_s(structWordList.passwordTab[0], stringSize, argv[count + 1]);
                        structWordList.nbPassword = 1;
                        break;
                    case 'U':
                        structWordList.nbUsername = LoadWordList(argv[count + 1], &(structWordList.usernameTab));
                        if (structWordList.nbUsername == 0) {
                            printf("[x] Fail to open file !\n");
                            return FALSE;
                        }
                        break;
                    case 'P':
                        structWordList.nbPassword = LoadWordList(argv[count + 1], &(structWordList.passwordTab));
                        if (structWordList.nbPassword == 0) {
                            printf("[x] Fail to open file !\n");
                            return FALSE;
                        }
                        break;
                    default:
                        printf("[x] Error unkown argrument '%s'!\n", argv[count]);
                        return FALSE;
                    }
                }
                if (strcmp(argv[count], "--continueSuccess") == 0) {
                    pBruteforceStruct->continueSuccess = TRUE;
                }
            }
        }
    }

    if (structWordList.nbUsername == 0) {
        // Load default wordlist
        structWordList.usernameTab = (char**)usernameList;
        structWordList.nbUsername = sizeof(usernameList) / sizeof(char*);
    }
    if (structWordList.nbPassword == 0) {
        // Load default wordlist
        structWordList.passwordTab = (char**)passwordList;
        structWordList.nbPassword = sizeof(passwordList) / sizeof(char*);
    }
    pBruteforceStruct->structWordList = structWordList;
    return TRUE;
}
// program exploit zerologon -d dc.domain.local
BOOL ParseExploitArg(int argc, char* argv[], pExploitStruct pExploitStruct) {
    if (strcmp(argv[2], "zerologon") == 0 && argc > 4) {
        UINT checkArgValidity = 0;

        pExploitStruct->exploit = ZERO_LOGON;
        pExploitStruct->exploitZeroLogon.isOnlyCheck = TRUE;
        pExploitStruct->exploitZeroLogon.serverFQDN[0] = 0x00;
        pExploitStruct->exploitZeroLogon.computerName[0] = 0x00;

        for (int count = 2; count < argc; count++) {
            size_t argLen = strlen(argv[count]);
            if ((argv[count][0] == '-' || argv[count][0] == '/') && argLen == 2) {
                BOOL nextNotNull = (argc > count + 1);

                if (argv[count][1] == 'd' && nextNotNull) {
                    DWORD pComputerName = CheckFQDN(argv[count + 1]);
                    if (pComputerName <= 0) {
                        printf("[!] Invalid FQDN %s\n", argv[count + 1]);
                        return FALSE;
                    }
                    swprintf_s(pExploitStruct->exploitZeroLogon.serverFQDN, MAX_PATH, L"%hs", argv[count + 1]);
                    swprintf_s(pExploitStruct->exploitZeroLogon.computerName, MAX_PATH, L"%.*hs", pComputerName, argv[count + 1]);
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
    } else if (strcmp(argv[2], "ms17") == 0 && argc == 4) {
        pExploitStruct->exploit = MS17_010;
        strcpy_s(pExploitStruct->exploitMs17_010.ipAddress, 16, argv[3]);
    } else if (strcmp(argv[2], "doublep") == 0 && argc == 4) {
        pExploitStruct->exploit = DOUBLE_PULSAR;
        strcpy_s(pExploitStruct->exploitDoublePulsar.ipAddress, 16, argv[3]);
    } else if (strcmp(argv[2], "printnightmare") == 0 && argc == 4) {
        pExploitStruct->exploit = PRINT_NIGHTMARE;


        /*if (!GetIpPortFromArg(argv[3], pBruteforceStruct)){
            char* ipAddress = NULL;
            if (!HostnameToIp(argv[3], &ipAddress) ||
                !GetIpPortFromArg(ipAddress, pBruteforceStruct)){
                printf("[!] Invalid format for the IP address '%s'\n", argv[3]);
                printf("[i] Valid format: 192.168.1.1 or 192.168.1.1:80\n");
                return FALSE;
            }
        }*/
        strcpy_s(pExploitStruct->exploitPrintNightmare.ipAddress, 16, argv[3]);
    } else {
        PrintMenuExploit();
        return FALSE;
    }
    return TRUE;
}


/*
    printf("\t-A USER_AGENT\tSet specific user agent\n");
    printf("\t-o PATH\t\tWrite to file instead of stdout\n");
    printf("\t-X METHOD\tSpecify request method to use\n\n");
*/
BOOL ParseCurlArg(int argc, char* argv[], pCurlStruct pCurlStruct) {
    pCurlStruct->isVerbose = FALSE;
    pCurlStruct->isSsl = FALSE;
    pCurlStruct->hostUrl = NULL;
    pCurlStruct->filePath = NULL;
    pCurlStruct->userAgent = NULL;
    pCurlStruct->method = NULL;

    pCurlStruct->agentInfo = FALSE;
    pCurlStruct->agentRand = FALSE;

    for (UINT i = 2; (int)i < argc; i++) {
        if ((argv[i][0] == '-'|| argv[i][0] == '/') && argv[i][1] != 0x00) {
            if (strlen(argv[i]) == 2) {
                if (i + 1 < (UINT)argc) { // TO CHECK !!!
                    switch (argv[i][1]) {
                    case 'A':
                        pCurlStruct->method = argv[i + 1];
                        break;
                    case 'o':
                        pCurlStruct->filePath = argv[i + 1];
                        break;
                    case 'X':
                        pCurlStruct->userAgent = argv[i + 1];
                        break;
                    default:
                        break;
                    }
                }
                switch (argv[i][1]) {
                case 'I':
                    pCurlStruct->agentInfo = TRUE;
                    break;
                case 'a':
                    pCurlStruct->agentRand = TRUE;
                    break;
                case 'v':
                    pCurlStruct->isVerbose = TRUE;
                    break;
                default:
                    break;
                }
            }
        } else {
            size_t strLen = strlen(argv[i]) + (size_t)1;
            if (MATCHN(argv[i], "https://", 8)) {
                pCurlStruct->isSsl = TRUE;
                pCurlStruct->hostUrl = (char*)malloc(strLen);
                if (pCurlStruct->hostUrl == NULL)
                    return FALSE;
                strcpy_s(pCurlStruct->hostUrl, strLen, argv[i]);
            }else if (MATCHN(argv[i], "http://", 7)) {
                pCurlStruct->hostUrl = (char*)malloc(strLen);
                if (pCurlStruct->hostUrl == NULL)
                    return FALSE;
                strcpy_s(pCurlStruct->hostUrl, strLen, argv[i]);
            }
        }
    }
    // Check incompatible arguments
    if (pCurlStruct->agentRand && pCurlStruct->agentInfo) {
        printf("[x] Arg error (-A and -a)!\n");
    }
    if (pCurlStruct->method != NULL && pCurlStruct->agentInfo) {
        printf("[x] Arg error (-I and -X)!\n");
    }
    // Check requirements 
    if (pCurlStruct->hostUrl == NULL)
        return FALSE;
    return TRUE;
}

BOOL ParseDosArg(int argc, char* argv[], pDosStruct pDosStruct) {
    // default: program dos IP port => 4
    if (argc < 4 || 10 < argc) {
        PrintMenuEnum();
        return FALSE;
    }
    pDosStruct->ipAddress = NULL;
    pDosStruct->port = 0;
    pDosStruct->attackType = INVALID_FULL;
    pDosStruct->time = 5*1000;
    pDosStruct->dataSize = 5*1000;

    for (UINT i = 2; (int)i < argc; i++) {
        if ((argv[i][0] == '-' || argv[i][0] == '/') && argv[i][1] != 0x00) {
            if (strlen(argv[i]) == 2 && i + 1 < (UINT)argc) {
                switch (argv[i][1]) {
                case 't':
                    pDosStruct->ipAddress = argv[i + 1];
                    break;
                case 'p':
                    pDosStruct->port = atoi(argv[i + 1]);
                    break;
                case 'd':
                    pDosStruct->dataSize = atoi(argv[i + 1]) * 1000;
                    break;
                case 'T':
                    pDosStruct->time = atoi(argv[i + 1]) * 1000;
                    break;
                default:
                    break;
                }
                i++;
            } else if (strlen(argv[i]) == 3 && argv[i][1] == 'a') {
                switch (argv[i][2]) {
                case 'S':
                    pDosStruct->attackType = TCP_FLOOD_SYN;
                    break;
                case 'C':
                    pDosStruct->attackType = TCP_FLOOD_FULL;
                    break;
                case 'U':
                    pDosStruct->attackType = UDP_FLOOD;
                    break;
                case 'P':
                    pDosStruct->attackType = PING_FLOOD;
                    break;
                case 'H':
                    pDosStruct->attackType = HTTP_FLOOD;
                    break;
                default:
                    break;
                }
            }
        }
    }
    if (pDosStruct->attackType == INVALID_FULL) {
        printf("[x] Attack argument must by set !\n");
        PrintMenuDos();
        return FALSE;
    }
    if (pDosStruct->ipAddress == NULL) {
        printf("[x] IP Address argument must by set !\n");
        PrintMenuDos();
        return FALSE;
    }
    if (pDosStruct->attackType != PING_FLOOD && pDosStruct->port == 0) {
        printf("[x] Port argument must by set !\n");
        PrintMenuDos();
        return FALSE;
    }
    return TRUE;
}
BOOL ParseEnumArg(int argc, char* argv[], pEnumStruct pEnumStruct){
    if (argc < 4 || 10 < argc){
        PrintMenuEnum();
        return FALSE;
    }

    pEnumStruct->username = NULL;
    pEnumStruct->password = NULL;

    // FOR SMB
    pEnumStruct->enumUser = FALSE;
    pEnumStruct->enumShare = FALSE;
    pEnumStruct->port = 0;


    if (strcmp(argv[2], "smb") == 0){
        pEnumStruct->ipAddress = argv[3];
        pEnumStruct->protocol = SMB;
        for (int count = 4; count < argc; count++){
            size_t argLen = strlen(argv[count]);
            if ((argv[count][0] == '-' || argv[count][0] == '/') && argLen == 2){
                switch (argv[count][1]){
                case 'u':
                    if (argc > count + 1)
                        pEnumStruct->username = argv[count + 1];
                    break;
                case 'p':
                    if (argc > count + 1)
                        pEnumStruct->password = argv[count + 1];
                    break;
                case 'U':
                    pEnumStruct->enumUser = TRUE;
                    break;
                case 'S':
                    pEnumStruct->enumShare = TRUE;
                    break;
                default:
                    printf("[X] Unknown argument: '%s'\n !", argv[count]);
                    break;
                }
            }
        }
    } else if (strcmp(argv[2], "ftp") == 0){
        pEnumStruct->protocol = FTP;
        pEnumStruct->ipAddress = argv[3];
        pEnumStruct->port = INTERNET_DEFAULT_FTP_PORT;

        for (int count = 4; count < argc; count++){
            size_t argLen = strlen(argv[count]);
            if ((argv[count][0] == '-' || argv[count][0] == '/') && argLen == 2){
                switch (argv[count][1]){
                case 'u':
                    if (argc > count + 1)
                        pEnumStruct->username = argv[count + 1];
                    break;
                case 'p':
                    if (argc > count + 1)
                        pEnumStruct->password = argv[count + 1];
                    break;
                case 'P':
                    if (argc > count + 1)
                        pEnumStruct->port = atoi(argv[count + 1]);
                    break;
                default:
                    printf("[X] Unknown argument: '%s'\n !", argv[count]);
                    break;
                }
            }
        }
    } else {
        PrintMenuEnum();
        return FALSE;
    }
    if (!pEnumStruct->enumUser && !pEnumStruct->enumShare){
        pEnumStruct->enumUser = TRUE;
        pEnumStruct->enumShare = TRUE;
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
        } else if (strcmp(argv[1], "enum") == 0) {
            PrintMenuEnum();
            return FALSE;
        } else if (strcmp(argv[1], "curl") == 0) {
            PrintMenuCurl();
            return FALSE;  
        } else if (strcmp(argv[1], "WAN") == 0 || strcmp(argv[1], "wan") == 0) {
            pListAgrument->programMode = ModeExternalIp;
            return TRUE;  
        } else if (strcmp(argv[1], "dos") == 0) {
            PrintMenuDos();
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
        } else if (strcmp(argv[1], "enum") == 0) {
            pListAgrument->programMode = ModeEnum;
            return ParseEnumArg(argc, argv, &(pListAgrument->enumStruct));
        } else if (strcmp(argv[1], "curl") == 0) {
            pListAgrument->programMode = ModeCurl;
            return ParseCurlArg(argc, argv, &(pListAgrument->curlStruct));
        } else if (strcmp(argv[1], "dos") == 0) {
            pListAgrument->programMode = ModeDos;
            return ParseDosArg(argc, argv, &(pListAgrument->dosStruct));
        } else {
            PrintMenu();
            return FALSE;
        }
    }
    return TRUE;
}