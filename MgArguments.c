#include <windows.h>
#include <stdio.h>
#include "MgArguments.h"

#define MAX_IP_ADDR_SIZE 15
#define MIN_IP_ADDR_SIZE 7


BOOL GetPortList(char* portListRaw, pArguments listAgrument) {
    char* next_token = NULL;
    size_t maxNbPort = strlen(portListRaw) / 2;
    char* portList = strtok_s(portListRaw, ",", &next_token);
    listAgrument->nbPort = 0;

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
        listAgrument->portList = portListInt;
        listAgrument->nbPort = 1;
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
        portListInt = (int*)realloc(portListInt, (countPort + 1) * sizeof(int));
        if (portListInt == NULL)
            return FALSE;

        listAgrument->portList = portListInt;
        listAgrument->nbPort = countPort;
    }
    return TRUE;
}

VOID PrintMenu() {
    printf("\n\nNetworkInfoGather.exe -l\n");
    printf("NetworkInfoGather.exe -i INTERFACE_NB [-sD/-sI/-sA/-sP/-sT]|[-t IP_ADDRESS] [-A/-sV/-b] [-p PORTS/-ps] [-o FILEPATH] \n\n");

    printf("Select interface:\n");
    printf("\t-l\t\tList interfaces\n");
    printf("\t-i INTERFACE_NB Select the interface\n\n");

    printf("Select host scan:\n");
    printf("\t-sD\t\tDisable host scan (Must be used with -t).\n");
    printf("\t-sI\t\tSelect ICMP scan.\n");
    printf("\t-sA\t\tSelect ARP scan [DEFAULT].\n");
    printf("\t-sP\t\tSelect passif mode (Require Administrator privilege).\n");
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
    


    
}
BOOL GetArguments(int argc, char* argv[], pArguments listAgrument) {
    listAgrument->isListInterface = FALSE;
    listAgrument->interfaceNb = 0;
    listAgrument->typeOfScan = ARP_Scan;
    listAgrument->advancedScan = FALSE;
    listAgrument->portScan = FALSE;
    listAgrument->bruteforce = FALSE;
    listAgrument->ouputFile = NULL;
    listAgrument->ipAddress = NULL;
    listAgrument->portList = NULL;
    listAgrument->nbPort = 0;

    if (argc == 1) {
        PrintMenu();
        return FALSE;
    } else if (argc == 2 && (strcmp(argv[1], "-l") == 0)) {
        listAgrument->isListInterface = TRUE;
        return TRUE;
    } else {
        for (int count = 1; count < argc; count++) {
            size_t argLen = strlen(argv[count]);
            if ((argv[count][0] == '-' || argv[count][0] == '/') && argLen > 1) {
                if (argLen == 2) {
                    BOOL nextNotNull = (argc > count + 1);

                    if (nextNotNull && argv[count][1] == 'o') {
                        if (fopen_s(&listAgrument->ouputFile, argv[count + 1], "a") != 0) {
                            printf("[x] Fail to open file %s\n", argv[count + 1]);
                            return FALSE;
                        }
                        count++;
                    } else if (nextNotNull && argv[count][1] == 't') {
                        size_t strSize = strlen(argv[count + 1]);
                        listAgrument->ipAddress = (char*)calloc(strSize + 1, 1);
                        if (listAgrument->ipAddress == NULL)
                            return FALSE;
                        strcpy_s(listAgrument->ipAddress, strSize + 1, argv[count + 1]);
                        count++;
                    } else if (nextNotNull && argv[count][1] == 'i') {
                        listAgrument->interfaceNb = atoi(argv[count + 1]);
                        count++;
                    } else if (nextNotNull && argv[count][1] == 'p') {
                        listAgrument->portScan = TRUE;
                        GetPortList(argv[count + 1], listAgrument); // check error
                        count++;
                    } else if (argv[count][1] == 'A') {
                        listAgrument->portScan = TRUE;
                        listAgrument->advancedScan = TRUE;
                        listAgrument->bruteforce = TRUE;
                    } else if (argv[count][1] == 'b') {
                        listAgrument->bruteforce = TRUE;
                    } else if (argv[count][1] == 'h' || argv[count][1] == '?') {
                        PrintMenu();
                        return FALSE;
                    }
                } else if (argLen == 3) {
                    if (argv[count][1] == 's' && strlen(argv[count]) == 3) {
                        if (argv[count][2] == 'D')
                            listAgrument->typeOfScan = Disable_Scan;
                        else if (argv[count][2] == 'I')
                            listAgrument->typeOfScan = ICMP_Scan;
                        else if (argv[count][2] == 'A')
                            listAgrument->typeOfScan = ARP_Scan;
                        else if (argv[count][2] == 'P')
                            listAgrument->typeOfScan = Passif_Packet_Sniffing;
                        else if (argv[count][2] == 'T')
                            listAgrument->typeOfScan = Passif_Scan;
                        
                        else if (argv[count][2] == 'V') {
                            listAgrument->portScan = TRUE;
                            listAgrument->advancedScan = TRUE;
                        }
                    } else if (argv[count][1] == 'p' && argv[count][2] == 's') {
                        listAgrument->portScan = TRUE;
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