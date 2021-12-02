#include <windows.h>
#include <stdio.h>
#include "portList.h"
#include "NetDiscovery.h"

#define RECV_BUFFER_SIZE 256 * 2

#define TIMEOUT_MS      500
//#define TIMEOUT_MS      10000

const char nbtname[] = {/* netbios name packet */
        0x80,0xf0,0x00,0x10,0x00,0x01,0x00,0x00,
        0x00,0x00,0x00,0x00,0x20,0x43,0x4b,0x41,
        0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
        0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
        0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
        0x41,0x41,0x41,0x41,0x41,0x00,0x00,0x21,
        0x00,0x01
};

int display(char* name, unsigned int number, unsigned int type, NETBIOS_Info* netbiosInfo) {
    /* list taken from http://support.microsoft.com/default.aspx?scid=KB;EN-US;q163409& */
          /* 0x04 - UNIQUE */
          /* 0x80 - GROUP */

    if (name != NULL && name[0] != 0x00 && number == 0x00) {
        UINT iNetbiosTab = netbiosInfo->nbNetBIOSRemoteMachineNameTab;
        for (UINT i = 0; i < iNetbiosTab; i++) {
            if (strcmp(netbiosInfo->netBIOSRemoteMachineNameTab[i].Name, name) == 0)
                return TRUE;
        }

        netbiosInfo->netBIOSRemoteMachineNameTab = (NETBIOS_R_M_N_TAB*)realloc(netbiosInfo->netBIOSRemoteMachineNameTab, (iNetbiosTab + 1) * sizeof(NETBIOS_R_M_N_TAB));
        if (netbiosInfo->netBIOSRemoteMachineNameTab == NULL) {
            return FALSE;
        }

        char* description = (char*)malloc(RECV_BUFFER_SIZE);
        if (description == NULL)
            return FALSE;
        memset(description, 0x0, RECV_BUFFER_SIZE);


        
        for (size_t i = 0; i < strlen(name); i++) /* replaces weird chars with dots */
            if (name[i] < 31 || name[i] > 126) name[i] = '.';

        
                
        netbiosInfo->netBIOSRemoteMachineNameTab[iNetbiosTab].isGroup = (type > 0x80);
        strcpy_s(netbiosInfo->netBIOSRemoteMachineNameTab[iNetbiosTab].Name,33 , name);
        netbiosInfo->nbNetBIOSRemoteMachineNameTab++;
            
        free(description);
        return TRUE;
    }
    return FALSE;

}

BOOL EnumNetBios(NetworkPcInfo* networkPcInfo) {
//BOOL EnumNetBios(char* ipAddress) {
    SOCKET pSocket;
    SOCKADDR_IN ssin;
    int remoteAddrLen = sizeof(SOCKADDR_IN);
    UCHAR* recv;

    memset(&ssin, 0, sizeof(SOCKADDR_IN));
    ssin.sin_family = AF_INET;
    ssin.sin_port = htons(PORT_UDP_NETBIOS); /* netbios-ns */
    ssin.sin_addr.s_addr = inet_addr(networkPcInfo->ipAddress);

    printf("\t[NETBIOS] Enumeration:\n");

    pSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (pSocket == INVALID_SOCKET) {
        printf("\t\t[NETBIOS] Error: Could not create socket.\n");
        return FALSE;
    }

    recv = (UCHAR*)calloc(RECV_BUFFER_SIZE, 1);
    if (recv == NULL) {
        printf("\t\t[-] Memory error !\n");
        closesocket(pSocket);
        return FALSE;
    }
    memset(recv, 0x0, RECV_BUFFER_SIZE);

    if (sendto(pSocket, nbtname, sizeof(nbtname), 0, (struct sockaddr*)&ssin, sizeof(ssin)) < 0) {
        printf("\t\t[-] Fail to send NetBios packet !\n");
        free(recv);
        closesocket(pSocket);
        return FALSE;
    } else {
        unsigned char* ptr;
        int total;
        char temp[16];
        static int timeout = TIMEOUT_MS;

        setsockopt(pSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

        if(recvfrom(pSocket, recv, RECV_BUFFER_SIZE - 1, 0, (struct sockaddr*)&ssin, &remoteAddrLen) == SOCKET_ERROR) {
            printf("\t\t[-] Timout reached.\n");
            free(recv);
            closesocket(pSocket);
            return FALSE;
        }

        networkPcInfo->NetbiosInfo = (NETBIOS_Info*)calloc(1, sizeof(NETBIOS_Info));
        if (networkPcInfo->NetbiosInfo == NULL) {
            printf("\t\t[-] Memory error !\n");
            free(recv);
            closesocket(pSocket);
            return FALSE;
        }
        networkPcInfo->isNetbiosInfo = TRUE;
        networkPcInfo->NetbiosInfo->macAddress[0] = 0x00;
        networkPcInfo->NetbiosInfo->nbNetBIOSRemoteMachineNameTab = 0;
        
        ptr = recv + 57;
        total = *(ptr - 1); /* max names */

        for (UINT i = 0; ptr < recv + RECV_BUFFER_SIZE; i++) {
            unsigned int nb_num;
            unsigned int nb_type;

            memset(temp, 0x0, sizeof(temp));
            strncpy_s(temp, sizeof(temp), ptr, 15);   /* copies the name into temp */

            ptr += 15;
            nb_num = *ptr;
            nb_type = *(ptr + 1);
            ptr += 3;

            if (i == total) {    /* max names reached */
                ptr -= 19;   /* sets the pointer to the mac_addres field */
                sprintf_s(networkPcInfo->NetbiosInfo->macAddress,40,"%02x-%02x-%02x-%02x-%02x-%02x",
                    *(ptr + 1), *(ptr + 2), *(ptr + 3),
                    *(ptr + 4), *(ptr + 5), *(ptr + 6));
                break;
            }
            if(temp[0] != 0x00)
                display(temp, nb_num, nb_type, networkPcInfo->NetbiosInfo);
        }
    }
    free(recv);
    closesocket(pSocket);


    for (int i = 0; i < networkPcInfo->NetbiosInfo->nbNetBIOSRemoteMachineNameTab; i++) {
        printf("\t\t[i] %s%s\n", 
            networkPcInfo->NetbiosInfo->netBIOSRemoteMachineNameTab[i].isGroup?
            "Domain Name: ": 
            "Hostname:    ", 
            networkPcInfo->NetbiosInfo->netBIOSRemoteMachineNameTab[i].Name);
    }
    if(networkPcInfo->NetbiosInfo->macAddress[0] != 0x00)
        printf("\t\t[i] Mac Address: %s\n", networkPcInfo->NetbiosInfo->macAddress);

 	return TRUE;
}