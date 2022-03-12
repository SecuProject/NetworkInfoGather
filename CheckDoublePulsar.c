#include <winsock2.h>
#include <iphlpapi.h>   // IPAddr
#include <stdio.h>
#include <ws2tcpip.h>   // inet_pton

#include "Network.h"

unsigned char SmbNegociate[] =
"\x00\x00\x00\x2f\xff\x53\x4d\x42\x72\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x88\x05\x00\x00\x00\x00\x00\x0c\x00\x02\x4e\x54"
"\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00";

unsigned char Session_Setup_AndX_Request[] =
"\x00\x00\x00\x48\xff\x53\x4d\x42\x73\x00"
"\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\xff\xff\x88\x05\x00\x00\x00\x00\x0d\xff\x00\x00\x00\xff"
"\xff\x02\x00\x88\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x01\x00\x00\x00\x0b\x00\x00\x00\x6e\x74\x00\x70\x79\x73\x6d"
"\x62\x00";

unsigned char TreeConnect_AndX_Request[] =
"\x00\x00\x00\x58\xff\x53\x4d\x42\x75\x00"
"\x00\x00\x00\x18\x07\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\xff\xfe\x00\x08\x00\x03\x04\xff\x00\x58\x00\x08"
"\x00\x01\x00\x2d\x00\x00\x5c\x00\x5c\x00\x31\x00\x37\x00\x32\x00"
"\x2e\x00\x32\x00\x32\x00\x2e\x00\x35\x00\x2e\x00\x34\x00\x36\x00"
"\x5c\x00\x49\x00\x50\x00\x43\x00\x24\x00\x00\x00\x3f\x3f\x3f\x3f"
"\x3f\x00";

unsigned char trans2_session_setup[] =
"\x00\x00\x00\x4E\xFF\x53\x4D\x42\x32\x00\x00\x00\x00\x18\x07\xC0"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xFF\xFE"
"\x00\x08\x41\x00\x0F\x0C\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
"\x00\xA6\xD9\xA4\x00\x00\x00\x0C\x00\x42\x00\x00\x00\x4E\x00\x01"
"\x00\x0E\x00\x0D\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00";

BOOL CheckDoublePulsar(char* ipAddress, int port){
    unsigned char recvbuff[2048];
    unsigned char uninstall_response[2048];

    DWORD    ret;
    WORD    userid, treeid;


    SOCKET sock = ConnectTcpServer(ipAddress, port);
    if (sock == INVALID_SOCKET)
        return FALSE;

    //send SMB negociate packet
    send(sock, (char*)SmbNegociate, sizeof(SmbNegociate) - 1, 0);
    if (recv(sock, (char*)recvbuff, sizeof(recvbuff), 0) == SOCKET_ERROR){
        printf("\t[w] SMBv1 is disable !\n");
        return FALSE;
    }

    //send Session Setup AndX request
    printf("\t[i] sending Session_Setup_AndX_Request!\n");
    ret = send(sock, (char*)Session_Setup_AndX_Request, sizeof(Session_Setup_AndX_Request) - 1, 0);
    if (ret <= 0){
        printf("send Session_Setup_AndX_Request error!\n");
        return FALSE;
    }
    recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

    //copy our returned userID value from the previous packet to the TreeConnect request packet
    userid = *(WORD*)(recvbuff + 0x20);       //get userid
    memcpy(TreeConnect_AndX_Request + 0x20, (char*)&userid, 2); //update userid

    //send TreeConnect request packet
    printf("\t[i] sending TreeConnect Request!\n");
    ret = send(sock, (char*)TreeConnect_AndX_Request, sizeof(TreeConnect_AndX_Request) - 1, 0);
    if (ret <= 0){
        printf("\t[x] send TreeConnect_AndX_Request error!\n");
        return FALSE;
    }
    recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

    //copy the treeID from the TreeConnect response
    treeid = *(WORD*)(recvbuff + 0x1c);       //get treeid

    //Replace tree ID and user ID in trans2 session setup packet
    memcpy(trans2_session_setup + 0x20, (char*)&userid, 2);  //update userid
    memcpy(trans2_session_setup + 0x1c, (char*)&treeid, 2);  //update treeid

    //send modified trans2 session request
    printf("\t[i] sending modified trans2 sessionsetup!\n");
    ret = send(sock, (char*)trans2_session_setup, sizeof(trans2_session_setup) - 1, 0);
    if (ret <= 0){
        printf("\t[x] send modified trans2 sessionsetup error!\n");
        return FALSE;
    }
    recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

    //if multiplex id = x51 or 81 then DoublePulsar is present
    if (recvbuff[34] == 0x51){
        printf("\t[i] Received data that DoublePulsar is installed!\n");
        printf("\t[i] Burning DoublePulsar...\n");
        WORD burn1, burn2, burn3, burn4, burn5;
        //burn1 = multiplex ID of 66 in decimal or x42 in hex
        //if successful.  x52 is returned which means the payload ran succesfully!
        burn1 = 66;       //update multiplex ID to x42
        //modified_trans2_session_setup[34] = "\x42"
        //burn command being sent in the timeout portion of the packet
        burn2 = 14;       //burn command - trans2_session_setup[49] = "\x0e"
        burn3 = 105;      //burn command - trans2_session_setup[50] = "\x69"
        burn4 = 0;        //burn command - trans2_session_setup[51] = "\x00"
        burn5 = 0;        //burn command - trans2_session_setup[52] = "\x00"

        //modify our trans2 session packet to include the burn command
        memcpy(trans2_session_setup + 0x22, (char*)&burn1, 1);
        memcpy(trans2_session_setup + 0x31, (char*)&burn2, 1);
        memcpy(trans2_session_setup + 0x32, (char*)&burn3, 1);
        memcpy(trans2_session_setup + 0x33, (char*)&burn4, 1);
        memcpy(trans2_session_setup + 0x34, (char*)&burn5, 1);

        send(sock, (char*)trans2_session_setup, sizeof(trans2_session_setup) - 1, 0);
        recv(sock, (char*)uninstall_response, 2048, 0);
        if (uninstall_response[34] == 0x52){
            printf("\t[*] DOUBLEPULSAR uninstall SUCCESSFUL!\n");
            closesocket(sock);
            return TRUE;
        } else{
            printf("\t[!] DOUBLEPULSAR uninstall UNSUCCESSFUL!\n");
        }
    } else{
        printf("\t[i] no backdoor installed!");
    }
    closesocket(sock);
    return FALSE;
}