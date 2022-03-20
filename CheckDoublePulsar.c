#include <winsock2.h>
#include <stdio.h>

#include "Network.h"
#include "XorRoutine.h"


unsigned char SmbNegociateXor[] = {
        0x31,0x33,0x33,0x18,0xce,0x60,0x7e,0x75,0x43,0x33,0x33,0x37,0x31,0x33,0x33,0x37,
        0x31,0x33,0x33,0x37,0x31,0x33,0x33,0x37,0x31,0x33,0x33,0x37,0x31,0x33,0xbb,0x32,
        0x31,0x33,0x33,0x37,0x31,0x3f,0x33,0x35,0x7f,0x67,0x13,0x7b,0x7c,0x13,0x03,0x19,
        0x00,0x01,0x33,0x37,
};
unsigned char Session_Setup_AndX_RequestXor[] = {
        0x31,0x33,0x33,0x7f,0xce,0x60,0x7e,0x75,0x42,0x33,0x33,0x37,0x31,0x3b,0x33,0x37,
        0x31,0x33,0x33,0x37,0x31,0x33,0x33,0x37,0x31,0x33,0x33,0x37,0xce,0xcc,0xbb,0x32,
        0x31,0x33,0x33,0x37,0x3c,0xcc,0x33,0x37,0x31,0xcc,0xcc,0x35,0x31,0xbb,0x36,0x37,
        0x31,0x33,0x33,0x37,0x31,0x33,0x33,0x37,0x31,0x33,0x33,0x36,0x31,0x33,0x33,0x3c,
        0x31,0x33,0x33,0x59,0x45,0x33,0x43,0x4e,0x42,0x5e,0x51,0x37,0x31,
};
unsigned char TreeConnect_AndX_RequestXor[] = {
        0x31,0x33,0x33,0x6f,0xce,0x60,0x7e,0x75,0x44,0x33,0x33,0x37,0x31,0x2b,0x34,0xff,
        0x31,0x33,0x33,0x37,0x31,0x33,0x33,0x37,0x31,0x33,0x33,0x37,0x31,0x33,0xcc,0xc9,
        0x31,0x3b,0x33,0x34,0x35,0xcc,0x33,0x6f,0x31,0x3b,0x33,0x36,0x31,0x1e,0x33,0x37,
        0x6d,0x33,0x6f,0x37,0x00,0x33,0x04,0x37,0x03,0x33,0x1d,0x37,0x03,0x33,0x01,0x37,
        0x1f,0x33,0x06,0x37,0x1f,0x33,0x07,0x37,0x07,0x33,0x6f,0x37,0x78,0x33,0x63,0x37,
        0x72,0x33,0x17,0x37,0x31,0x33,0x0c,0x08,0x0e,0x0c,0x0c,0x37,0x31,
};
unsigned char trans2_session_setupXor[] = {
        0x31,0x33,0x33,0x79,0xce,0x60,0x7e,0x75,0x03,0x33,0x33,0x37,0x31,0x2b,0x34,0xf7,
        0x31,0x33,0x33,0x37,0x31,0x33,0x33,0x37,0x31,0x33,0x33,0x37,0x31,0x3b,0xcc,0xc9,
        0x31,0x3b,0x72,0x37,0x3e,0x3f,0x33,0x37,0x31,0x32,0x33,0x37,0x31,0x33,0x33,0x37,
        0x31,0x95,0xea,0x93,0x31,0x33,0x33,0x3b,0x31,0x71,0x33,0x37,0x31,0x7d,0x33,0x36,
        0x31,0x3d,0x33,0x3a,0x31,0x33,0x33,0x37,0x31,0x33,0x33,0x37,0x31,0x33,0x33,0x37,
        0x31,0x33,0x33,
};

BOOL CheckDoublePulsar(char* ipAddress, int port){
    unsigned char recvbuff[2048];
    unsigned char uninstall_response[2048];
    const char key[] = "1337";

    DWORD    ret;
    WORD    userid, treeid;


    SOCKET sock = ConnectTcpServer(ipAddress, port);
    if (sock == INVALID_SOCKET)
        return FALSE;

    //send SMB negociate packet
    XorRoutine(SmbNegociateXor, sizeof(SmbNegociateXor), key);
    send(sock, (char*)SmbNegociateXor, sizeof(SmbNegociateXor) - 1, 0);
    if (recv(sock, (char*)recvbuff, sizeof(recvbuff), 0) == SOCKET_ERROR){
        printf("\t[w] SMBv1 is disable !\n");
        return FALSE;
    }

    //send Session Setup AndX request
    printf("\t[i] sending Session_Setup_AndX_Request!\n");
    XorRoutine(Session_Setup_AndX_RequestXor, sizeof(Session_Setup_AndX_RequestXor), key);
    ret = send(sock, (char*)Session_Setup_AndX_RequestXor, sizeof(Session_Setup_AndX_RequestXor) - 1, 0);
    if (ret <= 0){
        printf("send Session_Setup_AndX_Request error!\n");
        return FALSE;
    }
    recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

    //copy our returned userID value from the previous packet to the TreeConnect request packet
    userid = *(WORD*)(recvbuff + 0x20);       //get userid
    XorRoutine(TreeConnect_AndX_RequestXor, sizeof(TreeConnect_AndX_RequestXor), key);
    memcpy(TreeConnect_AndX_RequestXor + 0x20, (char*)&userid, 2); //update userid

    //send TreeConnect request packet
    printf("\t[i] sending TreeConnect Request!\n");
    ret = send(sock, (char*)TreeConnect_AndX_RequestXor, sizeof(TreeConnect_AndX_RequestXor) - 1, 0);
    if (ret <= 0){
        printf("\t[x] send TreeConnect_AndX_Request error!\n");
        return FALSE;
    }
    recv(sock, (char*)recvbuff, sizeof(recvbuff), 0);

    //copy the treeID from the TreeConnect response
    treeid = *(WORD*)(recvbuff + 0x1c);       //get treeid

    XorRoutine(trans2_session_setupXor, sizeof(trans2_session_setupXor), key);
    //Replace tree ID and user ID in trans2 session setup packet
    memcpy(trans2_session_setupXor + 0x20, (char*)&userid, 2);  //update userid
    memcpy(trans2_session_setupXor + 0x1c, (char*)&treeid, 2);  //update treeid

    //send modified trans2 session request
    printf("\t[i] sending modified trans2 sessionsetup!\n");
    ret = send(sock, (char*)trans2_session_setupXor, sizeof(trans2_session_setupXor) - 1, 0);
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
        memcpy(trans2_session_setupXor + 0x22, (char*)&burn1, 1);
        memcpy(trans2_session_setupXor + 0x31, (char*)&burn2, 1);
        memcpy(trans2_session_setupXor + 0x32, (char*)&burn3, 1);
        memcpy(trans2_session_setupXor + 0x33, (char*)&burn4, 1);
        memcpy(trans2_session_setupXor + 0x34, (char*)&burn5, 1);

        send(sock, (char*)trans2_session_setupXor, sizeof(trans2_session_setupXor) - 1, 0);
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