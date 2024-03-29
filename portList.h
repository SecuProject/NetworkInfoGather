
/* 
 * NetworkInfoGather
 * Copyright (C) 2023  SecuProject
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#ifndef PORT_LIST_HEADER_H
#define PORT_LIST_HEADER_H

////////////////// TCP //////////////////
//
#define PORT_FTP				21
#define PORT_SSH				22
#define PORT_TELNET				23
#define PORT_SMTP				25
#define PORT_DNS				53
#define PORT_HTTP				80
#define PORT_KERBEROS			88
//#define PORT_POP				110
//#define PORT_NFS				111
#define PORT_RPC				135
#define PORT_NETBIOS_SSN		139
#define PORT_LDAP				389
#define PORT_HTTPS				443
#define PORT_SMB				445
#define PORT_MSSQL				1433
#define PORT_ORACLEDB			1521
//#define PORT_NFS_ALT			2049
#define PORT_FTP_ALT			2121
#define PORT_SSH_ALT			2222
#define PORT_HTTP_GRAFANA		3000
#define PORT_MYSQL				3306
#define PORT_RDP				3389
#define PORT_POSTGRESQL			5432
#define PORT_DNS_ALT			5353
//#define PORT_VNC				5800
//#define PORT_VNC_ALT			5900
#define PORT_WINRM				5985
#define PORT_X11				6000
//#define PORT_REDIS			6379
#define PORT_HTTP_TOMCAT		8009
#define PORT_HTTP_PROXY			8080
#define PORT_HTTP_OTHER			8180
#define PORT_HTTP_DELUGE		8112
#define PORT_HTTP_PORTAINER		9000
#define PORT_HTTPS_PORTAINER	9443
//#define PORT_HTTP_IBM_TIVOLI	9495
#define PORT_HTTP_PROMETHEUS	9090
#define PORT_HTTP_MONGODB		27017
//
////////////////// TCP //////////////////


////////////////// UDP //////////////////
//
#define PORT_UDP_DNS		53
#define PORT_UDP_DHCP		67
#define PORT_UDP_DHCP2		68
#define PORT_UDP_NTP		123
#define PORT_UDP_NETBIOS	137			// netbios-ns
#define PORT_UDP_SNMP		161
#define PORT_UDP_SNMP2		162
//
////////////////// UDP //////////////////

#define NB_TAB_PORT_TCP		30
#define NB_TAB_PORT_UDP		6



extern const int portTcp[NB_TAB_PORT_TCP];
extern const int portUdp[NB_TAB_PORT_UDP];

#endif