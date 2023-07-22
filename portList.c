
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

#include "portList.h"

const int portTcp[] = {
	PORT_FTP,
	PORT_SSH,
	PORT_TELNET,
	PORT_SMTP,
	PORT_DNS,
	PORT_HTTP,
	PORT_KERBEROS,
	PORT_RPC,
	PORT_NETBIOS_SSN,
	PORT_LDAP,
	PORT_HTTPS,
	PORT_SMB,
	PORT_MSSQL,
	PORT_ORACLEDB,
	PORT_FTP_ALT,
	PORT_SSH_ALT,
	PORT_HTTP_GRAFANA,
	PORT_MYSQL,
	PORT_RDP,
	PORT_DNS_ALT,
	PORT_POSTGRESQL,
	PORT_WINRM,
	PORT_HTTP_PORTAINER,
	PORT_HTTP_TOMCAT,
	PORT_HTTP_PROXY,
	PORT_HTTP_OTHER,
	PORT_HTTP_DELUGE,
	PORT_HTTPS_PORTAINER,
	PORT_HTTP_PROMETHEUS,
	PORT_HTTP_MONGODB
};
/*

#define PORT_UDP_DNS	53
#define PORT_UDP_DHCP	67
#define PORT_UDP_DHCP	68
#define PORT_UDP_NTP	123
#define PORT_UDP_SNMP	161
#define PORT_UDP_SNMP	162

67, 68	Dynamic Host Configuration Protocol (DHCP)
*/
const int portUdp[] = {
	PORT_UDP_NETBIOS,
	PORT_UDP_DHCP,
	PORT_UDP_DHCP2,
	PORT_UDP_NTP,
	PORT_UDP_SNMP,
	PORT_UDP_SNMP2,
};