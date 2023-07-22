
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

#include <windows.h>
#include <stdio.h>
//#include <winldap.h>
//#include <winber.h>

#include "MgArguments.h"
#include "EnumLDAP.h"


//#pragma comment(lib, "Wldap32.lib")

// #define DN_MAX_SIZE 1000

/*
Windows documentation:
- https://docs.microsoft.com/en-gb/previous-versions/windows/desktop/ldap/example-code-for-establishing-a-session-over-ssl
- https://docs.microsoft.com/en-gb/previous-versions/windows/desktop/ldap/example-code-for-establishing-a-session-without-encryption
*/

BOOL BruteForceLDAP(char* ipAddress, int port, StructWordList structWordList, StructCredentials* structCredentials) { 
	//TODO
	return TRUE; 
}
BOOL EnumLDAP(char* ipAddress, int port, StructWordList structWordList, FILE* pFile) { 
	//TODO
	return TRUE; 
}
