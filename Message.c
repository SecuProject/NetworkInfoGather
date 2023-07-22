
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

#include <Windows.h>
#include <stdio.h>

VOID PrintSocketError(const char* format, ...) {
	va_list args;
	va_start(args, format);
	printf("[x] ");
	vprintf(format, args);
	va_end(args);
	printf("%lu", WSAGetLastError());
	return;
}
VOID PrintMsgError3(const char* format, ...) {
	va_list args;
	va_start(args, format);
	printf("\t\t[x] ");
	vprintf(format, args);
	va_end(args);
	printf("%lu", GetLastError());
	return;
}
VOID PrintMsgError2(const char* format, ...) {
	va_list args;
	va_start(args, format);
	printf("\t[x] ");
	vprintf(format, args);
	va_end(args);
	printf("%lu", GetLastError());
	return;
}

VOID PrintMsgError(const char* format, ...) {
	va_list args;
	va_start(args, format);
	printf("[x] ");
	vprintf(format, args);
	va_end(args);
	printf("%lu", GetLastError());
	return;
}
BOOL PrintOut(FILE* pFile, const char* format, ...) {
	va_list args;
	va_start(args, format);
	vprintf(format, args);
	if (pFile != NULL)
		vfprintf(pFile, format, args);
	va_end(args);
	return TRUE;
}
BOOL PrintVerbose(BOOL isVerbose, const char* format, ...) {
	if (isVerbose) {
		va_list args;
		va_start(args, format);
		vprintf(format, args);
		va_end(args);
	}
	return TRUE;
}