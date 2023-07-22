
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

#ifndef MESSAGE_HEADER_H
#define MESSAGE_HEADER_H

VOID PrintSocketError(const char* format, ...);
VOID PrintMsgError(const char* format, ...);
VOID PrintMsgError2(const char* format, ...);
VOID PrintMsgError3(const char* format, ...);
BOOL PrintOut(FILE* pFile, const char* format, ...);
BOOL PrintVerbose(BOOL isVerbose, const char* format, ...);

#endif