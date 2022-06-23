#ifndef MESSAGE_HEADER_H
#define MESSAGE_HEADER_H

VOID PrintSocketError(const char* format, ...);
VOID PrintMsgError(const char* format, ...);
VOID PrintMsgError2(const char* format, ...);
VOID PrintMsgError3(const char* format, ...);
BOOL PrintOut(FILE* pFile, const char* format, ...);
BOOL PrintVerbose(BOOL isVerbose, const char* format, ...);

#endif