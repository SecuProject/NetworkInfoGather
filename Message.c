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