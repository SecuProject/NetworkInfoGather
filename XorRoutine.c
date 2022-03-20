#include <Windows.h>

void XorRoutine(unsigned char data[], int size, const char* Key){
    for (int i = 0; i < size; i++)
        data[i] = (data[i] ^ Key[(i % strlen(Key))]);
}