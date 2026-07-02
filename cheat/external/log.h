#pragma once
#include <stdio.h>
inline FILE* _logFile() {
    static FILE* f = nullptr;
    if (!f) f = _fsopen("C:\\Users\\K\\AppData\\Local\\Temp\\ext_debug.txt", "w", _SH_DENYNO);
    return f;
}
#define Log(Arg, ...) do { \
    printf("[penisfinger] " Arg "\n", ##__VA_ARGS__); \
    if (_logFile()) { fprintf(_logFile(), "[penisfinger] " Arg "\n", ##__VA_ARGS__); fflush(_logFile()); } \
} while(0)

// big file