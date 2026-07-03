#pragma once
#include <stdio.h>

// ---------------------------------------------------------------------------
// Dual-output logging — prints to stdout and appends to a debug log file.
// The file is opened once (lazy init, shared-read mode so other tools can
// tail it while the cheat is running).
// ---------------------------------------------------------------------------
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
