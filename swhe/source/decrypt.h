#pragma once
#include <Windows.h>
#include <cstdint>

// ---------------------------------------------------------------------------
// decrypt.h — decryption stub for Unturned (Unity/Mono).
//
// Unturned does not use pointer encryption on its managed objects, so
// decrypt_read<T> is a straight passthrough to the normal read<T> (via
// read_buffer).  This header exists to keep the codebase compatible with
// other targets (e.g., EAC/BattlEye-protected games) that do use pointer
// encryption and would provide a real decryption implementation here.
// ---------------------------------------------------------------------------

// Stub — no encryption for Unturned (Unity/Mono).
// decrypt_read<T> just falls through to the normal read<T>.

namespace Decrypt {
    inline bool Init() { return true; }
}

// Read a value from the target process at 'addr' — no decryption applied.
template<typename T>
inline T decrypt_read(uint64_t addr) {
    extern void read_buffer(DWORD64 addressToRead, void* buffer, size_t size);
    T val{};
    read_buffer(addr, &val, sizeof(T));
    return val;
}

// Alias — same as decrypt_read since there is no encryption to bypass.
template<typename T>
inline T decrypt_read_fast(uint64_t addr) {
    return decrypt_read<T>(addr);
}
