/*
 * mem_swhe.h - Low-level SWHE (Shatter Window Hook Exploit) memory primitives
 *
 * This file wraps WaryasSWHE, which abuses the Win32 shatter attack surface:
 * SetWindowsHookExA installs a hook on the target process's message queue,
 * then crafted SendMessage calls trick the hooked window procedure into
 * performing arbitrary reads/writes in the target's address space.
 *
 * This gives us cross-process memory access without any kernel driver,
 * relying entirely on user-mode Win32 APIs (SetWindowsHookExA, SendMessage).
 * The trade-off is that the target must have a visible window with a message
 * loop, and each SendMessage round-trip has a payload size limit.
 */

#pragma once
#include <Windows.h>
#include <cstdint>
#include <cstring>
#include "../WaryasSWHE/exploit.hpp"

// Global SWHE state — initialized once in Memory::init(), used everywhere.
// g_proc:       Identifies the target process (PID, HWND, window class).
// g_exploit:    The exploit object that performs reads/writes via the hook.
// g_swhe_ready: Set true only after both g_proc and g_exploit initialize
//               successfully. All read/write helpers bail early if false.
inline CProcess g_proc;
inline CExploit g_exploit;
inline bool g_swhe_ready = false;

namespace SwheRead {
    inline uint64_t ReadU64(uint64_t addr) {
        if (!g_swhe_ready) return 0;
        return g_exploit.ReadU64(addr);
    }

    /*
     * ReadBuffer - Chunked read that works around the SWHE per-call payload limit.
     *
     * Each SendMessage-based read can transfer at most ~0x700 bytes (1792 bytes)
     * because the exploit packs the data into message parameters whose combined
     * size is constrained by the window-message payload. Larger reads are split
     * into 0x700-byte chunks and reassembled here so callers can request
     * arbitrarily sized reads transparently.
     */
    inline void ReadBuffer(uint64_t addr, void* buf, size_t size) {
        if (!g_swhe_ready || !buf || !size) return;
        uint8_t* dst = (uint8_t*)buf;
        while (size > 0) {
            size_t chunk = (size > 0x700) ? 0x700 : size;
            g_exploit.ReadData(addr, dst, chunk);
            addr += chunk;
            dst += chunk;
            size -= chunk;
        }
    }

    inline void WriteU64(uint64_t addr, uint64_t val) {
        if (!g_swhe_ready) return;
        g_exploit.WriteU64(addr, val);
    }

    /*
     * WriteBuffer - Writes an arbitrary buffer to the target process.
     *
     * Unlike ReadBuffer, writes are not chunked here because the exploit's
     * WriteData handles its own segmentation internally.
     */
    inline void WriteBuffer(uint64_t addr, void* buf, size_t size) {
        if (!g_swhe_ready || !buf || !size) return;
        g_exploit.WriteData(addr, (BYTE*)buf, size);
    }
}
