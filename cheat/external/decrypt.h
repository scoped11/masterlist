#pragma once
/*
 * decrypt.h — CTF memory decryption layer
 *
 * Transparent decryption for fictional game memory encryption schemes.
 * Two paths:
 *   1. Kernel atomic:  IOCTL_DECRYPT_READ does read+decrypt in one kernel call
 *                      (no timing window for AC to detect)
 *   2. Usermode fast:  read normally via GmrMem, decrypt client-side
 *                      (faster, but two operations = small timing gap)
 *
 * Usage:
 *   Decrypt::Init();                          // open Betest device
 *   Decrypt::SetKey(0, DECRYPT_XOR_CHAIN, myKey, 0);
 *   auto val = decrypt_read<uint64_t>(addr);  // atomic kernel decrypt-read
 *   // or: auto val = decrypt_read_fast<uint64_t>(addr);  // usermode path
 */

#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <vector>

// Must match BetestDriver.c definitions
#define _DECRYPT_NONE        0
#define _DECRYPT_XOR_STATIC  1
#define _DECRYPT_XOR_CHAIN   2
#define _DECRYPT_PTR_ENCRYPT 3
#define _DECRYPT_ROT_ADD     4

#define _IOCTL_DECRYPT_READ        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_READ_DATA)
#define _IOCTL_SET_DECRYPT_KEY     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_WRITE_DATA)
#define _IOCTL_INSTALL_DECRYPT_HOOK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED, FILE_WRITE_DATA)
#define _IOCTL_READ_KEYBUF         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x814, METHOD_BUFFERED, FILE_READ_DATA)

#pragma pack(push, 1)
struct DecryptReadReq {
    uint64_t ProcessId;
    uint64_t Address;
    uint32_t Size;
    uint32_t Mode;
    uint32_t KeySlot;
    uint32_t Pad;
};

struct SetKeyReq {
    uint32_t KeySlot;
    uint32_t Mode;
    uint64_t Key;
    uint64_t Key2;
};

struct InstallHookReq {
    uint64_t ProcessId;
    uint64_t TargetVA;
    uint32_t KeyOffset;
    uint32_t Pad;
};
#pragma pack(pop)

namespace Decrypt
{
    inline HANDLE g_hDev = INVALID_HANDLE_VALUE;
    inline uint32_t g_pid = 0;

    // Per-slot key cache for the usermode fast path
    struct KeySlot {
        uint32_t mode = 0;
        uint64_t key = 0;
        uint64_t key2 = 0;
        bool active = false;
    };
    inline KeySlot g_slots[4] = {};

    inline bool Init()
    {
        if (g_hDev != INVALID_HANDLE_VALUE) return true;
        // Use the same Betest device handle — reopen if needed
        g_hDev = CreateFileA("\\\\.\\MsFlt0",
                             GENERIC_READ | GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE,
                             nullptr, OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL, nullptr);
        return g_hDev != INVALID_HANDLE_VALUE;
    }

    inline void SetPid(uint32_t pid) { g_pid = pid; }

    // Push a key to both kernel and local cache
    inline bool SetKey(uint32_t slot, uint32_t mode, uint64_t key, uint64_t key2 = 0)
    {
        if (slot >= 4) return false;
        g_slots[slot] = { mode, key, key2, true };

        if (g_hDev == INVALID_HANDLE_VALUE) return false;
        SetKeyReq req{ slot, mode, key, key2 };
        DWORD ret = 0;
        return DeviceIoControl(g_hDev, _IOCTL_SET_DECRYPT_KEY,
                               &req, sizeof(req), nullptr, 0, &ret, nullptr) != FALSE;
    }

    // ── Kernel atomic path ──────────────────────────────────────────────────
    // Single IOCTL: read game memory + decrypt in kernel space.
    inline bool ReadDecrypt(uint64_t address, void* buffer, uint32_t size,
                            uint32_t slot = 0, uint32_t modeOverride = 0)
    {
        if (g_hDev == INVALID_HANDLE_VALUE || !buffer || !size) return false;
        DecryptReadReq req{};
        req.ProcessId = g_pid;
        req.Address   = address;
        req.Size      = size;
        req.Mode      = modeOverride;
        req.KeySlot   = slot;

        DWORD returned = 0;
        return DeviceIoControl(g_hDev, _IOCTL_DECRYPT_READ,
                               &req, sizeof(req),
                               buffer, size,
                               &returned, nullptr) && returned == size;
    }

    // ── Usermode fast path ──────────────────────────────────────────────────
    // Read via GmrMem (normal path), then decrypt client-side.
    // Faster due to fewer IOCTL round-trips, but creates a small timing gap.

    inline uint64_t RotL64(uint64_t v, int n)
    {
        return (v << n) | (v >> (64 - n));
    }

    inline void DecryptBufferLocal(uint8_t* buf, uint32_t size,
                                    uint32_t mode, uint64_t key, uint64_t key2)
    {
        uint32_t i;
        switch (mode) {
        case _DECRYPT_XOR_STATIC:
            for (i = 0; i + 8 <= size; i += 8)
                *(uint64_t*)(buf + i) ^= key;
            for (; i < size; i++)
                buf[i] ^= ((uint8_t*)&key)[i & 7];
            break;

        case _DECRYPT_XOR_CHAIN: {
            uint64_t k = key;
            for (i = 0; i + 8 <= size; i += 8) {
                uint64_t enc = *(uint64_t*)(buf + i);
                *(uint64_t*)(buf + i) = enc ^ k;
                k = RotL64(k, 13) ^ enc;
            }
            break;
        }

        case _DECRYPT_PTR_ENCRYPT:
            for (i = 0; i + 8 <= size; i += 8) {
                uint64_t addr = key2 + i;
                *(uint64_t*)(buf + i) ^= (key ^ (addr >> 3));
            }
            break;

        case _DECRYPT_ROT_ADD: {
            uint32_t k32 = (uint32_t)(key & 0xFFFFFFFF);
            for (i = 0; i + 4 <= size; i += 4) {
                *(uint32_t*)(buf + i) -= k32;
                k32 = (k32 >> 7) | (k32 << 25);
            }
            break;
        }
        default:
            break;
        }
    }

    inline bool ReadDecryptFast(uint64_t address, void* buffer, uint32_t size,
                                 uint32_t slot = 0)
    {
        // Read via the normal GmrMem path
        if (!GmrMem::Read(address, buffer, size)) return false;
        if (slot >= 4 || !g_slots[slot].active) return true;
        DecryptBufferLocal((uint8_t*)buffer, size,
                           g_slots[slot].mode, g_slots[slot].key,
                           g_slots[slot].key2);
        return true;
    }

    // ── Hook installer ──────────────────────────────────────────────────────
    // Patches the game's decryption function to capture key material.
    inline bool InstallHook(uint64_t targetVA, uint32_t keyOffset = 0)
    {
        if (g_hDev == INVALID_HANDLE_VALUE) return false;
        InstallHookReq req{};
        req.ProcessId = g_pid;
        req.TargetVA  = targetVA;
        req.KeyOffset = keyOffset;
        DWORD ret = 0;
        return DeviceIoControl(g_hDev, _IOCTL_INSTALL_DECRYPT_HOOK,
                               &req, sizeof(req), nullptr, 0, &ret, nullptr) != FALSE;
    }

    // Read captured key material from the kernel hook
    inline bool ReadCapturedKey(void* buffer, uint32_t maxLen, uint32_t* outLen)
    {
        if (g_hDev == INVALID_HANDLE_VALUE) return false;
        DWORD returned = 0;
        bool ok = DeviceIoControl(g_hDev, _IOCTL_READ_KEYBUF,
                                   nullptr, 0,
                                   buffer, maxLen,
                                   &returned, nullptr) != FALSE;
        if (ok && outLen) *outLen = returned;
        return ok;
    }

    // ── Key discovery ───────────────────────────────────────────────────────
    // Scan game memory for likely XOR key by reading a region where we know the
    // plaintext (e.g., a vtable pointer that must point into a known module range).
    inline uint64_t FindXorKey(uint64_t encryptedPtr, uint64_t knownModuleBase)
    {
        // If the encrypted value XOR'd with a candidate key should produce
        // a VA in [moduleBase, moduleBase+0x10000000), brute-force the upper bits.
        // For simple single-key XOR: key = encrypted ^ expected
        // We don't know exact expected, but we know the high 32 bits of the module VA.
        uint64_t enc = 0;
        GmrMem::Read(encryptedPtr, &enc, sizeof(enc));
        if (!enc) return 0;

        // High 32 bits of kernel/game VA are predictable
        uint64_t expectedHigh = knownModuleBase & 0xFFFFFFFF00000000ULL;
        uint64_t keyHigh = (enc ^ expectedHigh) & 0xFFFFFFFF00000000ULL;

        // Try key candidates where low 32 bits produce a reasonable offset
        for (uint32_t lowGuess = 0; lowGuess < 0x10000000; lowGuess += 0x1000) {
            uint64_t candidate = keyHigh | lowGuess;
            uint64_t decoded = enc ^ candidate;
            if (decoded >= knownModuleBase && decoded < knownModuleBase + 0x10000000) {
                return candidate;
            }
        }
        return 0;
    }
}

// ── Drop-in replacements for read<T> when decryption is active ──────────────

// Atomic kernel decrypt-read (safest)
template <class T>
inline T decrypt_read(uint64_t addr, uint32_t slot = 0)
{
    T val{};
    Decrypt::ReadDecrypt(addr, &val, sizeof(T), slot);
    return val;
}

// Fast usermode decrypt-read
template <class T>
inline T decrypt_read_fast(uint64_t addr, uint32_t slot = 0)
{
    T val{};
    Decrypt::ReadDecryptFast(addr, &val, sizeof(T), slot);
    return val;
}

// Decrypt a pointer value (common CTF pattern)
inline uintptr_t decrypt_ptr(uint64_t addr, uint32_t slot = 0)
{
    return decrypt_read<uintptr_t>(addr, slot);
}
