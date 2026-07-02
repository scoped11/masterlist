#pragma once
// Internal (in-process) memory access — replaces GmrMem kernel driver IOCTLs
// with direct pointer dereference. Used when DLL is injected into Unturned.exe.
#include <Windows.h>
#include <cstring>
#include <cstdint>
#include <vector>

namespace GmrMem
{
    inline HANDLE s_hDevice = INVALID_HANDLE_VALUE;
    inline ULONG  s_pid     = 0;

    inline bool Init(ULONG pid)
    {
        s_pid = pid;
        return true;
    }

    inline void Close() {}

    inline bool Read(ULONG64 address, void* buffer, ULONG size)
    {
        if (!address || !buffer || !size) return false;
        __try {
            memcpy(buffer, (const void*)address, size);
            return true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            memset(buffer, 0, size);
            return false;
        }
    }

    inline bool Write(ULONG64 address, const void* data, ULONG size)
    {
        if (!address || !data || !size) return false;
        __try {
            DWORD oldProt;
            VirtualProtect((void*)address, size, PAGE_EXECUTE_READWRITE, &oldProt);
            memcpy((void*)address, data, size);
            VirtualProtect((void*)address, size, oldProt, &oldProt);
            return true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    template<typename T>
    inline T Read(ULONG64 address)
    {
        T val{};
        Read(address, &val, sizeof(T));
        return val;
    }

    template<typename T>
    inline void Write(ULONG64 address, T value)
    {
        Write(address, &value, sizeof(T));
    }
}
