#pragma once
// Drop-in kernel read/write via Betest.sys (IOCTLs 0x805 / 0x806)
// Replaces ReadProcessMemory / WriteProcessMemory.
// Call BetestMem::Init() once at startup; then use BetestMem::Read / Write.

#include <windows.h>
#include <cstdint>
#include <vector>
#include <string>

#define _BETEST_IOCTL_READ_PROC    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_READ_DATA)
#define _BETEST_IOCTL_WRITE_PROC   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_WRITE_DATA)
#define _BETEST_IOCTL_DELETE_SYM   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_WRITE_DATA)
#define _BETEST_IOCTL_HIDE_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_WRITE_DATA)

#pragma pack(push, 1)
struct _BetestProcReadReq  { uint64_t ProcessId; uint64_t Address; uint32_t Size; uint32_t Pad; };
struct _BetestProcWriteReq { uint64_t ProcessId; uint64_t Address; uint32_t Size; uint32_t Pad; uint8_t Data[1]; };
#pragma pack(pop)

namespace BetestMem {

inline HANDLE g_hDev = INVALID_HANDLE_VALUE;
inline DWORD  g_pid  = 0;

inline bool Init(DWORD targetPid) {
    const char* names[] = {
        "\\\\.\\MsFlt0", "\\\\.\\WdFilter1", "\\\\.\\FltMgr2",
        "\\\\.\\NdProxy0", "\\\\.\\TdiFilter", "\\\\.\\MsSecFlt",
        "\\\\.\\WfpDrv0", "\\\\.\\NtFilter1",
    };
    for (int i = 0; i < 8; i++) {
        g_hDev = CreateFileA(names[i],
                             GENERIC_READ | GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE,
                             nullptr, OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL, nullptr);
        if (g_hDev != INVALID_HANDLE_VALUE) break;
    }
    if (g_hDev == INVALID_HANDLE_VALUE) return false;
    g_pid = targetPid;

    // Delete the symlink immediately — we already have the handle,
    // so no one else can open the device by name anymore.
    DWORD ret = 0;
    DeviceIoControl(g_hDev, _BETEST_IOCTL_DELETE_SYM,
                    nullptr, 0, nullptr, 0, &ret, nullptr);

    return true;
}

// Hide a process from task managers and BE's process enumeration (DKOM).
inline bool HideProcess(DWORD pid) {
    uint64_t id = pid;
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, _BETEST_IOCTL_HIDE_PROCESS,
                           &id, sizeof(id), nullptr, 0, &ret, nullptr) != FALSE;
}

inline bool Read(uint64_t address, void* buffer, size_t size) {
    _BetestProcReadReq req{};
    req.ProcessId = g_pid;
    req.Address   = address;
    req.Size      = static_cast<uint32_t>(size);

    DWORD returned = 0;
    return DeviceIoControl(g_hDev,
                           _BETEST_IOCTL_READ_PROC,
                           &req,    sizeof(req),
                           buffer,  static_cast<DWORD>(size),
                           &returned, nullptr) && returned == size;
}

inline bool Write(uint64_t address, const void* data, size_t size) {
    size_t reqSize = offsetof(_BetestProcWriteReq, Data) + size;
    std::vector<uint8_t> buf(reqSize);
    auto* req    = reinterpret_cast<_BetestProcWriteReq*>(buf.data());
    req->ProcessId = g_pid;
    req->Address   = address;
    req->Size      = static_cast<uint32_t>(size);
    memcpy(req->Data, data, size);

    DWORD returned = 0;
    return DeviceIoControl(g_hDev,
                           _BETEST_IOCTL_WRITE_PROC,
                           buf.data(), static_cast<DWORD>(reqSize),
                           nullptr, 0,
                           &returned, nullptr) != FALSE;
}

template <class T>
inline T Read(uint64_t address) {
    T val{};
    Read(address, &val, sizeof(T));
    return val;
}

template <class T>
inline void Write(uint64_t address, const T& val) {
    Write(address, &val, sizeof(T));
}

} // namespace BetestMem
