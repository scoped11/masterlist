#pragma once
/*
 * gmr_mem.hpp — User-mode interface to Betest.sys (kernel read/write)
 *
 * Uses Betest driver's IOCTLs (0x805 / 0x806, METHOD_BUFFERED).
 * Dynamic device name discovery — tries all names from the driver's pool.
 */
#include <Windows.h>
#include <cstring>
#include <cstdint>
#include <vector>

#define BETEST_IOCTL_READ   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_READ_DATA)
#define BETEST_IOCTL_WRITE  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_WRITE_DATA)
#define BETEST_IOCTL_DEL_SYM CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_WRITE_DATA)

#pragma pack(push, 1)
struct BETEST_READ_REQ {
    uint64_t ProcessId;
    uint64_t Address;
    uint32_t Size;
    uint32_t Pad;
};
struct BETEST_WRITE_REQ {
    uint64_t ProcessId;
    uint64_t Address;
    uint32_t Size;
    uint32_t Pad;
    uint8_t  Data[1];
};
#pragma pack(pop)

namespace GmrMem
{
    inline HANDLE s_hDevice = INVALID_HANDLE_VALUE;
    inline ULONG  s_pid     = 0;

    inline bool Init(ULONG pid)
    {
        s_pid = pid;
        if (s_hDevice != INVALID_HANDLE_VALUE)
            return true;

        const char* names[] = {
            "\\\\.\\MsFlt0", "\\\\.\\WdFilter1", "\\\\.\\FltMgr2",
            "\\\\.\\NdProxy0", "\\\\.\\TdiFilter", "\\\\.\\MsSecFlt",
            "\\\\.\\WfpDrv0", "\\\\.\\NtFilter1",
        };
        for (int i = 0; i < 8; i++) {
            s_hDevice = CreateFileA(
                names[i],
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr, OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL, nullptr
            );
            if (s_hDevice != INVALID_HANDLE_VALUE) {
                DWORD ret = 0;
                DeviceIoControl(s_hDevice, BETEST_IOCTL_DEL_SYM,
                    nullptr, 0, nullptr, 0, &ret, nullptr);
                return true;
            }
        }
        return false;
    }

    inline void Close()
    {
        if (s_hDevice != INVALID_HANDLE_VALUE)
        {
            CloseHandle(s_hDevice);
            s_hDevice = INVALID_HANDLE_VALUE;
        }
    }

    inline bool Read(ULONG64 address, void* buffer, ULONG size)
    {
        if (s_hDevice == INVALID_HANDLE_VALUE || !buffer || !size)
            return false;
        BETEST_READ_REQ req{};
        req.ProcessId = s_pid;
        req.Address   = address;
        req.Size      = size;
        DWORD returned = 0;
        BOOL ok = DeviceIoControl(
            s_hDevice, BETEST_IOCTL_READ,
            &req, sizeof(req),
            buffer, size,
            &returned, nullptr
        );
        return ok && returned == size;
    }

    inline bool Write(ULONG64 address, const void* data, ULONG size)
    {
        if (s_hDevice == INVALID_HANDLE_VALUE || !data || !size)
            return false;
        size_t reqSize = offsetof(BETEST_WRITE_REQ, Data) + size;
        std::vector<uint8_t> buf(reqSize);
        auto* req = reinterpret_cast<BETEST_WRITE_REQ*>(buf.data());
        req->ProcessId = s_pid;
        req->Address   = address;
        req->Size      = size;
        memcpy(req->Data, data, size);
        DWORD returned = 0;
        return DeviceIoControl(
            s_hDevice, BETEST_IOCTL_WRITE,
            buf.data(), (DWORD)reqSize,
            nullptr, 0,
            &returned, nullptr
        ) != FALSE;
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
