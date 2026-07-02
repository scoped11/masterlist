#pragma once
// loader_security.hpp — Anti-cracking, anti-tamper, anti-debug hardening
// Compile-time and runtime integrity checks to resist reverse engineering

#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <intrin.h>

// ── PE self-integrity: CRC32 of own .text section ────────────────────────
static uint32_t SecurityCRC32(const void* data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    const uint8_t* p = (const uint8_t*)data;
    for (size_t i = 0; i < len; i++) {
        crc ^= p[i];
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ ((crc & 1) ? 0xEDB88320U : 0U);
    }
    return ~crc;
}

struct IntegrityState {
    uint32_t textCRC;
    uintptr_t textBase;
    size_t    textSize;
    uint32_t iatHash;
    bool      initialized;
};

static IntegrityState g_integrity = {};

static bool SecurityInitIntegrity() {
    HMODULE hMod = GetModuleHandleA(nullptr);
    if (!hMod) return false;

    auto* dos = (IMAGE_DOS_HEADER*)hMod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = (IMAGE_NT_HEADERS64*)((uintptr_t)hMod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            g_integrity.textBase = (uintptr_t)hMod + sec[i].VirtualAddress;
            g_integrity.textSize = sec[i].Misc.VirtualSize;
            g_integrity.textCRC = SecurityCRC32((void*)g_integrity.textBase, g_integrity.textSize);

            // IAT hash: XOR all import thunk addresses
            auto& importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            if (importDir.VirtualAddress) {
                auto* imp = (IMAGE_IMPORT_DESCRIPTOR*)((uintptr_t)hMod + importDir.VirtualAddress);
                uint32_t h = 0;
                while (imp->Name) {
                    if (imp->FirstThunk) {
                        auto* thunk = (IMAGE_THUNK_DATA64*)((uintptr_t)hMod + imp->FirstThunk);
                        while (thunk->u1.Function) {
                            h ^= (uint32_t)(thunk->u1.Function & 0xFFFFFFFF);
                            h = (h << 7) | (h >> 25);
                            thunk++;
                        }
                    }
                    imp++;
                }
                g_integrity.iatHash = h;
            }
            g_integrity.initialized = true;
            return true;
        }
    }
    return false;
}

static bool SecurityCheckIntegrity() {
    if (!g_integrity.initialized) return false;
    uint32_t currentCRC = SecurityCRC32((void*)g_integrity.textBase, g_integrity.textSize);
    if (currentCRC != g_integrity.textCRC) return false;

    HMODULE hMod = GetModuleHandleA(nullptr);
    auto* dos = (IMAGE_DOS_HEADER*)hMod;
    auto* nt = (IMAGE_NT_HEADERS64*)((uintptr_t)hMod + dos->e_lfanew);
    auto& importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress) {
        auto* imp = (IMAGE_IMPORT_DESCRIPTOR*)((uintptr_t)hMod + importDir.VirtualAddress);
        uint32_t h = 0;
        while (imp->Name) {
            if (imp->FirstThunk) {
                auto* thunk = (IMAGE_THUNK_DATA64*)((uintptr_t)hMod + imp->FirstThunk);
                while (thunk->u1.Function) {
                    h ^= (uint32_t)(thunk->u1.Function & 0xFFFFFFFF);
                    h = (h << 7) | (h >> 25);
                    thunk++;
                }
            }
            imp++;
        }
        if (h != g_integrity.iatHash) return false;
    }
    return true;
}

// ── Extended anti-debug: multiple vectors ────────────────────────────────
static bool SecurityAntiDebugDeep() {
    int threats = 0;

    // NtQuerySystemInformation: KernelDebugger check
    typedef NTSTATUS(NTAPI* NtQSI_t)(ULONG, PVOID, ULONG, PULONG);
    auto NtQSI = (NtQSI_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (NtQSI) {
        struct { BOOLEAN DebuggerEnabled; BOOLEAN DebuggerNotPresent; } sysDbg = {};
        if (NtQSI(0x23, &sysDbg, sizeof(sysDbg), nullptr) == 0) {
            if (sysDbg.DebuggerEnabled && !sysDbg.DebuggerNotPresent)
                threats++;
        }
    }

    // NtQueryInformationProcess: ProcessDebugObjectHandle
    typedef NTSTATUS(NTAPI* NtQIP_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    auto NtQIP = (NtQIP_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    if (NtQIP) {
        HANDLE debugObj = nullptr;
        NTSTATUS st = NtQIP(GetCurrentProcess(), 0x1E, &debugObj, sizeof(debugObj), nullptr);
        if (st == 0 && debugObj) threats++;
    }

    // PEB->NtGlobalFlag: typical debugger flags (FLG_HEAP_ENABLE_TAIL_CHECK etc)
    typedef NTSTATUS(NTAPI* NtQIP2_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    auto NtQIP2 = (NtQIP2_t)NtQIP;
    if (NtQIP2) {
        struct { ULONG_PTR Reserved[6]; PVOID PebBase; } pbi = {};
        if (NtQIP2(GetCurrentProcess(), 0, &pbi, sizeof(pbi), nullptr) == 0 && pbi.PebBase) {
            DWORD ntGlobalFlag = *(DWORD*)((uintptr_t)pbi.PebBase + 0xBC);
            if (ntGlobalFlag & 0x70) threats++;
        }
    }

    // Heap flags: RtlProcessHeap -> Flags/ForceFlags
    PVOID heap = GetProcessHeap();
    if (heap) {
        DWORD heapFlags = *(DWORD*)((uintptr_t)heap + 0x70);
        DWORD heapForce = *(DWORD*)((uintptr_t)heap + 0x74);
        if (heapFlags & 0x40000060) threats++;
        if (heapForce != 0) threats++;
    }

    // CloseHandle with invalid handle — debugger catches STATUS_INVALID_HANDLE
    __try {
        CloseHandle((HANDLE)0xDEADBEEFull);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        threats++;
    }

    // RDTSC timing: detect single-step
    LARGE_INTEGER f, a, b;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&a);
    volatile int x = 0;
    for (int i = 0; i < 50; i++) x ^= i;
    QueryPerformanceCounter(&b);
    double us = ((double)(b.QuadPart - a.QuadPart) / f.QuadPart) * 1e6;
    if (us > 3000.0) threats++;

    // Check for common hooks on NtQueryInformationProcess
    if (NtQIP) {
        uint8_t* fn = (uint8_t*)NtQIP;
        if (fn[0] == 0xE9 || fn[0] == 0xFF) threats++;
    }

    return threats == 0;
}

// ── Anti-dump: scramble PE headers in memory ─────────────────────────────
static void SecurityAntiDump() {
    HMODULE hMod = GetModuleHandleA(nullptr);
    if (!hMod) return;

    DWORD oldProt;
    if (VirtualProtect(hMod, 0x1000, PAGE_READWRITE, &oldProt)) {
        auto* dos = (IMAGE_DOS_HEADER*)hMod;
        auto* nt = (IMAGE_NT_HEADERS64*)((uintptr_t)hMod + dos->e_lfanew);
        // Zero optional header fields that dumpers rely on
        nt->OptionalHeader.SizeOfImage = 0;
        nt->OptionalHeader.ImageBase = 0;
        nt->OptionalHeader.AddressOfEntryPoint = 0;
        // Zero data directories except imports (we still need those)
        for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
            if (i == IMAGE_DIRECTORY_ENTRY_IMPORT) continue;
            nt->OptionalHeader.DataDirectory[i].VirtualAddress = 0;
            nt->OptionalHeader.DataDirectory[i].Size = 0;
        }
        VirtualProtect(hMod, 0x1000, oldProt, &oldProt);
    }
}

// ── Anti-attach: set process as debug-hardened ───────────────────────────
static void SecurityAntiAttach() {
    typedef NTSTATUS(NTAPI* NtSIP_t)(HANDLE, ULONG, PVOID, ULONG);
    auto NtSIP = (NtSIP_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationProcess");
    if (NtSIP) {
        // ProcessBreakOnTermination = 0x1D
        ULONG breakOnTerm = 1;
        NtSIP(GetCurrentProcess(), 0x1D, &breakOnTerm, sizeof(breakOnTerm));
    }
}

// ── Heartbeat: background thread that periodically checks integrity ──────
static volatile bool g_heartbeatActive = false;
static volatile bool g_heartbeatPaused = false;
static HANDLE g_heartbeatThread = nullptr;

static DWORD WINAPI HeartbeatThread(LPVOID) {
    while (g_heartbeatActive) {
        Sleep(2000 + (GetTickCount() % 1000));

        if (g_heartbeatPaused) continue;

        if (!SecurityCheckIntegrity()) {
            if (g_heartbeatPaused) continue;
            HMODULE h = GetModuleHandleA(nullptr);
            DWORD old;
            if (h && VirtualProtect(h, 0x1000, PAGE_READWRITE, &old)) {
                SecureZeroMemory(h, 0x1000);
            }
            TerminateProcess(GetCurrentProcess(), 0xDEAD);
        }

        if (g_heartbeatPaused) continue;

        if (!SecurityAntiDebugDeep()) {
            if (g_heartbeatPaused) continue;
            TerminateProcess(GetCurrentProcess(), 0xDEAD);
        }
    }
    return 0;
}

static void SecurityStartHeartbeat() {
    if (g_heartbeatActive) return;
    g_heartbeatActive = true;
    g_heartbeatThread = CreateThread(nullptr, 0, HeartbeatThread, nullptr, 0, nullptr);
}

static void SecurityPauseHeartbeat() { g_heartbeatPaused = true; }
static void SecurityResumeHeartbeat() { g_heartbeatPaused = false; }

static void SecurityStopHeartbeat() {
    g_heartbeatActive = false;
    if (g_heartbeatThread) {
        WaitForSingleObject(g_heartbeatThread, 3000);
        CloseHandle(g_heartbeatThread);
        g_heartbeatThread = nullptr;
    }
}

// ── Master init: call once before any meaningful work ────────────────────
static bool SecurityInit() {
    if (!SecurityInitIntegrity()) return false;
    SecurityAntiDump();
    SecurityStartHeartbeat();
    return true;
}

static void SecurityShutdown() {
    SecurityStopHeartbeat();
}
