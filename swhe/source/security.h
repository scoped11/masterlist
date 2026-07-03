// ============================================================================
// security.h -- Anti-Debug, Anti-Dump, and Self-Integrity Protection
// ============================================================================
//
// This header implements a multi-layered security system to protect the
// cheat from analysis and reverse engineering. It runs entirely in usermode
// and uses only Windows native APIs (ntdll syscalls, PEB inspection, etc.)
//
// Protection layers:
//   1. Thread hiding     -- NtSetInformationThread(ThreadHideFromDebugger)
//   2. Anti-debug        -- 8 independent detection vectors
//   3. Anti-dump         -- PE header zeroing to break memory dumpers
//   4. Anti-attach       -- ProcessBreakOnTermination flag
//   5. Self-integrity    -- CRC32 of .text section + IAT hash verification
//   6. Heartbeat thread  -- continuous background monitoring loop
//   7. Window cloaking   -- random window class name generation
//
// Usage:
//   Security::Init()     -- runs all protections at startup
//   Security::Shutdown() -- cleanly stops the heartbeat thread
//
// ============================================================================

#pragma once
#include <Windows.h>
#include <winternl.h>
#include <cstdint>
#include <cstring>
#include <intrin.h>
#include <string>
#include "log.h"

// ── Thread hiding ───────────────────────────────────────────────────────
// Calls NtSetInformationThread with ThreadHideFromDebugger (0x11) to make
// the thread invisible to debuggers. A hidden thread won't trigger debug
// events (breakpoints, single-step, etc.), so even if a debugger is
// attached it can't observe this thread's execution.
namespace Security {

inline void HideThread(HANDLE hThread = GetCurrentThread()) {
    typedef NTSTATUS(NTAPI* pfnNtSetInformationThread)(HANDLE, ULONG, PVOID, ULONG);
    auto fn = (pfnNtSetInformationThread)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtSetInformationThread");
    if (fn) fn(hThread, 0x11, NULL, 0); // 0x11 = ThreadHideFromDebugger
}

// ── Anti-debug: multiple detection vectors ─────────────────────────────
// Runs 8+ independent checks to detect debuggers, analysis tools, and
// instrumentation. Returns true if the environment appears clean.
//
// Detection vectors:
//   1. IsDebuggerPresent()       -- checks PEB.BeingDebugged flag
//   2. NtQueryInformationProcess(ProcessDebugPort=7)
//                                -- nonzero debug port = debugger attached
//   3. NtQueryInformationProcess(ProcessDebugObjectHandle=0x1E)
//                                -- debug object exists = debugger present
//   4. PEB.NtGlobalFlag          -- FLG_HEAP_* flags set by debugger (0x70)
//   5. NtQuerySystemInformation(SystemKernelDebuggerInformation=0x23)
//                                -- kernel debugger active on the machine
//   6. Hook detection            -- checks if NtQueryInformationProcess
//                                   starts with JMP (0xE9) or indirect JMP
//                                   (0xFF), indicating an inline hook
//   7. Heap flags                -- HeapFlags/ForceFlags at known offsets
//                                   in the process heap header (debugger
//                                   sets HEAP_TAIL_CHECKING_ENABLED etc.)
//   8. Invalid handle test       -- CloseHandle(0xDEADBEEF) under SEH;
//                                   a debugger intercepts the invalid handle
//                                   exception before our handler runs
//   9. Timing check              -- measures a trivial loop with QPC;
//                                   single-stepping inflates the elapsed
//                                   time beyond 3000 microseconds
inline bool AntiDebugCheck() {
    int threats = 0;

    // Vector 1: PEB.BeingDebugged flag (simplest check, easily bypassed
    // but catches naive attachments)
    if (IsDebuggerPresent()) threats++;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll) {
        typedef NTSTATUS(NTAPI* NtQIP_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        auto NtQIP = (NtQIP_t)GetProcAddress(ntdll, "NtQueryInformationProcess");
        if (NtQIP) {
            // Vector 2: ProcessDebugPort (class 7)
            // If a debugger is attached, the kernel sets the debug port to a
            // nonzero value.
            ULONG_PTR debugPort = 0;
            if (NtQIP(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), NULL) == 0 && debugPort)
                threats++;

            // Vector 3: ProcessDebugObjectHandle (class 0x1E)
            // If a debug object handle exists, a debugger created it.
            HANDLE debugObj = nullptr;
            if (NtQIP(GetCurrentProcess(), 0x1E, &debugObj, sizeof(debugObj), NULL) == 0 && debugObj)
                threats++;

            // Vector 4: NtGlobalFlag in the PEB
            // Debuggers set FLG_HEAP_ENABLE_TAIL_CHECK (0x10),
            // FLG_HEAP_ENABLE_FREE_CHECK (0x20), and
            // FLG_HEAP_VALIDATE_PARAMETERS (0x40) -- mask 0x70.
            struct { ULONG_PTR Reserved[6]; PVOID PebBase; } pbi = {};
            if (NtQIP(GetCurrentProcess(), 0, &pbi, sizeof(pbi), NULL) == 0 && pbi.PebBase) {
                DWORD ntGlobalFlag = *(DWORD*)((uintptr_t)pbi.PebBase + 0xBC);
                if (ntGlobalFlag & 0x70) threats++;
            }
        }

        // Vector 5: Kernel debugger detection
        // SystemKernelDebuggerInformation (class 0x23) reports whether a
        // kernel debugger (WinDbg, KD) is active on the system.
        typedef NTSTATUS(NTAPI* NtQSI_t)(ULONG, PVOID, ULONG, PULONG);
        auto NtQSI = (NtQSI_t)GetProcAddress(ntdll, "NtQuerySystemInformation");
        if (NtQSI) {
            struct { BOOLEAN DebuggerEnabled; BOOLEAN DebuggerNotPresent; } sysDbg = {};
            if (NtQSI(0x23, &sysDbg, sizeof(sysDbg), nullptr) == 0)
                if (sysDbg.DebuggerEnabled && !sysDbg.DebuggerNotPresent)
                    threats++;
        }

        // Vector 6: Inline hook detection on NtQueryInformationProcess
        // If the first byte is a JMP (E9) or indirect JMP (FF), someone
        // has hooked the function -- likely an instrumentation tool.
        if (NtQIP) {
            uint8_t* fn = (uint8_t*)NtQIP;
            if (fn[0] == 0xE9 || fn[0] == 0xFF) threats++;
        }
    }

    // Vector 7: Heap flags inspection
    // When a process is created under a debugger, the heap manager sets
    // additional validation flags. We check HeapFlags at offset 0x70
    // and ForceFlags at offset 0x74 in the process heap header.
    PVOID heap = GetProcessHeap();
    if (heap) {
        DWORD heapFlags = *(DWORD*)((uintptr_t)heap + 0x70);
        DWORD heapForce = *(DWORD*)((uintptr_t)heap + 0x74);
        if (heapFlags & 0x40000060) threats++;
        if (heapForce != 0) threats++;
    }

    // Vector 8: Invalid handle trick
    // Closing an obviously invalid handle raises STATUS_INVALID_HANDLE.
    // A debugger intercepts this exception before our SEH handler runs,
    // so under a debugger the __except block is never reached.
    __try {
        CloseHandle((HANDLE)0xDEADBEEFull);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        threats++;
    }

    // Vector 9: Timing check
    // A trivial loop should complete in well under 3000 microseconds.
    // Single-stepping in a debugger inflates the time dramatically.
    LARGE_INTEGER f, a, b;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&a);
    volatile int x = 0;
    for (int i = 0; i < 50; i++) x ^= i;
    QueryPerformanceCounter(&b);
    double us = ((double)(b.QuadPart - a.QuadPart) / f.QuadPart) * 1e6;
    if (us > 3000.0) threats++;

    return threats == 0;
}

// ── Anti-dump: scramble PE headers in memory ────────────────────────────
// Zeros critical PE header fields (SizeOfImage, ImageBase, EntryPoint,
// and most data directory entries) to break tools that dump the process
// from memory (e.g. pe-sieve, Scylla, Process Hacker).
// The import directory is preserved so the process can continue to
// resolve DLL imports normally.
inline void AntiDump() {
    HMODULE hMod = GetModuleHandleA(nullptr);
    if (!hMod) return;
    DWORD oldProt;
    // Make the first page (PE headers) writable
    if (VirtualProtect(hMod, 0x1000, PAGE_READWRITE, &oldProt)) {
        auto* dos = (IMAGE_DOS_HEADER*)hMod;
        auto* nt = (IMAGE_NT_HEADERS64*)((uintptr_t)hMod + dos->e_lfanew);
        // Zero the fields that dumpers rely on to reconstruct the PE
        nt->OptionalHeader.SizeOfImage = 0;
        nt->OptionalHeader.ImageBase = 0;
        nt->OptionalHeader.AddressOfEntryPoint = 0;
        // Zero all data directory entries except imports (index 1)
        for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
            if (i == IMAGE_DIRECTORY_ENTRY_IMPORT) continue; // keep imports alive
            nt->OptionalHeader.DataDirectory[i].VirtualAddress = 0;
            nt->OptionalHeader.DataDirectory[i].Size = 0;
        }
        // Restore original page protection
        VirtualProtect(hMod, 0x1000, oldProt, &oldProt);
    }
}

// ── Anti-attach ─────────────────────────────────────────────────────────
// Sets ProcessBreakOnTermination (class 0x1D) via NtSetInformationProcess.
// This marks the process as "critical" -- if it terminates unexpectedly
// (e.g. a debugger detaches and kills it), the system will BSOD. This
// makes casual debugger attachment risky since detaching would crash
// the machine.
inline void AntiAttach() {
    typedef NTSTATUS(NTAPI* NtSIP_t)(HANDLE, ULONG, PVOID, ULONG);
    auto fn = (NtSIP_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationProcess");
    if (fn) {
        ULONG breakOnTerm = 1;
        fn(GetCurrentProcess(), 0x1D, &breakOnTerm, sizeof(breakOnTerm)); // ProcessBreakOnTermination
    }
}

// ── Self-integrity: CRC32 of .text section + IAT hash ───────────────────
// Two-part tamper detection:
//   1. CRC32 of the .text section -- detects code patching (breakpoints,
//      inline hooks, binary patches)
//   2. Rolling XOR hash of IAT entries -- detects IAT hooking (redirecting
//      imported function pointers to hook trampolines)
//
// InitIntegrity() takes the baseline snapshot at startup.
// CheckIntegrity() re-computes both hashes and compares against baseline.
namespace detail {
    // Standard CRC32 implementation (polynomial 0xEDB88320)
    inline uint32_t CRC32(const void* data, size_t len) {
        uint32_t crc = 0xFFFFFFFF;
        const uint8_t* p = (const uint8_t*)data;
        for (size_t i = 0; i < len; i++) {
            crc ^= p[i];
            for (int j = 0; j < 8; j++)
                crc = (crc >> 1) ^ ((crc & 1) ? 0xEDB88320U : 0U);
        }
        return ~crc;
    }

    // Baseline integrity state captured at startup
    struct IntegrityState {
        uint32_t textCRC;     // CRC32 of the .text section
        uintptr_t textBase;   // VA of the .text section start
        size_t textSize;      // size in bytes of the .text section
        uint32_t iatHash;     // rolling XOR-rotate hash of all IAT entries
        bool initialized;     // true once baseline has been captured
    };

    inline IntegrityState g_integrity = {};
}

// Captures the baseline CRC32 and IAT hash. Must be called before any
// code modification (i.e. before AntiDump, since that modifies headers
// not code). Returns true if the .text section was found and hashed.
inline bool InitIntegrity() {
    HMODULE hMod = GetModuleHandleA(nullptr);
    if (!hMod) return false;
    auto* dos = (IMAGE_DOS_HEADER*)hMod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = (IMAGE_NT_HEADERS64*)((uintptr_t)hMod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    // Walk the section table to find .text
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            // Hash the entire .text section
            detail::g_integrity.textBase = (uintptr_t)hMod + sec[i].VirtualAddress;
            detail::g_integrity.textSize = sec[i].Misc.VirtualSize;
            detail::g_integrity.textCRC = detail::CRC32(
                (void*)detail::g_integrity.textBase, detail::g_integrity.textSize);

            // Build a rolling hash of all IAT function pointers.
            // Each thunk's lower 32 bits are XORed in with a 7-bit rotation
            // to produce an order-dependent fingerprint.
            auto& importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            if (importDir.VirtualAddress) {
                auto* imp = (IMAGE_IMPORT_DESCRIPTOR*)((uintptr_t)hMod + importDir.VirtualAddress);
                uint32_t h = 0;
                while (imp->Name) {
                    if (imp->FirstThunk) {
                        auto* thunk = (IMAGE_THUNK_DATA64*)((uintptr_t)hMod + imp->FirstThunk);
                        while (thunk->u1.Function) {
                            h ^= (uint32_t)(thunk->u1.Function & 0xFFFFFFFF);
                            h = (h << 7) | (h >> 25); // rotate left 7 bits
                            thunk++;
                        }
                    }
                    imp++;
                }
                detail::g_integrity.iatHash = h;
            }
            detail::g_integrity.initialized = true;
            return true;
        }
    }
    return false;
}

// Re-computes the .text CRC32 and IAT hash, comparing against the
// baseline from InitIntegrity(). Returns false if either has changed,
// indicating code patching or IAT hooking.
inline bool CheckIntegrity() {
    if (!detail::g_integrity.initialized) return false;

    // Check 1: .text section CRC32 -- detects breakpoints, patches, hooks
    uint32_t currentCRC = detail::CRC32(
        (void*)detail::g_integrity.textBase, detail::g_integrity.textSize);
    if (currentCRC != detail::g_integrity.textCRC) return false;

    // Check 2: IAT hash -- detects function pointer redirection
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
        if (h != detail::g_integrity.iatHash) return false;
    }
    return true;
}

// ── Heartbeat thread ────────────────────────────────────────────────────
// A background thread that continuously monitors for tampering.
// Every 2-3 seconds (randomized to avoid timing-based detection), it:
//   1. Runs CheckIntegrity() to verify .text + IAT are untouched
//   2. Runs AntiDebugCheck() to look for newly attached debuggers
// If either check fails, it:
//   1. Zeros the first page of the module (destroys PE headers + code)
//   2. Terminates the process immediately
// The thread itself is hidden from debuggers via HideThread().
inline volatile bool g_heartbeatActive = false;
inline HANDLE g_heartbeatThread = nullptr;

inline DWORD WINAPI HeartbeatProc(LPVOID) {
    HideThread(); // make this thread invisible to debuggers
    while (g_heartbeatActive) {
        // Randomized sleep interval: 2000-3000ms
        Sleep(2000 + (GetTickCount() % 1000));
        if (!CheckIntegrity() || !AntiDebugCheck()) {
            // Tamper detected: zero the module's first page and terminate
            HMODULE h = GetModuleHandleA(nullptr);
            DWORD old;
            if (h && VirtualProtect(h, 0x1000, PAGE_READWRITE, &old))
                SecureZeroMemory(h, 0x1000);
            TerminateProcess(GetCurrentProcess(), 0);
        }
    }
    return 0;
}

inline void StartHeartbeat() {
    if (g_heartbeatActive) return;
    g_heartbeatActive = true;
    g_heartbeatThread = CreateThread(nullptr, 0, HeartbeatProc, nullptr, 0, nullptr);
}

inline void StopHeartbeat() {
    g_heartbeatActive = false;
    if (g_heartbeatThread) {
        WaitForSingleObject(g_heartbeatThread, 3000);
        CloseHandle(g_heartbeatThread);
        g_heartbeatThread = nullptr;
    }
}

// ── Random window class name ────────────────────────────────────────────
// Generates a plausible-looking Windows system class name to disguise the
// cheat's overlay window. The name combines a common Microsoft prefix
// (e.g. "Microsoft", "Explorer", "System") with a suffix (e.g. "Host",
// "Manager", "Provider") and a hex timestamp for uniqueness.
// Example output: "ExplorerBroker_3A7F", "SystemHandler_1B2C"
inline std::string GenerateWindowClass() {
    static const char* prefixes[] = {
        "Microsoft", "Windows", "Shell", "Explorer", "Desktop",
        "Taskbar", "System", "Runtime", "Service", "Helper"
    };
    static const char* suffixes[] = {
        "Host", "Worker", "Manager", "Provider", "Handler",
        "Broker", "Client", "Agent", "Monitor", "Bridge"
    };
    DWORD t = GetTickCount();
    char buf[64];
    sprintf_s(buf, "%s%s_%X",
        prefixes[t % 10], suffixes[(t / 10) % 10], t & 0xFFFF);
    return std::string(buf);
}

// ── Master init ─────────────────────────────────────────────────────────
// Initializes all security layers in the correct order:
//   1. HideThread()      -- hide the main thread from debuggers
//   2. AntiDebugCheck()   -- bail out immediately if debugger detected
//   3. InitIntegrity()    -- snapshot .text CRC32 + IAT hash baseline
//   4. AntiDump()         -- zero PE headers to break memory dumpers
//   5. AntiAttach()       -- mark process as critical (BSOD on kill)
//   6. StartHeartbeat()   -- launch continuous monitoring thread
inline bool Init() {
    HideThread();
    if (!AntiDebugCheck()) {
        Log("Security check failed");
        return false;
    }
    InitIntegrity();
    AntiDump();
    AntiAttach();
    StartHeartbeat();
    return true;
}

inline void Shutdown() {
    StopHeartbeat();
}

} // namespace Security
