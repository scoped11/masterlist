#pragma once
/*
 * betest_stealth.hpp — CTF process stealth via Betest.sys
 *
 * Usermode API for all stealth IOCTLs:
 *   - CR3 swap (static single-donor)
 *   - CR3 shuffle (per-core rotation with auto-donor)
 *   - DKOM process hiding
 *   - Full stealth composite (DKOM + CR3 shuffle + token + PEB + handles)
 *   - Handle table scrubbing
 *   - Thread hiding
 *
 * Usage:
 *   Stealth::Init();
 *   Stealth::FullStealthEx(cheatPid, gamePid, STEALTH_SHUFFLE | STEALTH_AUTO_DONORS | STEALTH_SCRUB_HANDLES);
 *   // ... cheat runs ...
 *   Stealth::StopShuffle();  // restore CR3 before exit
 */

#include <Windows.h>
#include <cstdint>

// Must match BetestDriver.c IOCTL definitions
#define _IOCTL_HIDE_PROCESS      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_WRITE_DATA)
#define _IOCTL_CR3_SWAP          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80C, METHOD_BUFFERED, FILE_WRITE_DATA)
#define _IOCTL_CR3_RESTORE       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_WRITE_DATA)
#define _IOCTL_HIDE_THREADS      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x816, METHOD_BUFFERED, FILE_WRITE_DATA)
#define _IOCTL_SWAP_TOKEN        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x817, METHOD_BUFFERED, FILE_WRITE_DATA)
#define _IOCTL_SANITIZE_PEB      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x818, METHOD_BUFFERED, FILE_WRITE_DATA)
#define _IOCTL_FULL_STEALTH      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x819, METHOD_BUFFERED, FILE_WRITE_DATA)
#define _IOCTL_SCRUB_HANDLES     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81D, METHOD_BUFFERED, FILE_WRITE_DATA)
#define _IOCTL_CR3_SHUFFLE       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x822, METHOD_BUFFERED, FILE_WRITE_DATA)
#define _IOCTL_CR3_SHUFFLE_STOP  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x825, METHOD_BUFFERED, FILE_WRITE_DATA)
#define _IOCTL_FULL_STEALTH_EX   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x826, METHOD_BUFFERED, FILE_WRITE_DATA)
// CTF Tasks 9-13
#define _IOCTL_UNIFIED_NEUTRALIZE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x827, METHOD_BUFFERED, FILE_WRITE_DATA)
#define _IOCTL_HOOK_AC_DECRYPT    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x828, METHOD_BUFFERED, FILE_WRITE_DATA)
#define _IOCTL_READ_AC_PLAINTEXT  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x829, METHOD_BUFFERED, FILE_READ_DATA)
#define _IOCTL_DEEP_HIDE          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x82A, METHOD_BUFFERED, FILE_WRITE_DATA)
#define _IOCTL_ENCRYPT_POOL       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x82B, METHOD_BUFFERED, FILE_WRITE_DATA)
#define _IOCTL_POLYMORPHIC_STUB   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x82C, METHOD_BUFFERED, FILE_READ_DATA)
#define _IOCTL_CLEANUP_TRACES     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x82D, METHOD_BUFFERED, FILE_WRITE_DATA)
// CTF Tasks 14-22
#define _IOCTL_PATCHGUARD_SAFE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x82E, METHOD_BUFFERED, FILE_WRITE_DATA)
#define _IOCTL_OBFUSCATE_REGION   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x82F, METHOD_BUFFERED, FILE_WRITE_DATA)
#define _IOCTL_HOLLOW_PROCESS     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x830, METHOD_BUFFERED, FILE_WRITE_DATA)
#define _IOCTL_INDIRECT_SYSCALL   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x831, METHOD_BUFFERED, FILE_READ_DATA)
#define _IOCTL_MUTATE_DRIVER      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x832, METHOD_BUFFERED, FILE_WRITE_DATA)
#define _IOCTL_DELAYED_OP         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x833, METHOD_BUFFERED, FILE_WRITE_DATA)
#define _IOCTL_EPT_SAFE_WRITE     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x834, METHOD_BUFFERED, FILE_WRITE_DATA)
#define _IOCTL_CLEAN_EVENT_LOG    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x835, METHOD_BUFFERED, FILE_WRITE_DATA)
#define _IOCTL_FULL_SELF_CLEAN    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x836, METHOD_BUFFERED, FILE_WRITE_DATA)
// Tasks 23-32
#define _IOCTL_PG_RESIST          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x837, METHOD_BUFFERED, FILE_WRITE_DATA)
#define _IOCTL_HV_EVASION         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x838, METHOD_BUFFERED, FILE_WRITE_DATA)
#define _IOCTL_HIDE_KTHREADS      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x839, METHOD_BUFFERED, FILE_WRITE_DATA)
#define _IOCTL_KILL_TELEMETRY     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x83A, METHOD_BUFFERED, FILE_WRITE_DATA)
#define _IOCTL_RUNTIME_POLYMORPH  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x83B, METHOD_BUFFERED, FILE_WRITE_DATA)
#define _IOCTL_PG_BYPASS          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x83C, METHOD_BUFFERED, FILE_WRITE_DATA)
#define _IOCTL_DEEP_HV_EVASION   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x83D, METHOD_BUFFERED, FILE_WRITE_DATA)
#define _IOCTL_ANTI_DEBUG         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x83E, METHOD_BUFFERED, FILE_WRITE_DATA)
#define _IOCTL_ENCRYPT_DRIVER_MEM CTL_CODE(FILE_DEVICE_UNKNOWN, 0x83F, METHOD_BUFFERED, FILE_WRITE_DATA)
#define _IOCTL_BARE_METAL_STABLE  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x840, METHOD_BUFFERED, FILE_WRITE_DATA)

// Flags for FullStealthEx
#define STEALTH_SHUFFLE       0x01
#define STEALTH_SCRUB_HANDLES 0x02
#define STEALTH_AUTO_DONORS   0x04

// Flags for UnifiedNeutralize
#define NEUT_BE   0x01
#define NEUT_EAC  0x02
#define NEUT_ACE  0x04
#define NEUT_VGK  0x08
#define NEUT_ALL  0x0F

// Flags for DeepHide
#define DEEP_UNLINK_DRIVER  0x01
#define DEEP_POOL_SCRAMBLE  0x02
#define DEEP_DEVICE_BLEND   0x04
#define DEEP_TIMER_CLEANUP  0x08
#define DEEP_SECTION_UNLINK 0x10
#define DEEP_PROCESS_DEEP   0x20
#define DEEP_ALL            0x3F

// Flags for CleanupTraces
#define CLEANUP_ZERO_DRIVER  0x01
#define CLEANUP_REMOVE_REG   0x02
#define CLEANUP_SCRUB_ETW    0x04
#define CLEANUP_RESTORE_CR3  0x08
#define CLEANUP_RESTORE_OB   0x10
#define CLEANUP_ALL          0x1F

// Flags for MutateDriver
#define MUTATE_TEXT   0x01
#define MUTATE_RDATA  0x02
#define MUTATE_IOCTLS 0x04

// Flags for FullSelfClean
#define SELFCLEAN_HOOKS        0x01
#define SELFCLEAN_EVENT_LOGS   0x02
#define SELFCLEAN_TEMP_OBJECTS 0x04
#define SELFCLEAN_REGISTRY     0x08
#define SELFCLEAN_CR3          0x10
#define SELFCLEAN_DRIVER_MEM   0x20
#define SELFCLEAN_ALL          0x3F

#pragma pack(push, 1)
struct CR3SwapReq {
    uint64_t TargetPid;
    uint64_t SpoofCR3;   // 0 = auto from System
};

struct CR3ShuffleReq {
    uint64_t TargetPid;
    uint64_t DonorPids[4];  // 0 = use System for that slot
    uint32_t DonorCount;    // 0 = auto-pick, 1-4 = manual
    uint32_t Pad;
};

struct FullStealthReq {
    uint64_t TargetPid;
    uint64_t SpoofCR3;
};

struct FullStealthExReq {
    uint64_t TargetPid;      // cheat process to hide
    uint64_t GamePid;        // game process (for handle scrubbing)
    uint64_t DonorPids[4];   // manual donor PIDs (ignored if AUTO_DONORS)
    uint32_t DonorCount;     // 0 = auto, 1-4 = manual
    uint32_t Flags;          // STEALTH_* bitmask
};

struct ScrubHandlesReq {
    uint64_t GamePid;
    uint64_t CheatPid;
};

struct UnifiedNeutralizeReq {
    uint32_t Flags;         // NEUT_* bitmask (0x0F = all)
    uint32_t RescanMs;      // deferred re-scan interval (0 = no re-scan)
};

struct HookACDecryptReq {
    uint64_t AcBase;        // 0 = auto-find
    uint32_t ScanLen;       // 0 = default 0x100000
    uint32_t Pad;
};

struct DeepHideReq {
    uint64_t TargetPid;     // 0 = driver-only
    uint32_t Flags;         // DEEP_* bitmask
    uint32_t Pad;
};

struct EncryptPoolReq {
    uint64_t Address;
    uint32_t Size;
    uint32_t Encrypt;       // 1 = encrypt, 0 = decrypt
};

struct PolymorphicStubReq {
    uint32_t StubType;      // 0=NOP sled, 1=junk arith, 2=encrypted call
    uint32_t Size;          // 0 = default 64
    uint64_t TargetAddr;    // address for encrypted call
};

struct CleanupTracesReq {
    uint32_t Flags;         // CLEANUP_* bitmask
    uint32_t Pad;
};

// Tasks 14-22
struct PatchGuardSafeReq {
    uint32_t Action;        // 0 = clean DPC/timer, 1 = integrity bypass
    uint32_t Pad;
};

struct ObfuscateRegionReq {
    uint64_t Address;
    uint32_t Size;
    uint32_t Action;        // 0 = obfuscate, 1 = deobfuscate, 2 = re-roll key
};

struct HollowProcessReq {
    uint64_t TargetPid;
    uint64_t PayloadAddr;
    uint32_t PayloadSize;
    uint32_t Pad;
};

struct IndirectSyscallReq {
    uint32_t SyscallNumber;
    uint32_t ArgCount;
    uint64_t Args[8];
};

struct MutateDriverReq {
    uint32_t Flags;         // MUTATE_* bitmask
    uint32_t Pad;
};

struct DelayedOpReq {
    uint32_t OpCode;        // 0=neutralize, 1=deep hide, 2=full stealth
    uint32_t DelayMs;
    uint64_t Pid;
};

struct EptSafeWriteReq {
    uint64_t Address;
    uint32_t Size;
    uint32_t Pad;
    uint8_t  Data[1];       // variable length
};

struct FullSelfCleanReq {
    uint32_t Flags;         // SELFCLEAN_* bitmask
    uint32_t Pad;
};

// Tasks 23-32
struct PgResistReq { uint32_t Flags; uint32_t Pad; };
struct HvEvasionReq { uint32_t Flags; uint32_t Pad; };
struct HideKThreadReq { uint64_t Pid; uint32_t Flags; uint32_t Pad; };
struct KillTelemReq { uint32_t Flags; uint32_t Pad; };
struct RuntimePolyReq { uint32_t Flags; uint32_t Seed; };
struct PgBypassReq { uint32_t Action; uint32_t Pad; };
struct DeepHvReq { uint32_t Flags; uint32_t Pad; };
struct AntiDebugReq { uint32_t Flags; uint32_t Pad; };
struct DrvEncryptReq { uint32_t Action; uint32_t Flags; };
struct BareMetalReq { uint32_t Flags; uint32_t Pad; };

#define PGR_CLEAN_TIMERS    0x01
#define PGR_ZERO_PE_HDRS    0x02
#define PGR_AVOID_SCANNED   0x04
#define PGR_FLUSH_DPC       0x08
#define PGR_RELOCATE_CODE   0x10
#define PGR_ALL             0x1F

#define HVE_DETECT_HV       0x01
#define HVE_BYPASS_EPT      0x02
#define HVE_ALT_MEM_ACCESS  0x04
#define HVE_HIDE_FROM_HV    0x08
#define HVE_ALL             0x0F

#define KTH_HIDE_THREADS    0x01
#define KTH_CLEAN_APC       0x02
#define KTH_REDUCE_FOOTPRINT 0x04
#define KTH_ALL             0x07

#define TEL_DISABLE_ETW     0x01
#define TEL_BLOCK_REPORTS   0x02
#define TEL_CLEAN_SESSIONS  0x04
#define TEL_PATCH_CKCL      0x08
#define TEL_ALL             0x0F

#define RPOLY_MUTATE_TEXT   0x01
#define RPOLY_SHUFFLE_IAT   0x02
#define RPOLY_MORPH_STRUCTS 0x04
#define RPOLY_REKEY         0x08
#define RPOLY_ALL           0x0F

#define DHV_DETECT_EPT_SHADOW 0x01
#define DHV_USE_MDL_ACCESS    0x02
#define DHV_PHYS_MAP          0x04
#define DHV_SPLIT_TLB         0x08
#define DHV_ALL               0x0F

#define ADB_DETECT_DEBUGGER  0x01
#define ADB_SELF_PROTECT     0x02
#define ADB_INTEGRITY_CHECK  0x04
#define ADB_ANTI_ATTACH      0x08
#define ADB_ALL              0x0F

#define DENC_CODE_SECTION    0x01
#define DENC_DATA_SECTION    0x02
#define DENC_RDATA_SECTION   0x04
#define DENC_ALL             0x07

#define BMS_TLB_FLUSH        0x01
#define BMS_BUILD_DETECT     0x02
#define BMS_SAFE_CAVE        0x04
#define BMS_ALL              0x07

#pragma pack(pop)

namespace Stealth {

inline HANDLE g_hDev = INVALID_HANDLE_VALUE;

inline bool Init()
{
    if (g_hDev != INVALID_HANDLE_VALUE) return true;
    g_hDev = CreateFileA("\\\\.\\MsFlt0",
                         GENERIC_READ | GENERIC_WRITE,
                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                         nullptr, OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL, nullptr);
    return g_hDev != INVALID_HANDLE_VALUE;
}

inline void SetHandle(HANDLE h) { g_hDev = h; }

// ── Individual stealth operations ──────────────────────────────────────────

// DKOM: unlink from ActiveProcessLinks / SessionProcessLinks / PspCidTable
inline bool HideProcess(uint32_t pid)
{
    uint64_t id = pid;
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, _IOCTL_HIDE_PROCESS,
                           &id, sizeof(id), nullptr, 0, &ret, nullptr) != FALSE;
}

// Static CR3 swap: replace target's CR3 with a single donor (0 = System)
inline bool CR3Swap(uint32_t targetPid, uint64_t spoofCR3 = 0)
{
    CR3SwapReq req{};
    req.TargetPid = targetPid;
    req.SpoofCR3  = spoofCR3;
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, _IOCTL_CR3_SWAP,
                           &req, sizeof(req), nullptr, 0, &ret, nullptr) != FALSE;
}

// CR3 restore: undo a previous CR3 swap
inline bool CR3Restore(uint32_t pid)
{
    uint64_t id = pid;
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, _IOCTL_CR3_RESTORE,
                           &id, sizeof(id), nullptr, 0, &ret, nullptr) != FALSE;
}

// CR3 shuffle: per-core rotation with 1-4 donors
// Pass donorCount=0 for auto-pick (svchost/lsass/services CR3s)
inline bool CR3Shuffle(uint32_t targetPid,
                       const uint64_t* donorPids = nullptr,
                       uint32_t donorCount = 0)
{
    CR3ShuffleReq req{};
    req.TargetPid  = targetPid;
    req.DonorCount = donorCount;
    if (donorPids && donorCount > 0) {
        for (uint32_t i = 0; i < donorCount && i < 4; i++)
            req.DonorPids[i] = donorPids[i];
    }
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, _IOCTL_CR3_SHUFFLE,
                           &req, sizeof(req), nullptr, 0, &ret, nullptr) != FALSE;
}

// Stop CR3 shuffle and restore original CR3
inline bool StopShuffle()
{
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, _IOCTL_CR3_SHUFFLE_STOP,
                           nullptr, 0, nullptr, 0, &ret, nullptr) != FALSE;
}

// Hide all threads of a process (CID table removal)
inline bool HideThreads(uint32_t pid)
{
    uint64_t id = pid;
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, _IOCTL_HIDE_THREADS,
                           &id, sizeof(id), nullptr, 0, &ret, nullptr) != FALSE;
}

// Copy System token to target process
inline bool SwapToken(uint32_t pid)
{
    uint64_t id = pid;
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, _IOCTL_SWAP_TOKEN,
                           &id, sizeof(id), nullptr, 0, &ret, nullptr) != FALSE;
}

// Zero PEB ImagePathName/CommandLine, overwrite ImageFileName with "svchost.exe"
inline bool SanitizePEB(uint32_t pid)
{
    uint64_t id = pid;
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, _IOCTL_SANITIZE_PEB,
                           &id, sizeof(id), nullptr, 0, &ret, nullptr) != FALSE;
}

// Remove handles to cheatPid from gamePid's handle table
inline bool ScrubHandles(uint32_t gamePid, uint32_t cheatPid)
{
    ScrubHandlesReq req{};
    req.GamePid  = gamePid;
    req.CheatPid = cheatPid;
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, _IOCTL_SCRUB_HANDLES,
                           &req, sizeof(req), nullptr, 0, &ret, nullptr) != FALSE;
}

// ── Composite stealth operations ───────────────────────────────────────────

// Basic: DKOM + static CR3 swap + token + PEB
inline bool FullStealth(uint32_t pid, uint64_t spoofCR3 = 0)
{
    FullStealthReq req{};
    req.TargetPid = pid;
    req.SpoofCR3  = spoofCR3;
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, _IOCTL_FULL_STEALTH,
                           &req, sizeof(req), nullptr, 0, &ret, nullptr) != FALSE;
}

// Extended: DKOM + CR3 shuffle + token + PEB + optional handle scrub
// flags: STEALTH_SHUFFLE | STEALTH_AUTO_DONORS | STEALTH_SCRUB_HANDLES
inline bool FullStealthEx(uint32_t cheatPid, uint32_t gamePid = 0,
                          uint32_t flags = STEALTH_SHUFFLE | STEALTH_AUTO_DONORS,
                          const uint64_t* donorPids = nullptr,
                          uint32_t donorCount = 0)
{
    FullStealthExReq req{};
    req.TargetPid  = cheatPid;
    req.GamePid    = gamePid;
    req.Flags      = flags;
    req.DonorCount = donorCount;
    if (donorPids && donorCount > 0) {
        for (uint32_t i = 0; i < donorCount && i < 4; i++)
            req.DonorPids[i] = donorPids[i];
    }
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, _IOCTL_FULL_STEALTH_EX,
                           &req, sizeof(req), nullptr, 0, &ret, nullptr) != FALSE;
}

// ── CTF Tasks 9-13: New APIs ───────────────────────────────────────────────

// Task 9: Unified neutralize — fire all AC neutralization in one call
// flags: NEUT_BE | NEUT_EAC | NEUT_ACE | NEUT_VGK (or NEUT_ALL)
// rescanMs: auto-repeat interval (0 = fire once)
inline bool UnifiedNeutralize(uint32_t flags = NEUT_ALL, uint32_t rescanMs = 0)
{
    UnifiedNeutralizeReq req{};
    req.Flags = flags;
    req.RescanMs = rescanMs;
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, _IOCTL_UNIFIED_NEUTRALIZE,
                           &req, sizeof(req), nullptr, 0, &ret, nullptr) != FALSE;
}

// Task 10: Hook AC's decrypt routine to capture plaintext
inline bool HookACDecrypt(uint64_t acBase = 0, uint32_t scanLen = 0)
{
    HookACDecryptReq req{};
    req.AcBase = acBase;
    req.ScanLen = scanLen;
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, _IOCTL_HOOK_AC_DECRYPT,
                           &req, sizeof(req), nullptr, 0, &ret, nullptr) != FALSE;
}

// Task 10: Read captured plaintext from AC decrypt hook
inline uint32_t ReadACPlaintext(void* buffer, uint32_t maxLen)
{
    DWORD returned = 0;
    if (!DeviceIoControl(g_hDev, _IOCTL_READ_AC_PLAINTEXT,
                         nullptr, 0, buffer, maxLen, &returned, nullptr))
        return 0;
    return returned;
}

// Task 11: Deep hide — extended driver + process stealth
inline bool DeepHide(uint32_t targetPid = 0, uint32_t flags = DEEP_ALL)
{
    DeepHideReq req{};
    req.TargetPid = targetPid;
    req.Flags = flags;
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, _IOCTL_DEEP_HIDE,
                           &req, sizeof(req), nullptr, 0, &ret, nullptr) != FALSE;
}

// Task 13: Encrypt/decrypt kernel pool memory
inline bool EncryptPool(uint64_t addr, uint32_t size, bool encrypt = true)
{
    EncryptPoolReq req{};
    req.Address = addr;
    req.Size = size;
    req.Encrypt = encrypt ? 1 : 0;
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, _IOCTL_ENCRYPT_POOL,
                           &req, sizeof(req), nullptr, 0, &ret, nullptr) != FALSE;
}

// Task 12: Generate polymorphic code stub
inline uint32_t GetPolymorphicStub(void* buffer, uint32_t bufLen,
                                   uint32_t stubType = 0, uint32_t size = 64,
                                   uint64_t targetAddr = 0)
{
    PolymorphicStubReq req{};
    req.StubType = stubType;
    req.Size = size;
    req.TargetAddr = targetAddr;
    DWORD returned = 0;
    if (!DeviceIoControl(g_hDev, _IOCTL_POLYMORPHIC_STUB,
                         &req, sizeof(req), buffer, bufLen, &returned, nullptr))
        return 0;
    return returned;
}

// Task 12: Cleanup all traces before unload
inline bool CleanupTraces(uint32_t flags = CLEANUP_ALL)
{
    CleanupTracesReq req{};
    req.Flags = flags;
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, _IOCTL_CLEANUP_TRACES,
                           &req, sizeof(req), nullptr, 0, &ret, nullptr) != FALSE;
}

// ── CTF Tasks 14-22: New APIs ──────────────────────────────────────────────

// Task 14: PatchGuard-safe operations
inline bool PatchGuardSafe(uint32_t action = 0)
{
    PatchGuardSafeReq req{};
    req.Action = action;
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, _IOCTL_PATCHGUARD_SAFE,
                           &req, sizeof(req), nullptr, 0, &ret, nullptr) != FALSE;
}

// Task 15: Memory obfuscation (0=obfuscate, 1=deobfuscate, 2=re-roll key)
inline bool ObfuscateRegion(uint64_t addr, uint32_t size, uint32_t action = 0)
{
    ObfuscateRegionReq req{};
    req.Address = addr;
    req.Size = size;
    req.Action = action;
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, _IOCTL_OBFUSCATE_REGION,
                           &req, sizeof(req), nullptr, 0, &ret, nullptr) != FALSE;
}

// Task 16: Process hollowing — replace target process image with payload
inline bool HollowProcess(uint32_t targetPid, uint64_t payloadAddr, uint32_t payloadSize)
{
    HollowProcessReq req{};
    req.TargetPid = targetPid;
    req.PayloadAddr = payloadAddr;
    req.PayloadSize = payloadSize;
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, _IOCTL_HOLLOW_PROCESS,
                           &req, sizeof(req), nullptr, 0, &ret, nullptr) != FALSE;
}

// Task 16: Indirect syscall — call Nt* by SSN, bypassing inline hooks
inline int32_t IndirectSyscall(uint32_t ssn, const uint64_t* args, uint32_t argCount)
{
    IndirectSyscallReq req{};
    req.SyscallNumber = ssn;
    req.ArgCount = argCount;
    if (args && argCount > 0) {
        for (uint32_t i = 0; i < argCount && i < 8; i++)
            req.Args[i] = args[i];
    }
    int32_t result = 0;
    DWORD returned = 0;
    DeviceIoControl(g_hDev, _IOCTL_INDIRECT_SYSCALL,
                    &req, sizeof(req), &result, sizeof(result),
                    &returned, nullptr);
    return result;
}

// Task 17: Mutate driver code in-place for anti-signature
inline bool MutateDriver(uint32_t flags = MUTATE_TEXT)
{
    MutateDriverReq req{};
    req.Flags = flags;
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, _IOCTL_MUTATE_DRIVER,
                           &req, sizeof(req), nullptr, 0, &ret, nullptr) != FALSE;
}

// Task 19: Schedule a delayed operation (fire after delayMs)
inline bool DelayedOp(uint32_t opCode, uint32_t delayMs, uint32_t pid = 0)
{
    DelayedOpReq req{};
    req.OpCode = opCode;
    req.DelayMs = delayMs;
    req.Pid = pid;
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, _IOCTL_DELAYED_OP,
                           &req, sizeof(req), nullptr, 0, &ret, nullptr) != FALSE;
}

// Task 20: EPT-safe write — write kernel memory avoiding hypervisor detection
inline bool EptSafeWrite(uint64_t addr, const void* data, uint32_t size)
{
    if (!data || !size || size > 4096) return false;
    uint8_t buf[sizeof(EptSafeWriteReq) + 4096];
    auto* req = reinterpret_cast<EptSafeWriteReq*>(buf);
    req->Address = addr;
    req->Size = size;
    req->Pad = 0;
    memcpy(req->Data, data, size);
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, _IOCTL_EPT_SAFE_WRITE,
                           buf, (DWORD)(sizeof(EptSafeWriteReq) - 1 + size),
                           nullptr, 0, &ret, nullptr) != FALSE;
}

// Task 21: Clean event logs
inline bool CleanEventLogs()
{
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, _IOCTL_CLEAN_EVENT_LOG,
                           nullptr, 0, nullptr, 0, &ret, nullptr) != FALSE;
}

// Task 21: Full self-clean — comprehensive cleanup before exit
inline bool FullSelfClean(uint32_t flags = SELFCLEAN_ALL)
{
    FullSelfCleanReq req{};
    req.Flags = flags;
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, _IOCTL_FULL_SELF_CLEAN,
                           &req, sizeof(req), nullptr, 0, &ret, nullptr) != FALSE;
}

// Task 22: Dynamic names — try all known device names to find the driver
inline bool InitDynamic()
{
    if (g_hDev != INVALID_HANDLE_VALUE) return true;

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
        if (g_hDev != INVALID_HANDLE_VALUE) return true;
    }
    return false;
}

// ── Tasks 23-32 API ────────────────────────────────────────────────────────

inline bool PatchGuardResist(uint32_t flags = PGR_ALL)
{
    PgResistReq req{}; req.Flags = flags;
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, _IOCTL_PG_RESIST,
                           &req, sizeof(req), nullptr, 0, &ret, nullptr) != FALSE;
}

inline bool HypervisorEvasion(uint32_t flags = HVE_ALL)
{
    HvEvasionReq req{}; req.Flags = flags;
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, _IOCTL_HV_EVASION,
                           &req, sizeof(req), nullptr, 0, &ret, nullptr) != FALSE;
}

inline bool HideKernelThreads(uint64_t pid = 0, uint32_t flags = KTH_ALL)
{
    HideKThreadReq req{}; req.Pid = pid; req.Flags = flags;
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, _IOCTL_HIDE_KTHREADS,
                           &req, sizeof(req), nullptr, 0, &ret, nullptr) != FALSE;
}

inline bool KillTelemetry(uint32_t flags = TEL_ALL)
{
    KillTelemReq req{}; req.Flags = flags;
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, _IOCTL_KILL_TELEMETRY,
                           &req, sizeof(req), nullptr, 0, &ret, nullptr) != FALSE;
}

inline bool RuntimePolymorph(uint32_t flags = RPOLY_ALL, uint32_t seed = 0)
{
    RuntimePolyReq req{}; req.Flags = flags; req.Seed = seed;
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, _IOCTL_RUNTIME_POLYMORPH,
                           &req, sizeof(req), nullptr, 0, &ret, nullptr) != FALSE;
}

inline bool PatchGuardBypass(uint32_t action = 0)
{
    PgBypassReq req{}; req.Action = action;
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, _IOCTL_PG_BYPASS,
                           &req, sizeof(req), nullptr, 0, &ret, nullptr) != FALSE;
}

inline bool DeepHvEvasion(uint32_t flags = DHV_ALL)
{
    DeepHvReq req{}; req.Flags = flags;
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, _IOCTL_DEEP_HV_EVASION,
                           &req, sizeof(req), nullptr, 0, &ret, nullptr) != FALSE;
}

inline bool AntiDebug(uint32_t flags = ADB_ALL)
{
    AntiDebugReq req{}; req.Flags = flags;
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, _IOCTL_ANTI_DEBUG,
                           &req, sizeof(req), nullptr, 0, &ret, nullptr) != FALSE;
}

inline bool EncryptDriverMem(uint32_t action = 0, uint32_t flags = DENC_ALL)
{
    DrvEncryptReq req{}; req.Action = action; req.Flags = flags;
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, _IOCTL_ENCRYPT_DRIVER_MEM,
                           &req, sizeof(req), nullptr, 0, &ret, nullptr) != FALSE;
}

inline bool BareMetalStable(uint32_t flags = BMS_ALL)
{
    BareMetalReq req{}; req.Flags = flags;
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, _IOCTL_BARE_METAL_STABLE,
                           &req, sizeof(req), nullptr, 0, &ret, nullptr) != FALSE;
}

} // namespace Stealth

/*
 * ── Usage examples ─────────────────────────────────────────────────────────
 *
 * Example 1: Full stealth with auto CR3 shuffle + handle scrub
 *
 *   #include "betest_stealth.hpp"
 *
 *   int main() {
 *       DWORD cheatPid = GetCurrentProcessId();
 *       DWORD gamePid  = FindGamePid();  // your game PID finder
 *
 *       Stealth::Init();
 *
 *       // One call does everything:
 *       //   - DKOM (APL/SPL/CID unlink)
 *       //   - Thread hiding
 *       //   - CR3 shuffle with auto-picked svchost/lsass donors
 *       //   - Token swap to System
 *       //   - PEB sanitization (ImagePathName/CommandLine zeroed)
 *       //   - Handle scrub (removes cheat handles from game's table)
 *       Stealth::FullStealthEx(cheatPid, gamePid,
 *           STEALTH_SHUFFLE | STEALTH_AUTO_DONORS | STEALTH_SCRUB_HANDLES);
 *
 *       // ... cheat runs normally via kernel read/write ...
 *
 *       // Before exit: stop the CR3 shuffle timer and restore original CR3
 *       Stealth::StopShuffle();
 *       return 0;
 *   }
 *
 *
 * Example 2: Manual CR3 shuffle with specific donor PIDs
 *
 *   Stealth::Init();
 *   uint64_t donors[] = { 600, 800, 1200 };  // PIDs of svchost instances
 *   Stealth::CR3Shuffle(cheatPid, donors, 3);
 *   // ... later ...
 *   Stealth::StopShuffle();
 *
 *
 * Example 3: Piecemeal stealth (manual control)
 *
 *   Stealth::Init();
 *   Stealth::HideProcess(cheatPid);       // DKOM
 *   Stealth::HideThreads(cheatPid);       // CID table
 *   Stealth::CR3Shuffle(cheatPid);        // auto-donor shuffle
 *   Stealth::SwapToken(cheatPid);         // System token
 *   Stealth::SanitizePEB(cheatPid);       // PEB zeroing
 *   Stealth::ScrubHandles(gamePid, cheatPid);  // handle table cleanup
 *
 *
 * Example 4: Full lifecycle with Tasks 9-13
 *
 *   Stealth::Init();
 *
 *   // Neutralize ALL anti-cheats with 5-second re-scan
 *   Stealth::UnifiedNeutralize(NEUT_ALL, 5000);
 *
 *   // Hook AC's decrypt routine to capture memory scan results
 *   Stealth::HookACDecrypt();
 *
 *   // Apply full stealth with CR3 shuffle
 *   Stealth::FullStealthEx(cheatPid, gamePid,
 *       STEALTH_SHUFFLE | STEALTH_AUTO_DONORS | STEALTH_SCRUB_HANDLES);
 *
 *   // Deep-hide the driver itself (pool tags, section, device)
 *   Stealth::DeepHide(0, DEEP_ALL);
 *
 *   // ... cheat runs ...
 *
 *   // Read what the AC's decrypt routine decrypted (memory scan intercept)
 *   uint8_t buf[4096];
 *   uint32_t n = Stealth::ReadACPlaintext(buf, sizeof(buf));
 *
 *   // Before exit: clean up everything
 *   Stealth::CleanupTraces(CLEANUP_ALL);
 *
 *
 * Example 5: Full lifecycle with Tasks 14-22
 *
 *   // Use dynamic name discovery (Task 22)
 *   Stealth::InitDynamic();  // tries all 8 device names
 *
 *   // Schedule delayed neutralization (Task 19) — fires 10s after AC boots
 *   Stealth::DelayedOp(0, 10000);  // opCode=0 (neutralize all), delay=10s
 *
 *   // After AC startup completes:
 *   Stealth::UnifiedNeutralize(NEUT_ALL, 5000);
 *   Stealth::PatchGuardSafe(0);    // clean DPC/timer lists (Task 14)
 *   Stealth::PatchGuardSafe(1);    // zero PE checksums (Task 14)
 *   Stealth::MutateDriver(MUTATE_TEXT);  // polymorphic .text (Task 17)
 *
 *   // Full stealth
 *   Stealth::FullStealthEx(cheatPid, gamePid,
 *       STEALTH_SHUFFLE | STEALTH_AUTO_DONORS | STEALTH_SCRUB_HANDLES);
 *
 *   // ... cheat runs ...
 *
 *   // Clean exit (Task 21)
 *   Stealth::FullSelfClean(SELFCLEAN_ALL);
 */
