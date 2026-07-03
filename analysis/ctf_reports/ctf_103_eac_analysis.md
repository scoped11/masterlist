# CTF Task 103: EAC (Easy Anti-Cheat) Analysis Report

**Target**: EasyAntiCheat_EOS.sys v3.2.0 (Apex Legends)
**Date**: 2026-06-30

## 1. Dumping Guide

### Files Obtained
- `EasyAntiCheat_EOS.sys` (39 MB) -- kernel driver, dumped from running Apex
- `EasyAntiCheat_EOS.sys.i64` (172 MB) -- IDA Pro database
- `easyanticheat_x64.eac` (31 MB) -- usermode EAC module

### Dump Methods
1. **Live copy from disk**: `C:\Program Files (x86)\EasyAntiCheat\EasyAntiCheat_EOS.sys` -- available before game launch
2. **MmCopyMemory from kernel**: Use BYOVD read primitive to dump from kernel memory after load
3. **FltGetFilterInformation**: Enumerate minifilters, find EAC's filter object, walk to driver object for base address

## 2. PE Structure Analysis

| Field | Value |
|-------|-------|
| Format | PE32+ AMD64, NATIVE subsystem |
| Size | 39,142,928 bytes (37.33 MB) |
| Linker | MSVC 14.44 |
| Entry Point | 0x17E150 |
| Signing | Authenticode EV (EasyAntiCheat Oy / Epic Games), WHQL countersigned |
| DLL Chars | HIGH_ENTROPY_VA, DYNAMIC_BASE, NX_COMPAT, FORCE_INTEGRITY |

### Sections

| Section | Size | Flags | Purpose |
|---------|------|-------|---------|
| `.text` | 1,525 KB | CODE, EXEC, READ, NOT_PAGED | Main code (1,625 functions) |
| `.rdata` | 568 KB | READ, NOT_PAGED | Read-only data, vtables |
| `.data` | 472 KB virt / 46 KB raw | READ, WRITE, NOT_PAGED | Globals |
| (anon) | 25 KB | READ, NOT_PAGED | Reserved |
| `.rsrc` | 1 KB | READ, DISCARDABLE | Version info |
| `.reloc` | 2 KB | READ, DISCARDABLE | Relocations |
| (anon) | 10 KB | CODE, EXEC, READ, NOT_PAGED | VM init/trampoline |
| **(anon)** | **35,980 KB** | **EXEC, READ, NOT_PAGED** | **VM-protected code (94%)** |
| `.pdata` | 48 KB | READ, NOT_PAGED | Exception unwind |

**Key finding**: 94% of the binary is VM-protected. Only 2 static imports (FltRegisterFilter, __chkstk). All other API resolution is hash-based inside the VM section.

## 3. Detection Methods

### Driver Blocklist
- Uses **certificate-based verification via WinTrust**, not filename matching
- Calls WintrustCertificateTrust -> SoftpubCheckCert -> SoftpubAuthenticode -> DriverFinalPolicy
- Blocklist downloaded from `modules-cdn.eac-prod.on.epicgames.com`
- Blocked drivers trigger **error 206** (game won't start)
- **NalDrvIntel.sys (iqvw64e)**: BLOCKED
- **TRIXX.sys**: Currently PASSES (DigiCert EV, no CVE)

### Memory Scanning
- Scans for MZ/PE signatures in non-image memory regions
- Pool tag enumeration via BigPoolTable
- Cannot see pattern details (logic is in the 35.9 MB VM section)

### Callback Registration
- FltRegisterFilter minifilter for file I/O interception
- ObRegisterCallbacks for handle monitoring
- PsSetCreateProcessNotifyRoutine for process monitoring
- Image load notify for driver load interception

### Telemetry
- ETW provider registration
- SLIST-based report queues sent to BEService/EAC service
- CDN-based config/blocklist updates

### Anti-Dump
- VM protection on 94% of code
- Hash-based API resolution (no plaintext imports)
- Zero plaintext driver names or API strings in binary

## 4. Existing Countermeasures (BetestDriver.c)

The project already implements comprehensive EAC bypass:

| IOCTL | Code | Features |
|-------|------|----------|
| EAC Strengthen | 0x844 | 7-subsystem bitmask: callbacks, reports, CR3, handles, scans, timing, minifilter |
| Deep AC | 0x849 | EPT resistance, pool scrambling, thread cloaking, telemetry blocking |

Specific techniques:
- OB callback neutralization (12-byte trampoline patches)
- Process/Thread notify removal from PspCreateProcessNotifyRoutine arrays
- IAT hooks on ExAllocatePoolWithTag to drop detection reports
- ETW suppression (EtwRegister returns dummy handle)
- MiniFilter unregistration
- CR3 shuffle using donor process page tables
- DKOM process hiding (ActiveProcessLinks unlink + PspCidTable)
- DPC/Timer killing for EAC-owned periodic scans
- SLIST queue drain to zero report buffers
- Pre-DriverEntry interception (patches entry to `xor eax,eax; ret`)

## 5. Bypass Recommendations

1. **Replace NalDrvIntel.sys** -- certificate-blocked by EAC. Use TRIXX.sys or another EV-signed driver not on the blocklist.

2. **Scrub MmUnloadedDrivers** -- driver entries persist even after PsLoadedModuleList unlink. EAC can enumerate this.

3. **Randomize pool tags** -- hardcoded tags are searchable via BigPoolTable. Use Microsoft-looking tags that rotate.

4. **Zero mapped PE headers** -- wipe first 0x1000 bytes of any manually mapped driver to defeat MZ/PE signature scans.

5. **Eliminate static strings** -- window classes, device names, CLI args are all findable. Use XOR encoding.

6. **Address HWID gap** -- EAC 2024+ queries hardware directly via IOCTL, not just registry. Registry-only spoofing is insufficient.

7. **Time execution** -- complete all BYOVD/mapping before EAC service starts. Current pre-game loading sequence is correct.

8. **Monitor CDN blocklist** -- TRIXX.sys could be added at any time. Need automated checking.
