# CTF Task 104: ACE Anti-Cheat Analysis Report

**Target**: ACE Anti-Cheat (Delta Force)
**Date**: 2026-06-30

## 1. Dumping Guide

### Current State
No ACE driver binaries exist in the project. Need to obtain:
- `ACE-Base64.sys` -- main kernel driver
- `ACE-Guard64.sys` -- secondary guard driver
- `ACE-Base.dll` -- usermode component
- ACE service executables

### Dump Methods
1. **Direct copy**: `C:\Program Files\ACE\<game_id>\` on a Delta Force installation
2. **Service binary path**: Query `HKLM\SYSTEM\CurrentControlSet\Services\ACE-Base` for ImagePath
3. **Kernel dump**: Use BYOVD read primitive after ACE loads (requires timing before ACE's self-protection activates)

## 2. Detection Methods (Inferred from Countermeasures)

The BetestDriver has 4 dedicated ACE IOCTLs revealing what ACE detects:

### IOCTL 0x846 -- ACE Strengthen (Task 42, 6 features)
- OB callback registration for handle monitoring
- DPC/timer/workitem-based periodic integrity scans
- Hypervisor/EPT detection (CPUID vendor, feature bits, timing, IDT/GDT, MSR faults)
- Early-load driver protection
- CR3+DKOM stealth requirements
- Memory scan evasion

### IOCTL 0x847 -- Advanced ACE Evasion (Task 43, 4 features)
- HV+EPT bypass (deeper than basic CPUID checks)
- Advanced memory scan evasion
- Process/thread hiding
- Early-init protection

### IOCTL 0x848 -- Final ACE (Task 44, 6 features)
- RDTSC timing normalization (detects timing anomalies from VM/hooks)
- Code section encryption
- Stack frame sanitization
- Kernel callback cleaning
- Multi-vector HV detection
- Self-test validation

### IOCTL 0x849 -- Deep AC (Task 49, 5 features)
- EPT resistance
- Pool memory scrambling
- Thread cloaking
- Telemetry blocking
- PatchGuard stability

## 3. Existing Countermeasures

### Mapper Integration
CLI flags: `--ace`, `--adv`, `--final`, `--delta`, `--ace-map`
Auto-detection: scans for `aceservice`/`ace-base`/`acesvc` processes, enables all hardening automatically.

Full hardening command: `--ace 3f --adv f --final 3f --delta 1f`

### Delta Force Cheat (deltaforce_external.cpp)
- Jittered sleep timing to defeat ACE timing profiling
- DKOM process hiding
- Streamproof overlay

### VM Test Results
`vm/vm_transfer/diag.txt` shows a successful prior run with full ACE hardening stack.

## 4. What's Missing

1. **ACE driver binaries** -- needed for IDA/Ghidra static analysis
2. **IDA analysis scripts** -- only EAC scripts exist (`eac_ida_analysis.py`, `eac_ida_part2.py`); need ACE equivalents
3. **Delta Force offsets** -- `df_offsets.ini` has all game-specific offsets zeroed (GWorld, Health, Camera)
4. **UE5 SDK dumper** -- needed to populate Delta Force offsets

## 5. Recommendations

1. **Obtain ACE binaries** from a Delta Force installation for full RE
2. **Adapt EAC IDA scripts** for ACE binary analysis
3. **Run UE5 SDK dumper** against Delta Force to populate offsets
4. **Test full hardening stack** (`--ace 3f --adv f --final 3f --delta 1f`) on VMTEST
5. **ACE timing detection is the key differentiator** -- RDTSC normalization is critical; ACE is more aggressive about timing checks than EAC or BE
