# CTF Task 110: BattlEye Analysis Report

**Target**: BEDaisy.sys (Arma Reforger and other BE-protected games)
**Date**: 2026-06-30

## 1. Dumping Guide

### Files Needed
- `BEDaisy.sys` -- kernel driver (not in project, needs extraction)
- BEClient usermode modules

### Dump Methods
1. **Direct copy**: `C:\Program Files (x86)\Common Files\BattlEye\BEDaisy.sys`
2. **Game-specific path**: `<game_dir>\BattlEye\BEDaisy.sys`
3. **Kernel dump**: Use BYOVD after BEDaisy loads, before self-protection activates
4. **Ironic self-exploitation**: BEDaisy's own IOCTLs can dump its own image (project already implements this)

### BEDaisy IOCTL Interface (from primitive_bedaisy.hpp)

| IOCTL | Code | Function |
|-------|------|----------|
| Read | `0x0022200C` | MmCopyMemory -- arbitrary kernel VA read |
| Write | `0x00222008` | memcpy -- arbitrary kernel VA write |
| Alloc | `0x00222004` | ExAllocatePoolWithTag(NonPagedPoolExecute) |

Device paths: `\\.\BEDaisy`, `\\.\battleye`, `\\.\BattlEye`, `\\.\BattlEye\BEDaisy`, `\\.\Global\BattlEye`

## 2. Existing Project Code

| File | Purpose |
|------|---------|
| `source/mapper/primitive_bedaisy.hpp` | BYOVD primitive using BEDaisy itself |
| `betest_legacy/source/test_bedaisy.cpp` | Sanity test (opens device, reads ntoskrnl MZ) |
| `betest_legacy/binaries/mapper_bedaisy.exe` | Pre-built mapper using BEDaisy |
| `betest_legacy/binaries/test_bedaisy.exe` | Pre-built test |

## 3. Detection Methods (from BetestDriver.c countermeasures)

### Kernel Callbacks
- PsSetCreateProcessNotifyRoutineEx
- ObRegisterCallbacks on PsProcessType/PsThreadType
- Image load notify routines

### Report Queue
- SLIST-based report queues to BEService
- Drained by `DrainSListQueues()`

### DPC Timers
- Periodic scanning via DPC routines
- Killed by `KillDPCsForRange()`

### System Threads
- Kernel threads for continuous monitoring
- Killed by `KillACSystemThreads()`

### ETW Telemetry
- ETW provider registration for telemetry
- Suppressed by hooking EtwRegister

### Registry Presence
- `HKLM\SYSTEM\CurrentControlSet\Services\BEService`
- `HKLM\SYSTEM\CurrentControlSet\Services\BEDaisy`
- `HKLM\SOFTWARE\BattlEye`

### Heartbeat
- User-to-kernel heartbeat mechanism
- Intercepted by BE_HEARTBEAT_KILL

## 4. Existing Countermeasures (IOCTL 0x852)

| Flag | Value | Action |
|------|-------|--------|
| BE_CB_NEUTRALIZE | 0x01 | Strip process/thread/image notify callbacks |
| BE_REPORT_KILL | 0x02 | Block report queue to BEService |
| BE_HEARTBEAT_KILL | 0x04 | Kill heartbeat mechanism |
| BE_EARLY_LOAD | 0x08 | Hook early-load path |
| BE_ANTI_DETECT | 0x10 | CPUID-based HV detection evasion |

Full enable: `--battleye 1f`

Auto-detection: mapper scans for beclient/beservice/bedaisy processes and enables all countermeasures.

## 5. Bypass Strategies for External Cheats

1. **BYOVD self-exploitation** -- already implemented. BEDaisy's own IOCTLs provide kernel R/W/Alloc.
2. **Callback stripping** -- `--battleye 1f` strips all BE monitoring before game launch.
3. **DKOM process hiding** -- existing IOCTL_HIDE_PROCESS with CR3 swap and token manipulation.
4. **Pre-launch timing** -- load BYOVD and complete all mapping before BE initializes.

## 6. Recommendations

1. **Obtain BEDaisy.sys** from Arma Reforger installation for static RE in IDA
2. **IOCTL fuzzing** -- extend test_bedaisy.cpp to probe additional IOCTL codes beyond the 3 documented
3. **Version comparison** -- BEDaisy changes per game; IOCTL codes and structures may differ
4. **BEDaisy as BYOVD** is uniquely ironic and effective -- it's a production-signed driver with R/W/X primitives that BE itself trusts
