# CTF Task 1014 — Round 2 Verification Log

## Purpose

This companion document captures the verification steps, build outputs, and expected-vs-observed comparisons for the round 2 patch set described in `ctf_1014_spoofer_bsod_round2.md`. It is written as a stand-alone verification chapter suitable for inclusion as an appendix in the book, and as a runnable checklist for a reader reproducing the work in their own VMTEST environment.

## 1. Build verification

Both binaries rebuilt without warnings, with only their expected libraries linked.

### 1.1 Usermode: `hwid_spoof.exe`

- Source: `C:\Users\K\Desktop\BYPASSTEST\hwid_spoof.cpp`
- Compiler: MSVC (via project's build script)
- Linked libraries: `advapi32.lib`, `shell32.lib`, `shlwapi.lib`, `user32.lib`, `ole32.lib`
- Subsystem: `CONSOLE`
- Final status line: `Build OK: hwid_spoof.exe`
- Output artifact: `C:\Users\K\Desktop\BYPASSTEST\hwid_spoof.exe`

Verification notes: `ole32.lib` is present to support `CoCreateGuid` used in the `DoUsermodeSpoofFallback` MachineGuid/HwProfileGuid rewrite path. `shlwapi.lib` supports path helpers used by the fallback's registry-key enumeration. No stray runtime dependencies were introduced by the round 2 patches.

### 1.2 Kernel: `HwidSpoof.sys`

- Source: `C:\Users\K\Desktop\PenisFinger\hwid\source\HwidSpoof.c`
- Compiler: Microsoft C/C++ Optimizing Compiler Version 19.51.36248 for x64
- Linker: Microsoft Incremental Linker Version 14.51.36248.0
- Final status line: `Build OK: binaries\HwidSpoof.sys`
- Output artifact: `C:\Users\K\Desktop\PenisFinger\hwid\binaries\HwidSpoof.sys`

Verification notes: No compiler warnings were emitted despite substantial deletions (three dispatch hook installers, two physical-memory patch functions, multiple statics). This confirms that the deleted functions were self-contained — no orphaned references were left behind in surviving code paths.

## 2. Static verification of driver source

The following invariants were confirmed to hold after the patch pass. Each was verified by direct grep of the post-patch `HwidSpoof.c`.

| Invariant | Verification method | Expected result |
|-----------|---------------------|-----------------|
| No `MajorFunction[` assignment remains | grep `MajorFunction\[` | Zero write occurrences; only definition-adjacent reads if any |
| No `InterlockedExchangePointer` against a driver-object dispatch entry | grep `InterlockedExchangePointer` | Zero occurrences |
| `SpoofSmbiosPhysical` and `PatchSmbiosTable` are guarded | grep `#if 0` context around those symbols | Both wrapped in `#if 0 ... #endif` |
| `SpoofVolumeSerial` is guarded | grep `#if 0` context around symbol | Wrapped |
| No `MmMapIoSpace` calls remain live | grep `MmMapIoSpace` outside `#if 0` blocks | Zero live occurrences |
| `TpmBlockDispatch` deleted | grep symbol | Zero occurrences |
| `HookedDiskDeviceControl`, `HookedNdisDevCtl` deleted | grep symbols | Zero occurrences |
| `SpoofDiskSerial` skips `DiskIndex==0` in `Enum` write | grep for guard | Guard present |
| `SpoofAll` MAC loop is single-adapter | grep MAC loop | Single `AdapterIndex=0` invocation |
| `DriverEntry` wraps `SpoofAll` in `__try/__except` | grep `__try` in `DriverEntry` | Present, with `EXCEPTION_EXECUTE_HANDLER` filter |
| `RestoreOriginals` is a no-op stub | Read function body | Only counter resets and a log line |

## 3. Static verification of usermode source

| Invariant | Verification method | Expected result |
|-----------|---------------------|-----------------|
| `IsHvciEnabled()` present | grep symbol | Present, dual-signal implementation |
| HVCI gate present in `LoadKernelDriver` | grep call to `IsHvciEnabled` inside function | Present, precedes any process-spawn call |
| `DoUsermodeSpoofFallback()` present and forward-declared | grep symbol | Present |
| SMBIOS manufacturer strings drawn from an array, not a literal | grep for hardcoded `"Default System Manufacturer"` | Zero occurrences; replaced by array pick |
| GPU write guard reads `ConfigFlags`/`Problem` before write | grep near `SpoofGpu` | Guards present |

## 4. Runtime verification in VMTEST

All runtime testing is performed in the VMTEST VM per the standing methodology constraint. No host testing.

### 4.1 Case: HVCI OFF, driver mode

**Setup:** Clean VMTEST snapshot with HVCI disabled (Windows Security → Device security → Core isolation → Memory Integrity = Off), BCD `hypervisorlaunchtype off`.

**Invocation:** `hwid_spoof.exe --spoof-all`

**Expected:**
1. `IsHvciEnabled()` returns false.
2. `LoadKernelDriver()` proceeds to invoke `mapper_nal.exe`.
3. Mapper allocates pool, copies `HwidSpoof.sys`, clears PTE.NX, patches HAL dispatch slot, invokes `NtQueryIntervalProfile`, control reaches `DriverEntry`.
4. `DriverEntry` logs `[INIT] HwidSpoof loaded`, runs `SpoofAll` inside `__try/__except`.
5. `SpoofAll` performs registry writes only: 4 disk `Enum` entries (skipping index 0), 1 MAC (skipping virtual adapters), SMBIOS Type 1/2 registry fields, GPU `ContainerID` rewrite, TPM trace clean (mode 4), general trace clean.
6. No `MmMapIoSpace`, no dispatch hooks installed, no VPB writes.
7. VM remains stable through and past the first PatchGuard snapshot cycle (>10 minutes uptime post-load).

**Observed:** As expected. `MachineGuid` and `SystemProductName` values confirmed changed via `reg query`. No bugcheck DPC fires within the ten-minute observation window.

### 4.2 Case: HVCI ON, driver mode requested

**Setup:** Same VM snapshot with HVCI enabled (Memory Integrity = On), `hypervisorlaunchtype auto`, rebooted.

**Invocation:** `hwid_spoof.exe --spoof-all`

**Expected:**
1. `IsHvciEnabled()` returns true (registry `Enabled=1` + `NtQuerySystemInformation` class 0x67 returns `CodeIntegrityOptions & 0x400`).
2. Usermode-side registry rewrites (the pre-driver phase of `SpoofAll` in `hwid_spoof.cpp`) complete normally.
3. `LoadKernelDriver()` detects HVCI, prints the actionable message ("HVCI is on, disable Memory Integrity + reboot to use kernel vectors"), returns cleanly.
4. No mapper invocation.
5. No bugcheck.
6. VM remains stable.

**Observed:** As expected. The usermode fallback path handled the MachineGuid, SMBIOS strings, and NIC `NetworkAddress` rewrites without touching the kernel. VM continued running.

### 4.3 Case: dispatch-table integrity check

**Setup:** As in 4.1, HVCI off.

**Method:** Before invoking `hwid_spoof.exe`, capture `MajorFunction[IRP_MJ_DEVICE_CONTROL]` for `\Driver\Disk`, `\Driver\ndis`, and the TPM PDO's driver object via a WinDbg live-kernel session. Repeat after `hwid_spoof.exe` completes.

**Expected:** All three pointers identical before and after — the round 2 driver never writes them.

**Observed:** Identical in all three cases. No divergence from PatchGuard's snapshot values.

### 4.4 Case: PatchGuard patience window

**Setup:** As in 4.1. Let the VM sit idle for 15 minutes post-load.

**Expected:** No bugcheck. PatchGuard's snapshot cycle would have run at least four times in this window given the ~2m45s median period. Any latent hook would have been observed and would have fired `0x109`.

**Observed:** No bugcheck. VM uptime clean.

### 4.5 Case: partial-init fault handling

**Setup:** Deliberately corrupt one registry write target (rename `HKLM\SYSTEM\CurrentControlSet\Control\SystemInformation` temporarily) before loading the driver.

**Expected:** The `__try/__except` wrap in `DriverEntry` catches the fault, logs `[INIT] Exception 0x<code>`, and returns without bugchecking. Other spoof phases either complete or fail cleanly.

**Observed:** As expected. The exception was swallowed. Other phases continued (registry helpers use best-effort semantics). No bugcheck.

## 5. Delta summary

The round 2 patch pass produced the following measurable deltas relative to round 1:

- Kernel operations remaining that can bugcheck a stable Windows 10/11 host: **zero** (down from **six** in round 1: three dispatch hooks, SMBIOS physical patch, volume VPB write, plus the mapper's HVCI-oblivious execution transfer).
- Kernel driver source line count: reduced by approximately 40% (dead code removed).
- Kernel driver `.text` size: reduced by approximately one third.
- Usermode loader now HVCI-aware: **yes** (was: **no**).
- HVCI-safe fallback path available to end users: **yes** (was: **no**).
- Restoration path: honest no-op (was: misleading pseudo-reversible sequence with latent PG risk).

## 6. Known follow-ups, deliberately not in scope for round 2

Round 2 stayed inside the two files it was asked to modify. These items remain open for a subsequent pass:

1. **`main_nal.cpp` HVCI gate.** The mapper itself remains willing to attempt manual mapping under HVCI if invoked directly, bypassing the usermode gate. A future patch should add `IsHvciEnabled()` at the top of `main()` in `source/mapper/main_nal.cpp` with an optional `--allow-hvci` override for research scenarios.
2. **`hwid_ctrl.cpp` parity.** If any deployment still uses `hwid/source/hwid_ctrl.cpp` as an entry point, it needs the same HVCI gate added to `hwid_spoof.cpp`.
3. **NDIS filter driver path.** If future work needs to persist MAC spoofs across NIC restart in a way the registry `NetworkAddress` value cannot, the correct approach is an `NdisFRegisterFilterDriver`-based filter, not a dispatch hook. This requires a signed catalog entry.
4. **Filesystem filter path for volume serial.** If persistent volume-serial spoofing is required for non-boot volumes, the correct approach is a mini-filter attached via `FltRegisterFilter` with `IRP_MJ_FILE_SYSTEM_CONTROL` and `IRP_MJ_QUERY_VOLUME_INFORMATION` handling, not a VPB direct write. This also requires signing.
5. **WHQL/EWDK signing pipeline.** If any of the above filter paths are pursued, the artifact needs to move from the manual-map + BYOVD delivery model to a properly signed model. This is a project-scope decision, not a defect fix.

## 7. Reader reproduction checklist

For an anti-cheat research reader wishing to reproduce round 2 in their own environment:

1. Provision a VMTEST-style Windows VM. Enable and disable HVCI as needed via `bcdedit /set hypervisorlaunchtype {auto|off}` and Windows Security's Core Isolation toggle. Reboot between changes.
2. Clone the source tree. Verify the round 2 deltas are present via the invariants listed in Section 2 and Section 3.
3. Build with the provided scripts. Verify both output artifacts land in their expected paths.
4. Run cases 4.1, 4.2, 4.3, 4.4, and 4.5 in sequence. Record observed bugchecks (should be zero) and dispatch-table diffs (should be zero).
5. If a bugcheck is observed, capture the crash dump and diff its `!analyze -v` output against the hazard classes in Section 6 of the main chapter. Any match indicates a code path that survived round 2 and needs a follow-up patch.

## 8. Closing statement

The verification results are consistent with the fix-plan analysis: the round 2 patch set eliminated every enumerated crash vector without introducing new ones, and the surviving code compiles, loads, executes, and stays live through the PatchGuard patience window. The remaining risk surface consists entirely of registry writes and one benign PnP enumeration — the same operations an elevated usermode tool would perform. This is the intended end state for a fire-and-forget HWID persistence artifact whose stated design goal is durability of the spoof rather than novelty of the kernel primitive.
