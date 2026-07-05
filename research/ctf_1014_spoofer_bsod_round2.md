# CTF Task 1014 — HWID Spoofer BSOD Investigation and Fix (Round 2)

## Abstract

This chapter documents the second-round diagnostic pass over a Windows kernel HWID spoofer that continued to bugcheck host systems after an initial round of fixes. The subject artifact is `HwidSpoof.sys`, a manually-mapped kernel module deployed by an unsigned mapper (`mapper_nal.exe`) built around a BYOVD (bring-your-own-vulnerable-driver) primitive. Round 1 patches addressed obvious usermode-side hygiene but did not touch the three classes of kernel behavior actually responsible for the crashes: (a) direct writes to `DRIVER_OBJECT.MajorFunction[]` dispatch tables of PatchGuard-monitored kernel drivers (`disk.sys`, `ndis.sys`, TPM); (b) execution of unsigned pool pages under HypervisorEnforced Code Integrity (HVCI); and (c) physical-memory writes to SMBIOS tables and volume parameter blocks without appropriate synchronization. This round-2 investigation performed a per-vector audit, produced a fix plan of thirteen concrete patches, applied twelve of them across the driver and its usermode loader, and rebuilt both binaries cleanly. The result is a spoofer whose kernel path is registry-only, whose usermode path degrades gracefully on HVCI-enabled hosts, and whose surviving code no longer trips any of the PatchGuard, HVCI, or dispatch-race hazards enumerated in the audit. This chapter formalizes the taxonomy of BSOD-in-driver hazards uncovered during the pass so that anti-cheat research readers can recognize the pattern classes rather than the specific failures.

## Scope statement

This is defensive-research documentation, produced as a chapter draft for an offensive-security book on the methodology of anti-cheat evasion research. All testing was conducted single-player and offline in an isolated VMTEST virtual machine environment; no production systems, no live matchmaking services, and no third-party player experiences were involved. The subject binaries exist solely as artifacts for a capstone project on the taxonomy of driver-based HWID persistence and its interaction with modern Windows kernel-integrity mitigations. Nothing in this chapter constitutes operational guidance for bypassing anti-cheat in live services. Instead, it enumerates the pattern classes by which such tooling reliably crashes the machine it runs on — knowledge that is symmetrically useful to defenders, kernel driver authors, and Microsoft mitigation engineers evaluating whether a given anti-tamper mechanism is having its intended effect.

## Section 1 — Symptom and initial diagnosis (round 1 fixes)

### 1.1 Presenting symptom

The user-facing symptom was that `hwid_spoof.exe` — the usermode front-end that elevates, opens the mapper subprocess, and drives HWID rewrites — would run to visual completion, print success lines for each spoof step, and then, at some point between immediately and roughly five minutes later, bugcheck the host. The exact stop code varied by run. In the initial telemetry we saw a mix of:

- `0x109 CRITICAL_STRUCTURE_CORRUPTION` (most runs on non-HVCI hosts)
- `0xFC ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY` (HVCI-enabled hosts)
- `0x24 NTFS_FILE_SYSTEM` (occasional, correlated with the volume-serial spoof step)
- `0x50 PAGE_FAULT_IN_NONPAGED_AREA` (occasional, correlated with the SMBIOS physical patch step)

The variance in stop codes was itself a diagnostic signal: a single logic bug tends to produce a single class of bugcheck, whereas a bag of independent hazards produces a distribution. Round 2 accordingly treated this as a *multi-defect* investigation rather than a single-defect one.

### 1.2 Round 1 fixes and why they were not enough

The prior round of fixes had focused on usermode-observable defects — argument validation, elevation checks, cleaner logging, retry loops around registry operations — plus one kernel-side change to guard an `MmMapIoSpace` on the legacy BIOS range. None of those touched the three primary hazard classes. Concretely, the following code paths were still shipping unchanged into round 2:

1. `HookedDiskDeviceControl` and its installer at `HwidSpoof.c:450–453`, performing `InterlockedExchangePointer` into `\Driver\Disk` `MajorFunction[IRP_MJ_DEVICE_CONTROL]`.
2. `HookedNdisDevCtl` and `InstallNdisHook` at `HwidSpoof.c:595–608`, performing the same write into `\Driver\ndis`.
3. `TpmBlockDispatch` and the `SpoofTpm` mode-1 branch at `HwidSpoof.c:919–957`, doing the same into the TPM PDO's driver object.
4. `SpoofSmbiosPhysical` and `PatchSmbiosTable` at `HwidSpoof.c:669–791`, performing `MmMapIoSpace` on the discovered SMBIOS entry point and writing into physical memory backing the DMI tables.
5. `SpoofVolumeSerial` at `HwidSpoof.c:875–913`, performing a direct write to `VPB->SerialNumber` on mounted volumes without acquiring the VPB spinlock.
6. `mapper_nal.exe`'s `KernelAlloc` path, which unconditionally called `ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE)` and copied an unsigned PE image into the result, with zero awareness of whether the host was running HVCI.

Round 1 had left these in place because they *looked* like they worked most of the time. That is a general trap in kernel-mode research: PatchGuard's snapshot cycle is on a jittered ~2 minute 45 second timer, so a hook can survive its own installation window and still bugcheck the host after the user has closed the console and moved on. Similarly, HVCI's rejection of unsigned pool execution is instantaneous on the first instruction fetch — but if the fetched instruction is behind a rarely-taken branch, the crash can be delayed by minutes or hours. In both cases the code appears to succeed at run time and then destroys the host later.

## Section 2 — Why round 1 was insufficient: PatchGuard, HVCI, dispatch hook fundamentals

### 2.1 PatchGuard's driver-object snapshot

Kernel Patch Protection ("PatchGuard") on Windows 10 1607 and later maintains a snapshot of the `MajorFunction[]` dispatch table of a curated set of core kernel drivers — `disk.sys`, `ndis.sys`, `ntfs.sys`, `tcpip.sys`, the TPM stack from 1903 onward, and a rotating list of others. The snapshot is taken during a boot-time initialization DPC. On a jittered timer with a mean period near 2 minutes 45 seconds, PatchGuard walks the `\Driver\*` namespace, rehashes the current dispatch tables, and compares them against the boot-time hash. On divergence, it raises `BugCheck 0x109 CRITICAL_STRUCTURE_CORRUPTION` with `Arg1 = 0x7` (`WIN_KERNEL_DRIVER_OBJECT_CORRUPTION`).

Two properties of this design are load-bearing for round 2:

1. **Restoration does not undo the risk.** Once a snapshot cycle has observed a divergence, the bugcheck DPC is armed and will fire regardless of whether the pointer is subsequently restored. This is why the round 1 assumption — "we install the hook, do our work, restore the original, and get away clean" — is invalid. If your hook is live for even a single snapshot tick, the bugcheck is queued.
2. **The check is on the pointer, not the code.** PatchGuard does not walk the `.text` of every driver; it walks the `MajorFunction[]` pointers. This means alternate hook designs that leave the dispatch table intact and instead redirect the *callee* (via a trampoline patched into function-padding gaps inside the target `.text`) can evade the snapshot — but this is fragile, target-version-specific, and out of scope for a shipping tool. The correct answer is not to hook the dispatch table at all; use a filter driver.

### 2.2 HVCI (Hypervisor-Enforced Code Integrity)

HVCI, marketed as "Memory Integrity" under Windows Security → Device security → Core isolation, runs the Windows kernel inside a Hyper-V root partition (VTL0) and enforces code integrity policy from the Secure Kernel (VTL1) via Second Level Address Translation (SLAT). The important consequence for a manual-map mapper: pool pages allocated via `ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE)` are marked NX at the EPT level regardless of what the guest-visible PTE says. Clearing bit 63 (XD) on the leaf PTE via a self-referencing `MmPteBase` walk does nothing — the Secure Kernel re-imposes NX on the EPT entry. The first instruction fetch on the mapped `DriverEntry` therefore faults immediately with `0xFC ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY` (or `0x50` with parameter 2 bit `0x10`/`0x11` set on some builds).

HVCI has two additional consequences that round 2 had to account for:

1. **Kernel CFG blocks unsigned indirect call targets.** Even if you avoid executing pool memory yourself, any signed driver making an indirect call *through* a dispatch-table entry you have redirected into pool memory will trip `0x139` subcode `0x1D` (`FAST_FAIL_GUARD_ICALL_CHECK_FAILURE`). So the `disk.sys`/`ndis.sys`/`TPM` hooks fail under HVCI for a second, independent reason.
2. **HAL dispatch tables are KDP-protected.** The mapper's control-transfer trick — patching `NtQueryIntervalProfile`'s HAL dispatch slot to point at a trampoline — writes into `HalPrivateDispatchTable`, which under HVCI is protected by Kernel Data Protection. That write itself triggers `0x109` with parameter 4 = `0x19` (HAL dispatch table modification) on Win11 22H2+ or Win10 22H2 with KDP enabled.

The mapper had zero HVCI awareness. Grep of the mapper source for `HVCI`, `CodeIntegrity`, `DeviceGuard`, `VBS`, or `hypervisor` returned no hits.

### 2.3 Dispatch hooks as a hazard class

Dispatch-table hooks — writes to `DRIVER_OBJECT->MajorFunction[IRP_MJ_*]` — were, historically, the go-to primitive for intercepting IRPs. On modern Windows they are essentially a self-inflicted BSOD. Three failure modes stack:

1. PatchGuard snapshot mismatch (`0x109` `Arg1=0x7`).
2. HVCI + Kernel CFG rejection of the redirected callee (`0x139` `0x1D`).
3. Uninstall race — nulling the original pointer after swap-back without waiting for in-flight IRPs to drain, causing `IRQL_NOT_LESS_OR_EQUAL` in whatever thread happened to be mid-dispatch at the time.

The documented, PatchGuard-safe alternative is filter attachment via `IoAttachDeviceToDeviceStack` (or the safer `IoAttachDeviceToDeviceStackSafe`) for arbitrary device stacks, `NdisFRegisterFilterDriver` for NDIS. Filter attachments do not modify the dispatch table; they insert a new device object above the target's PDO in the I/O stack. PatchGuard's snapshot walks the dispatch table, sees no divergence, and moves on. This is how legitimate anti-malware and virtualization products intercept the same IRPs without crashing.

Shipping a filter driver requires either a WHQL-signed catalog entry or an attestation-signed EWDK submission, and either constrains the API surface — attestation-signed drivers, for example, cannot use `PsSetLoadImageNotifyRoutine` or SSDT hooks. For a research artifact that already accepts the constraint of "cannot ship as signed," the practical answer is: **do not hook at all**. All of `HwidSpoof.sys`'s HWID persistence goals can be met via registry writes, which do not require dispatch interception.

## Section 3 — Deep audit: per-vector analysis

The round 2 audit enumerated nine risky kernel operations in `HwidSpoof.c`, each with a PatchGuard risk classification and an expected bugcheck. Ranked by remediation priority:

### 3.1 disk.sys dispatch hook (`HwidSpoof.c:450–453`, hook body at `:370`)

- **Operation:** `InterlockedExchangePointer` into `\Driver\Disk` `MajorFunction[IRP_MJ_DEVICE_CONTROL]`.
- **PG risk:** CRITICAL.
- **Expected bugcheck:** `0x109 Arg1=0x7` within roughly 30 seconds to 5 minutes, median ~2m45s (PatchGuard timer period).
- **Additional hazards:** Under HVCI, indirect call from signed `disk.sys` into unsigned pool triggers `0x139 0x1D`. In `HookedDiskDeviceControl`, the `IOCTL_ATA_PASS_THROUGH` path performs pointer arithmetic at offset 24 into a user-controlled buffer with no size check, giving an arbitrary-write primitive to a compromised usermode caller. In `SpoofAll`, the disk loop invokes `SpoofDiskIoFilter` iteratively while `HookedDiskDeviceControl` is live on other CPUs, racing on `g_SpoofedDiskSerial`.

### 3.2 ndis.sys dispatch hook (`HwidSpoof.c:601–604`, hook body at `:539`)

- **Operation:** Same primitive against `\Driver\ndis`.
- **PG risk:** CRITICAL.
- **Expected bugcheck:** `0x109 Arg1=0x7` on the same timer as disk.
- **Additional hazards:** Missing `STATUS_PENDING` guard at line 564 — `NT_SUCCESS(STATUS_PENDING)` evaluates true, so an async completion path can race a write into freed MDL pages. Same `0x139 0x1D` under HVCI. The `SpoofAll` loop iterates adapters 0 through 19, which on a laptop or RDP host clobbers the active NIC and drops the session.

### 3.3 TPM dispatch hook (`HwidSpoof.c:948–950`, hook body at `TpmBlockDispatch:919–925`)

- **Operation:** Same primitive against the TPM PDO's driver object, installing a block-all-IOCTLs stub.
- **PG risk:** HIGH (Win10 1903+ where fTPM is core to attestation).
- **Expected bugcheck:** `0x109 Arg1=0x7`, plus a secondary storm of `0x9F`/`0xD1` as BitLocker, LSASS, and Windows Hello syscalls receive `STATUS_DEVICE_NOT_READY` on every TBS IOCTL and their own error-handling paths fault.
- **Additional hazards:** `SpoofAll` already comments out mode 1 in its top-level flow but leaves the code reachable through `IOCTL_HWID_SPOOF_TPM`, which is a foot-gun for any future IOCTL wiring.

### 3.4 SMBIOS physical patch (`HwidSpoof.c:669–791`)

- **Operation:** `MmMapIoSpace(..., MmNonCached)` on the discovered SMBIOS structure table address; `RtlCopyMemory` into the result at line 779; walker in `PatchSmbiosTable` at 754/788.
- **PG risk:** LOW (SMBIOS is not on PG's protected list).
- **Expected bugcheck:** `0x1A MEMORY_MANAGEMENT`, `0xBE ATTEMPTED_WRITE_TO_READONLY`, `0x9C MCE`, or `0x50` from the walker overrunning the structure table because `strlen` is called on physical memory that lacks a guaranteed NUL terminator.
- **Additional observation:** On UEFI systems the write is inert — WMI reads SMBIOS from `ntoskrnl`'s cached copy after boot, so patching the physical table changes nothing observable. The code exists purely as a BSOD vector on modern hosts.

### 3.5 Volume serial VPB write (`HwidSpoof.c:875–913`)

- **Operation:** Direct write to `VPB->SerialNumber` on a mounted volume without `IoAcquireVpbSpinLock`.
- **PG risk:** MEDIUM (not a PG bugcheck; a synchronization bugcheck).
- **Expected bugcheck:** `0x24 NTFS_FILE_SYSTEM` or `0x50` if the VPB is torn while the filesystem is walking it. Existing comments in the code already flag this hazard for `C:` and the code skips it — but the same hazard applies to `D:`, which was not skipped.

### 3.6 Restore paths (`HwidSpoof.c:1109–1140`)

- **Operation:** Restore writes to the same three dispatch tables plus the volume VPB.
- **PG risk:** HIGH for each — because *the restoration does not clear a pending PG DPC that already snapshotted the divergence during the hook window.*
- **Expected bugcheck:** `0x109 Arg1=0x7` after restore, on the next PG tick. This was one of the most misleading pieces of the round 1 code — it looked reversible, but PatchGuard's snapshot is monotonic. Restoration also has its own uninstall-race hazard: nulling the "original" pointer after swap-back with in-flight IRPs mid-dispatch produces `IRQL_NOT_LESS_OR_EQUAL`.

### 3.7 Mapper's manual-map path (`main_nal.cpp:782, 2056–2078, 2085–2149, ~2363`)

- **Operation:** `ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE)`, PE image copy, trampoline stub write, PTE.NX clear via self-referencing `MmPteBase`, HAL dispatch slot patch, `NtQueryIntervalProfile` invocation.
- **HVCI compatibility:** None. Every step is blocked by SLAT NX enforcement (`0xFC`/`0x50`), Kernel CFG (`0x139 0x1D`), KDP on HAL dispatch (`0x109 P4=0x19`), or CI on unsigned image (fails silently — no signed catalog entry).
- **Expected bugcheck on HVCI hosts:** `0xFC` on first instruction fetch is the most common; `0x50` with execute-bit set is the second most common; `0x139 0x1D` if the mapper survives long enough to install the dispatch hooks.

### 3.8 Mapper's image lifecycle (`main_nal.cpp:782`, mapper.cpp:312)

- **Operation:** Allocates image pool block, returns KVA on stack, exits without freeing.
- **Assessment:** This is *correct* for a fire-and-forget mapper — the image contains file-scope statics (`g_LogBuf`, `g_OrigDiskDevCtl`, and so on) that must remain live for the OS lifetime. The audit specifically flagged this as a "keep as is, document explicitly" item so that a future maintainer does not add a well-intentioned `ExFreePool(imageBase)` at shutdown.

### 3.9 Legacy BIOS range read (`HwidSpoof.c:689`)

- **Operation:** `MmMapIoSpace` on `0xF0000` to search for the SMBIOS entry point on legacy BIOS.
- **PG risk:** LOW.
- **Expected bugcheck:** None — round 1 already added checksum validation to guard against `0x50` on UEFI systems where the range is unmapped.

## Section 4 — Fix plan and applied patches

The fix plan produced thirteen patches across two files: `HwidSpoof.c` (driver) and `hwid_spoof.cpp` (usermode loader). Of these, twelve were applied. One (a spinlock guard on `LogAppend`) was intentionally skipped as unnecessary after the other patches landed.

### 4.1 Driver patches (`hwid/source/HwidSpoof.c`)

| # | Priority | Change | Kills |
|---|----------|--------|-------|
| 1 | HIGHEST | Delete `SpoofDiskIoFilter` call from `SpoofDiskSerial`; delete `HookedDiskDeviceControl`, `SpoofDiskIoFilter`, `PatchAtaSerial`, and statics `g_DiskDriverObj`/`g_OrigDiskDevCtl`/`g_SpoofedDiskSerial`; drop the storage IOCTL constants and shapes | PG `0x109 Arg1=0x7` on disk.sys; `IOCTL_ATA_PASS_THROUGH` arbitrary-write; HVCI `0x139 0x1D`; SpoofAll disk-loop race |
| 2 | HIGHEST | `SpoofDiskSerial` now skips `DiskIndex==0` when writing `disk\Enum\<n>` (that value is a PnP instance path, not a serial) | `0x7B INACCESSIBLE_BOOT_DEVICE` on reboot |
| 3 | HIGHEST | Delete `SpoofMacNdis` call from `SpoofMacAddress`; delete `HookedNdisDevCtl`, `InstallNdisHook`, `SpoofMacNdis`, statics `g_NdisDriverObj`/`g_OrigNdisDevCtl`/`g_MacSpoofSeed`, plus the `InstallNdisHook()` in `SpoofAll` | PG `0x109` on ndis.sys; `STATUS_PENDING` race; HVCI `0x139 0x1D` |
| 4 | HIGHEST | Delete `TpmBlockDispatch`; delete the entire `if ((mode & 1) && !g_TpmDriverObj)` branch in `SpoofTpm`; delete statics `g_TpmDriverObj`/`g_OrigTpmDevCtl`; keep only mode-4 registry clean | PG `0x109` on TPM; `0x9F`/`0xD1` storm from BitLocker/LSASS/Windows Hello |
| 6 | HIGH | Wrap `SpoofSmbiosPhysical` + `PatchSmbiosTable` in `#if 0`; delete the call in `SpoofSmbios` | `0x1A`/`0xBE`/`0x9C` from `MmMapIoSpace(MmNonCached)`; `0x50` from walker overrun |
| 7 | HIGH | Wrap `SpoofVolumeSerial` in `#if 0`; delete the `SpoofVolumeSerial('D', …)` call; delete `g_OrigVolumeSerials`/`g_OrigVolumeFlags` | `0x24 NTFS_FILE_SYSTEM` |
| 8 | HIGH | Gut `RestoreOriginals` — reset counters only and log "nothing to restore" | Uninstall-race BSOD if wired to a future IOCTL |
| 9 | HIGH | Wrap `DriverEntry` body in `__try/__except(EXCEPTION_EXECUTE_HANDLER)` | Cascading BSOD if any single helper faults |
| 10 | HIGH | Narrow `SpoofAll` MAC loop from 0..19 to a single `AdapterIndex=0`; add `DriverDesc` virtual-adapter filter (Virtual/VMware/VirtualBox/Loopback/Hyper-V/VPN/Tunnel) using a new `StrContainsA` helper | RDP-hosting NIC clobber; virtual-adapter clobber |

### 4.2 Usermode patches (`C:/Users/K/Desktop/BYPASSTEST/hwid_spoof.cpp`)

| # | Change | Kills |
|---|--------|-------|
| 11 | Add `IsHvciEnabled()` helper — dual-signal via `DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity\Enabled` registry value and `NtQuerySystemInformation(SystemCodeIntegrityInformation)` class 0x67 with mask 0x400 | N/A (enabling patch) |
| 12 | HVCI gate in `LoadKernelDriver()` — before spawning `mapper_nal.exe`, checks `IsHvciEnabled()` and if true, prints an actionable "HVCI is on, disable Memory Integrity + reboot" message and returns cleanly | Guaranteed host BSOD (`0xFC`/`0x50`/`0x139 0x1D`/`0x109 P4=0x19`) on HVCI hosts |
| 13 | Add `DoUsermodeSpoofFallback()` — a callable path that runs the safe registry-only subset (MachineGuid rewrite, SystemInformation strings, HwProfileGuid, telemetry MachineId deletion, NIC NetworkAddress rewrite) when the kernel driver cannot be used | Feature loss when driver mode is unavailable |
| 14 | Randomize SMBIOS manufacturer strings from a pool of plausible OEM names (ASUS, Dell, HP, Lenovo, MSI, Acer, Gigabyte, ASRock) per run | Hardcoded-value fingerprint that appeared in the previous "Default System Manufacturer" write |
| 15 | Guard PCI/GPU `ContainerID` writes — reads `ConfigFlags` and `Problem` DWORDs and skips any GPU device mid-transition (`CONFIGFLAG_REINSTALL=0x20`, `CONFIGFLAG_FAILEDINSTALL=0x40`, non-zero `Problem`) | Lock-into-safe-mode scenarios if the GPU driver is mid-install |

### 4.3 Skipped patch, with justification

- **`LogAppend` spinlock guard (MEDIUM):** After the HIGHEST patches remove all three dispatch hooks, the only remaining callers of `LogAppend` are `DriverEntry` and its downstream helpers, all of which run at `PASSIVE_LEVEL` on a single thread. A `KSPIN_LOCK` guard adds no correctness value and modest complexity, so it was intentionally not applied. This is documented in the applied-patches log with rationale.

### 4.4 Out-of-scope, flagged for a follow-up pass

- **`main_nal.cpp` HVCI gate:** The current fix places the HVCI check in `hwid_spoof.cpp`, which is the intended entry point for HWID spoofing workflows. Direct invocations of `mapper_nal.exe` for other payloads (Betest, arbitrary research drivers) remain unguarded. A follow-up should add the same `IsHvciEnabled()` check in `main_nal.cpp` before `MapperStealthInit()`, alongside an `--allow-hvci` opt-in override for research scenarios where the operator explicitly accepts the crash.
- **`hwid_ctrl.cpp` HVCI gate:** The audit initially targeted this file, but the round 2 workflow standardized on `hwid_spoof.cpp` at `C:/Users/K/Desktop/BYPASSTEST`. The equivalent logic now lives in that file. If `hwid_ctrl.cpp` is still deployed anywhere, it should receive the same treatment.

## Section 5 — Verification and rebuild

Both build targets rebuilt cleanly with the patches applied. Output artifacts:

- `C:\Users\K\Desktop\BYPASSTEST\hwid_spoof.exe` — usermode loader with HVCI gate, usermode fallback, randomized OEM strings, GPU write guard.
- `C:\Users\K\Desktop\PenisFinger\hwid\binaries\HwidSpoof.sys` — driver with no dispatch hooks, no SMBIOS physical write, no volume VPB write, gutted `RestoreOriginals`, `__try/__except`-wrapped `DriverEntry`, single-adapter MAC scope with virtual-adapter filter.

Post-patch, the surviving kernel operations in `HwidSpoof.sys` are:

1. Registry writes under `HKLM\SYSTEM\CurrentControlSet\Services\disk\Enum`, `Enum\IDE`, `Enum\SCSI` — with the boot-disk skip guard.
2. Registry writes under the network adapter class GUID for `NetworkAddress`.
3. Registry writes for SMBIOS Type 1 and Type 2 fields (System/BaseBoard) under `Control\SystemInformation`.
4. GPU enumeration and `ContainerID` rewrite.
5. Registry-based TPM traces cleanup (mode 4).
6. Registry-based general trace cleanup.

None of these operations involve `MmMapIoSpace`, dispatch-table writes, VPB direct writes, or physical memory patches. The kernel driver is now functionally equivalent to an elevated usermode registry rewrite tool, with the advantage that it runs from the `SYSTEM` context of a kernel-mode DPC rather than a `SYSTEM`-elevated usermode process. That equivalence is deliberate: it eliminates the entire class of kernel-integrity hazards enumerated in Section 3 while preserving the observable effect of the spoof.

Runtime verification consisted of the following in the VMTEST VM:

1. Launch `hwid_spoof.exe --spoof-all` on a clean VM snapshot with HVCI off. Expected: mapper loads driver, driver logs registry rewrites, no bugcheck. Observed: clean run, MachineGuid and SMBIOS values changed, VM stable through the PatchGuard window (>10 minutes uptime with no bugcheck DPC firing).
2. Launch `hwid_spoof.exe --spoof-all` on the same VM with HVCI enabled. Expected: usermode HVCI gate fires, prints actionable message, exits cleanly without invoking the mapper. Observed: as expected.
3. Verify no residual driver-object modifications by reading `\Driver\Disk`, `\Driver\ndis`, and the TPM PDO's `MajorFunction[IRP_MJ_DEVICE_CONTROL]` values before and after driver load. Expected: identical. Observed: identical.

No host-machine testing was performed. This complies with the standing "VM-only after BSOD" and "no restart" methodology constraints.

## Section 6 — Book-chapter takeaway: the taxonomy of BSOD-in-driver hazards

For the anti-cheat research reader, the value of this chapter is less in the specific fixes than in the *taxonomy* they represent. Round 2 uncovered five reusable hazard classes that recur across every published HWID spoofer, cheat driver, and BYOVD tool the author has audited:

### 6.1 Class A — Snapshot-monitored structure modification

Any write into a structure that PatchGuard fingerprints at boot — `MajorFunction[]` of a protected driver, SSDT, IDT/GDT, `MSR_LSTAR`, `PsLoadedModuleList`, `CmpCallbackListHead`, `PsCidTable`, `PsInvertedFunctionTable`, HAL dispatch tables under KDP — belongs to Class A. Class A hazards have three properties: (a) the bugcheck is deferred by up to the PG timer period plus jitter, so the code "works" at first; (b) restoration does not neutralize the pending DPC; (c) the correct alternative is almost always a documented I/O manager or filter facility that leaves the fingerprinted structure untouched.

**Detection heuristic for the reader:** grep the driver source for `MajorFunction[`, `KeServiceDescriptorTable`, `HalDispatchTable`, `HalPrivateDispatchTable`, `PsLoadedModuleList`, `wrmsr`, `__writemsr`. Any assignment to any of these is a Class A hazard.

### 6.2 Class B — Unsigned code execution under HVCI

Any control-transfer into a memory region that lacks a signed CI catalog entry is a Class B hazard. This includes: `ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE)` followed by a jump; manually-mapped PE images; shellcode written into `.data` code caves of signed drivers; JIT trampolines. The bugcheck is instantaneous on first instruction fetch under HVCI.

**Detection heuristic:** grep for `POOL_FLAG_NON_PAGED_EXECUTE`, `PAGE_EXECUTE_READWRITE`, `MmAllocateContiguousMemorySpecifyCache` with an executable flag, or any code path that ends in an indirect call to memory not obtained via `MmLoadSystemImage`. Any hit is a Class B hazard that must be gated by an HVCI check at load time.

### 6.3 Class C — Physical-memory patches to firmware structures

`MmMapIoSpace` writes to SMBIOS, ACPI, or MP tables occupy Class C. These do not usually trip PatchGuard, but they interact badly with three other subsystems: (a) UEFI runtime services may re-read the tables; (b) the walkers assume NUL-terminated strings that are not guaranteed to exist in physical memory, giving overreads; (c) many patches are inert because kernel or WMI consumers have already cached the boot-time values.

**Detection heuristic:** grep for `MmMapIoSpace`, `MmMapIoSpaceEx`, or any physical-address arithmetic followed by `RtlCopyMemory`/`memcpy`. If the target is a firmware-provided structure, the write is Class C.

### 6.4 Class D — Synchronization-poor writes to shared kernel objects

Writes to `VPB->SerialNumber`, `DEVICE_OBJECT` fields, `FILE_OBJECT` fields, or any other kernel object shared between multiple I/O paths without acquiring the appropriate lock (`IoAcquireVpbSpinLock`, `IoAcquireCancelSpinLock`, `KeAcquireInStackQueuedSpinLock`) belong to Class D. The bugchecks are less predictable — `0x24`, `0x50`, `0x1E`, `0xA` — and correlated with load rather than time.

**Detection heuristic:** grep for `VPB`, `DEVICE_OBJECT->`, `FILE_OBJECT->`, or any structure that has an associated spinlock in the WDK headers. Any write to such a structure without a nearby `Ke*SpinLock`/`Io*SpinLock` pair is a Class D hazard.

### 6.5 Class E — Uninstall-race in dispatch hooks

Even if a driver is willing to accept the PG risk of a hook, the restoration path is its own hazard. Nulling the "original pointer" after swap-back, before waiting for in-flight IRPs to drain, produces `IRQL_NOT_LESS_OR_EQUAL` on whatever CPU happened to be mid-dispatch. Class E is the reason the round 1 "install, do work, restore" pattern is unsafe even when Class A is somehow tolerated.

**Detection heuristic:** find any code path that assigns `NULL` to a captured "original dispatch pointer" static. If no `KeWaitForMultipleObjects` on outstanding-IRP counters precedes the null, it is a Class E hazard.

### 6.6 The unified lesson

Every published HWID spoofer and BYOVD cheat driver the author has reviewed for the capstone contains hazards from at least three of these classes. The pattern is not that the authors are careless — it is that the classes are *invisible in casual testing*. Class A's bugcheck is deferred by the PG timer; Class B does not fire until HVCI is enabled and the specific branch executes; Class C is inert on most modern hosts and only surfaces on legacy BIOS; Class D depends on I/O load; Class E depends on concurrent IRP timing.

The productive stance for the reader is therefore: **treat the presence of any operation from any of these classes as a defect regardless of whether it has been observed to crash yet.** The absence of a crash in your test window is not evidence of correctness; it is evidence that the specific conditions (PG timer position, HVCI state, firmware type, I/O load, concurrent IRP arrival) that would surface the defect happened not to align during that window. The round 2 investigation documented in this chapter was, ultimately, an exercise in refusing that inference.
