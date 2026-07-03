# VGK (Vanguard) Static Analysis — vgk.sys

**Date**: 2026-07-02
**File**: `C:\Program Files\Riot Vanguard\vgk.sys`
**Size**: 52,634,264 bytes (50.2 MB)
**Build**: 1.18.3-77+20260625.030831 (June 25, 2026)
**TimeDateStamp**: 0x6A3C9CC9

---

## 1. PE Structure

| Field | Value |
|-------|-------|
| Machine | x64 (0x8664) |
| Sections | 16 |
| ImageBase | 0x140000000 |
| SizeOfImage | 49.8 MB |
| EntryPoint | 0x2BA713C (in .riot1) |
| Exports | `Egg`, `Egg2` |

### Section Table

| Name | VirtSize | Characteristics | Purpose |
|------|----------|-----------------|---------|
| .text | 680 KB | RXE | Main code (cleartext) |
| _ENTROPY | 64 B | RXE | PRNG/entropy state |
| .rdata | 48 KB | R | Read-only data, string constants, BYOVD blocklist |
| .data | 90 KB | RW | Initialized data |
| .stub0 | 286 KB | RXE | Thunk/trampoline code |
| **.grfn1** | **43.9 MB** | RXE | **VM-protected code blob (Guardian framework)** |
| .riot0 | 392 KB | RW | Riot data section |
| .riot1 | 6.4 MB | RXE | Additional code (unprotected) |

The `.grfn1` section is 88% of the binary. All core detection logic is inside this custom VM.

### Imports (3 DLLs only)

**cng.sys**: BCryptVerifySignature, BCryptFinishHash, BCryptCreateHash, BCryptOpenAlgorithmProvider (signature verification)

**ntoskrnl.exe**: strcmp, ExAllocatePoolWithTag, KeIpiGenericCall, ZwQuerySystemInformation, MmMapLockedPagesSpecifyCache, MmAllocatePagesForMdl, IoCreateFileEx, KeQuerySystemTimePrecise, KeRegisterBugCheckReasonCallback, KeInitializeApc, KeInsertQueueApc, ObReferenceObjectByHandle, etc.

**HAL.dll**: KeQueryPerformanceCounter (timing)

Everything else is resolved dynamically inside the VM blob. The import table is intentionally minimal.

---

## 2. DMA Detection Mechanisms

### 2.1 IOMMU Direct Interface

```
\Device\IommuChipsetEnabler     (0xAA6B0)
HalpDmaGetIommuInterface        (0xAA6D0)
```

VGK opens `\Device\IommuChipsetEnabler` and calls the undocumented HAL function `HalpDmaGetIommuInterface` to get direct access to the IOMMU hardware abstraction layer. This means:

- **VGK can enable IOMMU enforcement even if the BIOS doesn't**
- VGK can create restrictive IOMMU page tables targeting specific BDFs
- VGK can intercept and block DMA transactions from suspected devices
- Per the DMA research doc (May 2026): VGK uses IOMMU to generate page faults against detected DMA devices, corrupting FPGA firmware

### 2.2 What's in the VM Blob (43.9 MB)

Cannot be analyzed statically. Based on public knowledge and the DMA research doc, the VM blob likely contains:

- PCIe device enumeration (SetupDiGetClassDevs, WMI queries)
- Full 4KB config space fingerprinting
- BAR emulation testing (A/B functional testing)
- BME (Bus Master Enable) flipping
- Memory honeypots with cache timing detection
- Boot-time device baseline comparison
- Link width mismatch detection

### 2.3 Other Detection Infrastructure

```
\Device\gobbledygook            (decoy device name?)
SysDispAffinity                 (CPU affinity manipulation)
KeIpiGenericCall                (IPI to all CPUs — cache manipulation/timing)
KeQueryPerformanceCounter       (high-precision timing)
KeQuerySystemTimePrecise        (timing measurement)
```

`KeIpiGenericCall` + `KeQueryPerformanceCounter` together suggest timing-based detection — VGK can measure cache coherency latency caused by DMA snooping.

---

## 3. BYOVD Driver Blocklist

VGK checks for these device paths (each appears **8 times** in .rdata — once per detection variant/phase):

| Device Path | Driver | In Our Project? |
|-------------|--------|-----------------|
| `\DosDevices\RTCore` | RTCore64 (MSI Afterburner) | **YES** (primitive_rtcore.hpp) |
| `\DosDevices\Global\CPUZ` | CPU-Z | No |
| `\DosDevices\WinRing0` | WinRing0 | No |
| `\DosDevices\WinIoB` | WinIo | No |
| `\DosDevices\NTIOLib` | NTIOLib | No |
| `\DosDevices\ALSysIO` | ALSysIO | No |
| `\DosDevices\AIDA64Driver` | AIDA64 | No |
| `\DosDevices\NVFLASH` | NVIDIA Flash | No |
| `\DosDevices\inpout` | InpOut32/64 | No |
| `\DosDevices\EneTechIo` | ENE Technology | No |
| `\DosDevices\GLCKIo2` | GLCKIo2 | No |
| `\DosDevices\Asusgio` | ASUS GIO | No |
| `\DosDevices\AsUpdateio` | ASUS Update | No |
| `\Device\ATSZIO` | ASUS ATK0100 | No |
| `\DosDevices\ZemanaAntiMalware` | Zemana AM | No |
| `\DosDevices\BS_Def` | BS_Def | No |
| `\DosDevices\CITMDRV` | CITM | No |
| `\DosDevices\SE64` | SE64 | No |
| `\DosDevices\driveragent%d` | DriverAgent | No |
| `\Device\genericdrv` | Generic BYOVD | No |
| `\DosDevices\HOSTNT` | HOSTNT | No |

### String Signature Detection (PE scanning)

VGK also scans loaded kernel module memory for known vulnerable driver debug strings:

```
"NalDeviceControl: InputBuffer was NULL"
"Nal Windows Driver Loaded"
"Nov 14 2013"                              (NalDrv build date)
"MAPMEM.SYS: memory successfully mapped"
"Leaving MsIoDispatch"
"Leaving WinIoDispatch"
```

Each of these appears **8 times** — once per detection copy. This is the PE scanner that detects NalDrv even without checking the device path.

### NOT in the Blocklist

| Driver | Device Path | Status |
|--------|-------------|--------|
| **CorsairLLAccess64** | `\DosDevices\CorsairLLAccess64` | **NOT DETECTED** |
| **TRIXX** | Unknown path | **NOT DETECTED** |
| **ThrottleStop** | Unknown path | **NOT DETECTED** |
| **SIV** | Unknown path | **NOT DETECTED** |
| **LnvMSRIO** | Unknown path | **NOT DETECTED** |

These are our BYOVD primitives that VGK currently has no cleartext signatures for. Note: they could still be detected by the VM blob via other means (certificate checks, pool tag scanning, etc.).

### Other Detection

```
WindowsKernelExplorerFalsifyDriverCharacteristic
```

VGK detects attempts to falsify driver characteristics (spoofing signed driver properties).

---

## 4. Certificate and Attestation

```
SHA256, SHA384, SHA512                     (hash algorithms)
BCRYPT_OBJECT_LENGTH                       (crypto init)
BCryptVerifySignature                      (signature verification)
1.2.840.113549.1.1.5                       (sha1WithRSAEncryption)
1.2.840.113549.1.1.11                      (sha256WithRSAEncryption)
1.2.840.113549.1.1.12                      (sha384WithRSAEncryption)
1.2.840.113549.1.1.13                      (sha512WithRSAEncryption)
Microsoft Primitive Provider               (MS crypto provider)
RSAPUBLICBLOB                              (RSA key import)
win32kbase.sys, win32kfull.sys             (monitored system modules)
```

VGK performs certificate chain verification on loaded drivers and monitors win32k modules for tampering.

---

## 5. Protected Executables

```
vgc.exe                                    (Vanguard client)
VALORANT-Win64-Shipping.exe                (game executable)
```

---

## 6. Assessment: Will Our Firmware Be Flagged?

### BYOVD Assessment

| Primitive | VGK Detection | Risk |
|-----------|--------------|------|
| NalDrv (Intel) | **DETECTED** — PE string scan finds "NalDeviceControl", "Nal Windows Driver Loaded" | **HIGH** |
| RTCore64 | **DETECTED** — device path `\DosDevices\RTCore` | **HIGH** |
| CorsairLLAccess64 | Not in blocklist | **LOW** (currently) |
| TRIXX | Not in blocklist | **LOW** (currently) |
| ThrottleStop | Not in blocklist | **LOW** (currently) |
| SIV | Not in blocklist | **LOW** (currently) |
| LnvMSRIO | Not in blocklist | **LOW** (currently) |

**Conclusion**: NalDrv and RTCore are burned against Vanguard. Corsair, TRIXX, ThrottleStop, SIV, and LnvMSRIO are currently undetected in the cleartext blocklist. However, the 43.9 MB VM blob could contain additional detection.

### DMA/FPGA Assessment

| Detection Vector | Risk | Mitigation |
|------------------|------|------------|
| IOMMU enforcement | **CRITICAL** | VGK enables IOMMU even if BIOS doesn't; can block all DMA |
| Device enumeration | **HIGH** | Must pass full PCIe device emulation |
| Config space fingerprinting | **HIGH** | Must clone entire 4KB from donor device |
| BME flipping | **HIGH** | Firmware must not auto-restore BME |
| A/B functional testing | **HIGH** | Emulated device must actually function |
| Memory honeypots | **MEDIUM** | Read-only DMA at low frequency with randomized patterns |
| Link width mismatch | **MEDIUM** | 75T is x1 only — must emulate a device that uses x1 |
| Boot-time baseline | **HIGH** | Card must be installed before Vanguard boot |
| EPT monitoring | **HIGH** | VGK hypervisor can detect physical memory access patterns |
| Firmware corruption | **CRITICAL** | VGK (May 2026) generates IOMMU page faults to corrupt FPGA firmware |

**Overall DMA viability against VGK: VERY LOW.** Vanguard is the hardest anti-cheat for DMA. The IOMMU enforcement alone is a near-hard block. The firmware corruption attack (generating page faults to brick the FPGA) is unprecedented.

---

## 7. Limitations of This Analysis

- **43.9 MB of detection logic is unanalyzable** — the `.grfn1` VM blob cannot be reverse-engineered from static strings alone
- IDA Pro with custom deobfuscation would be needed to analyze the VM blob
- VGK updates frequently (CDN-pushed) — the blocklist can change at any time
- The blocklist may use hashed values in the VM blob rather than cleartext strings
- Some detection may occur in the usermode component (vgc.exe) rather than vgk.sys

---

## 8. Easter Eggs

```
https://imgur.com/a/PiWvsB0                (embedded imgur link)
"Protected by Riot Vanguard."              (ASCII art shield in .rdata)
$$PUKE                                     (section name)
```
