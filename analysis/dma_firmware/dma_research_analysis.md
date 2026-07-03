# DMA Research Analysis: i9-12900K + CaptainDMA 75T vs Modern Anti-Cheats

**Date**: 2026-07-01
**Hardware**: Intel Core i9-12900K (Alder Lake), CaptainDMA 75T FPGA
**Anti-Cheats Analyzed**: EAC v3.2.0, BattlEye (BEDaisy), ACE (Delta Force), VGK (Vanguard)
**Source Data**: Project dump analysis (ctf_103, ctf_104, ctf_110), IDA Pro databases, stealth audit

---

## 1. Intel i9-12900K: IOMMU / VT-d Analysis

### 1.1 VT-d Architecture on Alder Lake

The i9-12900K (Alder Lake, 12th Gen) implements Intel VT-d 3.0 with the following characteristics:

**IOMMU Units**: Alder Lake exposes two DMAR (DMA Remapping) units visible in the ACPI DMAR table:
- **DRHD 0**: Covers integrated GPU and CPU-attached PCIe devices (lanes from the CPU die)
- **DRHD 1**: Covers chipset-attached devices via the DMI 4.0 link to the Z690/Z790 PCH

**Key VT-d 3.0 Features on 12th Gen**:
- First-level (process) and second-level (domain) page tables
- Scalable Mode Translation (SM) support
- Posted interrupts
- Page Request Interface (PRI) for ATS/PASID
- Interrupt remapping (IR)
- x2APIC support

**Consumer Board Default State**: On most Z690/Z790 consumer motherboards, VT-d is **enabled in BIOS by default** but Windows may not activate Kernel DMA Protection unless:
1. The firmware advertises DMAr (DMA Remapping) in ACPI via the DMAR table with proper OPT-IN flags
2. Secure Boot is enabled
3. UEFI firmware sets the pre-boot DMA protection policy

Many consumer Z690/Z790 boards do NOT set the pre-boot DMA protection flags, meaning the IOMMU is present but may not be enforcing DMA isolation for external PCIe devices at boot time.

### 1.2 PCIe Topology on Alder Lake

Alder Lake splits PCIe lanes between CPU-direct and chipset:

| Source | Lanes | Gen | Devices |
|--------|-------|-----|---------|
| CPU | x16 + x4 | PCIe 5.0/4.0 | Primary GPU, M.2 SSD |
| Z690 PCH | x12 | PCIe 4.0/3.0 | Secondary slots, USB, SATA, NVMe |
| DMI 4.0 | x8 | PCIe 4.0 | CPU ↔ PCH interconnect |

**DMA implications**:
- A DMA card in a **chipset PCIe slot** (most x1/x4 slots) routes through the DMI link and the PCH's IOMMU unit (DRHD 1)
- A DMA card in a **CPU-direct slot** (primary x16, or M.2) routes through the CPU's IOMMU unit (DRHD 0)
- The DMI 4.0 link adds ~100ns latency for chipset-attached devices
- If IOMMU is enforcing, the translation table used depends on which DRHD unit handles the device's source-id (BDF)

### 1.3 IOMMU Bypass Considerations

**VT-d is not a hard barrier for DMA cards on consumer platforms because**:
1. **Pre-boot gap**: Before the OS loads IOMMU drivers, all DMA is unrestricted. PCIe devices enumerated during POST have full memory access.
2. **1:1 identity mapping**: Many consumer BIOS implementations create identity-mapped (passthrough) IOMMU domains for all devices during early boot. The OS *can* override this, but Windows only does so for Kernel DMA Protection-eligible devices.
3. **Kernel DMA Protection scope**: Windows Kernel DMA Protection (introduced in 1803) only protects against hot-plugged Thunderbolt/external devices. Devices present at boot in internal PCIe slots are typically trusted.
4. **IOMMU group granularity**: On Z690/Z790, PCIe slots may share IOMMU groups. If ANY device in a group has passthrough access, all devices in that group do.

**12th Gen vs Older Generations**:
- 10th Gen (Comet Lake): VT-d 2.5, no scalable mode, fewer IOMMU units
- 11th Gen (Rocket Lake): VT-d 3.0 introduced, but consumer adoption identical
- 12th Gen (Alder Lake): Hardware capability identical to 11th Gen from IOMMU perspective. The difference is firmware maturity — more Z690 boards properly implement DMAR tables, but enforcement still depends on Secure Boot + OEM policy
- **Bottom line**: For an internal PCIe DMA card present at boot, IOMMU behavior is effectively identical across 10th-12th Gen on consumer boards

### 1.5 CVE-2025-11901: Pre-Boot IOMMU Failure on 600/700 Series

**Critical finding**: Discovered by **Nick Peterson and Mohamed Al-Sharifi of Riot Games** (Vanguard team), disclosed December 2025 (CVE-2025-11901 / VU#382314, CVSS 7.0). Four CVEs across ASUS, ASRock, Gigabyte, and MSI motherboards with Intel 500-800 series chipsets:
- Firmware reports DMA protection as active via ACPI/UEFI
- **IOMMU is never actually configured during early boot** ("Sleeping Bouncer" — guard reported on duty but asleep)
- Attack window: power-on through OS kernel IOMMU driver initialization
- A DMA device can perform unrestricted reads/writes to ALL physical memory during this pre-boot phase
- Board-level firmware bug, not silicon. Patches have been released by affected vendors.

### 1.6 ACS (Access Control Services) Weaknesses on Consumer Z690/Z790

Consumer boards have **poor ACS support**:
- ACS capabilities (Source Validation, Transaction Blocking, Request Redirect) may exist in hardware but remain disabled in firmware
- Multiple endpoints frequently share IOMMU groups because root ports lack ACS
- Lane bifurcation changes device-to-root-port assignments dynamically, altering isolation topology
- Onboard controllers (USB, SATA, Wi-Fi, audio) often share downstream ports with no ACS isolation
- Linux `pcie_acs_override` can force artificial group splitting but destroys real isolation guarantees

### 1.7 IOTLB Deferred Invalidation Window

Linux's VT-d driver defers IOTLB cache invalidation for performance: entries are batched and flushed when the queue exceeds 256 entries or every 10ms. This creates a window where a memory region has been unmapped but **stale IOTLB entries still permit DMA access**. A malicious PCIe device can exploit this to access memory belonging to other devices during the invalidation delay.

### 1.8 Intel TME/MKTME: Transparent to DMA

Alder Lake supports TME-MK (Total Memory Encryption with Multi-Key):
- **Encryption engine placement**: Dedicated AES-XTS engines reside **on each memory controller**, between the LLC and DRAM
- **Data is plaintext inside the CPU** (caches, core pipeline) and encrypted only on the physical DDR bus
- **DMA reads through PCIe see PLAINTEXT**: The memory controller decrypts transparently for all requestors, including DMA devices
- TME protects against cold boot attacks and physical DRAM interposers, NOT against logical DMA access
- **Bottom line**: TME is irrelevant for PCIe-based DMA attacks

### 1.9 ATS (Address Translation Services) Bypass

**Critical**: PCIe 4.0+ devices supporting ATS can cache IOVA-to-physical translations in their own Address Translation Cache (ATC). Once cached, they can issue DMA requests using **bare physical addresses**, bypassing IOMMU translation entirely. Linux trusts all internal PCIe devices for ATS by default. An FPGA in an internal M.2 or PCIe slot could potentially use ATS to bypass VT-d.

### 1.10 Cache Coherency — Works in DMA's Favor

On x86-64 including Alder Lake, **all PCIe DMA is hardware cache-coherent by default**:
- DMA reads automatically snoop CPU caches (L1/L2/LLC) and return the most current data
- Even if a CPU core modified a value that's still in cache (not flushed to DRAM), a DMA read returns the up-to-date value
- The "No Snoop" TLP hint can skip snooping for performance, but VT-d's Snoop Control can override this
- P-core vs E-core distinction is irrelevant — both share the same coherency domain via the shared LLC
- **This means the common concern about "stale DMA reads" is largely unfounded on Intel platforms**

### 1.11 P-core vs E-core: No DMA Differentiation

The hybrid architecture does NOT create distinct DMA behavior:
- Both core types share a unified physical address space and shared LLC
- DMA requests hit the same memory controller regardless of which core last touched the data
- Intel Thread Director handles scheduling but has zero impact on the DMA path

### 1.4 Relevant BIOS Settings

Settings on Z690/Z790 that affect DMA access:
- **VT-d**: Enable/Disable (disabling removes all IOMMU protection)
- **Above 4G Decoding**: Affects BAR allocation for PCIe devices, sometimes needed for FPGA cards
- **Re-Size BAR**: May affect MMIO window for FPGA
- **Thunderbolt Security Level**: Only relevant for TB devices, not internal PCIe
- **Secure Boot**: Required for Kernel DMA Protection
- **CSM/Legacy Boot**: Disabling CSM is required for full Secure Boot chain

---

## 2. CaptainDMA 75T: Hardware and Firmware Analysis

### 2.1 Hardware Specifications

| Specification | Detail |
|--------------|--------|
| FPGA | Xilinx Artix-7 XC7A75T-484 (75,520 logic cells, 28nm TSMC) |
| PCIe | Gen 2.0 x1 (single lane, ~400 MB/s raw after 8b/10b) |
| USB Bridge | FTDI FT601 USB 3.2 Gen 2 to FIFO (~300 MB/s practical) |
| JTAG | CH347 chip (requires custom OpenOCD build, non-standard) |
| Form Factor | PCIe half-height card (50x30mm module on carrier) |
| Power | 3.3V, ~1.2A max |
| Max Throughput | ~190-220 MB/s sustained (USB-limited, not PCIe-limited) |
| Kill Switch | Physical on/off switch to deactivate without removal |
| Price Range | $100-200 USD |

The "75T" designation refers to the Artix-7 75T FPGA:
- **75T**: 75,520 logic cells, 105 BRAMs — enough for full config space emulation + complex TLP handling
- **35T**: 33,280 logic cells, 50 BRAMs — constrained, cannot fit the most complex emulation firmware

**Measured Performance Comparison (75T vs 35T)**:

| Metric | 35T | 75T |
|--------|-----|-----|
| Average throughput | 18.3 MB/s | 40.2 MB/s |
| Max latency spike | 1.8 ms | 0.6 ms |
| Response time (tuned) | 4.7 ms | 2.8 ms |
| Timestamp jitter | ±1.5 ms | ±0.4 ms |
| Data loss rate | 0.7% | 0.1% |
| Thermal (sustained) | 78°C | 69°C |
| Frame drop rate | 12/10min | 1/10min |

The 75T is the most widely recommended card across the ecosystem — it's the sweet spot between cost and capability. The 100T offers more headroom for the most complex scenarios but at higher cost.

### 2.2 How DMA Read/Write Works at the PCIe Level

FPGA-based DMA cards perform memory access via **PCIe Transaction Layer Packets (TLPs)**:

**Read Path** (DMA card reads host physical memory):
1. FPGA crafts a **Memory Read Request TLP** (MRd) with:
   - Requester ID: BDF (Bus:Device:Function) of the FPGA's emulated PCIe device
   - Address: Target physical address (32-bit or 64-bit)
   - Length: Number of DWORDs to read (max 1024 per TLP = 4096 bytes)
   - Tag: Transaction identifier for matching completions
2. TLP traverses PCIe fabric to the Root Complex (CPU/chipset)
3. Root Complex performs the memory read (or IOMMU blocks/translates)
4. Root Complex returns a **Completion with Data (CplD)** TLP
5. FPGA receives data from CplD

**Write Path** (DMA card writes to host physical memory):
1. FPGA crafts a **Memory Write Request TLP** (MWr) with:
   - Address: Target physical address
   - Data: Payload to write (up to 4096 bytes per TLP)
2. Memory writes are **posted** — no completion returned
3. Write takes effect when it reaches the memory controller
4. No confirmation mechanism (fire-and-forget)

**Key TLP parameters**:
- Max Payload Size: Negotiated during PCIe link training (128/256/512 bytes typical)
- Max Read Request Size: Also negotiated, up to 4096 bytes
- Relaxed Ordering: Affects memory consistency guarantees
- No Snoop: Bypasses CPU cache coherency (important for DMA detection)

### 2.3 Firmware Capabilities

The pcileech-fpga ecosystem provides the primary open-source firmware framework for cards like the CaptainDMA 75T. Key capabilities:

**Device Emulation**: The FPGA can emulate any PCIe device by responding to Configuration Space reads with arbitrary Vendor ID, Device ID, Class Code, and capability structures. This is critical because:
- Anti-cheats enumerate PCIe devices via `SetupDiGetClassDevs` / WMI
- Unknown or suspicious device IDs are flagged
- The FPGA must emulate a plausible device (network card, USB controller, etc.)

**Configuration Space**: The FPGA presents a full PCIe config space including:
- Header (Type 0 or Type 1)
- Capability list (PM, MSI/MSI-X, PCIe Extended Capability)
- BARs (Base Address Registers) — can be configured for MMIO regions
- Subsystem Vendor/Device ID

**TLP Filtering**: The FPGA can selectively respond to or ignore certain TLP types, allowing it to:
- Respond to config reads (appear as a real device)
- Generate memory read/write TLPs on demand
- Filter incoming TLPs that might probe the device

### 2.4 Known Limitations

1. **Speed**: ~190-220 MB/s sustained (USB bridge bottleneck, not PCIe). For targeted reads (CR3 walk, specific offsets), latency per read is ~1-5μs. Full 32GB RAM scan: ~2.5 minutes.

2. **Cache Coherency**: On Intel x86-64, this is largely a non-issue. Root Complex hardware snoops CPU caches by default for standard MemRd TLPs (No Snoop = 0). DMA reads get coherent data transparently — the Root Complex forces cache writebacks as needed. Only reads with No Snoop = 1 risk stale data.

3. **IOMMU**: If VT-d is enforcing, all memory read/write TLPs are translated through IOMMU page tables. Reads to addresses not mapped for the device's domain return UR (Unsupported Request) completions. However, most consumer boards don't enforce for internal PCIe devices.

4. **Detection Surface**: The card is a physical PCIe device that:
   - Appears in PCIe configuration space (must emulate a known device)
   - Generates TLPs that traverse the root complex
   - May be detectable via PCIe link training anomalies or timing patterns
   - Leaves registry artifacts even after physical removal

5. **No CPU Register Access**: DMA operates on physical memory only. Cannot read/write CPU registers (CR3, MSRs, etc.) directly. Must walk page tables from physical memory.

6. **CH347 JTAG Complexity**: Non-standard JTAG programmer requires vendor-specific software and custom-compiled OpenOCD build. A second PC is typically needed for flashing.

7. **Firmware Shelf Life**: Custom firmware needs replacement every 3-5 months as anti-cheat detection signatures evolve.

---

## 3. Anti-Cheat Detection Mechanisms Relevant to DMA

### 3.1 EAC (EasyAntiCheat) v3.2.0

**From our dump analysis (ctf_103_eac_analysis.md, eac_ida_deep.txt)**:

| Mechanism | DMA Relevance | Detail |
|-----------|--------------|--------|
| **Certificate-based driver blocklist** | LOW | DMA card has no driver to block, but the emulated device ID matters |
| **VM protection (94% of binary)** | MEDIUM | Detection logic is obfuscated, making it hard to know exactly what's checked |
| **BigPoolTable enumeration** | LOW for DMA | Scans for manually mapped drivers in kernel pool — DMA doesn't create pool allocations |
| **MZ/PE signature scan** | LOW for DMA | Scans non-image memory for PE headers — only relevant if DMA is used to MAP a driver |
| **ObRegisterCallbacks** | NONE for DMA | Monitors handle operations — DMA bypasses handles entirely |
| **PsSetCreateProcessNotifyRoutine** | NONE for DMA | Process creation callbacks — irrelevant for pure DMA reads |
| **FltRegisterFilter** | NONE for DMA | Filesystem minifilter — irrelevant |
| **ETW telemetry** | NONE for DMA | ETW traces software events — DMA generates no software events |
| **CDN blocklist updates** | MEDIUM | Could add PCIe device ID fingerprints to blocklist |
| **Hash-based API resolution** | N/A | Makes static analysis of detection logic difficult |

**EAC DMA-Specific Concerns**:
- EAC's 35.9 MB VM-protected section could contain PCIe enumeration code, but this is unverifiable from static analysis
- EAC is known to query `SetupDiGetClassDevs` for device enumeration
- WinTrust certificate chain verification is thorough — the BYOVD blocklist uses certificate hashes, not filenames
- **CDN-updated blocklist** means new device fingerprints can be pushed at any time

### 3.2 BattlEye (BEDaisy.sys)

**From our dump analysis (ctf_110_battleye_analysis.md)**:

| Mechanism | DMA Relevance | Detail |
|-----------|--------------|--------|
| **Kernel R/W/Alloc IOCTLs** | IRONIC | BEDaisy itself provides MmCopyMemory-based R/W — a software-level BYOVD primitive more powerful than DMA |
| **DPC/Timer scans** | LOW for DMA | Periodic scans for anomalies — but scans virtual memory, not physical |
| **SLIST report queues** | NONE for DMA | Reports software events to BEService |
| **Heartbeat mechanism** | NONE for DMA | User↔kernel heartbeat, software-only |
| **ObRegisterCallbacks** | NONE for DMA | Handle monitoring, DMA bypasses handles |
| **System threads** | LOW | Monitoring threads scan for anomalies — could include device enumeration |

**BattlEye DMA-Specific Concerns**:
- BattlEye has been publicly reported to enumerate PCIe devices via WMI queries
- BE checks for unknown devices in specific PCIe slots
- BE kernel driver has thread-based periodic integrity checks that COULD walk physical memory ranges
- **Key difference from EAC**: BattlEye's detection code is NOT VM-protected, making it more analyzable via IDA

### 3.3 ACE Anti-Cheat (Delta Force / Tencent)

**From our dump analysis (ctf_104_ace_analysis.md)**:

| Mechanism | DMA Relevance | Detail |
|-----------|--------------|--------|
| **Hypervisor/EPT detection** | MEDIUM | ACE checks for virtualization — relevant if DMA is combined with HV |
| **RDTSC timing normalization** | LOW for DMA | Timing checks target software hooks, not DMA |
| **OB callbacks** | NONE for DMA | Handle monitoring |
| **CR3+DKOM stealth** | HIGH | ACE validates CR3 integrity — if DMA modifies page tables, ACE may detect |
| **Multi-vector HV detection** | MEDIUM | CPUID, IDT/GDT base, MSR timing — not directly DMA but related if HV is part of the stack |
| **Code section encryption** | N/A | Protects ACE's own code from analysis |
| **Stack frame sanitization** | N/A | Software defense |
| **Self-test validation** | LOW for DMA | ACE validates its own integrity, not external devices |

**ACE DMA-Specific Concerns**:
- ACE is the **most aggressive** about timing-based detection
- ACE's hypervisor detection suite (4 IOCTLs worth of checks) suggests awareness of hardware-assisted attacks
- **RDTSC normalization** means ACE profiles execution timing — could potentially detect DMA-induced memory latency anomalies (cache line invalidation patterns)
- ACE validates CR3 values — if DMA reads use a CR3 that ACE has marked as suspicious, the walk may produce inconsistent results
- **Tencent's resources** suggest ACE likely has the most sophisticated DMA detection of all analyzed anti-cheats

### 3.4 VGK (Vanguard / Riot)

**No VGK dump exists in the project**. However, from public knowledge:

| Mechanism | DMA Relevance | Detail |
|-----------|--------------|--------|
| **Boot-time driver (vgk.sys)** | HIGH | Loads at boot via ELAM — sees all devices before most drivers |
| **TPM attestation** | MEDIUM | Can attest hardware state, potentially detecting FPGA presence |
| **Secure Boot enforcement** | LOW for DMA | Verifies boot chain integrity, not PCIe devices directly |
| **Kernel-mode hypervisor** | HIGH | VGK runs its own hypervisor on some configurations |
| **PCIe device enumeration** | HIGH | Known to enumerate PCIe devices aggressively |
| **IOMMU awareness** | MEDIUM | Reported to check IOMMU state |
| **DMA detection** | VERY HIGH | Vanguard is publicly known to have specific DMA card detection |

**VGK DMA-Specific Concerns**:
- Vanguard is considered the **hardest** anti-cheat to bypass with DMA
- Boot-time ELAM driver means VGK sees the PCIe topology before game launch
- VGK has been reported to:
  - Enumerate all PCIe devices and compare against a whitelist
  - Check for devices with unusual configuration spaces
  - Monitor for PCIe hot-plug events
  - Validate IOMMU configuration
  - Check for DMA-capable devices in unexpected slots
- **Ring 0 hypervisor** means VGK can monitor physical memory access patterns via EPT/NPT violations

### 3.5 Cross-Anti-Cheat DMA Detection Summary

| Detection Method | EAC | BE | ACE | VGK |
|-----------------|-----|-----|-----|-----|
| PCIe device enumeration | Likely (VM'd) | Yes | Unknown | Yes (aggressive) |
| WMI device queries | Yes | Yes | Unknown | Yes |
| Config space fingerprinting | Unknown | Yes (0x40/0x60) | Unknown | Yes (full 4KB) |
| BAR emulation testing | Unknown | Unknown | Unknown | Yes |
| A/B functional testing | Yes (2025+) | Unknown | Unknown | Yes (2025+) |
| Lane width mismatch | Unknown | Unknown | Unknown | FACEIT |
| BME flipping | No | No | No | Yes |
| Memory honeypots | No | No | No | Yes |
| IOMMU state checking | Unknown | Unknown | Unknown | Yes |
| IOMMU firmware attack | No | No | No | Yes (May 2026) |
| Physical memory integrity | Pool/MZ scans | Unknown | CR3 validation | Yes (EPT) |
| Timing anomaly detection | Unknown | Unknown | Yes (RDTSC) | Yes (cache timing) |
| Device driver presence check | Yes (blocklist) | Unknown | Unknown | Yes |
| Boot-time device baseline | No | No | No | Yes (ELAM) |

---

## 4. DMA Techniques: Viable vs Mitigated (2026)

### 4.1 Core Technique: Physical Memory Read via PCIe TLP

**Status**: VIABLE on most consumer platforms

The fundamental DMA read technique — crafting MRd TLPs to read arbitrary physical addresses — remains functional because:
1. Most consumer motherboards don't enforce IOMMU for internal PCIe devices
2. Kernel DMA Protection only targets Thunderbolt/external hot-plug
3. No OS-level mechanism monitors for read-only DMA access

**Requirements**:
- Physical PCIe slot access (M.2 or adapter)
- IOMMU disabled or identity-mapped for the device
- Knowledge of target physical addresses (requires CR3 + page table walk)

### 4.2 CR3 Walking from DMA

**Status**: VIABLE but increasingly difficult

To read virtual memory from DMA, you need the target process's CR3 (page directory base):

**Approach 1: EPROCESS Scan**
- Scan physical memory for EPROCESS structures (the kernel's process descriptor)
- Match by ImageFileName field (offset 0x5A8 on 19045) and UniqueProcessId (0x440)
- Extract DirectoryTableBase (offset 0x028)
- **This is exactly what our codebase does** — see `CorsairBootstrapCR3()` in primitive_corsair.hpp and `TrixxBootstrapCR3()` in primitive_trixx.hpp
- **Viability**: Works from DMA. Physical memory scan for EPROCESS patterns is well-established.
- **Risk**: Anti-cheats that randomize EPROCESS layout or relocate it could break offset assumptions

**Approach 2: KPCR/KPRCB Chain**
- Read KPCR from a known physical address (GS base, accessible via IA32_GS_BASE MSR — but DMA can't read MSRs)
- Alternative: scan for KPCR/KPRCB patterns in low physical memory
- Walk KPCR → KPRCB → CurrentThread → EPROCESS → CR3

**Approach 3: PML4 Self-Reference**
- Scan physical pages looking for self-referencing PML4 entries
- A PML4 entry that points back to its own page indicates a page table root
- **This is Phase 3 of our CR3 bootstrap** — see primitive_corsair.hpp:403-431
- **Note**: Windows KPTI (Kernel Page Table Isolation) maintains shadow page tables — the user-mode CR3 has fewer kernel mappings

**KPTI Complication**:
- Windows 10/11 with KPTI enabled maintains TWO CR3 values per process:
  - Kernel CR3: Full kernel + user mappings (used during syscalls)
  - User CR3: Minimal kernel mappings (used during user execution)
- The DTB in EPROCESS is the kernel CR3
- User CR3 is typically kernel CR3 + 0x1000 (adjacent page)
- **Our code handles this** — see KPTI upgrade logic at primitive_corsair.hpp:457-474

### 4.3 Device ID Spoofing / Emulation

**Status**: REQUIRED for anti-cheat evasion

Modern anti-cheats enumerate PCIe devices. An FPGA presenting as an unknown device or with default config space values will be flagged.

**Viable approach**: Configure FPGA firmware to emulate a legitimate device:
- Network controller (Intel I225-V, Realtek RTL8125)
- USB host controller (Intel xHCI)
- NVMe controller (Samsung, WD)
- Audio controller (Realtek ALC)

**Requirements for convincing emulation**:
1. Correct Vendor ID / Device ID / Revision
2. Proper Class Code (matches device type)
3. Realistic Capability list (PM, MSI-X, PCIe extended caps)
4. BAR configuration matching the emulated device
5. Subsystem Vendor/Device ID matching motherboard vendor
6. **Device-specific registers**: Some anti-cheats read device-specific config space offsets that differ per real device

**What makes this hard**:
- Anti-cheats can compare the device's config space against a database of known-good devices
- If the emulated device type doesn't match the PCIe slot type (e.g., NVMe controller in a x1 slot), it's suspicious
- Link speed/width must match what the emulated device would negotiate

### 4.4 TLP Timing Normalization

**Status**: RELEVANT for ACE/VGK, less critical for EAC/BE

DMA reads have different timing characteristics than normal memory access:
- Normal CPU memory read: 50-100ns (DRAM), 1-5ns (cache hit)
- DMA read through PCIe: 500ns-5μs (round-trip TLP)
- DMA read through IOMMU: Additional 200-500ns translation overhead

**Detection method**: Anti-cheats can measure the time between writing a value to memory and detecting that a process read it, or measure timing anomalies in page table access patterns.

**Mitigation**: 
- Read memory infrequently (reduce scan rate)
- Avoid rapid sequential reads of adjacent addresses (pattern detection)
- Use No Snoop TLP attribute to avoid cache coherency traffic that might be monitored

### 4.5 Physical Memory Write via DMA

**Status**: VIABLE but higher detection risk

DMA writes (MWr TLPs) can modify any physical memory page. This enables:
- Modifying game state (health, position, etc.)
- Patching kernel code (disabling anti-cheat checks)
- Modifying page table entries (creating new virtual mappings)

**Detection risks of DMA writes**:
- **Code integrity checks**: Anti-cheats periodically hash their own code sections. DMA-written patches are detectable.
- **PatchGuard (KPP)**: Monitors kernel code integrity. DMA writes to kernel code trigger PatchGuard BSOD.
- **HVCI (Hypervisor-enforced Code Integrity)**: Uses EPT to make kernel code pages read-only from DMA perspective (if IOMMU is properly configured).
- **Cache coherency**: DMA write bypasses CPU cache. The CPU may continue executing stale cached code/data. Requires CLFLUSH or WBINVD to force cache line invalidation — but DMA can't execute CPU instructions.

### 4.6 Anti-Cheat DMA Detection Evolution Timeline

| Year | Event |
|------|-------|
| 2016 | PCILeech released, opens DMA attacks to wider audience |
| 2017 | BattlEye: master abort detection, VID/PID checking (false positives with legit capture cards) |
| 2018 | EAC: Xilinx-7 config space signing (bypassed via capability pointer manipulation) |
| 2019 | FACEIT: VID/PID + heuristic detection (bypassed by changing device identifiers) |
| 2022 | Vanguard: Bus Master Enable flipping, interrupt mechanism verification (both bypassed) |
| 2023 | `drvscan` release transforms detection capabilities; config space hardening across anti-cheats |
| 2023 | pcileech-WiFi source code released, distributes emulation knowledge |
| 2024 | pcileech-multimedia source released, enables rapid VID/PID cycling |
| Jan 2025 | VGK and EAC: randomized A/B functionality testing of emulated devices |
| Feb 2025 | FACEIT: custom IOMMU loading at high Elo ranks |
| Mid-2025 | VGK, EAC, and FACEIT all implement IOMMU enforcement in same month |
| Aug 2025 | FACEIT: full IOMMU enforcement for players above 3,000 Elo |
| Nov 2025 | FACEIT: TPM 2.0 and Secure Boot mandatory for all players |
| Late 2025 | VGK: blocks systems with pre-boot DMA gap (IOMMU reported but uninitialized) |
| Dec 2025 | CVE-2025-11901: ASUS/ASRock/Gigabyte/MSI pre-boot IOMMU failure disclosed |
| 2025 | PUBG (Krafton): ~260,000 DMA-based cheaters banned via AI behavioral analysis |
| Oct 2026 | FACEIT: Windows 11 mandatory (planned) |

### 4.7 A/B Functional Testing (Current State of the Art, 2025+)

Modern anti-cheats now perform **randomized behavioral testing** of emulated devices:
- If the FPGA claims to be a USB controller, the AC sends USB packets and validates responses
- WiFi card emulation: anti-cheat sends WiFi protocol packets and verifies proper responses
- NIC emulation: fake packet analysis to verify networking behavior
- Audio codec emulation: verification that audio functionality works
- These tests are **randomized and varied** to prevent static firmware responses
- A DMA card that claims to be a WiFi adapter but cannot respond to a fake WiFi packet = flagged

This is the current cutting edge of DMA detection and the hardest to defeat with firmware alone.

### 4.7.1 BAR Emulation Detection (EmuScan / drvscan)

Anti-cheats and community tools (drvscan, EmuScan) now test for **dumb emulation** — where an FPGA responds to config space reads but BARs are non-functional:

- **Probe**: Write to a BAR's MMIO region, read back, verify device-specific behavior
- **WiFi card**: send a fake 802.11 management frame, check for interrupt or register state change
- **NIC**: trigger a DMA ring operation, verify completion queue updates
- **NVMe**: submit an Identify Controller command, verify response matches claimed device

A device whose config space is perfect but whose BARs are black holes (return all-zeros or echo writes) is flagged as emulated. This is why A/B functional testing (§4.7) is so effective — config space cloning alone is insufficient.

### 4.7.2 PCIe Lane Width Detection

FACEIT specifically blocks **Xilinx Artix-7 Series** devices except at x4 link width. Detection mechanisms:

- **Link Capabilities register** (offset 0x0C in PCIe Capability): reports Max Link Width
- **Link Status register** (offset 0x12): reports Negotiated Link Width
- **Mismatch detection**: If a device claims x4 Max but actually negotiated x1 (which the 75T does), this is detectable
- The CaptainDMA 75T is PCIe Gen2 **x1** — it will always negotiate x1 regardless of what firmware claims in config space
- The actual negotiated width is reported by the **root port**, not the device itself — firmware cannot spoof this

### 4.7.3 Bus Master Enable (BME) Flipping

Vanguard (VGK) toggles the **Bus Master Enable** bit (PCI Command Register, bit 2) on suspicious devices:

- VGK clears BME → device can no longer issue DMA transactions
- If the device re-enables BME (firmware monitoring Command register writes), VGK flags it as a DMA card
- Legitimate devices have their BME managed by their kernel driver, not by self-monitoring firmware
- This is a simple but effective behavioral test: only a device designed for DMA would detect and restore its own BME

### 4.7.4 Memory Honeypots (VGK)

Vanguard places **decoy game data** at known physical addresses to detect DMA reads:

- Fake player positions, health values, or game state at specific physical pages
- **Cache timing detection**: when DMA reads a cache line, it causes a cache coherency event (snoop). Vanguard measures cache line access timing from the CPU side
- If a honeypot page's cache lines show access latency consistent with a PCIe snoop response (rather than a cache hit from normal CPU access), VGK infers DMA activity
- This is probabilistic — single reads may not trigger, but repeated polling of honeypot pages over time builds statistical confidence
- **Implication**: even read-only DMA is detectable if the anti-cheat controls what physical pages contain interesting data and monitors access patterns

### 4.7.5 BattlEye Config Space Deep Scan

BattlEye reads specific config space offsets to validate device identity:

- **Offset 0x40**: Device-specific capability block (varies by device type — this is where manufacturer-specific features live)
- **Offset 0x60**: Power management or MSI capability (depending on device)
- An FPGA that returns zeros or generic values at these offsets instead of device-specific capability structures fails the check
- **Implication for firmware**: Must clone the ENTIRE extended config space (4 KB) from a donor device, not just the first 64 bytes

### 4.8 Techniques That No Longer Work (Mitigated)

| Technique | Era | Why It Fails Now |
|-----------|-----|-----------------|
| Raw DMA with default FPGA config space | Pre-2020 | Anti-cheats enumerate devices; unknown devices = ban |
| Reading \Device\PhysicalMemory from user mode | Pre-Win10 | Restricted to kernel mode since Windows 10 |
| Direct MmMapIoSpace from unsigned driver | Pre-HVCI | HVCI blocks unsigned kernel code entirely |
| PCI BAR-based physical memory access | Pre-VT-d | IOMMU can translate/block BAR access (when enforced) |
| Simple DMA read with no device emulation | Pre-2022 | BE/EAC/VGK now fingerprint PCIe devices |
| DMA to modify PatchGuard data structures | Pre-2018 | PatchGuard checks are too frequent and unpredictable |
| Using common DMA tools (Inception, PCILeech default) | Pre-2021 | Default config space signatures are blocklisted |

### 4.9 Techniques Discussed as Currently Viable (2026)

| Technique | Viability | Notes |
|-----------|-----------|-------|
| Custom FPGA firmware with device emulation | HIGH | Requires proper device ID, config space, link params |
| CR3 walking from physical memory scan | HIGH | Well-established, our codebase already implements this |
| Read-only DMA (ESP/radar only) | HIGHEST | No memory modifications = no integrity check violations |
| Page table manipulation from DMA | MEDIUM | Can redirect virtual pages, but integrity checks evolving |
| Scatter-read patterns (randomized timing) | HIGH | Avoids timing-based detection |
| Device-specific config space cloning | HIGH | Clone config from a real device of the same type |
| PCIe Gen2 x1 operation (conservative link) | HIGH | Matches common expansion cards, less suspicious |

---

## 5. Windows Kernel DMA Protection and OS Mitigations

### 5.1 Kernel DMA Protection

Windows Kernel DMA Protection (since 1803) uses VT-d to create restrictive IOMMU page tables. When enabled:
- Context table entries for all PCI devices point to zero-filled second-level PML4 structures
- All DMA access blocked by default until trusted drivers explicitly map regions
- External/hot-plug devices with incompatible drivers blocked from DMA until user sign-in
- Devices with DMA-remapping-compatible drivers allowed DMA to assigned regions only

**Critical limitation**: Targets external hot-plug (Thunderbolt/USB4) by default. Internal PCIe devices are generally **trusted** unless OEM marks the slot as user-accessible via ACPI `_DSD`. An FPGA DMA card in an internal PCIe slot is treated as trusted by default.

### 5.2 HVCI and VBS

- **HVCI** (Memory Integrity) prevents unsigned/tampered code from executing in kernel mode via hypervisor-enforced code integrity. DMA reads are unaffected, but DMA-based kernel code injection is blocked.
- **VBS** creates isolated VTL1 environment — secrets stored there (Credential Guard) cannot be accessed even with kernel code execution. VBS alone doesn't prevent DMA reads of VTL0 memory.
- **Combined VBS + IOMMU** is defense-in-depth: IOMMU restricts which pages DMA can access, VBS isolates the most sensitive secrets.
- Windows 11 enables VBS and HVCI by default on new installs.

### 5.3 Secured-Core PC Stack

Full Secured-Core requirements (most gaming PCs do NOT meet these):
- VBS + HVCI enabled
- Kernel DMA Protection enabled
- DRTM via System Guard Secure Launch
- TPM 2.0 with measured boot
- Secure Boot
- SMM isolation

Most consumer gaming platforms lack DRTM firmware support and cannot be retroactively upgraded.

---

## 6. Assessment: CaptainDMA 75T on i9-12900K vs Each Anti-Cheat

### 6.1 vs EAC (Apex Legends, Fortnite, etc.)

**Difficulty**: MEDIUM

**Key factors**:
- EAC's detection logic is 94% VM-protected (hard to audit exactly what's checked)
- EAC updates blocklists via CDN — new device fingerprints can appear at any time
- EAC's driver verification is certificate-based (WinTrust), not relevant for DMA
- BigPoolTable / MZ signature scans only catch software-level mapping, not DMA reads

**What would work**:
- Read-only DMA for ESP/radar (read game state, render externally)
- FPGA emulating a plausible device (network card or USB controller)
- CR3 walking via EPROCESS scan (identical technique to our existing CorsairBootstrapCR3)

**What would likely fail**:
- Default pcileech config space (likely fingerprinted)
- High-frequency sequential physical memory scans (timing anomaly)
- DMA writes to EAC's code sections (integrity checks)

### 6.2 vs BattlEye (Arma, DayZ, PUBG, etc.)

**Difficulty**: MEDIUM

**Key factors**:
- BattlEye enumerates PCIe devices via WMI
- BE's detection code is NOT VM-protected (more analyzable)
- BE has specific DMA card detection reported in community
- **Ironic**: BEDaisy itself is a more powerful BYOVD than DMA (kernel R/W/Alloc via IOCTL)

**What would work**:
- Proper device emulation (must pass WMI enumeration)
- Read-only DMA at conservative rates
- Using BEDaisy's own IOCTLs instead of DMA (per our existing primitive_bedaisy.hpp)

**What would likely fail**:
- Devices with zero or default subsystem IDs
- DMA from devices in unusual PCIe slots for their type
- Any DMA pattern that triggers timing anomalies in BE's monitoring threads

### 6.3 vs ACE (Delta Force)

**Difficulty**: HIGH

**Key factors**:
- ACE has the most aggressive timing detection (RDTSC normalization across 4 IOCTLs)
- ACE validates CR3 integrity — DMA CR3 walks that cause cache coherency traffic could be detected
- Multi-vector hypervisor detection suggests hardware-attack awareness
- Tencent's engineering resources make ACE a serious adversary

**What would work**:
- Very low-frequency reads with randomized timing (jitter)
- Read-only access to game state (no kernel/AC modifications)
- Device emulation matching hardware commonly found with the game's demographic

**What would likely fail**:
- Rapid CR3 walks (timing anomaly from cache invalidation)
- Any pattern that creates detectable PCIe traffic spikes
- DMA writes to any ACE-monitored memory region

### 6.4 vs VGK (Vanguard / Valorant)

**Difficulty**: VERY HIGH

**Key factors**:
- Boot-time ELAM driver sees full hardware topology before game launch
- VGK takes a device baseline at boot — any new device after baseline is suspicious
- VGK is publicly known to have specific DMA card detection
- TPM attestation can verify hardware state
- Ring 0 hypervisor enables EPT-based monitoring of physical memory access

**What would work**:
- DMA card installed BEFORE Vanguard boot (part of baseline) with perfect device emulation
- Reading memory at extremely low frequency with no pattern
- External rendering only (no writes)

**What would likely fail**:
- Hot-plugging a DMA card after boot (instant detection)
- Any device not in VGK's whitelist
- DMA reads that cause EPT violations (VGK hypervisor can monitor these)
- Configuration spaces that don't perfectly match the emulated device

**VGK Extreme Measure (May 2026)**: Vanguard began using IOMMU enforcement to generate repeated page faults against detected DMA devices, **corrupting FPGA firmware** and rendering NVMe/SATA-spoofed DMA hardware inoperable. This is the most aggressive anti-cheat action against DMA hardware to date.

### 6.5 Overall Assessment Matrix

| Factor | EAC | BE | ACE | VGK |
|--------|-----|-----|-----|-----|
| Device enumeration bypass | Need emulation | Need emulation | Unknown | Need perfect emulation |
| Read-only DMA viability | Good | Good | Possible with jitter | Marginal |
| Write DMA viability | Poor | Poor | Very Poor | Near impossible |
| CR3 walking | Works (same as BYOVD) | Works | Works with caution | Risky (EPT monitoring) |
| Timing detection risk | Low-Medium | Low | HIGH | HIGH |
| Config space depth check | Unknown (VM'd) | Medium | Unknown | Deep |
| Boot-time baseline | No | No | No | YES |
| Update frequency | CDN-based, fast | Moderate | Unknown | Frequent |

---

## 7. CaptainDMA 75T Specific Considerations for i9-12900K

### 7.1 Slot Selection and Link Width Constraint

For the i9-12900K system:
- **Recommended**: Chipset PCIe x1 slot — common for expansion cards, less suspicious
- **Avoid**: M.2 slot (would need to emulate NVMe, complex) or primary x16 slot (suspicious for a x1 device)
- **Alternative**: M.2 with adapter if the board has unused M.2 slots and the emulated device matches

**Critical hardware constraint**: The CaptainDMA 75T is Gen2 **x1 only**. The root port's Link Status register will always report x1 negotiated width. This limits device emulation targets to devices that genuinely operate at x1 — network cards (Intel I225-V), sound cards, or USB controllers. Emulating an NVMe (x4) or GPU (x16) while the root port reports x1 is a detectable mismatch. FACEIT specifically flags Artix-7 devices that claim wider link than actually negotiated.

### 7.2 BIOS Configuration

For DMA card operation on Z690/Z790:
1. VT-d: Can leave enabled (consumer boards typically don't enforce for internal PCIe)
2. Above 4G Decoding: Enable (ensures proper BAR allocation)
3. Secure Boot: If disabled, Kernel DMA Protection is off entirely
4. CSM: Disable (modern UEFI boot, reduces attack surface from anti-cheat perspective)

### 7.3 Performance Expectations

On i9-12900K with CaptainDMA 75T in chipset x1 slot:

| Operation | Estimated Time | Notes |
|-----------|---------------|-------|
| Single 8-byte read | 1-3 μs | Through DMI + PCH + PCIe |
| Page table walk (4 levels) | 4-12 μs | 4 sequential reads |
| Virtual memory read (page walk + data) | 5-15 μs | Full VA → PA translation + read |
| EPROCESS scan (8GB RAM) | 30-60 seconds | Sequential page scan |
| Full RAM scan (32GB) | 2-4 minutes | Sequential scan of all pages |
| Targeted game state read | 10-50 μs | Walk + read specific offset |
| Read loop at 60 Hz | 16.6 ms budget | Ample time for dozens of reads per frame |

### 7.4 Comparison: DMA vs BYOVD for This Hardware

| Factor | CaptainDMA 75T | BYOVD (Corsair/TRIXX) |
|--------|----------------|----------------------|
| **Speed** | 1-15 μs per read | <1 μs (kernel mode, no PCIe overhead) |
| **Detection surface** | Physical PCIe device | Driver in PsLoadedModuleList (unlinkable) |
| **Kernel write** | Yes (DMA MWr TLP) | Yes (IOCTL-based) |
| **Anti-cheat interaction** | None (hardware level) | May trigger callbacks/scans |
| **BSOD risk** | Low (no kernel code) | Medium (kernel code execution) |
| **Cost** | $100-200 hardware | Free (software only) |
| **Setup complexity** | High (firmware, emulation) | Medium (service install, IOCTL) |
| **PatchGuard risk** | None (no kernel hooks) | Medium (if hooking) |
| **Cross-game** | Universal (hardware) | Per-game AC compatibility |

### 7.5 Hybrid Approach Considerations

The most robust approach would combine BYOVD + DMA:
1. **DMA for reconnaissance**: Read game state externally (no kernel footprint)
2. **BYOVD for kernel operations**: If kernel-level modifications are needed (disabling AC checks, DKOM), use the existing BYOVD infrastructure
3. **DMA as fallback**: If BYOVD driver gets blocklisted, DMA provides an alternative read path
4. **BYOVD for CR3**: Use existing CorsairBootstrapCR3() via BYOVD for initial CR3 (faster than DMA EPROCESS scan), then use DMA for subsequent reads

---

## 8. Recommendations for Research Direction

### 8.1 Immediate (Low Risk)

1. **Firmware research**: Study pcileech-fpga source for Artix-7 75T to understand device emulation capabilities
2. **Config space cloning**: Dump the full PCIe config space of real devices on the i9-12900K system (Intel I225-V NIC, Realtek audio, etc.) for emulation targets
3. **IOMMU testing**: On the Z690/Z790 board, verify whether VT-d actually enforces DMA isolation for internal PCIe devices by checking DMAR table flags

### 8.2 Medium Term

4. **Device emulation profile**: Create a config space profile matching a legitimate device on the target system
5. **CR3 walking validation**: Port the existing CorsairBootstrapCR3 logic to a DMA-based reader (same page table walk, different physical memory access method)
6. **Anti-cheat device enumeration analysis**: Dump the WMI device list and SetupDi results that anti-cheats see, identify what a DMA card must match

### 8.3 Long Term

7. **Timing analysis**: Measure the actual timing characteristics of DMA reads vs normal memory access on the i9-12900K to understand detection windows
8. **EAC VM section analysis**: Attempt to lift or trace the VM-protected code in EAC to determine if PCIe enumeration is present
9. **VGK binary analysis**: Obtain and analyze vgk.sys for DMA-specific detection routines
10. **Scatter-read optimization**: Design a read pattern that minimizes timing anomaly surface while maintaining useful data refresh rates

---

## Appendix A: Relevant Project Files

| File | Purpose | DMA Relevance |
|------|---------|---------------|
| `build/ctf_103_eac_analysis.md` | EAC driver dump analysis | Detection mechanisms |
| `build/ctf_110_battleye_analysis.md` | BattlEye driver analysis | Detection mechanisms |
| `build/ctf_104_ace_analysis.md` | ACE anti-cheat analysis | Timing detection |
| `build/eac_ida_deep.txt` | IDA Pro segment/function analysis | VM protection scope |
| `build/eac_ida_deep2.txt` | API string search results | API resolution methods |
| `build/EasyAntiCheat_EOS.sys.i64` | Full IDA Pro database | RE reference |
| `build/byovd_candidates.log` | BYOVD driver candidate list | Alternative primitive comparison |
| `source/mapper/primitive_corsair.hpp` | Corsair BYOVD implementation | CR3 bootstrap reference |
| `source/mapper/primitive_trixx.hpp` | TRIXX BYOVD implementation | CR3 bootstrap reference |
| `source/mapper/mapper.hpp` | KernelPrimitives interface | Abstraction layer |

## Appendix B: Key EPROCESS Offsets (Windows 10 19045)

Used in CR3 walking — identical for BYOVD and DMA:

| Field | Offset | Usage |
|-------|--------|-------|
| Type | +0x000 | Header.Type == 0x03 (process object) |
| DirectoryTableBase | +0x028 | CR3 value for page table walk |
| UniqueProcessId | +0x440 | PID matching |
| ActiveProcessLinks | +0x448 | EPROCESS linked list (FLINK must be kernel VA) |
| ImageFileName | +0x5A8 | 15-byte process name for identification |

These offsets are build-specific and must be updated for different Windows builds.

## Appendix C: Research Sources

### DMA Tools and Frameworks
- pcileech (GitHub) — Ulf Frisk's DMA attack toolkit
- pcileech-fpga (GitHub) — FPGA firmware implementations for DMA cards
- MemProcFS — Virtual filesystem abstraction over DMA-acquired memory
- LeechCore — Memory acquisition library underlying pcileech/MemProcFS
- PCILeechFWGenerator (PyPI) — Automated firmware generation from donor device config

### Intel Platform Documentation
- Intel 12th Gen Datasheet Vol 1 — PCIe support, VT-d specification
- Intel VT-d Specification Rev 2.5/3.0 — DMAR table structure, context tables
- Intel 600 Series PCH Datasheet — Chipset PCIe lanes, DMI 4.0
- Intel TME-MK Datasheet — Memory encryption architecture (transparent to DMA)

### Security Research
- Thunderclap (NDSS 2019) — IOMMU bypass via legitimately mapped DMA regions
- Thunderspy (2020) — Thunderbolt 1/2/3 security vulnerabilities
- Thunderhammer (2025) — Rowhammer via PCIe/Thunderbolt DMA TLPs
- Deferred DMA Attack (DATE 2024) — IOMMU bypass in dynamic hypervisors
- CVE-2025-11901 — UEFI pre-boot IOMMU failure on Intel 600/700 series boards
- "If It Looks Like a Rootkit" (arXiv 2408.00500) — Critical examination of kernel-level AC

### Anti-Cheat Detection
- isdmadead.com — DMA anti-cheat evolution timeline (2016-2026)
- HWIDChanger blog — How anti-cheats detect DMA cheats in 2026
- dma.lystic.dev — Detection vectors and device technical details
- FACEIT Windows Security Requirements FAQ — IOMMU/VBS/TPM enforcement timeline
- DMA for Dummies — Anti-cheat detection methods overview

### PCIe TLP Technical References
- ctf.re — PCIe Part 2: DMA, MMIO, TLPs tutorial
- Xillybus — PCIe DMA requests and completions
- Pen Test Partners — DMA attack techniques and mitigations

### Microsoft Documentation
- Kernel DMA Protection for Thunderbolt — Windows DMA Protection mechanism
- OEM Kernel DMA Protection — Firmware requirements for DMA protection
- IOMMU DMA Remapping (WDDM 3.0) — GPU DMA isolation
- VBS/HVCI — Virtualization-based security features
- Credential Guard — VTL1 credential isolation
