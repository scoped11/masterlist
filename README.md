# Masterlist

Master index of all tools, drivers, mappers, cheats, and scripts across the PenisFinger and Unturned projects.

Last updated: 2026-07-02

---

## Repositories

| Repo | Description | Visibility |
|------|-------------|------------|
| [PenisFinger](https://github.com/scoped11/PenisFinger) | Core research repo — mapper, primitives, drivers, tools | Private |
| [PenisFingerVM](https://github.com/scoped11/PenisFingerVM) | VM testing sandbox for driver/mapper | Private |
| [masterlist](https://github.com/scoped11/masterlist) | This index | Private |

---

## 1. Mappers

| Name | Source | Binary | Primitive | Status | Notes |
|------|--------|--------|-----------|--------|-------|
| mapper_nal | `PenisFinger/source/mapper/main_nal.cpp` + `mapper.cpp` | `PenisFinger/build/mapper_nal.exe` | NalDrv (IOCTL 0x80862007) | Active | Main mapper — supports TRIXX, NalDrv, Corsair, RTCore, SIV primitives via `--driver` flag |
| mapper_unturned | `Unturned/source/mapper_unturned.cpp` + `mapper_core.cpp` | `Unturned/binaries/mapper_unturned.exe` | NalDrv only | Active | Clean Unturned-only mapper — no TRIXX, no CR3, no phys memory |
| mapper_bedaisy | `Unturned/source/mapper_bedaisy.cpp` | `Unturned/binaries/mapper_bedaisy.exe` | BEDaisy IOCTLs | DEAD | BattlEye patched IOCTLs 0x0022200C/0x00222008/0x00222004 |
| mapper_nal_dkom | — | `PenisFinger/build/mapper_nal_dkom.exe` | NalDrv | Active | DKOM-enhanced variant |

## 2. BYOVD Primitives

| Name | File | CVE / Method | Device | Blocked By | Notes |
|------|------|-------------|--------|------------|-------|
| NalDrv (Intel) | `primitive_nal.hpp` | CVE-2015-2291 | `\\.\Nal` | EAC | Kernel VA R/W via IOCTL 0x80862007. Cases: 15=read DWORD, 21=write DWORD, 0x33=memcpy |
| TRIXX (SIV) | `primitive_trixx.hpp` | BYOVD | `\\.\SIV` | — | Physical memory R/W. **BSOD on host** — PML4 scanner freezes with hypervisor. Use in VM only |
| Corsair | `primitive_corsair.hpp` | BYOVD | `\\.\CorsairLLAccess` | — | Physical memory R/W |
| RTCore | `primitive_rtcore.hpp` | CVE-2019-16098 | `\\.\RTCore64` | — | MSI Afterburner driver. Must be provided manually |
| SIV | `primitive_siv.hpp` | BYOVD | `\\.\SIV` | — | System Information Viewer driver |
| BEDaisy | `primitive_bedaisy.hpp` | — | `\\.\BEDaisy` | — | DEAD — IOCTLs patched by BattlEye |
| Betest | `primitive_betest.hpp` | Custom | `\\.\Betest` (masqueraded) | — | Custom cheat driver primitive. IOCTLs: 0x802 read, 0x803 write, 0x804 alloc |
| IQvW (alt NalDrv) | `primitive_iqvw.hpp` | CVE-2015-2291 | `\\.\Nal` | EAC | Alternative NalDrv struct layout |

## 3. Drivers

| Name | Source | Binary | Purpose | Notes |
|------|--------|--------|---------|-------|
| NalDrvIntel.sys | — (Intel signed) | `Unturned/binaries/NalDrvIntel.sys`, `PenisFinger/build/NalDrvIntel.sys` | BYOVD kernel R/W | Intel-signed, on Vulnerable Driver Blocklist (auto-disabled by mapper) |
| TRIXX.sys | — | `Unturned/binaries/TRIXX.sys` | BYOVD physical R/W | DO NOT USE on host — causes BSOD. VM only |
| Betest.sys | `Unturned/source/BetestDriver.c` | `Unturned/binaries/Betest.sys` | Cheat driver (read/write/alloc) | Masqueraded device names for stealth |
| GmrDrv.sys | `Unturned/driver_source/GmrDrv.c` | `Unturned/binaries/GmrDrv.sys` | Alt cheat driver | |
| HwidSpoof.sys | `Unturned/source/HwidSpoof.c` | `Unturned/binaries/HwidSpoof.sys` | HWID spoofing | Disk serial, NIC MAC, SMBIOS spoofing |
| CorsairLLAccess64.sys | — | `PenisFinger/run/CorsairLLAccess64.sys` | BYOVD primitive | Corsair iCUE driver |

## 4. Cheats

| Name | Source | Binary | Game | Mode | Notes |
|------|--------|--------|------|------|-------|
| externaltest | `PenisFinger/source/cheat/externaltest.cpp` | `PenisFinger/build/externaltest.exe`, `Unturned/binaries/externaltest.exe` | Unturned | External | ESP, aimbot, silent aim, no-recoil, speed/fly hack, god mode, overlay, full menu |
| unturned_internal | `Unturned/source/unturned_internal.cpp` | `Unturned/binaries/unturned_internal.dll` | Unturned | Internal (DLL) | Same features as external, in-process via `mem_internal.hpp` |
| apex_external | `PenisFinger/source/cheat/apex_external.cpp` | `PenisFinger/build/apex_external.exe` | Apex Legends | External | |
| df_external | `PenisFinger/source/cheat/deltaforce_external.cpp` | `PenisFinger/build/df_external.exe` | Delta Force | External | |
| BetestClient | `Unturned/source/BetestClient.cpp` | `Unturned/binaries/BetestClient.exe` | — | — | Driver communication test client |
| df_dma | `cheat/dma/deltaforce_dma.cpp` | — | Delta Force | DMA Radar | FPGA DMA via vmm.dll — runs on PC2, 2D radar + player list |
| abi_dma | `cheat/dma/arenabreakout_dma.cpp` | — | Arena Breakout: Infinite | DMA Radar | FPGA DMA via vmm.dll — player radar + loot radar |

## 5. Tools

| Name | Source | Binary | Purpose |
|------|--------|--------|---------|
| dumper_dma | `tools/dumper_dma.cpp` | — | DMA memory dumper via FPGA — reads unpacked memory at hardware level |
| dumper2 | `PenisFinger/tools/source/dumper2.cpp` | `PenisFinger/build/dumper2.exe` | Process/module memory dumper |
| static_dumper | `PenisFinger/tools/source/static_dumper.cpp` | `PenisFinger/build/static_dumper.exe` | Static PE dumper |
| apex_dumper | `PenisFinger/tools/source/apex_dumper.cpp` | `PenisFinger/build/apex_dumper.exe` | Apex Legends memory dumper |
| injector | `PenisFinger/source/injector/injector.cpp` | `PenisFinger/build/injector.exe` | DLL injector |
| ac_killer | `PenisFinger/tools/source/ac_killer.cpp` | `PenisFinger/build/ac_killer.exe` | Anti-cheat process terminator |
| ac_launch | `PenisFinger/tools/source/ac_launch.cpp` | `PenisFinger/build/ac_launch.exe` | Game launcher with AC bypass |
| be_freeze | `PenisFinger/tools/source/be_freeze.cpp` | `PenisFinger/build/be_freeze.exe` | BattlEye freeze/suspend |
| check_mz | — | `PenisFinger/build/check_mz.exe` | PE header validator |
| offset_mgr | `PenisFinger/tools/source/offset_mgr.cpp` | `PenisFinger/build/offset_mgr.exe` | Game offset manager |
| hwid_ctrl | `Unturned/source/hwid_ctrl.cpp` | `Unturned/binaries/hwid_ctrl.exe` | HWID spoof control (`--spoof-all`) |
| loader | `PenisFinger/betest_legacy/source/loader.cpp` | `PenisFinger/run/loader.exe` | Legacy loader — maps driver, launches cheat, cleans up |
| test_imports | — | `PenisFinger/build/test_imports.exe` | Import resolution tester |

## 6. Build Scripts

| Script | Location | Builds |
|--------|----------|--------|
| bld_nal.cmd | `PenisFinger/build_scripts/` | mapper_nal.exe |
| bld_apex.cmd | `PenisFinger/build_scripts/` | apex_external.exe |
| bld_apex_dumper.cmd | `PenisFinger/build_scripts/` | apex_dumper.exe |
| bld_df.cmd | `PenisFinger/build_scripts/` | df_external.exe |
| bld_ext.cmd | `PenisFinger/build_scripts/` | externaltest.exe |
| bld_inject.cmd | `PenisFinger/build_scripts/` | injector.exe |
| bld_internal.cmd | `PenisFinger/build_scripts/` | unturned_internal.dll |
| bld_loader.cmd | `PenisFinger/build_scripts/` | loader.exe |
| bld_dumper.cmd | `PenisFinger/build_scripts/` | dumper2.exe |
| bld_drv.cmd | `PenisFinger/build_scripts/` | Driver builds |
| build_unturned.cmd | `Unturned/` | mapper_unturned.exe |
| build-betest.ps1 | `Unturned/source/` | Betest.sys |

## 7. Launch Scripts

| Script | Location | Purpose |
|--------|----------|---------|
| launch.cmd | `Unturned/` | Maps HwidSpoof.sys + Betest.sys, runs externaltest.exe |
| spoof.cmd | `Unturned/` | Runs hwid_ctrl.exe --spoof-all (run before game) |

## 8. Shared Headers / Libraries

| File | Location | Purpose |
|------|----------|---------|
| mapper.hpp | Both repos | KernelPrimitives struct + MapResult + ManualMap API |
| mapper_core.cpp | `Unturned/source/` | ManualMap implementation (import resolution, relocations) |
| mapper.cpp | `PenisFinger/source/mapper/` | PenisFinger ManualMap implementation |
| mem.h | `Unturned/source/`, `PenisFinger/source/cheat/external/` | Memory read/write interface (driver or internal) |
| mem_internal.hpp | `Unturned/source/` | In-process memory access (direct pointer dereference) |
| mono.h | Both repos | Mono runtime class/field/method resolution for Unity games |
| loader_auth.hpp | `PenisFinger/source/mapper/` | Authentication system |
| loader_security.hpp | `PenisFinger/source/mapper/` | Security/integrity checks |

## 9. Key Technical Details

### NalDrv IOCTL Struct
```cpp
struct NalOp {
    uint64_t case_number;  // +0x00
    uint64_t pad;          // +0x08: 0
    uint64_t value;        // +0x10: read result / memcpy src
    uint64_t address;      // +0x18: target kernel VA / memcpy dst
    uint64_t writeVal;     // +0x20: write value / memcpy size
    uint64_t size;         // +0x28: unused
};
// IOCTL: 0x80862007 | Device: \\.\Nal
```

### Mapper Pipeline
1. Disable Vulnerable Driver Blocklist (registry)
2. Load NalDrv service (sc create + StartService)
3. Open device, get kernel R/W primitives
4. Resolve ntoskrnl base, HalDispatchTable, PsLoadedModuleList
5. Find PteBase via MmPteBase pattern scan
6. Find code cave in NalDrv .data section
7. Clear NX on cave pages via PTE manipulation
8. Wire AllocateKernelMemory via HAL dispatch trick
9. ManualMap target driver (sections, relocations, imports)
10. Execute DriverEntry via HAL dispatch stub
11. DKOM unlink NalDrv from PsLoadedModuleList
12. Unload NalDrv service + registry cleanup

### Anti-Cheat Compatibility
| Game | AC | NalDrv | TRIXX | DMA |
|------|-----|--------|-------|-----|
| Unturned | BattlEye | Works | BSOD on host | Works |
| Apex Legends | EAC | Blocked | Works (VM only) | Works |
| Delta Force | EAC | Blocked | Works (VM only) | Works — `deltaforce_dma.cpp` |
| Arena Breakout: Infinite | ACE | Blocked | N/A | Works — `arenabreakout_dma.cpp` |

### Host Machine
- CPU: Intel i9-12900K (VT-x on, VT-d off)
- GPU: NVIDIA RTX 5070
- OS: Windows 10 Pro 10.0.19045
- VM: VMware Workstation Pro (VMTEST sandbox)
- DMA card: Not installed

## 10. Known Issues / Warnings

- **TRIXX causes BSOD on host** — PML4 self-reference scanner freezes with hypervisor interference. Use `--driver nal` or test in VM only.
- **mapper_nal.exe argument order matters** — target .sys MUST be argv[1] BEFORE flags: `mapper_nal.exe Betest.sys --driver nal` (NOT `--driver nal Betest.sys`)
- **BEDaisy IOCTLs are dead** — mapper_bedaisy.exe no longer works
- **NalDrvIntel.sys is on Microsoft's Vulnerable Driver Blocklist** — mapper auto-disables the blocklist via registry
- **WdBroker service causes EAC to not boot** — do not create this service
- **Never restart host PC** — test in VMTEST VM only
- **All AC testing is single-player/offline** — research methodology for the book
