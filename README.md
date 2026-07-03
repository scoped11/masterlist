# Masterlist

Index of every artifact across the project: mappers, drivers, BYOVD primitives, cheats (DMA + external + internal), DMA firmware, HWID spoofer, dumpers, tools, build scripts, and shared headers.

---

## 1. Mapper Pipeline

Manual-map engine that loads unsigned kernel drivers via BYOVD (Bring Your Own Vulnerable Driver).

| File | Description |
|------|-------------|
| `mapper/main_nal.cpp` | Entry point — CLI arg parsing, driver selection (`--driver nal\|trixx\|corsair\|siv\|ts\|rtcore\|lnv`), BYOVD load/unload |
| `mapper/mapper.hpp` | Core manual-map engine — PE parsing, section copy, relocation, IAT resolution, TLS callbacks |
| `mapper/mapper.cpp` | Mapper implementation |

### BYOVD Primitives

| File | Driver | IOCTL / Method |
|------|--------|----------------|
| `mapper/primitive_nal.hpp` | NalDrvIntel (iqvw64e) | Phys R/W via IOCTL `0x80862007`, PML4 walk, virtual R/W |
| `mapper/primitive_trixx.hpp` | TRIXX (Sapphire GPU util) | MSR/phys R/W, PML4 scanner w/ `--cr3` override |
| `mapper/primitive_corsair.hpp` | CorsairLLAccess64 | Phys R/W |
| `mapper/primitive_siv.hpp` | SIVX64 (Sisoft Sandra) | Phys R/W |
| `mapper/primitive_ts.hpp` | ThrottleStop | MSR-based R/W |
| `mapper/primitive_rtcore.hpp` | RTCore64 (MSI Afterburner) | Phys R/W |
| `mapper/primitive_lnv.hpp` | LnvMSRIO (Lenovo) | MSR/phys R/W (testing) |

### Mapper Auth & Security

| File | Description |
|------|-------------|
| `mapper/loader_auth.hpp` | Loader authentication stub |
| `mapper/loader_security.hpp` | Loader security / anti-tamper |

### Built Binaries

| Binary | Location | Description |
|--------|----------|-------------|
| `mapper_nal.exe` | `build/`, `run/`, `vm/vm_transfer/` | Primary mapper (current) |
| `mapper_rtcore.exe` | `archive/` | RTCore64 variant (legacy) |
| `mapper_vbox.exe` | `archive/` | VirtualBox variant (legacy) |
| `mapper_vm.exe` | `archive/` | Hyper-V/VM-aware (legacy) |
| `mapper.exe` | `archive/` | Original mapper (legacy) |

---

## 2. Kernel Driver

| File | Description |
|------|-------------|
| `driver/BetestDriver.c` | Kernel driver source — hooks, callbacks, memory access primitives, anti-cheat bypass |
| `driver/embedded_data.h` | Embedded driver binary (byte array for mapper) |
| `driver/loader.cpp` | Service-based driver loader (`CreateService` + `StartService`) |
| `Betest.sys` | Built driver binary |

---

## 3. DMA Cheats (FPGA PCIe)

All DMA cheats run on **PC2** (radar PC with FPGA card), reading game memory from **PC1** (gaming PC) over PCIe. Multi-user web radar served on LAN; admin panel is localhost-only.

### R6 Siege DMA

| File | Description |
|------|-------------|
| `cheat/r6_dma.cpp` | Rainbow Six Siege — AnvilNext 2.0, sig-scanned offsets, encrypted pointer decryption, floor-tabbed radar, operator icons, admin panel |
| `r6_dma.exe` | Built binary |
| `r6_launch.bat` | Launch script |
| `r6_offsets.ini` | Offset config (auto-discovered by dumper2) |

### Delta Force DMA

| File | Description |
|------|-------------|
| `DMA/source/deltaforce_dma.cpp` | Delta Force — UE5, GWorld/ULevel/AActor chain |
| `df_dma.exe` | Built binary |
| `df_offsets.ini` | Offset config |

### Arena Breakout Infinite DMA

| File | Description |
|------|-------------|
| `DMA/source/arenabreakout_dma.cpp` | Arena Breakout Infinite — UE5, GWorld chain |
| `abi_dma.exe` | Built binary |
| `abi_offsets.ini` | Offset config |

### Unturned DMA

| File | Description |
|------|-------------|
| `DMA/dma_main.cpp` | Unturned DMA reader (runs on PC2) — Mono/.NET reflection, item/player/zombie radar |
| `DMA/dma_features.h` | Feature implementations |
| `DMA/dma_mem.h` | MemProcFS memory wrapper |
| `DMA/dma_config.h` | Configuration |
| `DMA/dma_webserver.h` | Embedded HTTP server for radar |
| `DMA/dma_webui.h` | Radar web UI (HTML/JS) |
| `DMA/dma_overlay.h` | GDI overlay for ESP |
| `DMA/dma_dumper.h` | DMA-based offset dumper |
| `DMA/dma_offsetdump.h` | Offset dump definitions |
| `DMA/esp_client.cpp` | Standalone ESP overlay client (runs on PC1, receives data from PC2) |
| `DMA/stealth_menu.cpp` | Stealth menu for DMA config |
| `CoopyyDMA.exe` | Built Unturned DMA binary |
| `unturned_client.exe` | Built ESP client binary |

### Universal DMA Radar

| File | Description |
|------|-------------|
| `DMA/source/dma_radar.cpp` | Engine-agnostic DMA radar — config-driven, works with any game offset config |
| `dma_radar.exe` | Built binary |

### DMA Offset Configs (all games)

| File | Game | Engine |
|------|------|--------|
| `r6_offsets.ini` | Rainbow Six Siege | AnvilNext 2.0 |
| `df_offsets.ini` | Delta Force | UE5 |
| `abi_offsets.ini` | Arena Breakout Infinite | UE5 |
| `apex_offsets.ini` | Apex Legends | Source 2 |
| `rust_offsets.ini` | Rust | Unity/IL2CPP |
| `tarkov_offsets.ini` | Escape from Tarkov | Unity/IL2CPP |
| `cs2_offsets.ini` | Counter-Strike 2 | Source 2 |
| `pubg_offsets.ini` | PUBG | UE4 |
| `hunt_offsets.ini` | Hunt: Showdown | CryEngine |
| `bf2042_offsets.ini` | Battlefield 2042 | Frostbite |
| `valorant_offsets.ini` | VALORANT | UE4 |
| `speeder_unturned.ini` | Unturned | Unity/Mono |

---

## 4. DMA Firmware (FPGA)

CaptainDMA 75T (Xilinx xc7a75tfgg484-2) PCIe FPGA card for DMA memory reads. Firmware built from pcileech-fpga.

| File | Description |
|------|-------------|
| `pcileech-fpga/` | Full pcileech-fpga source (cloned from `ufrisk/pcileech-fpga`) |
| `CaptainDMA/75t484_x1/` | Board-specific project (75T, 484-pin, x1 lane) |
| `ip/pcie_7x_0.xci` | Xilinx PCIe IP core config (VID/DID baked at synthesis) |
| `ip/pcileech_cfgspace.coe` | Shadow config space BRAM init (device identity for pcileech) |
| `ip/pcileech_cfgspace_writemask.coe` | Config space write masks (BAR sizing, register writability) |
| `src/pcileech_pcie_cfg_a7.sv` | Config management — DSN, command register auto-set, cfg_mgmt interface |
| `src/pcileech_pcie_a7.sv` | PCIe wrapper — IP core instantiation, TLP engine, shadow module |
| `src/pcileech_tlps128_cfgspace_shadow.sv` | Shadow config space — intercepts CfgRd/CfgWr TLPs when `cfgtlp_en` set |
| `src/pcileech_pcie_tlp_a7.sv` | TLP processing — bar controller, filter, TX mux |
| `vivado_combined_build.tcl` | Combined build script (generate + synth + impl + bitstream) |
| `pcileech_75t484_x1.bin` | Built bitstream binary |

### Firmware Build Notes

- Build with Vivado: `vivado -mode batch -source vivado_combined_build.tcl`
- `upgrade_ip [get_ips *]` on line 593 of generate script upgrades ALL IPs to installed Vivado version
- **DO NOT modify `pcie_7x_0.xci`** to change device identity — it regenerates the PCIe IP core and breaks TLP handling
- Identity changes go in the COE files only (shadow BRAM); pcileech software enables shadow mode at runtime
- Original pcileech-fpga COE uses sentinel pattern (`0xFFFFF000 + offset`), overwritten by pcileech software via USB
- Physical layer: Gen2 x1, FT601 USB3 for PC2 communication

### FPGA Tools

| File | Description |
|------|-------------|
| `openFPGALoader.exe` | FPGA bitstream flasher |
| `openocd.exe` | JTAG debugger |
| `CH347FpgaDownloadTool.exe` | CH347 USB-to-SPI/JTAG flasher |
| `zadig.exe` | USB driver installer (for FT601/CH347) |

---

## 5. External Cheats (ReadProcessMemory)

Standalone overlay cheats — read game memory from usermode, render with GDI overlay. Streamproof.

### Apex Legends External

| File | Description |
|------|-------------|
| `cheat/external/apex_external.cpp` | Source 2 — ESP, aimbot, triggerbot, no-recoil, skeleton, health bars |
| `apex_external.exe` | Built binary |

### Delta Force External

| File | Description |
|------|-------------|
| `cheat/external/deltaforce_external.cpp` | UE5 — same feature set as Apex, reads `df_offsets.ini` |
| `df_external.exe` | Built binary |

### Unturned External

| File | Description |
|------|-------------|
| `cheat/external/externaltest.cpp` | Mono reflection — player/zombie/item ESP |
| `externaltest.exe` | Built binary |

### Shared External Headers

| File | Description |
|------|-------------|
| `cheat/external/features.h` | Feature implementations (ESP, aimbot, triggerbot, radar) |
| `cheat/external/overlay.h` | GDI overlay rendering (streamproof) |
| `cheat/external/mem.h` / `mem.cpp` | Memory R/W with SEH |
| `cheat/external/mono.h` | Mono runtime reflection (class/field resolution) |
| `cheat/external/unturned.h` / `.cpp` | Unturned game class resolution |
| `cheat/external/math.h` | Angle calc, world-to-screen projection |
| `cheat/external/config.h` | Hotkeys and settings |
| `cheat/external/decrypt.h` | Pointer decryption |
| `cheat/external/xstr.h` | XOR string obfuscation |
| `cheat/external/betest_mem.hpp` | BattlEye test memory primitives |
| `cheat/external/betest_stealth.hpp` | BattlEye stealth helpers |
| `cheat/external/gmr_mem.hpp` | GmrDrv memory backend |

---

## 6. Internal Cheats (DLL Injection)

| File | Description |
|------|-------------|
| `dllmain.cpp` | Unturned internal — Mono reflection, 29 features, GDI overlay |
| `cheat/internal/unturned_internal.cpp` | Unturned internal alt implementation |
| `cheat/internal/mem_internal.hpp` | Internal memory helpers |
| `coopyy_dll.sln` | Visual Studio solution |

---

## 7. HWID Spoofer

Hardware ID spoofing for disk serial, MAC address, SMBIOS, and GPU identifiers.

| File | Description |
|------|-------------|
| `hwid/source/HwidSpoof.c` | Kernel driver — disk/NIC/SMBIOS/GPU serial spoofing via IRP hooks |
| `hwid/source/hwid_ctrl.cpp` | Usermode controller — `--spoof-all`, `--disk`, `--mac`, `--smbios`, `--gpu`, `--clean`, `--restore` |
| `HwidSpoof.sys` | Built driver binary |
| `hwid_ctrl.exe` | Built controller binary |

---

## 8. Dumpers & Offset Discovery

### Dumper2 (Primary)

Automated game offset discovery — replaces IDA dependency.

| File | Description |
|------|-------------|
| `tools/dumper2.cpp` | Multi-engine dumper: pattern scanning, heuristic offset discovery (string xref tracing, singleton pattern analysis, field offset enumeration), JVM/HotSpot class analysis |
| `dumper2.exe` | Built binary |

**Supported engines:**
- **AnvilNext 2.0** (R6 Siege) — manager string xref -> singleton global -> struct field offsets
- **UE5** (Delta Force, Arena Breakout) — GWorld/ULevel/AActor chain discovery
- **Unity/IL2CPP** (Rust) — metadata-driven offset extraction
- **Java/libGDX** (Stalcraft/STALZONE) — `gHotSpotVMStructs` walking, ClassLoaderDataGraph enumeration, field offset extraction

**Output:** `<game>_offsets.ini` and `<game>_jvm_classes.ini` (auto-generated, DMA-ready)

### Other Dumpers

| File | Description |
|------|-------------|
| `tools/dumper.cpp` | Original dumper (v1, pattern scan only) |
| `tools/dumper_dma.cpp` | DMA-based dumper (reads via FPGA instead of RPM) |
| `tools/static_dumper.cpp` | Static PE analysis dumper (offline, no running process needed) |
| `tools/apex_dumper.cpp` | Apex Legends specific dumper |
| `DMA/dma_dumper.h` | Inline DMA offset dumper |

### Process Dumps (raw PE dumps for offline analysis)

| File | Description |
|------|-------------|
| `RainbowSix.exe.dump.bin` | R6 Siege main executable (~106MB) |
| `RainbowSixHelper.exe.dump.bin` | R6 helper process |
| `RainbowSix_BE.exe.dump.bin` | R6 BattlEye launcher |
| `UbisoftConnectInstaller.exe.dump.bin` | Ubisoft Connect |

---

## 9. Injector

| File | Description |
|------|-------------|
| `injector/injector.cpp` | DLL injector — `CreateRemoteThread` + `LoadLibraryA`, ManualMap, Shellcode methods |
| `injector.exe` | Built binary |

---

## 10. Loader

| File | Description |
|------|-------------|
| `loader.exe` | GUI loader — AES-encrypted embedded binaries, auth, service setup |
| `run/loader.exe` | Deployed copy |

---

## 11. Tools & Utilities

### Anti-Cheat Tools

| File | Description |
|------|-------------|
| `tools/ac_killer.cpp` | Anti-cheat service killer |
| `tools/ac_launch.cpp` | Anti-cheat aware game launcher |
| `tools/be_freeze.cpp` | BattlEye freeze/suspend tool |
| `ToggleDefender.bat` | Windows Defender toggle |

### Driver Probes & Testing

| File | Description |
|------|-------------|
| `tools/probe.cpp` / `probe2.cpp` | Driver device probing (enumerate IOCTLs) |
| `tools/smoke_nal.cpp` | NalDrv IOCTL smoke test |
| `tools/driver_probe.cpp` | Generic driver probe |
| `tools/asusopen.cpp` / `asusprobe.cpp` / `asussec.cpp` | ASUS driver probe tools |
| `tools/nttest.cpp` | NT API test |
| `tools/check_mz.cpp` | PE MZ header validator |
| `tools/test_alloc.exe` | Kernel allocation tester |

### Offset Management

| File | Description |
|------|-------------|
| `tools/offset_mgr.cpp` | Offset manager — tracks and updates offsets across games |
| `tools/speeder_offsets.cpp` | Game offset scanner |
| `tools/scan.cpp` | Memory/module scanner |

---

## 12. BYOVD Driver Binaries

Vulnerable signed drivers used by the mapper pipeline.

| Driver | File | Status |
|--------|------|--------|
| NalDrvIntel (iqvw64e) | `NalDrv.sys` / `NalDrvIntel.sys` | Primary — on MS Vulnerable Driver Blocklist (mapper auto-disables) |
| TRIXX (Sapphire) | loaded from Sapphire install | Freezes under VBox/Hyper-V; works in VMware |
| CorsairLLAccess64 | `CorsairLLAccess64.sys` | Working |
| SIVX64 | `SIVX64.sys` | Working |
| ThrottleStop | `ThrottleStop.sys` | Working |
| RTCore64 | `RTCore64.sys` | Working |
| LnvMSRIO | `LnvMSRIO.sys` | Testing (Lenovo MSR I/O) |
| GmrDrv | `GmrDrv.sys` | Legacy |
| WdBroker | `WdBroker.sys` | Breaks EAC — do not use |

---

## 13. BattlEye Test Legacy

| File | Description |
|------|-------------|
| `betest_legacy/source/embedded_data.h` | Embedded driver binary |
| `betest_legacy/binaries/BetestClient.exe` | BE test client |
| `betest_legacy/binaries/loader.exe` | BE test loader |
| `betest_legacy/binaries/mapper_bedaisy.exe` | BEDaisy mapper variant |
| `betest_legacy/binaries/test_bedaisy.exe` | BEDaisy test harness |

---

## 14. VM Testing & Transfer

| File | Description |
|------|-------------|
| `vm/vm_transfer/` | Transfer folder — mapper binaries + drivers copied to VMTEST VM |
| `vm/vm_transfer/mapper_nal.exe` | Mapper copy for VM |
| `vm/vm_transfer/mapper_nal6-8.exe` | Versioned mapper copies |
| `vm/vm_transfer/transfer.iso` | ISO for VM file transfer |
| `vm/*.ps1` / `*.bat` / `*.vbs` | VM automation scripts (setup, test, deploy) |

---

## 15. Archive (Legacy / Deprecated)

| File | Description |
|------|-------------|
| `archive/mapper.exe` | Original mapper |
| `archive/mapper_rtcore.exe` | RTCore variant |
| `archive/mapper_vbox.exe` | VirtualBox variant |
| `archive/mapper_vboxinject.exe` / `.dll` | VBox injection variant |
| `archive/mapper_vm.exe` | Hyper-V variant |
| `archive/mapper_vi2.dll` / `vi3.dll` / `vi4.dll` | Injection DLL variants |
| `archive/GmrDrv_build_dupe.sys` | GmrDrv duplicate |
| `archive/NalDrv.sys` | NalDrv copy |
| `archive/NalDrvIntel_build_dupe.sys` | NalDrvIntel duplicate |
| `archive/gdAYW.sys` | Legacy driver |

---

## 16. Build Scripts

All in `build_scripts/`:

### DMA Cheats
| Script | Target |
|--------|--------|
| `bld_r6_dma.cmd` | R6 Siege DMA |
| `bld_df_dma.cmd` | Delta Force DMA |
| `bld_abi_dma.cmd` | Arena Breakout DMA |
| `bld_dma_radar.cmd` | Universal DMA radar |

### External Cheats
| Script | Target |
|--------|--------|
| `bld_apex.cmd` | Apex Legends external |
| `bld_df.cmd` | Delta Force external |
| `bld_ext.cmd` | Unturned external |

### Core
| Script | Target |
|--------|--------|
| `bld_nal.cmd` | Mapper (main_nal.cpp) |
| `bld_drv.cmd` | Kernel driver |
| `bld_inject.cmd` | Injector |
| `bld_loader.cmd` | Loader |
| `bld_internal.cmd` | Internal cheat DLL |

### Tools
| Script | Target |
|--------|--------|
| `bld2.cmd` | Dumper2 |
| `bld_dumper.cmd` | Dumper v1 |
| `bld_apex_dumper.cmd` | Apex dumper |
| `build_full.cmd` | Full rebuild (all targets) |

---

## Key Technical Notes

- **BYOVD pipeline**: `main_nal.cpp` loads a vulnerable signed driver, uses its phys R/W IOCTLs to walk PML4 and map unsigned code into kernel space
- **2PC DMA architecture**: PC1 = gaming PC (i9-12900K, runs games + AC), PC2 = radar PC (CaptainDMA 75T FPGA, runs MemProcFS + DMA cheats). PCIe x1 Gen2 link
- **DMA firmware identity**: PCIe IP core VID/DID is baked at synthesis (XCI); shadow BRAM provides identity to pcileech software over USB. Only modify COE files, never XCI
- **DMA radar is multi-user**: `/radar` endpoint accessible to anyone on LAN; admin panel (`/`, `/menu`, `/api/set`) is localhost-only
- **TRIXX freezes under VBox/Hyper-V**: use `--driver nal` in VMs with nested virtualization; TRIXX works in VMware Workstation
- **Dumper2 heuristic analysis**: replaces IDA — scans raw PE dumps for manager strings, traces code xrefs to find singleton globals, discovers struct field offsets. Works for R6 (AnvilNext), DF/AB (UE5), Rust (IL2CPP), Stalcraft (JVM/libGDX)
- **NalDrvIntel is on MS Vulnerable Driver Blocklist** — mapper auto-disables the blocklist on startup
- **WdBroker breaks EAC** — do not use
- **All AC testing is single-player/offline only**
- **Never restart the host PC** — test in VMTEST VM only
- **Mapper argv order**: `mapper_nal.exe <driver.sys> --driver <name>` (not reversed)

---

## 17. SWHE External Cheat (Usermode-Only)

Unturned external cheat using the **WaryasSWHE** (Shatter Window Hook Exploit) for memory access. No kernel driver, no mapper, no admin. Pure usermode exploit via `SetWindowsHookExA` + `SendMessageA(WM_APPCOMMAND)` through SHCore.dll shared memory.

See **[swhe/README.md](swhe/README.md)** for full setup guide, architecture docs, and how to add features / port to other games.

| File | Description |
|------|-------------|
| `swhe/source/main.cpp` | Entry point — security init, SWHE attach, Mono resolve, feature loop |
| `swhe/source/mem.h` / `mem.cpp` | Memory interface — `read<T>()`, `write<T>()` over SWHE |
| `swhe/source/mem_swhe.h` | SWHE wrapper — chunked R/W (0x700 limit), global CProcess/CExploit |
| `swhe/source/mono.h` | Mono runtime reflection — class/field/method discovery |
| `swhe/source/features.h` | All features — ESP, aimbot, weapon mods, movement, god mode |
| `swhe/source/overlay.h` | GDI overlay — streamproof (WDA_EXCLUDEFROMCAPTURE), menu, ESP rendering |
| `swhe/source/security.h` | Anti-debug (8 vectors), anti-dump, anti-attach, CRC32 integrity heartbeat |
| `swhe/source/unturned.h` / `.cpp` | Game classes + Mono offset resolution |
| `swhe/source/types/` | Game structs (SDG::Player, etc.) + Unity engine types (Transform, GameObject) |
| `swhe/WaryasSWHE/` | Exploit source — shared memory finder, gadget scanner, hook-triggered R/W |
| `swhe/build.cmd` | Build script |
| `swhe/unturned_swhe.exe` | Pre-built binary |

---

## 18. Session Transcripts

Full Claude Code conversation logs, extracted from all project sessions and organized by project.

See **[sessions/INDEX.md](sessions/INDEX.md)** for the full table with dates, first messages, and links.

| Project | Sessions | Description |
|---------|----------|-------------|
| [CTF-Competition](sessions/CTF-Competition/) | 10 | CTF challenge — driver hooking, BattlEye integration, Unturned + mapper pipeline |
| [Map-Project](sessions/Map-Project/) | 2 | Map/game utility sessions |
| [Misc](sessions/Misc/) | 1 | VMware Workstation Pro setup |
| [PenisFinger](sessions/PenisFinger/) | 27 | Main project — mapper, driver, DMA cheats, HWID spoofer, firmware, dumpers, stealth |
| [CTF-Downloads](sessions/CTF-Downloads/) | 2 | CTF download/setup sessions |

---

## Host Machine Profile

- **PC1** (Gaming/Build): i9-12900K, Windows 10 Pro
- **PC2** (Radar/DMA): CaptainDMA 75T FPGA, FT601 USB3
- **VMTEST**: VMware Workstation Windows 10 sandbox
