# Masterlist

Index of every artifact across the project: mappers, drivers, BYOVD primitives, cheats, DMA tools, build scripts, and shared headers.

## Mapper Pipeline

| File | Description |
|------|-------------|
| `mapper/main_nal.cpp` | Entry point — CLI arg parsing, driver selection (`--driver nal\|trixx\|corsair\|siv\|ts\|rtcore`), BYOVD load/unload |
| `mapper/mapper.hpp` | Core manual-map engine — PE parsing, section copy, relocation, IAT resolution, TLS callbacks |
| `mapper/mapper.cpp` | Mapper implementation |
| `mapper/primitive_nal.hpp` | NalDrv (Intel) BYOVD backend — phys R/W via IOCTL, PML4 walk, virtual R/W |
| `mapper/primitive_trixx.hpp` | TRIXX (Sapphire GPU util) BYOVD backend — MSR/phys R/W via DeviceIoControl |
| `mapper/primitive_corsair.hpp` | CorsairLLAccess64 BYOVD backend |
| `mapper/primitive_siv.hpp` | SIVX64 BYOVD backend |
| `mapper/primitive_ts.hpp` | ThrottleStop BYOVD backend |
| `mapper/primitive_rtcore.hpp` | RTCore64 (MSI Afterburner) BYOVD backend |
| `mapper/loader_auth.hpp` | Loader authentication stub |
| `mapper/loader_security.hpp` | Loader security/anti-tamper |

## Driver

| File | Description |
|------|-------------|
| `driver/BetestDriver.c` | Kernel driver source — hooks, callbacks, memory access primitives |
| `driver/embedded_data.h` | Embedded driver binary (byte array) |
| `driver/loader.cpp` | Service-based driver loader — `CreateService` + `StartService` |

## Cheats

### DMA Cheats (FPGA PCIe — MemProcFS/VMM)

| File | Description |
|------|-------------|
| `DMA/source/r6_dma.cpp` | Rainbow Six Siege — AnvilNext 2.0, encrypted pointers, map-based radar with floor tabs, localhost-only admin panel |
| `DMA/source/deltaforce_dma.cpp` | Delta Force — UE5, GWorld/ULevel/AActor chain |
| `DMA/source/arenabreakout_dma.cpp` | Arena Breakout Infinite — UE5, GWorld chain |
| `DMA/source/dma_radar.cpp` | Universal DMA radar — engine-agnostic, config-driven |
| `DMA/r6_dma.exe` | Built R6 Siege DMA binary |
| `DMA/r6_launch.bat` | R6 DMA launch script |
| `DMA/CoopyyDMA.exe` | Built Unturned DMA binary |
| `DMA/dma_main.cpp` | Unturned DMA main |
| `DMA/dma_features.h` | Unturned DMA feature implementations |
| `DMA/dma_mem.h` | DMA memory read/write (MemProcFS wrapper) |
| `DMA/dma_config.h` | DMA configuration |
| `DMA/dma_dumper.h` | DMA-based offset dumper |
| `DMA/dma_webserver.h` | Embedded HTTP server for radar |
| `DMA/dma_webui.h` | Radar web UI HTML/JS |
| `DMA/dma_overlay.h` | GDI overlay for ESP |
| `DMA/dma_offsetdump.h` | Offset dump definitions |
| `DMA/esp_client.cpp` | Standalone ESP overlay client |
| `DMA/stealth_menu.cpp` | Stealth menu for DMA config |

### DMA Offset Configs

| File | Game | Engine |
|------|------|--------|
| `DMA/offsets/r6_offsets.ini` | Rainbow Six Siege | AnvilNext 2.0 (Custom) |
| `cheat/dma/apex_offsets.ini` | Apex Legends | Source 2 |
| `cheat/dma/df_offsets.ini` | Delta Force | UE5 |
| `cheat/dma/abi_offsets.ini` | Arena Breakout Infinite | UE5 |
| `cheat/dma/rust_offsets.ini` | Rust | Unity/IL2CPP |
| `cheat/dma/tarkov_offsets.ini` | Escape from Tarkov | Unity/IL2CPP |
| `cheat/dma/cs2_offsets.ini` | Counter-Strike 2 | Source 2 |
| `cheat/dma/pubg_offsets.ini` | PUBG | UE4 |
| `cheat/dma/hunt_offsets.ini` | Hunt: Showdown | CryEngine |
| `cheat/dma/bf2042_offsets.ini` | Battlefield 2042 | Frostbite |
| `cheat/dma/valorant_offsets.ini` | VALORANT | UE4 |

### External Cheats (ReadProcessMemory)

| File | Description |
|------|-------------|
| `cheat/external/apex_external.cpp` | Apex Legends external — Source 2 |
| `cheat/external/deltaforce_external.cpp` | Delta Force external — UE5 |
| `cheat/external/externaltest.cpp` | Unturned external — Mono reflection |
| `cheat/external/features.h` | Feature implementations (ESP, aimbot, etc.) |
| `cheat/external/overlay.h` | GDI overlay rendering |
| `cheat/external/mem.h` / `mem.cpp` | Memory read/write with SEH |
| `cheat/external/mono.h` | Mono runtime reflection |
| `cheat/external/unturned.h` / `.cpp` | Unturned game class resolution |
| `cheat/external/math.h` | Angle calc, world-to-screen |
| `cheat/external/config.h` | Hotkeys and settings |
| `cheat/external/decrypt.h` | Pointer decryption |
| `cheat/external/xstr.h` | XOR string obfuscation |
| `cheat/external/betest_mem.hpp` | BattlEye test memory primitives |
| `cheat/external/betest_stealth.hpp` | BattlEye stealth helpers |
| `cheat/external/gmr_mem.hpp` | GmrDrv memory backend |

### Internal Cheats (DLL Injection)

| File | Description |
|------|-------------|
| `dllmain.cpp` | Unturned internal — Mono reflection, 29 features, GDI overlay |
| `cheat/internal/unturned_internal.cpp` | Unturned internal alt implementation |
| `cheat/internal/mem_internal.hpp` | Internal memory helpers |
| `external/` | Shared headers (same as cheat/external/) |
| `coopyy_dll.sln` | Visual Studio solution |

## Tools

| File | Description |
|------|-------------|
| `tools/dumper2.cpp` | **Game dumper** — engine detection, pattern scanning, **heuristic offset discovery** (string xref tracing, singleton pattern analysis, field offset enumeration). Supports R6/AnvilNext, UE5 (DF, AB), Unity/IL2CPP (Rust). Produces `_offsets.ini` automatically. |
| `tools/dumper2.exe` | Built dumper2 binary |
| `tools/dumper.cpp` | Original dumper (v1) |
| `tools/dumper_dma.cpp` | DMA-based dumper |
| `tools/static_dumper.cpp` | Static PE analysis dumper |
| `tools/apex_dumper.cpp` | Apex Legends specific dumper |
| `tools/offset_mgr.cpp` | Offset manager — tracks and updates offsets |
| `tools/ac_killer.cpp` | Anti-cheat service killer |
| `tools/ac_launch.cpp` | Anti-cheat aware game launcher |
| `tools/be_freeze.cpp` | BattlEye freeze/suspend tool |
| `tools/scan.cpp` | Memory scanner |
| `tools/probe.cpp` / `probe2.cpp` | Driver probe tools |
| `tools/smoke_nal.cpp` | NalDrv smoke test |
| `tools/nttest.cpp` | NT API test |
| `tools/asusopen.cpp` / `asusprobe.cpp` / `asussec.cpp` | ASUS driver probe tools |

## Injector

| File | Description |
|------|-------------|
| `injector/injector.cpp` | DLL injector — `CreateRemoteThread` + `LoadLibraryA` |

## Build Scripts

All in `build_scripts/`:

| Script | Target |
|--------|--------|
| `bld_nal.cmd` | Mapper (main_nal.cpp) |
| `bld_r6_dma.cmd` | R6 Siege DMA cheat |
| `bld_df_dma.cmd` | Delta Force DMA cheat |
| `bld_abi_dma.cmd` | Arena Breakout DMA cheat |
| `bld_dma_radar.cmd` | Universal DMA radar |
| `bld_apex.cmd` | Apex external cheat |
| `bld_df.cmd` | Delta Force external |
| `bld_apex_dumper.cmd` | Apex dumper |
| `bld2.cmd` | Dumper2 |
| `bld_dumper.cmd` | Dumper v1 |
| `bld_loader.cmd` | Driver loader |
| `bld_drv.cmd` | Kernel driver |
| `bld_inject.cmd` | Injector |
| `bld_internal.cmd` | Internal cheat DLL |
| `bld_ext.cmd` | External cheat |
| `build_full.cmd` | Full rebuild (all targets) |

## Key Technical Notes

- **BYOVD pipeline**: `main_nal.cpp` loads a vulnerable signed driver, uses its phys R/W IOCTLs to map unsigned code into kernel space
- **TRIXX freezes under VBox/Hyper-V**: use `--driver nal` in VMs with nested virtualization
- **TRIXX works in VMware Workstation**: safe for testing
- **DMA radar is multi-user**: `/radar` endpoint accessible to anyone on LAN; admin panel (`/`, `/menu`, `/api/set`) is localhost-only
- **Dumper2 heuristic analysis**: replaces IDA dependency — scans raw PE dumps for manager strings, traces code xrefs to find singleton globals, discovers struct field offsets, extracts sig patterns. Works for R6 (AnvilNext), Delta Force/Arena Breakout (UE5), Rust (Unity/IL2CPP)
- **All AC testing is single-player/offline only**
- **Never restart the host PC** — test in VMTEST VM
- **NalDrvIntel is on MS Vulnerable Driver Blocklist** — mapper auto-disables the blocklist on startup
